/* Delta Recorder transport.  See journal.h. */
#define _POSIX_C_SOURCE 200809L
#include "journal.h"
#include "jsonw.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define KIND_EVENT	1u
#define KIND_REJECTION	2u
#define KIND_ACK	3u

struct pending {
	struct pending *next;
	uint64_t seq, cookie;
	uint8_t *frame;
	size_t frame_len;
	char sha[65];
	int sent_once;		/* a complete copy reached the channel */
	uint64_t sent_at;
};

struct nfsp_journal {
	int fd, is_socket, failed;
	char session[NFSP_JOURNAL_SESSION_ID_MAX + 1];
	char rule_set_id[65];
	uint32_t retransmit_ms;
	uint64_t (*clock_ms)(void *);
	void *clock_arg;
	nfsp_journal_done_fn done;
	void *done_arg;

	uint64_t next_seq;
	struct pending *head, *tail;
	size_t npending;
	/* The copy being written.  It is finished even if its event is
	 * answered meanwhile: a half-written frame would desynchronise the
	 * channel. */
	uint8_t *tx;
	size_t tx_len, tx_off;
	uint64_t tx_seq;

	uint8_t *rx;
	size_t rx_len, rx_cap;
	struct nfsp_journal_stats stats;
};

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t now_ms(const struct nfsp_journal *j)
{
	return j->clock_ms ? j->clock_ms(j->clock_arg) : monotonic_ms();
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

uint8_t *nfsp_journal_frame(uint16_t kind, const uint8_t *payload,
			    size_t len, size_t *frame_len)
{
	uint8_t *f;

	if (len == 0 || len > NFSP_JOURNAL_MAX_PAYLOAD)
		return NULL;
	f = malloc(NFSP_JOURNAL_HEADER_LEN + len);
	if (f == NULL)
		return NULL;
	memcpy(f, "NFSPJNL1", 8);
	put16(f + 8, 1);
	put16(f + 10, kind);
	put32(f + 12, (uint32_t)len);
	nfsp_sha256(payload, len, f + 16);
	nfsp_sha256(f, 48, f + 48);
	memcpy(f + NFSP_JOURNAL_HEADER_LEN, payload, len);
	*frame_len = NFSP_JOURNAL_HEADER_LEN + len;
	return f;
}

static int valid_session_id(const char *s)
{
	size_t n = strlen(s);

	if (n == 0 || n > NFSP_JOURNAL_SESSION_ID_MAX)
		return 0;
	for (; *s; s++)
		if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
		      (*s >= '0' && *s <= '9') || strchr("_.:/-", *s)))
			return 0;
	return 1;
}

static int valid_event_type(const char *s)
{
	size_t n = 0;

	for (; s[n] != '\0'; n++)
		if (n >= 32 || !((s[n] >= 'A' && s[n] <= 'Z') || s[n] == '_'))
			return 0;
	return n > 0;
}

static int valid_hex64(const char *s)
{
	if (strlen(s) != 64)
		return 0;
	for (; *s; s++)
		if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f')))
			return 0;
	return 1;
}

int nfsp_journal_open(struct nfsp_journal **out,
		      const struct nfsp_journal_cfg *cfg)
{
	struct nfsp_journal *j;
	struct stat st;
	int flags;

	*out = NULL;
	if (cfg == NULL || cfg->fd < 0 || cfg->done == NULL ||
	    cfg->proxy_session_id == NULL || cfg->rule_set_id == NULL ||
	    !valid_session_id(cfg->proxy_session_id) ||
	    !valid_hex64(cfg->rule_set_id) || fstat(cfg->fd, &st) != 0)
		return -1;
	flags = fcntl(cfg->fd, F_GETFL, 0);
	if (flags < 0 || fcntl(cfg->fd, F_SETFL, flags | O_NONBLOCK) != 0)
		return -1;
	j = calloc(1, sizeof(*j));
	if (j == NULL)
		return -1;
	j->fd = cfg->fd;
	j->is_socket = S_ISSOCK(st.st_mode);
	strcpy(j->session, cfg->proxy_session_id);
	strcpy(j->rule_set_id, cfg->rule_set_id);
	j->retransmit_ms = cfg->retransmit_ms ? cfg->retransmit_ms :
			   NFSP_JOURNAL_DEFAULT_RETRANSMIT_MS;
	j->clock_ms = cfg->clock_ms;
	j->clock_arg = cfg->clock_arg;
	j->done = cfg->done;
	j->done_arg = cfg->done_arg;
	*out = j;
	return 0;
}

static void free_pending(struct pending *p)
{
	free(p->frame);
	free(p);
}

void nfsp_journal_close(struct nfsp_journal *j)
{
	if (j == NULL)
		return;
	while (j->head != NULL) {
		struct pending *p = j->head;

		j->head = p->next;
		free_pending(p);
	}
	if (j->fd >= 0)
		close(j->fd);
	free(j->tx);
	free(j->rx);
	free(j);
}

int nfsp_journal_submit(struct nfsp_journal *j, const char *event_type,
			const char *payload_json, size_t payload_len,
			uint64_t cookie, uint64_t *event_seq)
{
	struct nfsp_jbuf b;
	struct pending *p;
	uint8_t digest[NFSP_SHA256_LEN];

	if (j == NULL || event_type == NULL || payload_json == NULL ||
	    payload_len < 2 || payload_json[0] != '{' ||
	    payload_json[payload_len - 1] != '}' ||
	    !valid_event_type(event_type) || j->next_seq == UINT64_MAX)
		return -1;
	nfsp_jb_init(&b, NFSP_JOURNAL_MAX_REQUEST);
	nfsp_jb_raw(&b, "{");
	nfsp_jb_key(&b, "event_seq", 1);
	nfsp_jb_u64(&b, j->next_seq);
	nfsp_jb_key(&b, "event_type", 0);
	nfsp_jb_str(&b, event_type);
	nfsp_jb_key(&b, "payload", 0);
	nfsp_jb_rawn(&b, payload_json, payload_len);
	nfsp_jb_key(&b, "proxy_session_id", 0);
	nfsp_jb_str(&b, j->session);
	nfsp_jb_key(&b, "rule_set_id", 0);
	nfsp_jb_str(&b, j->rule_set_id);
	nfsp_jb_key(&b, "schema_version", 0);
	nfsp_jb_str(&b, "nfs-proxy-journal-request.v1");
	nfsp_jb_raw(&b, "}");
	if (b.failed) {
		nfsp_jb_free(&b);
		return -1;
	}
	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		nfsp_jb_free(&b);
		return -1;
	}
	p->frame = nfsp_journal_frame(KIND_EVENT, (const uint8_t *)b.p, b.len,
				      &p->frame_len);
	nfsp_sha256(b.p, b.len, digest);
	nfsp_sha256_hex(digest, p->sha);
	nfsp_jb_free(&b);
	if (p->frame == NULL) {
		free(p);
		return -1;
	}
	p->seq = j->next_seq++;
	p->cookie = cookie;
	if (j->tail != NULL)
		j->tail->next = p;
	else
		j->head = p;
	j->tail = p;
	j->npending++;
	j->stats.submitted++;
	if (event_seq != NULL)
		*event_seq = p->seq;
	return 0;
}

int nfsp_journal_fd(const struct nfsp_journal *j)
{
	return j->failed ? -1 : j->fd;
}

short nfsp_journal_events(const struct nfsp_journal *j)
{
	short ev = POLLIN;

	if (j->failed)
		return 0;
	if (j->tx_off < j->tx_len || (j->head != NULL && !j->head->sent_once))
		ev |= POLLOUT;
	return ev;
}

size_t nfsp_journal_pending(const struct nfsp_journal *j)
{
	return j->npending;
}

int nfsp_journal_failed(const struct nfsp_journal *j)
{
	return j->failed;
}

const struct nfsp_journal_stats *nfsp_journal_stats(
	const struct nfsp_journal *j)
{
	return &j->stats;
}

static void pop(struct nfsp_journal *j, enum nfsp_journal_outcome outcome,
		const char *reason)
{
	struct pending *p = j->head;

	j->head = p->next;
	if (j->head == NULL)
		j->tail = NULL;
	j->npending--;
	if (outcome == NFSP_JOURNAL_ACKED)
		j->stats.acked++;
	else if (outcome == NFSP_JOURNAL_REJECTED)
		j->stats.rejected++;
	else
		j->stats.lost++;
	j->done(j->done_arg, p->seq, p->cookie, outcome, reason);
	free_pending(p);
}

/* Every queued event is LOST: no host answer can arrive any more. */
static void fail(struct nfsp_journal *j)
{
	if (!j->failed) {
		j->failed = 1;
		if (j->fd >= 0) {
			close(j->fd);
			j->fd = -1;
		}
	}
	while (j->head != NULL)
		pop(j, NFSP_JOURNAL_LOST, "channel_failed");
}

/* 1 when a copy finished writing, so another may start. */
static int write_head(struct nfsp_journal *j)
{
	struct pending *p = j->head;
	uint64_t now = now_ms(j);

	if (j->tx_off >= j->tx_len) {
		if (p == NULL)
			return 0;
		if (p->sent_once && now - p->sent_at < j->retransmit_ms)
			return 0;
		if (p->sent_once)
			/* No answer: send the identical request again (§6). */
			j->stats.retransmits++;
		free(j->tx);
		j->tx = malloc(p->frame_len);
		if (j->tx == NULL) {
			j->tx_len = j->tx_off = 0;
			fail(j);
			return 0;
		}
		memcpy(j->tx, p->frame, p->frame_len);
		j->tx_len = p->frame_len;
		j->tx_off = 0;
		j->tx_seq = p->seq;
	}
	while (j->tx_off < j->tx_len) {
		ssize_t n = j->is_socket ?
			send(j->fd, j->tx + j->tx_off, j->tx_len - j->tx_off,
			     MSG_NOSIGNAL) :
			write(j->fd, j->tx + j->tx_off, j->tx_len - j->tx_off);

		if (n > 0) {
			j->tx_off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 0;
		fail(j);
		return 0;
	}
	j->stats.sent++;
	if (p != NULL && p->seq == j->tx_seq) {
		p->sent_once = 1;
		p->sent_at = now;
	}
	return 1;
}

/* 0: handled (matched or stale), -1: not a valid answer here. */
static int str_member(struct nfsp_jval obj, const char *key, char *out,
		      size_t cap)
{
	struct nfsp_jval v;

	return nfsp_json_member(obj, key, &v) == 0 &&
	       nfsp_json_str(v, out, cap) == 0 ? 0 : -1;
}

static int valid_reason(const char *s)
{
	size_t n = 0;

	for (; s[n] != '\0'; n++)
		if (n >= NFSP_JOURNAL_REASON_MAX || !((s[n] >= 'a' && s[n] <= 'z') ||
						      s[n] == '_'))
			return 0;
	return n > 0;
}

/* An answer is accepted only as the exact canonical document the host
 * sink writes (agent_pipeline/journal_framing.py JournalAck, and
 * journal_sink.py's reject response): every field present with its type
 * and bound, no other field, sorted keys, no whitespace.  Rebuilding it
 * from the values read and comparing the bytes checks all of that. */
static int same_doc(const struct nfsp_jbuf *b, const char *doc, size_t len)
{
	return !b->failed && b->len == len && memcmp(b->p, doc, len) == 0;
}

static int answer(struct nfsp_journal *j, unsigned kind, const char *doc,
		  size_t len)
{
	struct nfsp_jval root = { doc, len }, v, binding;
	uint64_t seq = 0, end = 0;
	int has_seq, ok;
	char reason[NFSP_JOURNAL_REASON_MAX + 1];
	char journal_id[NFSP_JOURNAL_SESSION_ID_MAX + 1];
	char sha[65], record_sha[65], session[NFSP_JOURNAL_SESSION_ID_MAX + 1];
	char rule_set_id[65], vm[NFSP_JOURNAL_SESSION_ID_MAX + 1];
	char channel[NFSP_JOURNAL_SESSION_ID_MAX + 1];
	struct nfsp_jbuf b;
	struct pending *p = j->head;

	if (nfsp_json_valid(doc, len) != 0 ||
	    str_member(root, "journal_id", journal_id, sizeof(journal_id)) != 0 ||
	    !valid_session_id(journal_id) ||
	    str_member(root, "request_sha256", sha, sizeof(sha)) != 0 ||
	    !valid_hex64(sha) ||
	    nfsp_json_member(root, "event_seq", &v) != 0)
		return -1;
	has_seq = kind == KIND_ACK || !nfsp_json_is_null(v);
	if (has_seq && nfsp_json_u64(v, &seq) != 0)
		return -1;
	nfsp_jb_init(&b, len + 1u);
	nfsp_jb_raw(&b, "{");
	if (kind == KIND_ACK) {
		if (nfsp_json_member(root, "committed_end_offset", &v) != 0 ||
		    nfsp_json_u64(v, &end) != 0 ||
		    end <= NFSP_JOURNAL_HEADER_LEN || end > (64u << 20) ||
		    str_member(root, "record_sha256", record_sha,
			       sizeof(record_sha)) != 0 ||
		    !valid_hex64(record_sha) ||
		    nfsp_json_member(root, "session_binding", &binding) != 0 ||
		    str_member(binding, "channel_id", channel,
			       sizeof(channel)) != 0 ||
		    !valid_session_id(channel) ||
		    str_member(binding, "proxy_session_id", session,
			       sizeof(session)) != 0 ||
		    str_member(binding, "rule_set_id", rule_set_id,
			       sizeof(rule_set_id)) != 0 ||
		    str_member(binding, "vm_instance_id", vm, sizeof(vm)) != 0 ||
		    !valid_session_id(vm)) {
			nfsp_jb_free(&b);
			return -1;
		}
		nfsp_jb_key(&b, "committed_end_offset", 1);
		nfsp_jb_u64(&b, end);
		nfsp_jb_key(&b, "event_seq", 0);
		nfsp_jb_u64(&b, seq);
		nfsp_jb_key(&b, "journal_id", 0);
		nfsp_jb_str(&b, journal_id);
		nfsp_jb_key(&b, "record_sha256", 0);
		nfsp_jb_str(&b, record_sha);
		nfsp_jb_key(&b, "request_sha256", 0);
		nfsp_jb_str(&b, sha);
		nfsp_jb_key(&b, "schema_version", 0);
		nfsp_jb_str(&b, "nfs-proxy-journal-ack.v1");
		nfsp_jb_key(&b, "session_binding", 0);
		nfsp_jb_raw(&b, "{");
		nfsp_jb_key(&b, "channel_id", 1);
		nfsp_jb_str(&b, channel);
		/* The binding must be this session's own. */
		nfsp_jb_key(&b, "proxy_session_id", 0);
		nfsp_jb_str(&b, j->session);
		nfsp_jb_key(&b, "rule_set_id", 0);
		nfsp_jb_str(&b, j->rule_set_id);
		nfsp_jb_key(&b, "vm_instance_id", 0);
		nfsp_jb_str(&b, vm);
		nfsp_jb_raw(&b, "}}");
	} else {
		if (str_member(root, "reason", reason, sizeof(reason)) != 0 ||
		    !valid_reason(reason)) {
			nfsp_jb_free(&b);
			return -1;
		}
		nfsp_jb_key(&b, "event_seq", 1);
		if (has_seq)
			nfsp_jb_u64(&b, seq);
		else
			nfsp_jb_raw(&b, "null");
		nfsp_jb_key(&b, "journal_id", 0);
		nfsp_jb_str(&b, journal_id);
		nfsp_jb_key(&b, "reason", 0);
		nfsp_jb_str(&b, reason);
		nfsp_jb_key(&b, "request_sha256", 0);
		nfsp_jb_str(&b, sha);
		nfsp_jb_key(&b, "schema_version", 0);
		nfsp_jb_str(&b, "nfs-proxy-journal-reject.v1");
		nfsp_jb_raw(&b, "}");
	}
	ok = same_doc(&b, doc, len);
	nfsp_jb_free(&b);
	if (!ok)
		return -1;
	if (p == NULL || (has_seq && seq < p->seq)) {
		/* The answer to a retransmission of an event already
		 * answered. */
		j->stats.stale_answers++;
		return 0;
	}
	if ((has_seq && seq != p->seq) || !p->sent_once ||
	    strcmp(sha, p->sha) != 0)
		return -1;
	pop(j, kind == KIND_ACK ? NFSP_JOURNAL_ACKED : NFSP_JOURNAL_REJECTED,
	    kind == KIND_ACK ? "" : reason);
	return 0;
}

static void read_answers(struct nfsp_journal *j)
{
	for (;;) {
		ssize_t n;

		if (j->rx_cap - j->rx_len < 4096u) {
			size_t cap = j->rx_cap ? j->rx_cap * 2u : 8192u;
			uint8_t *grown;

			if (cap > NFSP_JOURNAL_HEADER_LEN +
				  NFSP_JOURNAL_MAX_PAYLOAD + 8192u) {
				fail(j);
				return;
			}
			grown = realloc(j->rx, cap);
			if (grown == NULL) {
				fail(j);
				return;
			}
			j->rx = grown;
			j->rx_cap = cap;
		}
		n = read(j->fd, j->rx + j->rx_len, j->rx_cap - j->rx_len);
		if (n > 0) {
			j->rx_len += (size_t)n;
		} else if (n < 0 && errno == EINTR) {
			continue;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break;
		} else {
			/* EOF or an error: the host side is gone. */
			fail(j);
			return;
		}
		while (j->rx_len >= NFSP_JOURNAL_HEADER_LEN) {
			uint8_t digest[NFSP_SHA256_LEN];
			unsigned kind = (unsigned)j->rx[10] << 8 | j->rx[11];
			uint32_t len = get32(j->rx + 12);

			if (memcmp(j->rx, "NFSPJNL1", 8) != 0 ||
			    j->rx[8] != 0 || j->rx[9] != 1 ||
			    (kind != KIND_ACK && kind != KIND_REJECTION) ||
			    len == 0 || len > NFSP_JOURNAL_MAX_PAYLOAD) {
				fail(j);
				return;
			}
			nfsp_sha256(j->rx, 48, digest);
			if (memcmp(digest, j->rx + 48, NFSP_SHA256_LEN) != 0) {
				fail(j);
				return;
			}
			if (j->rx_len < NFSP_JOURNAL_HEADER_LEN + len)
				break;
			nfsp_sha256(j->rx + NFSP_JOURNAL_HEADER_LEN, len, digest);
			if (memcmp(digest, j->rx + 16, NFSP_SHA256_LEN) != 0 ||
			    answer(j, kind,
				   (const char *)j->rx + NFSP_JOURNAL_HEADER_LEN,
				   len) != 0) {
				fail(j);
				return;
			}
			memmove(j->rx, j->rx + NFSP_JOURNAL_HEADER_LEN + len,
				j->rx_len - NFSP_JOURNAL_HEADER_LEN - len);
			j->rx_len -= NFSP_JOURNAL_HEADER_LEN + len;
		}
	}
}

void nfsp_journal_pump(struct nfsp_journal *j)
{
	if (j->failed) {
		fail(j);
		return;
	}
	read_answers(j);
	while (!j->failed && write_head(j))
		;
	if (j->failed)
		fail(j);
}
