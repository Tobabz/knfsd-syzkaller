#define _POSIX_C_SOURCE 200809L
#include "proxy.h"
#include "framing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NFSP_MAX_CONNS 64u
#define NFSP_READ_CHUNK 16384u
#define NFSP_DEFAULT_CONNECT_MS 2000u
#define NFSP_EXTRA_FDS 8u

/* A record in a queue whose delivery someone waits for (on_forwarded). */
struct mark {
	size_t start, end;
	uint64_t token;
};

struct queue {
	uint8_t *buf;
	size_t len, off, cap;
	uint32_t pending_records;
	struct mark *marks;
	size_t nmarks, marks_cap;
};

struct conn {
	/* ConnectionRef identity.  Zero only while the slot is free. */
	uint64_t connection_id;
	int client_fd, backend_fd;
	unsigned client, backend;
	int connecting, connected;
	uint64_t connect_deadline_ms;
	int client_eof, backend_eof, client_wr_closed, backend_wr_closed;
	struct nfsp_framing c2s, s2c;
	struct queue to_backend, to_client;
	/* Target mode: a held record at the head of the framing buffer, and
	 * bytes read after it in the same chunk, not yet framed. */
	int held[2];
	uint64_t hold[2];
	struct queue backlog[2];
};

struct state {
	const struct nfsp_proxy_cfg *cfg;
	struct nfsp_proxy_stats *stats;
	struct conn conns[NFSP_MAX_CONNS];
	int listeners[NFSP_BACKENDS];
	struct in_addr clients[NFSP_CLIENTS];
	size_t limit;
	/* Monotonic over the whole run, never derived from a slot or an fd,
	 * so a reused slot cannot hand a new connection an old identity. */
	uint64_t next_connection_id;
	/* Canonical payload of a multi-fragment record.  One is enough: the
	 * event loop handles one record at a time on one thread. */
	struct nfsp_record_buf payload;
};

static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int tcp_nodelay(int fd)
{
	int one = 1;
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static int address(const char *ip, uint16_t port, struct sockaddr_in *out)
{
	if (ip == NULL) return -1;
	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;
	out->sin_port = htons(port);
	return inet_pton(AF_INET, ip, &out->sin_addr) == 1 ? 0 : -1;
}

static int listener(const struct nfsp_route *r, uint16_t *bound)
{
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	int fd = -1, one = 1;
	if (address(r->listen_ip, r->listen_port, &sa) != 0) return -1;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
	    bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(fd, 64) != 0 ||
	    getsockname(fd, (struct sockaddr *)&sa, &len) != 0 ||
	    nonblock(fd) != 0) {
		close(fd);
		return -1;
	}
	*bound = ntohs(sa.sin_port);
	return fd;
}

/* A stalled or filtered local backend must not stall the other route. */
static int start_backend(const struct nfsp_route *r, int *connecting)
{
	struct sockaddr_in sa;
	int fd;
	if (address(r->backend_ip, r->backend_port, &sa) != 0) return -1;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	if (nonblock(fd) != 0 || tcp_nodelay(fd) != 0) {
		close(fd);
		return -1;
	}
	if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) == 0) {
		*connecting = 0;
		return fd;
	}
	if (errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	*connecting = 1;
	return fd;
}

static struct nfsp_connection_ref conn_ref(const struct conn *c)
{
	struct nfsp_connection_ref ref;
	ref.connection_id = c->connection_id;
	ref.client = c->client;
	ref.backend = c->backend;
	return ref;
}

/* Every record still queued for this peer is not (completely) delivered. */
static void drop_marks(struct state *s, struct queue *q)
{
	for (size_t i = 0; i < q->nmarks; i++) {
		struct mark *m = &q->marks[i];
		size_t written = q->off > m->start ?
			(q->off < m->end ? q->off : m->end) - m->start : 0;
		if (s->cfg->on_forwarded != NULL)
			s->cfg->on_forwarded(m->token, 0, written, m->end - m->start,
					     s->cfg->relay_arg);
	}
	free(q->marks);
	q->marks = NULL;
	q->nmarks = q->marks_cap = 0;
}

static void conn_close(struct state *s, struct conn *c)
{
	if (c->client_fd < 0) return;
	drop_marks(s, &c->to_backend);
	drop_marks(s, &c->to_client);
	for (int d = 0; d < 2; d++) {
		if (c->held[d] && s->cfg->on_hold_dropped != NULL)
			s->cfg->on_hold_dropped(c->hold[d], s->cfg->relay_arg);
		c->held[d] = 0;
		free(c->backlog[d].buf);
		c->backlog[d].buf = NULL;
		c->backlog[d].len = c->backlog[d].cap = 0;
	}
	if (s->cfg->on_connection != NULL) {
		struct nfsp_connection_ref ref = conn_ref(c);
		s->cfg->on_connection(&ref, NFSP_CONN_CLOSED, s->cfg->on_connection_arg);
	}
	c->connection_id = 0;
	close(c->client_fd);
	if (c->backend_fd >= 0) close(c->backend_fd);
	nfsp_framing_free(&c->c2s);
	nfsp_framing_free(&c->s2c);
	free(c->to_backend.buf);
	free(c->to_client.buf);
	if (c->connected) s->stats->active--;
	c->client_fd = -1;
	c->backend_fd = -1;
}

static int add_mark(struct queue *q, uint64_t token, size_t start, size_t end)
{
	if (q->nmarks == q->marks_cap) {
		size_t cap = q->marks_cap ? q->marks_cap * 2u : 4u;
		struct mark *grown = realloc(q->marks, cap * sizeof(*grown));
		if (grown == NULL) return -1;
		q->marks = grown;
		q->marks_cap = cap;
	}
	q->marks[q->nmarks].start = start;
	q->marks[q->nmarks].end = end;
	q->marks[q->nmarks].token = token;
	q->nmarks++;
	return 0;
}

/* Report every mark whose last byte is now written. */
static void complete_marks(struct state *s, struct queue *q)
{
	size_t done = 0;
	while (done < q->nmarks && q->marks[done].end <= q->off) {
		struct mark *m = &q->marks[done++];
		if (s->cfg->on_forwarded != NULL)
			s->cfg->on_forwarded(m->token, 1, m->end - m->start,
					     m->end - m->start, s->cfg->relay_arg);
	}
	if (done != 0) {
		memmove(q->marks, q->marks + done,
			(q->nmarks - done) * sizeof(*q->marks));
		q->nmarks -= done;
	}
}

static int enqueue(struct queue *q, const uint8_t *p, size_t n, size_t max)
{
	uint8_t *grown;
	size_t cap;
	if (q->len > max || n > max - q->len) return -1;
	if (q->len + n > q->cap) {
		cap = q->cap ? q->cap : 4096u;
		while (cap < q->len + n) {
			if (cap > max / 2u) { cap = max; break; }
			cap *= 2u;
		}
		grown = realloc(q->buf, cap);
		if (grown == NULL) return -1;
		q->buf = grown;
		q->cap = cap;
	}
	memcpy(q->buf + q->len, p, n);
	q->len += n;
	q->pending_records++;
	return 0;
}

static int flush(struct state *s, struct conn *c, int dir)
{
	struct queue *q = dir == NFSP_DIR_C2S ? &c->to_backend : &c->to_client;
	int fd = dir == NFSP_DIR_C2S ? c->backend_fd : c->client_fd;
	while (q->off < q->len) {
		ssize_t n = send(fd, q->buf + q->off, q->len - q->off, MSG_NOSIGNAL);
		if (n > 0) {
			q->off += (size_t)n;
			if (q->nmarks != 0) complete_marks(s, q);
			continue;
		}
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
		s->stats->relay_errors++;
		return -1;
	}
	if (q->len != 0) {
		s->stats->delivered[c->client][c->backend][dir] += q->pending_records;
		q->len = q->off = 0;
		q->pending_records = 0;
	}
	return 0;
}

/* Hand the target path its canonical view of a record framing already
 * accepted.  A canonicalisation failure here can only be NOMEM, or framing.c
 * and rpc_record.c disagreeing about a record; either way the record is not
 * forwarded, because the observer would otherwise miss a record the peer
 * received. */
static int observe(struct state *s, struct conn *c, int dir,
		   const uint8_t *framed, size_t len)
{
	struct nfsp_rpc_record rec;
	if (nfsp_rpc_payload(framed, len, &s->payload, &rec.rpc_payload,
			     &rec.rpc_payload_len, &rec.nfrags) != NFSP_RECORD_OK)
		return -1;
	rec.conn = conn_ref(c);
	rec.direction = dir;
	return s->cfg->on_rpc_record(&rec, s->cfg->on_rpc_record_arg);
}

/* Queue the record at the head of the framing buffer as the verdict says
 * and consume it.  -1 closes the connection. */
static int forward(struct state *s, struct conn *c, int dir, size_t len,
		   const struct nfsp_relay_verdict *v)
{
	struct nfsp_framing *f = dir == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	struct queue *q = dir == NFSP_DIR_C2S ? &c->to_backend : &c->to_client;
	size_t ceiling = s->limit + NFSP_FRAG_HEADER_LEN, start = q->len;
	/* A rebuilt record must still be a whole, in-bounds record.
	 * Anything else would put bytes on the wire the peer cannot
	 * frame, so it is a mutation error and closes only this
	 * connection. */
	if (v->out == NULL || v->out_len < NFSP_FRAG_HEADER_LEN ||
	    v->out_len > ceiling) {
		s->stats->mutation_errors++;
		goto lost;
	}
	if (enqueue(q, v->out, v->out_len, ceiling + NFSP_READ_CHUNK) != 0) {
		s->stats->relay_errors++;
		goto lost;
	}
	if (v->completion != 0 &&
	    add_mark(q, v->completion, start, start + v->out_len) != 0) {
		/* The bytes are queued but cannot be reported: never send
		 * them unreported. */
		q->len = start;
		q->pending_records--;
		s->stats->relay_errors++;
		goto lost;
	}
	s->stats->records[c->client][c->backend][dir]++;
	nfsp_framing_consume(f, len);
	return 0;
lost:
	if (v->completion != 0 && s->cfg->on_forwarded != NULL)
		s->cfg->on_forwarded(v->completion, 0, 0, v->out_len,
				     s->cfg->relay_arg);
	return -1;
}

/* One complete record at the head of the framing buffer.  1: held. */
static int relay_one(struct state *s, struct conn *c, int dir, size_t len)
{
	struct nfsp_framing *f = dir == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	struct nfsp_relay_verdict v;
	int action;

	memset(&v, 0, sizeof(v));
	v.out = f->buf;
	v.out_len = len;
	if (s->cfg->on_relay != NULL) {
		struct nfsp_rpc_record rec;
		if (nfsp_rpc_payload(f->buf, len, &s->payload, &rec.rpc_payload,
				     &rec.rpc_payload_len, &rec.nfrags) !=
		    NFSP_RECORD_OK) {
			s->stats->record_refused++;
			return -1;
		}
		rec.conn = conn_ref(c);
		rec.direction = dir;
		action = s->cfg->on_relay(&rec, f->buf, len, &v,
					  s->cfg->relay_arg);
		if (action == NFSP_RELAY_HOLD) {
			c->held[dir] = 1;
			c->hold[dir] = v.hold;
			return 1;
		}
		if (action != NFSP_RELAY_FORWARD) {
			s->stats->record_refused++;
			return -1;
		}
		return forward(s, c, dir, len, &v);
	}
	if (s->cfg->on_rpc_record != NULL &&
	    observe(s, c, dir, f->buf, len) != 0) {
		s->stats->record_refused++;
		return -1;
	}
	/* Default: forward the record exactly as received.  The callback
	 * may redirect to a rebuilt record of a different length; framing
	 * is consumed by the ORIGINAL length either way, since that is
	 * what was read. */
	if (s->cfg->on_record != NULL &&
	    s->cfg->on_record(c->client, c->backend, dir, f->buf, len,
			      &v.out, &v.out_len, s->cfg->on_record_arg) != 0) {
		s->stats->mutation_errors++;
		return -1;
	}
	return forward(s, c, dir, len, &v);
}

/* Relay complete records until none is left or one is held. */
static int drain(struct state *s, struct conn *c, int dir)
{
	struct nfsp_framing *f = dir == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	while (!c->held[dir]) {
		size_t len = 0;
		int rc = nfsp_framing_peek(f, &len, NULL, NULL);
		if (rc < 0) {
			s->stats->framing_errors++;
			return -1;
		}
		if (rc == 0) break;
		if (relay_one(s, c, dir, len) < 0) return -1;
	}
	return 0;
}

/* Feed at most the framing budget at a time.  A TCP read may contain several
 * complete records, and a previous read may have left an almost-full record.
 * Drain after EACH bounded append instead of treating coalescing as corruption.
 * Once a record is held, the rest waits in the backlog, unframed. */
static int feed(struct state *s, struct conn *c, int dir,
		const uint8_t *data, size_t size)
{
	struct nfsp_framing *f = dir == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	size_t pos = 0, ceiling = s->limit + NFSP_FRAG_HEADER_LEN;
	while (pos < size) {
		size_t take = size - pos, room;
		if (c->held[dir]) {
			struct queue *b = &c->backlog[dir];
			if (enqueue(b, data + pos, size - pos,
				    ceiling + 2u * NFSP_READ_CHUNK) != 0) {
				s->stats->relay_errors++;
				return -1;
			}
			return 0;
		}
		if (f->len >= ceiling) goto bad_frame;
		room = ceiling - f->len;
		if (take > room) take = room;
		if (nfsp_framing_append(f, data + pos, take) != 0) goto bad_frame;
		pos += take;
		if (drain(s, c, dir) != 0) return -1;
	}
	return 0;
bad_frame:
	s->stats->framing_errors++;
	return -1;
}

/* Offer a held record again.  -1 closes the connection. */
static int resume(struct state *s, struct conn *c, int dir)
{
	struct nfsp_framing *f = dir == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	struct nfsp_relay_verdict v;
	struct queue backlog;
	size_t len = 0;
	int action, rc;

	if (!c->held[dir]) return 0;
	if (nfsp_framing_peek(f, &len, NULL, NULL) != 1) {
		s->stats->framing_errors++;
		return -1;
	}
	memset(&v, 0, sizeof(v));
	v.out = f->buf;
	v.out_len = len;
	action = s->cfg->on_hold(c->hold[dir], f->buf, len, &v,
				 s->cfg->relay_arg);
	if (action == NFSP_RELAY_HOLD) return 0;
	c->held[dir] = 0;
	if (action != NFSP_RELAY_FORWARD) {
		s->stats->record_refused++;
		return -1;
	}
	if (forward(s, c, dir, len, &v) != 0) return -1;
	if (drain(s, c, dir) != 0) return -1;
	if (c->backlog[dir].len == 0) return 0;
	backlog = c->backlog[dir];
	memset(&c->backlog[dir], 0, sizeof(c->backlog[dir]));
	rc = feed(s, c, dir, backlog.buf, backlog.len);
	free(backlog.buf);
	return rc;
}

static int read_side(struct state *s, struct conn *c, int side)
{
	uint8_t buf[NFSP_READ_CHUNK];
	int fd = side == NFSP_DIR_C2S ? c->client_fd : c->backend_fd;
	struct nfsp_framing *f = side == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	ssize_t n = recv(fd, buf, sizeof(buf), 0);
	if (n > 0) return feed(s, c, side, buf, (size_t)n);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return 0;
	if (n < 0) { s->stats->relay_errors++; return -1; }
	if (f->len != 0) { s->stats->framing_errors++; return -1; }
	if (side == NFSP_DIR_C2S) c->client_eof = 1;
	else c->backend_eof = 1;
	return 0;
}

static void half_close(struct conn *c)
{
	if (c->client_eof && c->to_backend.len == 0 && !c->backend_wr_closed) {
		shutdown(c->backend_fd, SHUT_WR);
		c->backend_wr_closed = 1;
	}
	if (c->backend_eof && c->to_client.len == 0 && !c->client_wr_closed) {
		shutdown(c->client_fd, SHUT_WR);
		c->client_wr_closed = 1;
	}
}

static void accept_route(struct state *s, unsigned backend)
{
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);
	struct conn *c = NULL;
	unsigned client;
	size_t i;
	int cfd = accept(s->listeners[backend], (struct sockaddr *)&peer, &plen);
	if (cfd < 0) return;
	for (client = 0; client < NFSP_CLIENTS; client++)
		if (peer.sin_addr.s_addr == s->clients[client].s_addr) break;
	if (client == NFSP_CLIENTS) {
		s->stats->rejected_client++;
		close(cfd);
		return;
	}
	for (i = 0; i < NFSP_MAX_CONNS; i++)
		if (s->conns[i].client_fd < 0) { c = &s->conns[i]; break; }
	if (c == NULL || nonblock(cfd) != 0 || tcp_nodelay(cfd) != 0) {
		s->stats->relay_errors++;
		close(cfd);
		return;
	}
	memset(c, 0, sizeof(*c));
	c->client_fd = cfd;
	c->backend_fd = -1;
	c->client = client;
	c->backend = backend;
	c->connection_id = s->next_connection_id++;
	nfsp_framing_init(&c->c2s, s->limit);
	nfsp_framing_init(&c->s2c, s->limit);
	s->stats->accepted[client][backend]++;
	if (s->cfg->on_connection != NULL) {
		struct nfsp_connection_ref ref = conn_ref(c);
		s->cfg->on_connection(&ref, NFSP_CONN_OPENED, s->cfg->on_connection_arg);
	}
	c->backend_fd = start_backend(&s->cfg->route[backend], &c->connecting);
	if (c->backend_fd < 0) {
		s->stats->connect_failed[client][backend]++;
		conn_close(s, c);
		return;
	}
	if (c->connecting) {
		unsigned ms = s->cfg->connect_timeout_ms ?
			s->cfg->connect_timeout_ms : NFSP_DEFAULT_CONNECT_MS;
		c->connect_deadline_ms = now_ms() + ms;
	} else {
		c->connected = 1;
		s->stats->connected[client][backend]++;
		s->stats->active++;
		if (s->stats->active > s->stats->peak_active)
			s->stats->peak_active = s->stats->active;
	}
}

static int finish_connect(struct state *s, struct conn *c)
{
	int err = 0;
	socklen_t len = sizeof(err);
	if (getsockopt(c->backend_fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
		s->stats->connect_failed[c->client][c->backend]++;
		return -1;
	}
	c->connecting = 0;
	c->connected = 1;
	s->stats->connected[c->client][c->backend]++;
	s->stats->active++;
	if (s->stats->active > s->stats->peak_active)
		s->stats->peak_active = s->stats->active;
	return 0;
}

int nfsp_proxy_run(const struct nfsp_proxy_cfg *cfg,
		   struct nfsp_proxy_stats *stats,
		   void (*on_ready)(const struct nfsp_proxy_stats *, void *),
		   void *ready_arg)
{
	struct state *s;
	unsigned b;
	size_t i;
	int rc = -1;
	if (cfg == NULL || stats == NULL || cfg->stop == NULL) return -1;
	s = calloc(1, sizeof(*s));
	if (s == NULL) return -1;
	s->cfg = cfg;
	s->stats = stats;
	s->limit = cfg->msg_limit ? cfg->msg_limit : NFSP_MSG_LIMIT_DEFAULT;
	s->next_connection_id = 1;
	/* Sentinels before the first goto out: calloc's zeros are valid fds
	 * and would make `out` close fd 0 and report never-opened slots as
	 * closed connections. */
	for (b = 0; b < NFSP_BACKENDS; b++) s->listeners[b] = -1;
	for (i = 0; i < NFSP_MAX_CONNS; i++) s->conns[i].client_fd = -1;
	if (s->limit > SIZE_MAX - NFSP_FRAG_HEADER_LEN - NFSP_READ_CHUNK ||
	    s->limit < NFSP_FRAG_HEADER_LEN) goto out;
	memset(stats, 0, sizeof(*stats));
	for (b = 0; b < NFSP_CLIENTS; b++)
		if (cfg->client_ip[b] == NULL ||
		    inet_pton(AF_INET, cfg->client_ip[b], &s->clients[b]) != 1) goto out;
	if (s->clients[0].s_addr == s->clients[1].s_addr) goto out;
	for (b = 0; b < NFSP_BACKENDS; b++) {
		s->listeners[b] = listener(&cfg->route[b], &stats->bound_port[b]);
		if (s->listeners[b] < 0) goto out;
	}
	if (on_ready != NULL) on_ready(stats, ready_arg);
	rc = 0;
	while (!atomic_load(cfg->stop)) {
		struct pollfd pfd[NFSP_BACKENDS + 2u * NFSP_MAX_CONNS + NFSP_EXTRA_FDS];
		int owner[NFSP_BACKENDS + 2u * NFSP_MAX_CONNS + NFSP_EXTRA_FDS];
		int side[NFSP_BACKENDS + 2u * NFSP_MAX_CONNS + NFSP_EXTRA_FDS];
		nfds_t count = 0;
		int n;
		uint64_t now = now_ms();
		if (cfg->on_tick != NULL)
			cfg->on_tick(cfg->on_tick_arg);
		/* A held record may have been decided by what on_tick read. */
		if (cfg->on_hold != NULL) {
			for (i = 0; i < NFSP_MAX_CONNS; i++) {
				struct conn *c = &s->conns[i];
				for (int d = 0; d < 2 && c->client_fd >= 0; d++)
					if (c->held[d] && resume(s, c, d) != 0)
						conn_close(s, c);
			}
		}
		if (cfg->on_stats != NULL)
			cfg->on_stats(stats, cfg->on_stats_arg);
		for (b = 0; b < NFSP_BACKENDS; b++) {
			pfd[count] = (struct pollfd){s->listeners[b], POLLIN, 0};
			owner[count] = -1;
			side[count++] = (int)b;
		}
		for (i = 0; i < NFSP_MAX_CONNS; i++) {
			struct conn *c = &s->conns[i];
			short ce = 0, be = 0;
			if (c->client_fd < 0) continue;
			if (c->connecting && now >= c->connect_deadline_ms) {
				stats->connect_failed[c->client][c->backend]++;
				conn_close(s, c);
				continue;
			}
			if (c->connecting) be = POLLOUT;
			else {
				if (!c->client_eof && c->to_backend.len == 0 &&
				    !c->held[NFSP_DIR_C2S]) ce |= POLLIN;
				if (!c->backend_eof && c->to_client.len == 0 &&
				    !c->held[NFSP_DIR_S2C]) be |= POLLIN;
				if (c->to_client.len) ce |= POLLOUT;
				if (c->to_backend.len) be |= POLLOUT;
			}
			pfd[count] = (struct pollfd){c->client_fd, ce, 0};
			owner[count] = (int)i;
			side[count++] = NFSP_DIR_C2S;
			pfd[count] = (struct pollfd){c->backend_fd, be, 0};
			owner[count] = (int)i;
			side[count++] = NFSP_DIR_S2C;
		}
		if (cfg->poll_fds != NULL) {
			size_t extra = cfg->poll_fds(&pfd[count], NFSP_EXTRA_FDS,
						     cfg->relay_arg);
			if (extra > NFSP_EXTRA_FDS) extra = NFSP_EXTRA_FDS;
			for (size_t e = 0; e < extra; e++) {
				owner[count] = -2;
				side[count++] = 0;
			}
		}
		n = poll(pfd, count, 50);
		if (n < 0) {
			if (errno == EINTR) continue;
			stats->relay_errors++;
			rc = -1;
			break;
		}
		if (n == 0) continue;
		for (nfds_t k = 0; k < count; k++) {
			struct conn *c;
			short ev = pfd[k].revents;
			if (ev == 0) continue;
			/* Extra descriptors are serviced by on_tick. */
			if (owner[k] == -2) continue;
			if (owner[k] < 0) {
				if (ev & POLLIN) accept_route(s, (unsigned)side[k]);
				else { stats->relay_errors++; rc = -1; }
				continue;
			}
			c = &s->conns[(size_t)owner[k]];
			if (c->client_fd < 0) continue;
			if (c->connecting) {
				if (side[k] == NFSP_DIR_S2C && ev != 0 &&
				    finish_connect(s, c) != 0) conn_close(s, c);
				continue;
			}
			if (ev & (POLLERR | POLLNVAL)) {
				stats->relay_errors++;
				conn_close(s, c);
				continue;
			}
			if (ev & POLLOUT) {
				int dir = side[k] == NFSP_DIR_C2S ? NFSP_DIR_S2C : NFSP_DIR_C2S;
				if (flush(s, c, dir) != 0) { conn_close(s, c); continue; }
			}
			if ((ev & (POLLIN | POLLHUP)) && !c->held[side[k]] &&
			    ((side[k] == NFSP_DIR_C2S && !c->client_eof && c->to_backend.len == 0) ||
			     (side[k] == NFSP_DIR_S2C && !c->backend_eof && c->to_client.len == 0))) {
				if (read_side(s, c, side[k]) != 0) { conn_close(s, c); continue; }
			}
			half_close(c);
			if (c->client_eof && c->backend_eof &&
			    c->to_backend.len == 0 && c->to_client.len == 0 &&
			    !c->held[0] && !c->held[1])
				conn_close(s, c);
		}
		if (rc != 0) break;
	}
out:
	for (i = 0; i < NFSP_MAX_CONNS; i++)
		if (s->conns[i].client_fd >= 0) conn_close(s, &s->conns[i]);
	for (b = 0; b < NFSP_BACKENDS; b++)
		if (s->listeners[b] >= 0) close(s->listeners[b]);
	nfsp_record_buf_free(&s->payload);
	free(s);
	return rc;
}
