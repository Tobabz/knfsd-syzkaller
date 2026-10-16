/* The Delta Recorder's host channel (journal.c) against a scripted host on a
 * socketpair, and the SHA-256 and JSON pieces it is built from.  The real
 * host sink is exercised end to end by tests/agent_pipeline/
 * test_journal_live.py; this pins the client's own rules: one outstanding
 * event, exact answer matching, retransmission, and LOST on any channel
 * failure. */
#define _POSIX_C_SOURCE 200809L
#include "journal.h"
#include "jsonw.h"
#include "sha256.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned checks, failures;
#define CHECK(x, ...) do { checks++; if (!(x)) { failures++; \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

#define SESSION "ps-1"
#define RSID "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

/* --- SHA-256 and JSON --------------------------------------------------- */

static void hex_of(const char *msg, size_t len, char out[65])
{
	uint8_t d[NFSP_SHA256_LEN];

	nfsp_sha256((const uint8_t *)msg, len, d);
	nfsp_sha256_hex(d, out);
}

static void test_sha256(void)
{
	char h[65];
	struct nfsp_sha256 ctx;
	uint8_t d[NFSP_SHA256_LEN], chunk[1001];

	printf("sha256: FIPS 180-2 vectors, incremental = one shot\n");
	hex_of("", 0, h);
	CHECK(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
	      "empty: %s", h);
	hex_of("abc", 3, h);
	CHECK(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
	      "abc: %s", h);
	hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, h);
	CHECK(strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
	      "two blocks: %s", h);
	memset(chunk, 'a', sizeof(chunk));
	nfsp_sha256_init(&ctx);
	for (unsigned i = 0; i < 1000; i++)
		nfsp_sha256_update(&ctx, chunk, i % 2 ? 999 : 1001);
	nfsp_sha256_final(&ctx, d);
	nfsp_sha256_hex(d, h);
	CHECK(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
	      "million a: %s", h);
}

static void test_json(void)
{
	struct nfsp_jbuf b;
	struct nfsp_jval root, v, inner;
	const char *doc;
	char s[16];
	uint64_t n;

	printf("json: canonical writer, strict reader\n");
	nfsp_jb_init(&b, 64);
	nfsp_jb_raw(&b, "{");
	nfsp_jb_key(&b, "a", 1);
	nfsp_jb_str(&b, "q\"\\x");
	nfsp_jb_key(&b, "b", 0);
	nfsp_jb_u64(&b, 18446744073709551615ull);
	nfsp_jb_key(&b, "c", 0);
	nfsp_jb_hex(&b, (const uint8_t *)"\x00\xff", 2);
	nfsp_jb_raw(&b, "}");
	CHECK(!b.failed && b.len == strlen("{\"a\":\"q\\\"\\\\x\",\"b\":18446744073709551615,\"c\":\"00ff\"}") &&
	      memcmp(b.p, "{\"a\":\"q\\\"\\\\x\",\"b\":18446744073709551615,\"c\":\"00ff\"}", b.len) == 0,
	      "writer: %.*s", (int)b.len, b.p);
	nfsp_jb_free(&b);

	nfsp_jb_init(&b, 64);
	nfsp_jb_str(&b, "tab\there");
	CHECK(b.failed, "a control character must not be written");
	nfsp_jb_free(&b);
	nfsp_jb_init(&b, 8);
	nfsp_jb_str(&b, "0123456789");
	CHECK(b.failed, "the limit must hold");
	nfsp_jb_free(&b);

	doc = "{\"x\":{\"y\":\"ok\",\"n\":42},\"z\":null,\"w\":[1,{\"k\":true}]}";
	root.p = doc;
	root.len = strlen(doc);
	CHECK(nfsp_json_valid(doc, root.len) == 0, "valid doc refused");
	CHECK(nfsp_json_member(root, "x", &inner) == 0 &&
	      nfsp_json_member(inner, "y", &v) == 0 &&
	      nfsp_json_str_eq(v, "ok") == 0 &&
	      nfsp_json_str(v, s, sizeof(s)) == 0 && strcmp(s, "ok") == 0,
	      "nested string");
	CHECK(nfsp_json_member(inner, "n", &v) == 0 &&
	      nfsp_json_u64(v, &n) == 0 && n == 42, "nested number");
	CHECK(nfsp_json_member(root, "z", &v) == 0 && nfsp_json_is_null(v),
	      "null");
	CHECK(nfsp_json_member(root, "y", &v) != 0, "a nested key is not a member");
	CHECK(nfsp_json_valid("{\"a\":1,\"a\":2}", 13) != 0 ||
	      nfsp_json_member((struct nfsp_jval){"{\"a\":1,\"a\":2}", 13}, "a",
			       &v) != 0, "a duplicate key must not be read");
	CHECK(nfsp_json_valid("{\"a\":1}x", 8) != 0, "trailing bytes");
	CHECK(nfsp_json_valid("{\"a\":1", 6) != 0, "truncated");
	CHECK(nfsp_json_valid("{\"a\":01}", 8) != 0, "leading zero");
	CHECK(nfsp_json_u64((struct nfsp_jval){"18446744073709551616", 20}, &n) != 0,
	      "u64 overflow");
}

/* --- the channel ------------------------------------------------------------ */

struct done_log {
	unsigned n;
	uint64_t seq[16], cookie[16];
	enum nfsp_journal_outcome outcome[16];
	char reason[16][NFSP_JOURNAL_REASON_MAX + 1];
};

static void on_done(void *arg, uint64_t seq, uint64_t cookie,
		    enum nfsp_journal_outcome outcome, const char *reason)
{
	struct done_log *l = arg;

	if (l->n >= 16)
		return;
	l->seq[l->n] = seq;
	l->cookie[l->n] = cookie;
	l->outcome[l->n] = outcome;
	snprintf(l->reason[l->n], sizeof(l->reason[0]), "%s", reason);
	l->n++;
}

static uint64_t fake_now;

static uint64_t fake_clock(void *arg)
{
	(void)arg;
	return fake_now;
}

struct host {
	int fd;
	uint8_t frame[4096];
	size_t len;		/* the last request frame read */
	char sha[65];
	uint64_t seq;
};

/* Read one request frame if there is one; 1 read, 0 nothing waiting. */
static int host_read(struct host *h)
{
	ssize_t n = recv(h->fd, h->frame, NFSP_JOURNAL_HEADER_LEN, MSG_DONTWAIT);
	uint32_t len;
	struct nfsp_jval root, v;

	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return 0;
	if (n != (ssize_t)NFSP_JOURNAL_HEADER_LEN)
		return -1;
	len = (uint32_t)h->frame[12] << 24 | (uint32_t)h->frame[13] << 16 |
	      (uint32_t)h->frame[14] << 8 | h->frame[15];
	if (len > sizeof(h->frame) - NFSP_JOURNAL_HEADER_LEN ||
	    recv(h->fd, h->frame + NFSP_JOURNAL_HEADER_LEN, len, MSG_WAITALL) !=
		    (ssize_t)len)
		return -1;
	h->len = NFSP_JOURNAL_HEADER_LEN + len;
	hex_of((const char *)h->frame + NFSP_JOURNAL_HEADER_LEN, len, h->sha);
	root.p = (const char *)h->frame + NFSP_JOURNAL_HEADER_LEN;
	root.len = len;
	if (nfsp_json_member(root, "event_seq", &v) != 0 ||
	    nfsp_json_u64(v, &h->seq) != 0)
		return -1;
	return 1;
}

static void host_send(struct host *h, uint16_t kind, const char *json)
{
	size_t len;
	uint8_t *f = nfsp_journal_frame(kind, (const uint8_t *)json,
					strlen(json), &len);

	CHECK(f != NULL && send(h->fd, f, len, MSG_NOSIGNAL) == (ssize_t)len,
	      "host send");
	free(f);
}

static void host_ack(struct host *h, uint64_t seq, const char *sha,
		     const char *session)
{
	char json[1024];

	snprintf(json, sizeof(json),
		 "{\"committed_end_offset\":200,\"event_seq\":%llu,"
		 "\"journal_id\":\"lane0.0001\",\"record_sha256\":\"%064d\","
		 "\"request_sha256\":\"%s\",\"schema_version\":"
		 "\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		 "\"channel_id\":\"c\",\"proxy_session_id\":\"%s\","
		 "\"rule_set_id\":\"" RSID "\",\"vm_instance_id\":\"vm\"}}",
		 (unsigned long long)seq, 0, sha, session);
	host_send(h, 3, json);
}

static void host_reject(struct host *h, uint64_t seq, const char *sha,
			const char *reason)
{
	char json[512];

	snprintf(json, sizeof(json),
		 "{\"event_seq\":%llu,\"journal_id\":\"lane0.0001\","
		 "\"reason\":\"%s\",\"request_sha256\":\"%s\","
		 "\"schema_version\":\"nfs-proxy-journal-reject.v1\"}",
		 (unsigned long long)seq, reason, sha);
	host_send(h, 2, json);
}

static struct nfsp_journal *open_pair(struct host *h, struct done_log *log)
{
	int sv[2];
	struct nfsp_journal_cfg cfg;
	struct nfsp_journal *j = NULL;

	memset(h, 0, sizeof(*h));
	memset(log, 0, sizeof(*log));
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return NULL;
	h->fd = sv[1];
	memset(&cfg, 0, sizeof(cfg));
	cfg.fd = sv[0];
	cfg.proxy_session_id = SESSION;
	cfg.rule_set_id = RSID;
	cfg.retransmit_ms = 100;
	cfg.clock_ms = fake_clock;
	cfg.done = on_done;
	cfg.done_arg = log;
	if (nfsp_journal_open(&j, &cfg) != 0) {
		close(sv[1]);
		return NULL;
	}
	return j;
}

static void submit(struct nfsp_journal *j, const char *type, const char *payload,
		   uint64_t cookie, uint64_t want_seq)
{
	uint64_t seq = 99;

	CHECK(nfsp_journal_submit(j, type, payload, strlen(payload), cookie,
				  &seq) == 0 && seq == want_seq,
	      "submit %s: seq %llu", type, (unsigned long long)seq);
}

static void test_one_outstanding_and_answers(void)
{
	struct host h;
	struct done_log log;
	struct nfsp_journal *j;
	uint8_t first[4096];
	size_t first_len;
	const char *want = "{\"event_seq\":0,\"event_type\":\"RULESET\","
		"\"payload\":{\"k\":1},\"proxy_session_id\":\"" SESSION "\","
		"\"rule_set_id\":\"" RSID "\",\"schema_version\":"
		"\"nfs-proxy-journal-request.v1\"}";
	char sha0[65];

	printf("journal: one outstanding event, exact answers, retransmission\n");
	fake_now = 1000;
	j = open_pair(&h, &log);
	if (j == NULL) { CHECK(0, "open"); return; }
	submit(j, "RULESET", "{\"k\":1}", 11, 0);
	submit(j, "GENERATION_OPEN", "{\"k\":2}", 12, 1);
	CHECK(log.n == 0, "no callback from submit");
	nfsp_journal_pump(j);
	CHECK(host_read(&h) == 1 && h.seq == 0, "seq 0 sent");
	CHECK(h.len - NFSP_JOURNAL_HEADER_LEN == strlen(want) &&
	      memcmp(h.frame + NFSP_JOURNAL_HEADER_LEN, want, strlen(want)) == 0,
	      "request not canonical: %.*s",
	      (int)(h.len - NFSP_JOURNAL_HEADER_LEN),
	      (const char *)h.frame + NFSP_JOURNAL_HEADER_LEN);
	memcpy(first, h.frame, h.len);
	first_len = h.len;
	memcpy(sha0, h.sha, sizeof(sha0));
	nfsp_journal_pump(j);
	CHECK(host_read(&h) == 0, "seq 1 sent while seq 0 is unanswered");

	/* No answer: the same bytes again after retransmit_ms. */
	fake_now += 150;
	nfsp_journal_pump(j);
	CHECK(host_read(&h) == 1 && h.len == first_len &&
	      memcmp(h.frame, first, first_len) == 0, "retransmission differs");
	CHECK(nfsp_journal_stats(j)->retransmits == 1, "retransmits %llu",
	      (unsigned long long)nfsp_journal_stats(j)->retransmits);

	host_ack(&h, 0, sha0, SESSION);
	nfsp_journal_pump(j);
	CHECK(log.n == 1 && log.seq[0] == 0 && log.cookie[0] == 11 &&
	      log.outcome[0] == NFSP_JOURNAL_ACKED, "seq 0 not ACKED");
	CHECK(host_read(&h) == 1 && h.seq == 1, "seq 1 not sent after the ACK");

	/* The second ACK of seq 0 (its retransmission's) is stale. */
	host_ack(&h, 0, sha0, SESSION);
	nfsp_journal_pump(j);
	CHECK(log.n == 1 && nfsp_journal_stats(j)->stale_answers == 1,
	      "stale answer not ignored");

	host_reject(&h, 1, h.sha, "wrong_lane");
	nfsp_journal_pump(j);
	CHECK(log.n == 2 && log.seq[1] == 1 && log.cookie[1] == 12 &&
	      log.outcome[1] == NFSP_JOURNAL_REJECTED &&
	      strcmp(log.reason[1], "wrong_lane") == 0, "seq 1 not REJECTED");
	CHECK(nfsp_journal_pending(j) == 0 && !nfsp_journal_failed(j),
	      "pending %zu", nfsp_journal_pending(j));

	/* An ACK naming the wrong request digest is not an answer to it: the
	 * channel cannot be trusted, and everything owed is LOST. */
	submit(j, "EXPOSURE_INTENT", "{\"k\":3}", 13, 2);
	submit(j, "FORWARD_COMPLETE", "{\"k\":4}", 14, 3);
	nfsp_journal_pump(j);
	CHECK(host_read(&h) == 1 && h.seq == 2, "seq 2 sent");
	host_ack(&h, 2, sha0, SESSION);
	nfsp_journal_pump(j);
	CHECK(log.n == 4 && log.outcome[2] == NFSP_JOURNAL_LOST &&
	      log.outcome[3] == NFSP_JOURNAL_LOST && log.seq[3] == 3,
	      "a mismatched ACK must lose every pending event (%u)", log.n);
	CHECK(nfsp_journal_failed(j) && nfsp_journal_fd(j) < 0 &&
	      nfsp_journal_events(j) == 0, "channel not failed");
	CHECK(nfsp_journal_submit(j, "RUN_COMPLETE", "{}", 2, 15, NULL) != 0 ||
	      (nfsp_journal_pump(j), log.n == 5 &&
	       log.outcome[4] == NFSP_JOURNAL_LOST),
	      "a failed channel must not accept or must lose new events");
	nfsp_journal_close(j);
	close(h.fd);
}

static void test_wrong_session_ack(void)
{
	struct host h;
	struct done_log log;
	struct nfsp_journal *j;

	printf("journal: an ACK for another session fails the channel\n");
	j = open_pair(&h, &log);
	if (j == NULL) { CHECK(0, "open"); return; }
	submit(j, "RULESET", "{}", 1, 0);
	nfsp_journal_pump(j);
	CHECK(host_read(&h) == 1, "sent");
	host_ack(&h, 0, h.sha, "ps-2");
	nfsp_journal_pump(j);
	CHECK(log.n == 1 && log.outcome[0] == NFSP_JOURNAL_LOST,
	      "another session's ACK accepted");
	nfsp_journal_close(j);
	close(h.fd);
}

/* Only the host's exact canonical document is an answer: a reduced, padded,
 * extended or reordered one fails the channel like any bad frame. */
#define ZERO64 "0000000000000000000000000000000000000000000000000000000000000000"

/* tmpl with its one '@' replaced by sha. */
static void with_sha(char *out, size_t cap, const char *tmpl, const char *sha)
{
	const char *at = strchr(tmpl, '@');
	size_t head = at ? (size_t)(at - tmpl) : strlen(tmpl);

	snprintf(out, cap, "%.*s%s%s", (int)head, tmpl, at ? sha : "",
		 at ? at + 1 : "");
}

static void test_ack_must_be_exact(void)
{
	static const char *const bad[] = {
		/* the five fields journal.c once checked, nothing else */
		"{\"event_seq\":0,\"request_sha256\":\"@\",\"schema_version\":"
		"\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		"\"proxy_session_id\":\"" SESSION "\",\"rule_set_id\":\"" RSID "\"}}",
		/* an extra field */
		"{\"committed_end_offset\":200,\"event_seq\":0,\"extra\":1,"
		"\"journal_id\":\"lane0.0001\",\"record_sha256\":\"" ZERO64 "\","
		"\"request_sha256\":\"@\",\"schema_version\":"
		"\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		"\"channel_id\":\"c\",\"proxy_session_id\":\"" SESSION "\","
		"\"rule_set_id\":\"" RSID "\",\"vm_instance_id\":\"vm\"}}",
		/* whitespace: valid JSON, not canonical */
		"{\"committed_end_offset\": 200,\"event_seq\":0,"
		"\"journal_id\":\"lane0.0001\",\"record_sha256\":\"" ZERO64 "\","
		"\"request_sha256\":\"@\",\"schema_version\":"
		"\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		"\"channel_id\":\"c\",\"proxy_session_id\":\"" SESSION "\","
		"\"rule_set_id\":\"" RSID "\",\"vm_instance_id\":\"vm\"}}",
		/* keys out of order */
		"{\"event_seq\":0,\"committed_end_offset\":200,"
		"\"journal_id\":\"lane0.0001\",\"record_sha256\":\"" ZERO64 "\","
		"\"request_sha256\":\"@\",\"schema_version\":"
		"\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		"\"channel_id\":\"c\",\"proxy_session_id\":\"" SESSION "\","
		"\"rule_set_id\":\"" RSID "\",\"vm_instance_id\":\"vm\"}}",
		/* an end offset inside the header: names no stored frame */
		"{\"committed_end_offset\":80,\"event_seq\":0,"
		"\"journal_id\":\"lane0.0001\",\"record_sha256\":\"" ZERO64 "\","
		"\"request_sha256\":\"@\",\"schema_version\":"
		"\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		"\"channel_id\":\"c\",\"proxy_session_id\":\"" SESSION "\","
		"\"rule_set_id\":\"" RSID "\",\"vm_instance_id\":\"vm\"}}",
		/* the binding without its host identity */
		"{\"committed_end_offset\":200,\"event_seq\":0,"
		"\"journal_id\":\"lane0.0001\",\"record_sha256\":\"" ZERO64 "\","
		"\"request_sha256\":\"@\",\"schema_version\":"
		"\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		"\"proxy_session_id\":\"" SESSION "\","
		"\"rule_set_id\":\"" RSID "\"}}",
	};

	printf("journal: an answer must be the host's exact canonical document\n");
	for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		struct host h;
		struct done_log log;
		struct nfsp_journal *j = open_pair(&h, &log);
		char json[1024];

		if (j == NULL) { CHECK(0, "open"); return; }
		submit(j, "RULESET", "{}", 1, 0);
		nfsp_journal_pump(j);
		CHECK(host_read(&h) == 1, "sent");
		with_sha(json, sizeof(json), bad[i], h.sha);
		host_send(&h, 3, json);
		nfsp_journal_pump(j);
		CHECK(log.n == 1 && log.outcome[0] == NFSP_JOURNAL_LOST,
		      "bad answer %u released the event", i);
		nfsp_journal_close(j);
		close(h.fd);
	}
	{
		/* A rejection that names no seq still answers the head. */
		struct host h;
		struct done_log log;
		struct nfsp_journal *j = open_pair(&h, &log);
		char json[512];

		if (j == NULL) { CHECK(0, "open"); return; }
		submit(j, "RULESET", "{}", 1, 0);
		nfsp_journal_pump(j);
		CHECK(host_read(&h) == 1, "sent");
		snprintf(json, sizeof(json),
			 "{\"event_seq\":null,\"journal_id\":\"lane0.0001\","
			 "\"reason\":\"malformed_request\",\"request_sha256\":"
			 "\"%s\",\"schema_version\":"
			 "\"nfs-proxy-journal-reject.v1\"}", h.sha);
		host_send(&h, 2, json);
		nfsp_journal_pump(j);
		CHECK(log.n == 1 && log.outcome[0] == NFSP_JOURNAL_REJECTED &&
		      strcmp(log.reason[0], "malformed_request") == 0,
		      "seq-less rejection");
		nfsp_journal_close(j);
		close(h.fd);
	}
}

static void test_split_answer_and_eof(void)
{
	struct host h;
	struct done_log log;
	struct nfsp_journal *j;
	char json[1024];
	uint8_t *f;
	size_t len;

	printf("journal: an answer split across reads; EOF loses the rest\n");
	j = open_pair(&h, &log);
	if (j == NULL) { CHECK(0, "open"); return; }
	submit(j, "RULESET", "{}", 1, 0);
	submit(j, "GENERATION_OPEN", "{}", 2, 1);
	nfsp_journal_pump(j);
	CHECK(host_read(&h) == 1, "sent");
	snprintf(json, sizeof(json),
		 "{\"committed_end_offset\":200,\"event_seq\":0,"
		 "\"journal_id\":\"lane0.0001\",\"record_sha256\":\"%064d\","
		 "\"request_sha256\":\"%s\",\"schema_version\":"
		 "\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		 "\"channel_id\":\"c\",\"proxy_session_id\":\"" SESSION "\","
		 "\"rule_set_id\":\"" RSID "\",\"vm_instance_id\":\"vm\"}}",
		 0, h.sha);
	f = nfsp_journal_frame(3, (const uint8_t *)json, strlen(json), &len);
	CHECK(f != NULL && send(h.fd, f, 50, 0) == 50, "first part");
	nfsp_journal_pump(j);
	CHECK(log.n == 0, "answered from half a frame");
	CHECK(f != NULL && send(h.fd, f + 50, len - 50, 0) == (ssize_t)(len - 50),
	      "rest");
	free(f);
	nfsp_journal_pump(j);
	CHECK(log.n == 1 && log.outcome[0] == NFSP_JOURNAL_ACKED, "split ACK");
	CHECK(host_read(&h) == 1 && h.seq == 1, "seq 1 sent");
	close(h.fd);
	nfsp_journal_pump(j);
	CHECK(log.n == 2 && log.outcome[1] == NFSP_JOURNAL_LOST &&
	      nfsp_journal_failed(j), "EOF did not lose seq 1");
	nfsp_journal_close(j);
}

static void test_bad_arguments(void)
{
	struct host h;
	struct done_log log;
	struct nfsp_journal *j;
	struct nfsp_journal_cfg cfg;
	int sv[2];

	printf("journal: bad session ids and payloads are refused up front\n");
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
	memset(&cfg, 0, sizeof(cfg));
	cfg.fd = sv[0];
	cfg.proxy_session_id = "bad id";
	cfg.rule_set_id = RSID;
	cfg.done = on_done;
	cfg.done_arg = &log;
	j = NULL;
	CHECK(nfsp_journal_open(&j, &cfg) != 0 && j == NULL,
	      "a session id with a space was accepted");
	close(sv[0]);
	close(sv[1]);
	j = open_pair(&h, &log);
	if (j == NULL) { CHECK(0, "open"); return; }
	CHECK(nfsp_journal_submit(j, "RULESET", "", 0, 1, NULL) != 0,
	      "empty payload accepted");
	CHECK(nfsp_journal_submit(j, "bad type", "{}", 2, 1, NULL) != 0,
	      "bad event type accepted");
	CHECK(nfsp_journal_pending(j) == 0, "a refused submit was queued");
	nfsp_journal_close(j);
	close(h.fd);
}

int main(void)
{
	test_sha256();
	test_json();
	test_one_outstanding_and_answers();
	test_wrong_session_ack();
	test_ack_must_be_exact();
	test_split_answer_and_eof();
	test_bad_arguments();
	printf("%u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
