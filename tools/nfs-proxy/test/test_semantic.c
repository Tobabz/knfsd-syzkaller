/* Tests for the semantic observer: records in, correlated decodes out.
 *
 * The observer is driven the way the proxy drives it (on_rpc_record and
 * on_connection), with NFSv4 messages built word by word, and checked
 * through on_decoded.  These are design 03-nfs-proxy/03 oracles 11a, 12 and
 * 13, plus the parts of the CALL/REPLY order (§6, §7) only the observer
 * owns: which direction a REPLY looks up, that a REPLY never borrows another
 * CALL's dispatch, and when a request summary may be used.
 */
#define _POSIX_C_SOURCE 200809L
#include "semantic.h"
#include "proxy.h"

#include <stdio.h>
#include <string.h>

extern const struct nfsp_schema_family nfsp_schema_family_nfs4;

static const struct nfsp_schema_family *const fams[] = {
	&nfsp_schema_family_nfs4,
};

static int failures;
static int checks;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: ", __FILE__, __LINE__);          \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
		}                                                              \
	} while (0)

#define NFS4_PROG	100003u
#define CB_PROG		0x40000000u	/* a callback program number */
#define OP_PUTFH	22u
#define OP_READDIR	26u
#define OP_SEQUENCE	53u
#define OP_PUTROOTFH	24u
#define OP_GETFH	10u

struct msg {
	uint8_t b[512];
	size_t n;
};

static void w32(struct msg *m, uint32_t v)
{
	m->b[m->n++] = (uint8_t)(v >> 24);
	m->b[m->n++] = (uint8_t)(v >> 16);
	m->b[m->n++] = (uint8_t)(v >> 8);
	m->b[m->n++] = (uint8_t)v;
}

static void wraw(struct msg *m, const char *s, size_t len)
{
	memcpy(m->b + m->n, s, len);
	m->n += len;
	while (m->n % 4u)
		m->b[m->n++] = 0;
}

static void call_header(struct msg *m, uint32_t xid, uint32_t prog,
			uint32_t vers, uint32_t proc)
{
	m->n = 0;
	w32(m, xid);
	w32(m, 0);		/* CALL */
	w32(m, 2);
	w32(m, prog);
	w32(m, vers);
	w32(m, proc);
	w32(m, 0);		/* cred AUTH_NONE */
	w32(m, 0);
	w32(m, 0);		/* verf AUTH_NONE */
	w32(m, 0);
}

static void reply_header(struct msg *m, uint32_t xid)
{
	m->n = 0;
	w32(m, xid);
	w32(m, 1);		/* REPLY */
	w32(m, 0);		/* MSG_ACCEPTED */
	w32(m, 0);		/* verf AUTH_NONE */
	w32(m, 0);
	w32(m, 0);		/* SUCCESS */
}

/* NFSv4.1: SEQUENCE, PUTROOTFH, GETFH. */
static void v41_call(struct msg *m, uint32_t xid)
{
	call_header(m, xid, NFS4_PROG, 4, 1);
	w32(m, 0);		/* tag */
	w32(m, 1);		/* minorversion */
	w32(m, 3);
	w32(m, OP_SEQUENCE);
	wraw(m, "sess-0123456789a", 16);
	w32(m, 1);
	w32(m, 0);
	w32(m, 0);
	w32(m, 0);
	w32(m, OP_PUTROOTFH);
	w32(m, OP_GETFH);
}

static void v41_reply(struct msg *m, uint32_t xid)
{
	reply_header(m, xid);
	w32(m, 0);		/* status */
	w32(m, 0);		/* tag */
	w32(m, 3);
	w32(m, OP_SEQUENCE);
	w32(m, 0);
	wraw(m, "sess-0123456789a", 16);
	w32(m, 1);
	w32(m, 0);
	w32(m, 63);
	w32(m, 63);
	w32(m, 0);
	w32(m, OP_PUTROOTFH);
	w32(m, 0);
	w32(m, OP_GETFH);
	w32(m, 0);
	w32(m, 4);
	wraw(m, "fh00", 4);
}

/* NFSv4.0: PUTFH, READDIR. */
static void v40_call(struct msg *m, uint32_t xid)
{
	call_header(m, xid, NFS4_PROG, 4, 1);
	w32(m, 0);		/* tag */
	w32(m, 0);		/* minorversion */
	w32(m, 2);
	w32(m, OP_PUTFH);
	w32(m, 4);
	wraw(m, "fh00", 4);
	w32(m, OP_READDIR);
	w32(m, 0);		/* cookie */
	w32(m, 0);
	wraw(m, "\0\0\0\0\0\0\0\0", 8);
	w32(m, 0x2000);
	w32(m, 0x8000);
	w32(m, 1);
	w32(m, 0x00100000);
}

/* The COMPOUND stops at its first failing operation (oracle 12). */
static void v40_reply_stale(struct msg *m, uint32_t xid)
{
	reply_header(m, xid);
	w32(m, 70);		/* NFS4ERR_STALE */
	w32(m, 0);
	w32(m, 1);
	w32(m, OP_PUTFH);
	w32(m, 70);
}

/* A CALL that ends inside the COMPOUND header: the minor version is never
 * read, so no dispatch can be complete. */
static void short_call(struct msg *m, uint32_t xid)
{
	call_header(m, xid, NFS4_PROG, 4, 1);
	w32(m, 0);		/* tag, then nothing */
}

static void cb_call(struct msg *m, uint32_t xid)
{
	call_header(m, xid, CB_PROG, 1, 1);
	w32(m, 0);
	w32(m, 1);
	w32(m, 1);
	w32(m, 0);
}

static void cb_reply(struct msg *m, uint32_t xid)
{
	reply_header(m, xid);
	w32(m, 0);
	w32(m, 0);
	w32(m, 0);
}

/* What on_decoded saw last, copied out of the event. */
struct seen {
	enum nfsp_rpc_status rpc_status;
	enum nfsp_txn_result txn;
	int has_entry;
	uint32_t entry_prog, entry_proc;
	int has_request;
	uint32_t request_nops, request_op0;
	enum nfsp_decode_status status;
	enum nfsp_dispatch_source source;
	int has_minor;
	uint32_t minor, nops;
};

static void on_decoded(const struct nfsp_semantic_event *ev, void *arg)
{
	struct seen *s = arg;

	memset(s, 0, sizeof(*s));
	s->rpc_status = ev->rpc_status;
	if (ev->rpc_status != NFSP_RPC_OK) {
		CHECK(!ev->msg && !ev->entry && !ev->request,
		      "an invalid envelope carries nothing");
		return;
	}
	s->txn = ev->txn;
	s->has_entry = ev->entry != NULL;
	if (ev->entry) {
		s->entry_prog = ev->entry->program;
		s->entry_proc = ev->entry->procedure;
	}
	s->has_request = ev->request != NULL;
	if (ev->request) {
		s->request_nops = ev->request->nops;
		s->request_op0 = ev->request->nops ? ev->request->opcodes[0] : 0;
	}
	s->status = ev->msg->status;
	s->source = ev->msg->dispatch_source;
	s->has_minor = ev->msg->has_minor;
	s->minor = ev->msg->minor_version;
	s->nops = ev->msg->nops;
}

static uint64_t clock_now;

static uint64_t test_clock(void *arg)
{
	(void)arg;
	return clock_now;
}

static struct seen seen;

static void setup(struct nfsp_semantic *s, enum nfsp_txn_forwarded fwd)
{
	struct nfsp_txn_cfg cfg = { 0, 0, 0, 1000, 1000 };

	memset(s, 0, sizeof(*s));
	s->families = fams;
	s->nfamilies = 1;
	s->forwarded = fwd;
	s->clock_ms = test_clock;
	s->on_decoded = on_decoded;
	s->on_decoded_arg = &seen;
	clock_now = 0;
	CHECK(nfsp_semantic_init(s, &cfg) == 0, "init");
}

static void feed(struct nfsp_semantic *s, uint64_t conn, int dir,
		 const struct msg *m)
{
	struct nfsp_rpc_record r;

	memset(&r, 0, sizeof(r));
	r.conn.connection_id = conn;
	r.direction = dir;
	r.rpc_payload = m->b;
	r.rpc_payload_len = m->n;
	r.nfrags = 1;
	CHECK(nfsp_semantic_record(&r, s) == 0, "the observer never refuses");
}

/* A CALL and its REPLY: the reply decodes with the CALL's dispatch, and the
 * request summary is there for request-dependent checks. */
static void test_call_reply(void)
{
	struct nfsp_semantic s;
	struct msg m;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v41_call(&m, 7);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	CHECK(seen.txn == NFSP_TXN_INSERTED && seen.status ==
	      NFSP_DECODE_DECODED && seen.nops == 3, "CALL: %s/%s",
	      nfsp_txn_strresult(seen.txn),
	      nfsp_decode_strstatus(seen.status));
	v41_reply(&m, 7);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_FOUND &&
	      seen.status == NFSP_DECODE_DECODED &&
	      seen.source == NFSP_DISPATCH_TRANSACTION_ENTRY &&
	      seen.has_minor && seen.minor == 1 && seen.nops == 3,
	      "REPLY: %s/%s", nfsp_txn_strresult(seen.txn),
	      nfsp_decode_strstatus(seen.status));
	CHECK(seen.has_request && seen.request_nops == 3 &&
	      seen.request_op0 == OP_SEQUENCE, "request summary");
	CHECK(s.stats.calls == 1 && s.stats.replies == 1 &&
	      s.stats.call_status[NFSP_DECODE_DECODED] == 1 &&
	      s.stats.reply_status[NFSP_DECODE_DECODED] == 1, "counters");
	nfsp_semantic_free(&s);
}

/* Two CALLs of different minor versions, replies in the other order: each
 * reply decodes under its own CALL's minor version. */
static void test_out_of_order_minors(void)
{
	struct nfsp_semantic s;
	struct msg m;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v40_call(&m, 1);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	v41_call(&m, 2);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	v41_reply(&m, 2);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.status == NFSP_DECODE_DECODED && seen.minor == 1,
	      "4.1 reply: %s", nfsp_decode_strstatus(seen.status));
	/* Oracle 12: a two-operation request, a one-result reply. */
	v40_reply_stale(&m, 1);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.status == NFSP_DECODE_DECODED && seen.has_minor &&
	      seen.minor == 0 && seen.nops == 1 && seen.request_nops == 2,
	      "early COMPOUND failure: %s",
	      nfsp_decode_strstatus(seen.status));
	nfsp_semantic_free(&s);
}

/* Oracle 11a: no CALL, or a CALL whose minor version was never read. */
static void test_no_dispatch(void)
{
	struct nfsp_semantic s;
	struct msg m;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v41_reply(&m, 9);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_MISSING &&
	      seen.status == NFSP_DECODE_TRANSACTION_CONTEXT_MISSING &&
	      seen.nops == 0, "no CALL: %s",
	      nfsp_decode_strstatus(seen.status));

	/* The same XID's CALL on another connection is not this one's. */
	v41_call(&m, 9);
	feed(&s, 2, NFSP_DIR_C2S, &m);
	v41_reply(&m, 9);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_MISSING &&
	      seen.status == NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
	      "other connection's CALL");

	short_call(&m, 10);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	CHECK(seen.txn == NFSP_TXN_INSERTED &&
	      seen.status == NFSP_DECODE_TRUNCATED,
	      "a short CALL still has an entry");
	v41_reply(&m, 10);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_FOUND &&
	      seen.status == NFSP_DECODE_DISPATCH_INCOMPLETE &&
	      !seen.has_request, "no minor: %s",
	      nfsp_decode_strstatus(seen.status));
	nfsp_semantic_free(&s);
}

/* Oracle 13: on one connection a forechannel CALL (C2S) and a backchannel
 * CALL (S2C) with the same XID are two transactions; each REPLY, which
 * travels the other way, finds its own. */
static void test_backchannel(void)
{
	struct nfsp_semantic s;
	struct msg m;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v41_call(&m, 5);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	cb_call(&m, 5);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_INSERTED &&
	      seen.status == NFSP_DECODE_UNSUPPORTED_SCHEMA,
	      "callback CALL: %s/%s", nfsp_txn_strresult(seen.txn),
	      nfsp_decode_strstatus(seen.status));
	cb_reply(&m, 5);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	CHECK(seen.txn == NFSP_TXN_FOUND && seen.entry_prog == CB_PROG &&
	      seen.status == NFSP_DECODE_UNSUPPORTED_SCHEMA,
	      "C2S REPLY finds the S2C CALL");
	v41_reply(&m, 5);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_FOUND && seen.entry_prog == NFS4_PROG &&
	      seen.status == NFSP_DECODE_DECODED && seen.minor == 1,
	      "S2C REPLY finds the C2S CALL: %s",
	      nfsp_decode_strstatus(seen.status));
	nfsp_semantic_free(&s);
}

/* When a legacy rewrite may change the CALL, the forwarded request is
 * unknown, and so is the dispatch: a rewrite of the minor version from 0 to
 * 1 would otherwise decode a 4.1 reply under the 4.0 schema.  The reply is
 * found, but gets no dispatch and no request summary. */
static void test_forwarded_unknown(void)
{
	struct nfsp_semantic s;
	struct msg m;

	setup(&s, NFSP_TXN_FWD_UNKNOWN);
	v40_call(&m, 3);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	v41_reply(&m, 3);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_FOUND && seen.has_entry &&
	      seen.status == NFSP_DECODE_TRANSACTION_CONTEXT_MISSING &&
	      seen.nops == 0 && !seen.has_request,
	      "no dispatch: %s", nfsp_decode_strstatus(seen.status));
	nfsp_semantic_free(&s);
}

/* A late reply to an expired, or ambiguous, CALL must not take the
 * request of a new CALL that reused the key while the old one is still
 * retained. */
static void test_reuse_after_unresolved(void)
{
	struct nfsp_semantic s;
	struct msg m;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v40_call(&m, 6);				/* A: PUTFH, READDIR */
	feed(&s, 1, NFSP_DIR_C2S, &m);
	clock_now = 1000;				/* A expires */
	v41_call(&m, 6);				/* B: SEQUENCE ... */
	feed(&s, 1, NFSP_DIR_C2S, &m);
	CHECK(seen.txn == NFSP_TXN_AMBIGUOUS_CALL,
	      "B on an expired, retained key: %s",
	      nfsp_txn_strresult(seen.txn));
	v40_reply_stale(&m, 6);				/* late reply to A */
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_AMBIGUOUS_REPLY && !seen.has_request &&
	      seen.status == NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
	      "late A reply: %s/%s", nfsp_txn_strresult(seen.txn),
	      nfsp_decode_strstatus(seen.status));
	nfsp_semantic_free(&s);

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v40_call(&m, 6);				/* A */
	feed(&s, 1, NFSP_DIR_C2S, &m);
	v41_call(&m, 6);				/* B, conflicting */
	feed(&s, 1, NFSP_DIR_C2S, &m);
	v41_reply(&m, 6);				/* B's reply */
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_AMBIGUOUS_REPLY, "ambiguous reply");
	v41_call(&m, 6);				/* B retransmitted */
	feed(&s, 1, NFSP_DIR_C2S, &m);
	CHECK(seen.txn == NFSP_TXN_AMBIGUOUS_CALL,
	      "retransmission on a retained ambiguous key: %s",
	      nfsp_txn_strresult(seen.txn));
	v40_reply_stale(&m, 6);				/* late reply to A */
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_AMBIGUOUS_REPLY && !seen.has_request &&
	      seen.status == NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
	      "late A reply: %s/%s", nfsp_txn_strresult(seen.txn),
	      nfsp_decode_strstatus(seen.status));
	nfsp_semantic_free(&s);
}

/* A different CALL on a live key: its reply decodes with no dispatch. */
static void test_ambiguous(void)
{
	struct nfsp_semantic s;
	struct msg m;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v41_call(&m, 4);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	CHECK(seen.txn == NFSP_TXN_DUPLICATE_EQUIVALENT, "retransmission");
	v40_call(&m, 4);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	CHECK(seen.txn == NFSP_TXN_AMBIGUOUS_CALL, "ambiguous");
	v41_reply(&m, 4);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_AMBIGUOUS_REPLY &&
	      seen.status == NFSP_DECODE_TRANSACTION_CONTEXT_MISSING &&
	      !seen.has_request, "ambiguous reply has no dispatch");
	nfsp_semantic_free(&s);
}

/* Lifecycle: a closed connection and a timed-out CALL leave no dispatch;
 * an invalid envelope touches nothing. */
static void test_lifecycle(void)
{
	struct nfsp_semantic s;
	struct nfsp_connection_ref c = { 1, 0, 0 };
	struct msg m;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	nfsp_semantic_connection(&c, NFSP_CONN_OPENED, &s);
	v41_call(&m, 1);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	nfsp_semantic_connection(&c, NFSP_CONN_CLOSED, &s);
	CHECK(s.txn.stats.outstanding == 0 &&
	      s.txn.stats.expired_connection_closed == 1, "closed");
	v41_reply(&m, 1);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_MISSING, "gone with its connection");

	v41_call(&m, 2);
	feed(&s, 2, NFSP_DIR_C2S, &m);
	clock_now = 1000;
	nfsp_semantic_tick(&s);
	v41_reply(&m, 2);
	feed(&s, 2, NFSP_DIR_S2C, &m);
	CHECK(seen.txn == NFSP_TXN_EXPIRED_ENTRY &&
	      seen.status == NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
	      "expired: %s", nfsp_txn_strresult(seen.txn));

	m.n = 6;
	feed(&s, 2, NFSP_DIR_C2S, &m);
	CHECK(seen.rpc_status != NFSP_RPC_OK && s.stats.rpc_invalid == 1 &&
	      s.txn.stats.outstanding == 0, "invalid envelope");
	CHECK(s.stats.connections_opened == 1 &&
	      s.stats.connections_closed == 1, "connection counters");
	nfsp_semantic_free(&s);
}

static void test_report(void)
{
	struct nfsp_semantic s;
	struct msg m;
	char buf[2048];
	FILE *f;

	setup(&s, NFSP_TXN_FWD_ORIGINAL);
	v41_call(&m, 1);
	feed(&s, 1, NFSP_DIR_C2S, &m);
	v41_reply(&m, 1);
	feed(&s, 1, NFSP_DIR_S2C, &m);
	f = fmemopen(buf, sizeof(buf), "w");
	CHECK(f != NULL, "fmemopen");
	if (f) {
		nfsp_semantic_report(&s, f);
		fclose(f);
		CHECK(strstr(buf, "semantic records=2 ") &&
		      strstr(buf, " call_decoded=1") &&
		      strstr(buf, " reply_decoded=1") &&
		      strstr(buf, "txn inserted=1 ") &&
		      strstr(buf, " found=1 "), "report: %s", buf);
	}
	nfsp_semantic_free(&s);
}

int main(void)
{
	test_call_reply();
	test_out_of_order_minors();
	test_no_dispatch();
	test_backchannel();
	test_forwarded_unknown();
	test_reuse_after_unresolved();
	test_ambiguous();
	test_lifecycle();
	test_report();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
