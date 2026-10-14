/* Tests for the Transaction Context table (design 03-nfs-proxy/03).
 *
 * Each test is one of the design's oracles (03 "테스트 oracle"), numbered as
 * there.  The table is driven directly, with a clock the test owns, so a
 * timeout or a retention is an exact millisecond and never a sleep.
 */
#include "txn.h"

#include <stdio.h>
#include <string.h>

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

#define C2S 0
#define S2C 1

static const uint8_t call_a[] = "CALL A bytes";
static const uint8_t call_b[] = "CALL B bytes";

static struct nfsp_txn_key key(uint64_t conn, int dir, uint32_t xid)
{
	struct nfsp_txn_key k = { conn, dir, xid };

	return k;
}

static enum nfsp_txn_result call(struct nfsp_txn *t, uint64_t conn, int dir,
				 uint32_t xid, const uint8_t *p, uint64_t now)
{
	struct nfsp_txn_key k = key(conn, dir, xid);
	struct nfsp_txn_entry *e;

	return nfsp_txn_call(t, &k, 100003, 4, 1, 1, 0, NFSP_TXN_FWD_ORIGINAL,
			     p, sizeof(call_a), now, &e);
}

static enum nfsp_txn_result reply(struct nfsp_txn *t, uint64_t conn,
				  int call_dir, uint32_t xid, uint64_t now)
{
	struct nfsp_txn_key k = key(conn, call_dir, xid);
	const struct nfsp_txn_entry *e;

	return nfsp_txn_reply(t, &k, now, &e);
}

static void init(struct nfsp_txn *t, uint32_t out, uint32_t per_conn,
		 uint32_t retained, uint32_t timeout, uint32_t retention)
{
	struct nfsp_txn_cfg c = { out, per_conn, retained, timeout, retention };

	CHECK(nfsp_txn_init(t, &c) == 0, "init");
}

/* 1, 2: a CALL then its REPLY is found once; replies out of order each find
 * their own CALL. */
static void test_basic_and_out_of_order(void)
{
	struct nfsp_txn t;
	struct nfsp_txn_entry *e;
	const struct nfsp_txn_entry *r;
	struct nfsp_txn_key k = key(7, C2S, 1);
	struct nfsp_reply_dispatch rd;

	init(&t, 0, 0, 0, 0, 0);
	CHECK(nfsp_txn_call(&t, &k, 100003, 4, 1, 6, 0, NFSP_TXN_FWD_ORIGINAL,
			    call_a, sizeof(call_a), 10, &e) ==
	      NFSP_TXN_INSERTED && e, "insert");
	CHECK(e->state == NFSP_TXN_AWAITING_REPLY && e->created_ms == 10,
	      "awaiting");
	CHECK(nfsp_txn_reply(&t, &k, 20, &r) == NFSP_TXN_FOUND && r == e,
	      "found");
	CHECK(r->state == NFSP_TXN_REPLIED && r->reply_seen_ms == 20,
	      "replied at 20");
	nfsp_txn_dispatch(r, &rd);
	CHECK(rd.source == NFSP_DISPATCH_TRANSACTION_ENTRY &&
	      rd.program == 100003 && rd.version == 4 && rd.procedure == 1 &&
	      rd.cred_flavor == 6 && !rd.has_minor, "dispatch from the entry");
	/* A second reply to the same CALL is still that CALL's. */
	CHECK(reply(&t, 7, C2S, 1, 21) == NFSP_TXN_FOUND &&
	      t.stats.duplicate_replies == 1, "duplicate reply");

	for (uint32_t x = 100; x < 110; x++)
		CHECK(call(&t, 7, C2S, x, call_a, 30) == NFSP_TXN_INSERTED,
		      "insert %u", x);
	for (uint32_t x = 109; x >= 100; x--) {
		struct nfsp_txn_key kk = key(7, C2S, x);

		CHECK(nfsp_txn_reply(&t, &kk, 40, &r) == NFSP_TXN_FOUND &&
		      r->key.xid == x, "out-of-order reply %u", x);
	}
	CHECK(t.stats.outstanding == 0, "nothing outstanding");
	nfsp_txn_free(&t);
}

/* 3, 4: the same XID on two connections, and in both directions of one
 * connection, are four transactions. */
static void test_key_parts(void)
{
	struct nfsp_txn t;
	const struct nfsp_txn_entry *r;
	struct nfsp_txn_key k;

	init(&t, 0, 0, 0, 0, 0);
	CHECK(call(&t, 1, C2S, 5, call_a, 0) == NFSP_TXN_INSERTED, "1/c2s");
	CHECK(call(&t, 2, C2S, 5, call_b, 0) == NFSP_TXN_INSERTED, "2/c2s");
	CHECK(call(&t, 1, S2C, 5, call_b, 0) == NFSP_TXN_INSERTED, "1/s2c");
	CHECK(call(&t, 2, S2C, 5, call_a, 0) == NFSP_TXN_INSERTED, "2/s2c");
	CHECK(t.stats.outstanding == 4, "four entries");

	k = key(2, S2C, 5);
	CHECK(nfsp_txn_reply(&t, &k, 1, &r) == NFSP_TXN_FOUND &&
	      r->key.connection_id == 2 && r->key.call_direction == S2C,
	      "the backchannel reply on 2 finds only its CALL");
	CHECK(reply(&t, 2, S2C, 5, 2) == NFSP_TXN_FOUND &&
	      t.stats.outstanding == 3, "the others are untouched");
	CHECK(reply(&t, 3, C2S, 5, 2) == NFSP_TXN_MISSING,
	      "another connection's XID is not borrowed");
	nfsp_txn_free(&t);
}

/* 5, 6: a retransmission is one entry; a different CALL on a live key makes
 * it ambiguous, and its reply is never found. */
static void test_duplicates(void)
{
	struct nfsp_txn t;
	struct nfsp_txn_entry *e;
	struct nfsp_txn_key k = key(1, C2S, 9);

	init(&t, 0, 0, 0, 0, 0);
	CHECK(call(&t, 1, C2S, 9, call_a, 0) == NFSP_TXN_INSERTED, "insert");
	CHECK(nfsp_txn_call(&t, &k, 100003, 4, 1, 1, 0, NFSP_TXN_FWD_ORIGINAL,
			    call_a, sizeof(call_a), 5, &e) ==
	      NFSP_TXN_DUPLICATE_EQUIVALENT && e->duplicate_calls == 1 &&
	      e->last_seen_ms == 5 && e->created_ms == 0,
	      "retransmission refreshes, does not replace");
	CHECK(t.stats.outstanding == 1 && t.stats.inserted == 1, "one entry");
	/* Same bytes but shorter: a different CALL. */
	CHECK(nfsp_txn_call(&t, &k, 100003, 4, 1, 1, 0, NFSP_TXN_FWD_ORIGINAL,
			    call_a, sizeof(call_a) - 1, 6, &e) ==
	      NFSP_TXN_AMBIGUOUS_CALL && e->state == NFSP_TXN_AMBIGUOUS,
	      "different length is ambiguous");
	CHECK(call(&t, 1, C2S, 9, call_a, 7) == NFSP_TXN_AMBIGUOUS_CALL,
	      "stays ambiguous, even for the first bytes again");
	CHECK(reply(&t, 1, C2S, 9, 8) == NFSP_TXN_AMBIGUOUS_REPLY,
	      "reply is ambiguous");
	CHECK(reply(&t, 1, C2S, 9, 9) == NFSP_TXN_AMBIGUOUS_REPLY,
	      "and stays ambiguous while retained");
	CHECK(t.stats.outstanding == 0 && t.stats.retained == 1,
	      "answered ambiguous entry is retained");

	CHECK(call(&t, 1, C2S, 10, call_a, 10) == NFSP_TXN_INSERTED, "insert");
	CHECK(call(&t, 1, C2S, 10, call_b, 11) == NFSP_TXN_AMBIGUOUS_CALL,
	      "different bytes are ambiguous");
	nfsp_txn_free(&t);
}

/* 7: a REPLY with no CALL is missing, and does not create anything. */
static void test_missing(void)
{
	struct nfsp_txn t;
	const struct nfsp_txn_entry *r;
	struct nfsp_txn_key k = key(1, C2S, 42);

	init(&t, 0, 0, 0, 0, 0);
	CHECK(nfsp_txn_reply(&t, &k, 0, &r) == NFSP_TXN_MISSING && !r,
	      "missing");
	CHECK(t.stats.outstanding == 0 && t.stats.retained == 0 &&
	      t.stats.missing == 1, "nothing recorded");
	nfsp_txn_free(&t);
}

/* 8: closing a connection drops its entries, and only its. */
static void test_connection_closed(void)
{
	struct nfsp_txn t;

	init(&t, 0, 0, 0, 0, 0);
	CHECK(call(&t, 1, C2S, 1, call_a, 0) == NFSP_TXN_INSERTED, "1a");
	CHECK(call(&t, 1, S2C, 2, call_a, 0) == NFSP_TXN_INSERTED, "1b");
	CHECK(call(&t, 1, C2S, 3, call_a, 0) == NFSP_TXN_INSERTED, "1c");
	CHECK(reply(&t, 1, C2S, 3, 1) == NFSP_TXN_FOUND, "1c replied");
	CHECK(call(&t, 2, C2S, 1, call_a, 0) == NFSP_TXN_INSERTED, "2a");
	nfsp_txn_connection_closed(&t, 1);
	CHECK(t.stats.expired_connection_closed == 2 &&
	      t.stats.outstanding == 1 && t.stats.retained == 0,
	      "two outstanding expired, the replied one dropped");
	CHECK(reply(&t, 1, C2S, 1, 2) == NFSP_TXN_MISSING, "gone");
	CHECK(reply(&t, 2, C2S, 1, 2) == NFSP_TXN_FOUND,
	      "the other connection keeps its entry");
	nfsp_txn_free(&t);
}

/* 9: an unanswered CALL expires after the timeout of silence; a late reply
 * is expired, not found; retention then forgets it. */
static void test_timeout(void)
{
	struct nfsp_txn t;
	const struct nfsp_txn_entry *r;
	struct nfsp_txn_key k = key(1, C2S, 1);

	init(&t, 0, 0, 0, 100, 50);
	CHECK(call(&t, 1, C2S, 1, call_a, 0) == NFSP_TXN_INSERTED, "insert");
	CHECK(call(&t, 1, C2S, 1, call_a, 60) ==
	      NFSP_TXN_DUPLICATE_EQUIVALENT, "retransmission at 60");
	nfsp_txn_tick(&t, 159);
	CHECK(t.stats.outstanding == 1, "alive until 100ms after the last CALL");
	nfsp_txn_tick(&t, 160);
	CHECK(t.stats.outstanding == 0 && t.stats.expired_timeout == 1,
	      "expired at 160");
	CHECK(nfsp_txn_reply(&t, &k, 170, &r) == NFSP_TXN_EXPIRED_ENTRY &&
	      r->state == NFSP_TXN_EXPIRED &&
	      r->expiry == NFSP_TXN_EXPIRED_TIMEOUT, "late reply is expired");
	CHECK(reply(&t, 1, C2S, 1, 210) == NFSP_TXN_MISSING,
	      "forgotten after the retention");
	/* An expired key may carry a new CALL. */
	CHECK(call(&t, 1, C2S, 1, call_b, 300) == NFSP_TXN_INSERTED,
	      "a new CALL after expiry");
	nfsp_txn_free(&t);
}

/* 10: a full table refuses, never overwrites a live entry; ended entries are
 * the only ones reclaimed. */
static void test_capacity(void)
{
	struct nfsp_txn t;

	init(&t, 4, 3, 2, 0, 0);
	for (uint32_t x = 0; x < 3; x++)
		CHECK(call(&t, 1, C2S, x, call_a, 0) == NFSP_TXN_INSERTED,
		      "conn 1 #%u", x);
	CHECK(call(&t, 1, C2S, 3, call_a, 0) == NFSP_TXN_CAPACITY_EXHAUSTED,
	      "per-connection bound");
	CHECK(call(&t, 2, C2S, 0, call_a, 0) == NFSP_TXN_INSERTED, "conn 2");
	CHECK(call(&t, 2, C2S, 1, call_a, 0) == NFSP_TXN_CAPACITY_EXHAUSTED,
	      "global bound");
	for (uint32_t x = 0; x < 3; x++)
		CHECK(reply(&t, 1, C2S, x, 1) == NFSP_TXN_FOUND,
		      "every live entry survived #%u", x);
	CHECK(reply(&t, 2, C2S, 0, 1) == NFSP_TXN_FOUND, "conn 2 survived");
	CHECK(t.stats.retained == 2 && t.stats.reclaimed == 2,
	      "retained bounded, oldest reclaimed");
	CHECK(reply(&t, 1, C2S, 0, 2) == NFSP_TXN_MISSING &&
	      reply(&t, 2, C2S, 0, 2) == NFSP_TXN_FOUND,
	      "the reclaimed one is the oldest");

	/* Fill the pool: 4 outstanding + 2 retained. */
	for (uint32_t x = 10; x < 14; x++)
		CHECK(call(&t, 3 + x % 2, C2S, x, call_a, 3) ==
		      NFSP_TXN_INSERTED, "refill %u", x);
	CHECK(t.stats.outstanding == 4 && t.stats.retained == 2, "full pool");
	CHECK(reply(&t, 3, C2S, 10, 4) == NFSP_TXN_FOUND, "retire one");
	CHECK(call(&t, 5, C2S, 20, call_a, 5) == NFSP_TXN_INSERTED,
	      "a slot comes from a retained entry, never a live one");
	for (uint32_t x = 11; x < 14; x++)
		CHECK(reply(&t, 3 + x % 2, C2S, x, 6) == NFSP_TXN_FOUND,
		      "live %u still found", x);
	CHECK(t.stats.peak_outstanding == 4, "peak");
	nfsp_txn_free(&t);
}

/* A replied key may be used again by a new CALL: the old transaction is
 * superseded, not mixed into the new one. */
static void test_supersede(void)
{
	struct nfsp_txn t;
	struct nfsp_txn_entry *e;
	struct nfsp_txn_key k = key(1, C2S, 3);

	init(&t, 0, 0, 0, 0, 0);
	CHECK(call(&t, 1, C2S, 3, call_a, 0) == NFSP_TXN_INSERTED, "first");
	CHECK(reply(&t, 1, C2S, 3, 1) == NFSP_TXN_FOUND, "replied");
	CHECK(nfsp_txn_call(&t, &k, 100003, 4, 1, 1, 0, NFSP_TXN_FWD_UNKNOWN,
			    call_b, sizeof(call_b), 2, &e) ==
	      NFSP_TXN_INSERTED && e->replies == 0 &&
	      e->forwarded == NFSP_TXN_FWD_UNKNOWN, "new transaction");
	CHECK(t.stats.superseded == 1 && t.stats.retained == 0, "superseded");
	nfsp_txn_free(&t);
}

/* The CALL's decode feeds the REPLY's dispatch: the minor version, and the
 * operations only when the decode kept them. */
static void test_enrich(void)
{
	struct nfsp_txn t;
	struct nfsp_txn_entry *e;
	const struct nfsp_txn_entry *r;
	struct nfsp_txn_key k = key(1, C2S, 1);
	struct nfsp_decoded_op ops[3] = {
		{ .opcode = 53 }, { .opcode = 22 }, { .opcode = 9 }
	};
	struct nfsp_decoded_msg m;
	struct nfsp_reply_dispatch rd;

	init(&t, 0, 0, 0, 0, 0);
	memset(&m, 0, sizeof(m));
	m.status = NFSP_DECODE_PARTIAL;
	m.has_minor = 1;
	m.minor_version = 2;
	m.ops = ops;
	m.nops = 3;
	CHECK(nfsp_txn_call(&t, &k, 100003, 4, 1, 1, 0, NFSP_TXN_FWD_ORIGINAL,
			    call_a, sizeof(call_a), 0, &e) == NFSP_TXN_INSERTED,
	      "insert");
	nfsp_txn_enrich(&t, e, &m);
	CHECK(e->original.decoded && e->original.nops == 3 &&
	      e->original.opcodes[0] == 53 && e->original.opcodes[2] == 9 &&
	      !e->original.ops_truncated, "partial keeps the prefix");
	CHECK(nfsp_txn_reply(&t, &k, 1, &r) == NFSP_TXN_FOUND, "found");
	nfsp_txn_dispatch(r, &rd);
	CHECK(rd.has_minor && rd.minor_version == 2, "minor version");

	k.xid = 2;
	m.status = NFSP_DECODE_MALFORMED;
	m.has_minor = 0;
	CHECK(nfsp_txn_call(&t, &k, 100003, 4, 1, 1, 0, NFSP_TXN_FWD_ORIGINAL,
			    call_a, sizeof(call_a), 0, &e) == NFSP_TXN_INSERTED,
	      "insert");
	nfsp_txn_enrich(&t, e, &m);
	CHECK(e->original.nops == 0 &&
	      e->original.status == NFSP_DECODE_MALFORMED,
	      "a refused decode keeps no operations");
	nfsp_txn_dispatch(e, &rd);
	CHECK(!rd.has_minor, "no minor: the reply decode is dispatch_incomplete");
	nfsp_txn_free(&t);
}

/* Many connections and XIDs at random: the table agrees with a model that
 * remembers every awaiting CALL, and its counts stay within the bounds. */
static void test_model(void)
{
	enum { CONNS = 5, XIDS = 40 };
	struct nfsp_txn t;
	int awaiting[CONNS][2][XIDS];
	uint64_t seed = 0x1234567;
	uint32_t n_await = 0;

	memset(awaiting, 0, sizeof(awaiting));
	init(&t, 64, 20, 16, 1u << 30, 1u << 30);
	for (int step = 0; step < 20000; step++) {
		uint32_t c, d, x;
		enum nfsp_txn_result res;

		seed = seed * 6364136223846793005ull + 1442695040888963407ull;
		c = (uint32_t)(seed >> 33) % CONNS;
		d = (uint32_t)(seed >> 40) & 1u;
		x = (uint32_t)(seed >> 45) % XIDS;
		if ((seed >> 60) & 1u) {
			res = call(&t, c + 1, (int)d, x, call_a, 0);
			if (awaiting[c][d][x])
				CHECK(res == NFSP_TXN_DUPLICATE_EQUIVALENT,
				      "dup %u/%u/%u", c, d, x);
			else if (res == NFSP_TXN_INSERTED) {
				awaiting[c][d][x] = 1;
				n_await++;
			} else
				CHECK(res == NFSP_TXN_CAPACITY_EXHAUSTED,
				      "insert %u/%u/%u: %s", c, d, x,
				      nfsp_txn_strresult(res));
		} else {
			res = reply(&t, c + 1, (int)d, x, 0);
			if (awaiting[c][d][x]) {
				CHECK(res == NFSP_TXN_FOUND, "found %u/%u/%u",
				      c, d, x);
				awaiting[c][d][x] = 0;
				n_await--;
			} else
				CHECK(res == NFSP_TXN_FOUND ||
				      res == NFSP_TXN_MISSING,
				      "unanswered %u/%u/%u: %s", c, d, x,
				      nfsp_txn_strresult(res));
		}
		CHECK(t.stats.outstanding == n_await &&
		      t.stats.outstanding <= 64 && t.stats.retained <= 16,
		      "counts at step %d", step);
		if (failures > 20)
			break;
	}
	nfsp_txn_free(&t);
}

int main(void)
{
	test_basic_and_out_of_order();
	test_key_parts();
	test_duplicates();
	test_missing();
	test_connection_closed();
	test_timeout();
	test_capacity();
	test_supersede();
	test_enrich();
	test_model();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
