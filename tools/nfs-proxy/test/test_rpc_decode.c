/* Tests for the target RPC envelope decoder.
 *
 * Vectors are built word by word from RFC 5531 §9 rather than captured, so
 * each expected offset is visible in the test.  The cross-check against the
 * legacy walk is the guard for design 06 §33 seam 1: for a single-fragment
 * record the two coordinate systems must differ by exactly the marker, and
 * any other difference means one of them is lying about where a field is.
 */
#include "rpc_decode.h"
#include "rpc_record.h"
#include "walk.h"

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

struct msg {
	uint8_t b[1024];
	size_t n;
};

static void w32(struct msg *m, uint32_t v)
{
	m->b[m->n++] = (uint8_t)(v >> 24);
	m->b[m->n++] = (uint8_t)(v >> 16);
	m->b[m->n++] = (uint8_t)(v >> 8);
	m->b[m->n++] = (uint8_t)v;
}

static void wopaque(struct msg *m, const char *s, size_t len)
{
	w32(m, (uint32_t)len);
	memcpy(m->b + m->n, s, len);
	m->n += len;
	while (m->n % 4u)
		m->b[m->n++] = 0;
}

/* NFSv4 COMPOUND CALL: AUTH_SYS cred of 5 bytes (padded to 8), AUTH_NONE verf,
 * then a COMPOUND header and one PUTROOTFH. */
static void build_call(struct msg *m)
{
	m->n = 0;
	w32(m, 0x11223344);		/*  0 xid */
	w32(m, NFSP_RPC_CALL);		/*  4 mtype */
	w32(m, 2);			/*  8 rpcvers */
	w32(m, 100003);			/* 12 prog */
	w32(m, 4);			/* 16 vers */
	w32(m, 1);			/* 20 proc COMPOUND */
	w32(m, 1);			/* 24 cred flavor AUTH_SYS */
	wopaque(m, "hello", 5);		/* 28 len, 32..37 body, pad to 40 */
	w32(m, 0);			/* 40 verf flavor */
	w32(m, 0);			/* 44 verf len */
	wopaque(m, "", 0);		/* 48 tag len (body starts here) */
	w32(m, 0);			/* 52 minorversion */
	w32(m, 1);			/* 56 opcount */
	w32(m, 24);			/* 60 OP_PUTROOTFH */
}

static void test_call(void)
{
	struct msg m;
	struct nfsp_rpc_envelope e;

	printf("CALL envelope: header fields, auth spans, body offset\n");
	build_call(&m);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_OK, "%s",
	      nfsp_rpc_strerror(e.status));
	CHECK(e.msg_type == NFSP_RPC_CALL && e.xid == 0x11223344u,
	      "type %u xid %08x", e.msg_type, e.xid);
	CHECK(e.rpcvers == 2 && e.prog == 100003 && e.vers == 4 && e.proc == 1,
	      "prog/vers/proc %u/%u/%u", e.prog, e.vers, e.proc);
	CHECK(e.cred.flavor == 1 && e.cred.encoded.off == 24 &&
	      e.cred.encoded.len == 16 && e.cred.body.off == 32 &&
	      e.cred.body.len == 5, "cred span %u+%u body %u+%u",
	      e.cred.encoded.off, e.cred.encoded.len, e.cred.body.off,
	      e.cred.body.len);
	CHECK(e.verf.flavor == 0 && e.verf.encoded.off == 40 &&
	      e.verf.encoded.len == 8 && e.verf.body.off == 48 &&
	      e.verf.body.len == 0, "verf span %u+%u", e.verf.encoded.off,
	      e.verf.encoded.len);
	CHECK(e.body.off == 48 && e.body.len == m.n - 48,
	      "body %u+%u, want 48+%zu", e.body.off, e.body.len, m.n - 48);
}

static void test_replies(void)
{
	struct msg m;
	struct nfsp_rpc_envelope e;

	printf("REPLY arms: accepted, prog mismatch, denied rpc/auth\n");

	m.n = 0;
	w32(&m, 7); w32(&m, 1); w32(&m, 0);	/* xid, REPLY, ACCEPTED */
	w32(&m, 0); w32(&m, 0);			/* verf AUTH_NONE */
	w32(&m, 0);				/* SUCCESS */
	w32(&m, 0xdead);			/* procedure results */
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_OK &&
	      e.msg_type == NFSP_RPC_REPLY && e.xid == 7 &&
	      e.reply_stat == NFSP_RPC_MSG_ACCEPTED &&
	      e.accept_stat == NFSP_RPC_SUCCESS && e.verf.encoded.off == 12 &&
	      e.body.off == 24 && e.body.len == 4,
	      "accepted SUCCESS: %s body %u+%u", nfsp_rpc_strerror(e.status),
	      e.body.off, e.body.len);
	CHECK(e.prog == 0 && e.proc == 0,
	      "a REPLY must not claim a procedure; the wire has none");

	m.n = 0;
	w32(&m, 8); w32(&m, 1); w32(&m, 0);
	w32(&m, 0); w32(&m, 0);
	w32(&m, NFSP_RPC_PROG_MISMATCH); w32(&m, 2); w32(&m, 4);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_OK &&
	      e.mismatch_low == 2 && e.mismatch_high == 4 && e.body.off == 32 &&
	      e.body.len == 0, "PROG_MISMATCH low/high");
	CHECK(nfsp_rpc_decode(m.b, m.n - 4, &e) == NFSP_RPC_TRUNCATED,
	      "PROG_MISMATCH without high must be truncated");

	m.n = 0;
	w32(&m, 9); w32(&m, 1); w32(&m, 1);	/* DENIED */
	w32(&m, NFSP_RPC_RPC_MISMATCH); w32(&m, 2); w32(&m, 2);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_OK &&
	      e.reply_stat == NFSP_RPC_MSG_DENIED &&
	      e.reject_stat == NFSP_RPC_RPC_MISMATCH && e.mismatch_high == 2 &&
	      e.verf.encoded.len == 0 && e.body.off == 24,
	      "DENIED RPC_MISMATCH");

	m.n = 0;
	w32(&m, 10); w32(&m, 1); w32(&m, 1);
	w32(&m, NFSP_RPC_AUTH_ERROR); w32(&m, 5);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_OK &&
	      e.reject_stat == NFSP_RPC_AUTH_ERROR && e.auth_stat == 5 &&
	      e.body.off == 20, "DENIED AUTH_ERROR");
}

static void test_fail_closed(void)
{
	struct msg m;
	struct nfsp_rpc_envelope e;

	printf("values outside RFC 5531 fail closed with a named reason\n");

	m.n = 0;
	w32(&m, 1); w32(&m, 2);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_MTYPE, "mtype 2");

	build_call(&m);
	m.b[11] = 3;
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_RPCVERS,
	      "rpcvers 3");

	build_call(&m);
	m.b[30] = 0x01; m.b[31] = 0x91;		/* cred len 401 */
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_AUTH_LEN,
	      "cred len 401 is over MAX_AUTH_BYTES: %s",
	      nfsp_rpc_strerror(e.status));
	m.b[28] = 0xff; m.b[29] = 0xff; m.b[30] = 0xff; m.b[31] = 0xfe;
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_AUTH_LEN,
	      "a length near 2^32 must not reach the padding arithmetic");

	m.n = 0;
	w32(&m, 1); w32(&m, 1); w32(&m, 2);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_REPLY_STAT,
	      "reply_stat 2");

	m.n = 0;
	w32(&m, 1); w32(&m, 1); w32(&m, 0); w32(&m, 0); w32(&m, 0); w32(&m, 6);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_ACCEPT_STAT,
	      "accept_stat 6");

	m.n = 0;
	w32(&m, 1); w32(&m, 1); w32(&m, 1); w32(&m, 2);
	CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_REJECT_STAT,
	      "reject_stat 2");

	/* auth_stat: RPCSEC_GSS 13/14 are the last defined values. */
	{
		const uint32_t ok[] = {0, 13, 14};
		const uint32_t bad[] = {15, 0xffffffffu};
		for (unsigned i = 0; i < 3; i++) {
			m.n = 0;
			w32(&m, 1); w32(&m, 1); w32(&m, 1);
			w32(&m, NFSP_RPC_AUTH_ERROR); w32(&m, ok[i]);
			CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_OK &&
			      e.auth_stat == ok[i], "auth_stat %u must decode", ok[i]);
		}
		for (unsigned i = 0; i < 2; i++) {
			m.n = 0;
			w32(&m, 1); w32(&m, 1); w32(&m, 1);
			w32(&m, NFSP_RPC_AUTH_ERROR); w32(&m, bad[i]);
			CHECK(nfsp_rpc_decode(m.b, m.n, &e) == NFSP_RPC_BAD_AUTH_STAT,
			      "auth_stat %u must fail closed: %s", bad[i],
			      nfsp_rpc_strerror(e.status));
		}
	}

	CHECK(nfsp_rpc_decode(NULL, 4, &e) == NFSP_RPC_TRUNCATED, "NULL");
	CHECK(nfsp_rpc_decode(m.b, 0, &e) == NFSP_RPC_TRUNCATED, "empty");
}

/* Every strict prefix of a valid envelope must fail, and stopped_at must not
 * point past the prefix.  A decoder that "succeeds" on a prefix would hand
 * the semantic layer a body span that runs off the record. */
static void test_truncation_sweep(void)
{
	struct msg m;
	struct nfsp_rpc_envelope e;
	size_t envelope_end;

	printf("every prefix of the envelope is truncated, never OK\n");
	build_call(&m);
	envelope_end = 48;
	for (size_t cut = 0; cut < envelope_end; cut++) {
		enum nfsp_rpc_status st = nfsp_rpc_decode(m.b, cut, &e);

		CHECK(st == NFSP_RPC_TRUNCATED, "cut %zu: %s", cut,
		      nfsp_rpc_strerror(st));
		CHECK(e.stopped_at <= cut, "cut %zu stopped at %u", cut,
		      e.stopped_at);
	}
	for (size_t cut = envelope_end; cut <= m.n; cut++) {
		CHECK(nfsp_rpc_decode(m.b, cut, &e) == NFSP_RPC_OK &&
		      e.body.off == envelope_end &&
		      (size_t)e.body.off + e.body.len == cut,
		      "cut %zu: body must end exactly at the payload end", cut);
	}
}

/* Seam 1: the legacy walk and this decoder must place every shared field at
 * offsets that differ by exactly the record marker. */
static void test_coordinates_match_legacy_walk(void)
{
	struct msg m;
	uint8_t framed[1024 + 4];
	struct nfsp_rpc_envelope e;
	struct nfsp_walk w;
	struct nfsp_record_buf scratch = {0};
	const uint8_t *p;
	size_t plen;
	uint32_t nfrags;
	const struct nfsp_slot *s;

	printf("payload coordinates = legacy walk coordinates - 4\n");
	build_call(&m);
	framed[0] = 0x80;
	framed[1] = 0;
	framed[2] = (uint8_t)(m.n >> 8);
	framed[3] = (uint8_t)m.n;
	memcpy(framed + 4, m.b, m.n);

	CHECK(nfsp_rpc_payload(framed, m.n + 4, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_OK, "canonicalise");
	CHECK(nfsp_rpc_decode(p, plen, &e) == NFSP_RPC_OK, "decode");
	nfsp_walk(framed, m.n + 4, &w);
	CHECK(w.status == NFSP_WALK_OK, "walk: %s", nfsp_walk_strerror(w.status));
	CHECK(w.xid == e.xid && w.prog == e.prog && w.vers == e.vers &&
	      w.proc == e.proc, "walk and decoder disagree on values");

	s = nfsp_walk_find(&w, NFSP_SR_CRED_FLAVOR);
	CHECK(s != NULL && s->offset == e.cred.encoded.off + 4u,
	      "cred flavor: walk %u decoder %u", s ? s->offset : 0,
	      e.cred.encoded.off);
	s = nfsp_walk_find(&w, NFSP_SR_VERF_FLAVOR);
	CHECK(s != NULL && s->offset == e.verf.encoded.off + 4u,
	      "verf flavor: walk %u decoder %u", s ? s->offset : 0,
	      e.verf.encoded.off);
	s = nfsp_walk_find(&w, NFSP_SR_TAG_LEN);
	CHECK(s != NULL && s->offset == e.body.off + 4u,
	      "procedure body: walk tag_len at %u, decoder body at %u",
	      s ? s->offset : 0, e.body.off);
	nfsp_record_buf_free(&scratch);
}

/* The decoder's input is canonical, so fragmenting the record differently
 * must not move a single span. */
static void test_fragmented_record_decodes_identically(void)
{
	struct msg m;
	uint8_t framed[2048];
	struct nfsp_rpc_envelope whole, split;
	struct nfsp_record_buf scratch = {0};
	const uint8_t *p;
	size_t plen;
	uint32_t nfrags;

	printf("a fragmented CALL decodes to the same envelope\n");
	build_call(&m);
	CHECK(nfsp_rpc_decode(m.b, m.n, &whole) == NFSP_RPC_OK, "whole");
	for (size_t frag = 1; frag <= m.n; frag++) {
		size_t off = 0, sent = 0;

		while (sent < m.n) {
			size_t chunk = m.n - sent < frag ? m.n - sent : frag;
			uint32_t hdr = (uint32_t)chunk |
				       (sent + chunk == m.n ? 0x80000000u : 0u);

			framed[off++] = (uint8_t)(hdr >> 24);
			framed[off++] = (uint8_t)(hdr >> 16);
			framed[off++] = (uint8_t)(hdr >> 8);
			framed[off++] = (uint8_t)hdr;
			memcpy(framed + off, m.b + sent, chunk);
			off += chunk;
			sent += chunk;
		}
		CHECK(nfsp_rpc_payload(framed, off, &scratch, &p, &plen,
				       &nfrags) == NFSP_RECORD_OK, "frag %zu", frag);
		CHECK(nfsp_rpc_decode(p, plen, &split) == NFSP_RPC_OK &&
		      memcmp(&whole, &split, sizeof(whole)) == 0,
		      "frag %zu: envelope differs from the unfragmented one",
		      frag);
	}
	nfsp_record_buf_free(&scratch);
}

int main(void)
{
	test_call();
	test_replies();
	test_fail_closed();
	test_truncation_sweep();
	test_coordinates_match_legacy_walk();
	test_fragmented_record_decodes_identically();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
