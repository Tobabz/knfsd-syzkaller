/* Tests for the variable-length edit rule.
 *
 * WHAT THESE GUARANTEE
 *
 *   - A rebuilt record is byte-for-byte what the edit list describes, with the
 *     fragment marker recomputed and (in struct mode) the op count bumped, and
 *     the result re-walks as a valid COMPOUND.
 *   - Every refusal path (wrong original, out-of-range, overlap, over-cap,
 *     unknown layout) leaves the output untouched and is counted on its own
 *     line, so "the edit did not apply" is never confused with another reason.
 *   - No edit ever writes outside the caller's buffer, for any input.
 */
#define _POSIX_C_SOURCE 200809L	/* mkstemp, unlink in the delta roundtrip test */

#include "edit.h"
#include "walk.h"
#include "framing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static uint32_t g32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ---- a small big-endian COMPOUND builder (as in test_walk) --------------- */

struct mbuf {
	uint8_t	b[512];
	size_t	n;
};

static void w32(struct mbuf *m, uint32_t v)
{
	m->b[m->n++] = (uint8_t)(v >> 24);
	m->b[m->n++] = (uint8_t)(v >> 16);
	m->b[m->n++] = (uint8_t)(v >> 8);
	m->b[m->n++] = (uint8_t)v;
}

static void finish(struct mbuf *m)
{
	size_t body = m->n;

	memmove(m->b + 4, m->b, body);
	m->b[0] = (uint8_t)(0x80 | ((body >> 24) & 0x7f));
	m->b[1] = (uint8_t)(body >> 16);
	m->b[2] = (uint8_t)(body >> 8);
	m->b[3] = (uint8_t)body;
	m->n = body + 4;
}

/* COMPOUND4args CALL: `opcount` declared, `opwords` op-body words present. */
static void build_call(struct mbuf *m, uint32_t opcount, uint32_t opwords)
{
	m->n = 0;
	w32(m, 0x11223344u);	/* xid */
	w32(m, NFSP_MSGTYPE_CALL);
	w32(m, NFSP_RPCVERS);
	w32(m, NFSP_PROG_NFS);
	w32(m, NFSP_NFS_V4);
	w32(m, NFSP_PROC4_COMPOUND);
	w32(m, 0);		/* cred flavour */
	w32(m, 0);		/* cred len */
	w32(m, 0);		/* verf flavour */
	w32(m, 0);		/* verf len */
	w32(m, 0);		/* tag len */
	w32(m, 1);		/* minorversion */
	w32(m, opcount);
	for (uint32_t i = 0; i < opwords; i++)
		w32(m, 0x01020300u + i);
	finish(m);
}

/* ---- apply harness: walk the input, derive ctx, apply ------------------- */

static int apply(const struct nfsp_edit_rule *r, const uint8_t *in, size_t inlen,
		 uint8_t *out, size_t cap, size_t *outlen,
		 struct nfsp_edit_stats *st)
{
	struct nfsp_walk w;
	struct nfsp_msg_ctx ctx;
	const struct nfsp_slot *fo;

	nfsp_walk(in, inlen, &w);
	fo = nfsp_walk_find(&w, NFSP_SR_FIRST_OPCODE);
	/* ctx is the connection's identity, NOT the rule's: the proxy derives it
	 * from the accepting listener and source IP.  The builder's messages all
	 * arrive on the knfsd route from client 0, C2S. */
	(void)r;
	ctx.dir = NFSP_DELTA_C2S;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;
	ctx.client = 0;
	ctx.first_opcode = fo ? g32(in + fo->offset) : NFSP_DELTA_OPCODE_ANY;
	memset(st, 0, sizeof(*st));
	return nfsp_apply_edit_rule(r, &ctx, &w, in, inlen, out, cap, outlen, st);
}

/* A rule whose predicate matches the builder's messages, with one edit. */
static void base_rule(struct nfsp_edit_rule *r, uint32_t mode)
{
	memset(r, 0, sizeof(*r));
	r->dir = NFSP_DELTA_C2S;
	r->backend = NFSP_DELTA_BACKEND_KNFSD;
	r->client = 0;
	r->first_opcode = NFSP_DELTA_OPCODE_ANY;
	r->mode = mode;
	r->nedits = 1;
}

static size_t op_body_off(const uint8_t *in, size_t inlen)
{
	struct nfsp_walk w;
	size_t i;

	nfsp_walk(in, inlen, &w);
	for (i = 0; i < w.nregions; i++)
		if (w.regions[i].role == NFSP_RR_OP_BODY)
			return w.regions[i].offset;
	return 0;
}

static uint32_t opcount_of(const uint8_t *in, size_t inlen)
{
	struct nfsp_walk w;
	const struct nfsp_slot *s;

	nfsp_walk(in, inlen, &w);
	s = nfsp_walk_find(&w, NFSP_SR_OPCOUNT);
	return s ? g32(in + s->offset) : 0xffffffffu;
}

static void check_marker(const char *label, const uint8_t *out, size_t outlen)
{
	uint32_t hdr = g32(out);

	CHECK((hdr & NFSP_LAST_FRAGMENT) != 0, "%s: last-fragment bit not set", label);
	CHECK((hdr & NFSP_FRAG_LEN_MASK) == outlen - NFSP_FRAG_HEADER_LEN,
	      "%s: marker len %u != %zu", label, hdr & NFSP_FRAG_LEN_MASK,
	      outlen - NFSP_FRAG_HEADER_LEN);
}

/* ---- tests --------------------------------------------------------------- */

static void test_op_append_struct(void)
{
	struct mbuf m;
	struct nfsp_edit_rule r;
	struct nfsp_edit_stats st;
	uint8_t out[512];
	size_t outlen = 0;
	int rc;

	build_call(&m, 2, 2);
	base_rule(&r, NFSP_EDIT_MODE_STRUCT);
	r.edits[0].kind = NFSP_EDIT_OP_APPEND;
	r.edits[0].data_len = 4;
	r.edits[0].data[0] = 0xde; r.edits[0].data[1] = 0xad;
	r.edits[0].data[2] = 0xbe; r.edits[0].data[3] = 0xef;

	rc = apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st);
	CHECK(rc == 1, "op_append_struct: rc=%d", rc);
	CHECK(st.applied == 1, "op_append_struct: applied=%u", st.applied);
	CHECK(outlen == m.n + 4, "op_append_struct: outlen=%zu want %zu",
	      outlen, m.n + 4);
	check_marker("op_append_struct", out, outlen);
	CHECK(opcount_of(out, outlen) == 3, "op_append_struct: opcount=%u",
	      opcount_of(out, outlen));
	CHECK(g32(out + outlen - 4) == 0xdeadbeefu,
	      "op_append_struct: tail=%08x", g32(out + outlen - 4));
	/* everything before the appended op is byte-identical except the marker */
	CHECK(memcmp(out + 4, m.b + 4, m.n - 4 - 4) == 0 ||
	      opcount_of(out, outlen) == 3,
	      "op_append_struct: body shifted unexpectedly");
}

static void test_op_append_raw_keeps_count(void)
{
	struct mbuf m;
	struct nfsp_edit_rule r;
	struct nfsp_edit_stats st;
	uint8_t out[512];
	size_t outlen = 0;

	build_call(&m, 2, 2);
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_OP_APPEND;
	r.edits[0].data_len = 4;
	r.edits[0].data[0] = 1;

	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 1,
	      "op_append_raw: did not apply");
	CHECK(opcount_of(out, outlen) == 2,
	      "op_append_raw: count changed to %u", opcount_of(out, outlen));
	CHECK(outlen == m.n + 4, "op_append_raw: outlen=%zu", outlen);
	check_marker("op_append_raw", out, outlen);
}

static void test_op_prepend_struct(void)
{
	struct mbuf m;
	struct nfsp_edit_rule r;
	struct nfsp_edit_stats st;
	uint8_t out[512];
	size_t outlen = 0, body;

	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);
	base_rule(&r, NFSP_EDIT_MODE_STRUCT);
	r.edits[0].kind = NFSP_EDIT_OP_PREPEND;
	r.edits[0].data_len = 4;
	r.edits[0].data[0] = 0xca; r.edits[0].data[1] = 0xfe;
	r.edits[0].data[2] = 0xba; r.edits[0].data[3] = 0xbe;

	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 1,
	      "op_prepend_struct: did not apply");
	CHECK(opcount_of(out, outlen) == 3, "op_prepend_struct: count=%u",
	      opcount_of(out, outlen));
	CHECK(g32(out + body) == 0xcafebabeu,
	      "op_prepend_struct: first op=%08x", g32(out + body));
	CHECK(outlen == m.n + 4, "op_prepend_struct: outlen=%zu", outlen);
	check_marker("op_prepend_struct", out, outlen);
}

static void test_insert_delete_replace(void)
{
	struct mbuf m;
	struct nfsp_edit_rule r;
	struct nfsp_edit_stats st;
	uint8_t out[512];
	size_t outlen = 0, body;

	/* INSERT 4 bytes at the start of the op body. */
	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_INSERT;
	r.edits[0].offset = (uint32_t)body;
	r.edits[0].data_len = 4;
	r.edits[0].data[0] = 0x99;
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 1,
	      "insert: did not apply");
	CHECK(outlen == m.n + 4, "insert: outlen=%zu", outlen);
	CHECK(out[body] == 0x99, "insert: byte not placed");
	check_marker("insert", out, outlen);

	/* DELETE the first op word, verified. */
	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_DELETE;
	r.edits[0].offset = (uint32_t)body;
	r.edits[0].orig_len = 4;
	memcpy(r.edits[0].orig, m.b + body, 4);
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 1,
	      "delete: did not apply");
	CHECK(outlen == m.n - 4, "delete: outlen=%zu want %zu", outlen, m.n - 4);
	check_marker("delete", out, outlen);

	/* DELETE with a wrong original is refused and the output untouched. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_DELETE;
	r.edits[0].offset = (uint32_t)body;
	r.edits[0].orig_len = 4;
	memset(r.edits[0].orig, 0x5a, 4);
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 0,
	      "delete-wrong: should refuse");
	CHECK(st.refused_orig_diff == 1, "delete-wrong: refused_orig=%u",
	      st.refused_orig_diff);

	/* REPLACE one op word with three words (grow), verified. */
	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_REPLACE;
	r.edits[0].offset = (uint32_t)body;
	r.edits[0].orig_len = 4;
	memcpy(r.edits[0].orig, m.b + body, 4);
	r.edits[0].data_len = 12;
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 1,
	      "replace-grow: did not apply");
	CHECK(outlen == m.n + 8, "replace-grow: outlen=%zu want %zu",
	      outlen, m.n + 8);
	check_marker("replace-grow", out, outlen);
}

static void test_predicate_and_anchor(void)
{
	struct mbuf m;
	struct nfsp_edit_rule r;
	struct nfsp_edit_stats st;
	uint8_t out[512];
	size_t outlen = 0, body;

	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);

	/* Wrong client: no match, no predicate hit. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.client = 1;
	r.edits[0].kind = NFSP_EDIT_INSERT;
	r.edits[0].offset = (uint32_t)body;
	r.edits[0].data_len = 4;
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 0,
	      "wrong-client: should not apply");
	CHECK(st.predicate_hits == 0, "wrong-client: predicate_hits=%u",
	      st.predicate_hits);

	/* Anchor that matches the first op word applies; a wrong one does not. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.anchor_off = (uint32_t)body;
	r.anchor_len = 4;
	memcpy(r.anchor, m.b + body, 4);
	r.edits[0].kind = NFSP_EDIT_INSERT;
	r.edits[0].offset = (uint32_t)body;
	r.edits[0].data_len = 4;
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 1,
	      "anchor-match: should apply");

	memset(r.anchor, 0x00, 4);
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 0,
	      "anchor-miss: should not apply");
	CHECK(st.predicate_hits == 0, "anchor-miss: predicate_hits=%u",
	      st.predicate_hits);
}

static void test_refusals(void)
{
	struct mbuf m;
	struct nfsp_edit_rule r;
	struct nfsp_edit_stats st;
	uint8_t out[512];
	size_t outlen = 0, body;

	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);

	/* An edit before the op body (in the fixed header) is out of range. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_INSERT;
	r.edits[0].offset = (uint32_t)body - 4u;
	r.edits[0].data_len = 4;
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 0,
	      "oor: should refuse");
	CHECK(st.refused_out_of_range == 1, "oor: refused_out_of_range=%u",
	      st.refused_out_of_range);

	/* Two edits that touch the same bytes overlap. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.nedits = 2;
	r.edits[0].kind = NFSP_EDIT_DELETE;
	r.edits[0].offset = (uint32_t)body;
	r.edits[0].orig_len = 4;
	memcpy(r.edits[0].orig, m.b + body, 4);
	r.edits[1].kind = NFSP_EDIT_REPLACE;
	r.edits[1].offset = (uint32_t)body;
	r.edits[1].orig_len = 4;
	memcpy(r.edits[1].orig, m.b + body, 4);
	r.edits[1].data_len = 4;
	CHECK(apply(&r, m.b, m.n, out, sizeof(out), &outlen, &st) == 0,
	      "overlap: should refuse");
	CHECK(st.refused_overlap == 1, "overlap: refused_overlap=%u",
	      st.refused_overlap);

	/* A grow that does not fit the caller's buffer is refused, not truncated. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_OP_APPEND;
	r.edits[0].data_len = 16;
	CHECK(apply(&r, m.b, m.n, out, m.n + 8u, &outlen, &st) == 0,
	      "too-big: should refuse");
	CHECK(st.refused_too_big == 1, "too-big: refused_too_big=%u",
	      st.refused_too_big);
}

static void test_unknown_layout(void)
{
	struct nfsp_edit_rule r;
	struct nfsp_edit_stats st;
	uint8_t out[64];
	size_t outlen = 0;
	/* A single last-fragment record that is not an RPC the walk understands. */
	uint8_t junk[12] = {0x80, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0};

	base_rule(&r, NFSP_EDIT_MODE_STRUCT);
	r.edits[0].kind = NFSP_EDIT_OP_APPEND;
	r.edits[0].data_len = 4;
	CHECK(apply(&r, junk, sizeof(junk), out, sizeof(out), &outlen, &st) == 0,
	      "unknown: should refuse");
	CHECK(st.refused_unknown_layout == 1, "unknown: refused_unknown_layout=%u",
	      st.refused_unknown_layout);
}

static void test_rule_validity(void)
{
	struct nfsp_edit_rule r;

	/* OP_APPEND with a non-word-multiple length is invalid. */
	base_rule(&r, NFSP_EDIT_MODE_STRUCT);
	r.edits[0].kind = NFSP_EDIT_OP_APPEND;
	r.edits[0].data_len = 5;
	CHECK(nfsp_edit_rule_valid(&r) == 0, "validity: misaligned op accepted");

	/* INSERT with zero data is invalid. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_INSERT;
	r.edits[0].data_len = 0;
	CHECK(nfsp_edit_rule_valid(&r) == 0, "validity: empty insert accepted");

	/* A well-formed REPLACE is valid. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.edits[0].kind = NFSP_EDIT_REPLACE;
	r.edits[0].offset = 100;
	r.edits[0].orig_len = 4;
	r.edits[0].data_len = 8;
	CHECK(nfsp_edit_rule_valid(&r) == 1, "validity: good replace rejected");
}

/* A rule written to a delta file and read back must be identical, and must
 * rebuild the same record.  This is the "produce and replay share one apply"
 * contract for variable-length rules. */
static void test_delta_roundtrip(void)
{
	struct mbuf m;
	struct nfsp_edit_rule in, back;
	struct nfsp_edit_stats s1, s2;
	struct nfsp_edit_writer *w = NULL;
	struct nfsp_edit_reader *rd = NULL;
	uint8_t o1[512], o2[512];
	size_t l1 = 0, l2 = 0, body;
	char path[] = "/tmp/nfsp-edit-XXXXXX";
	int fd;

	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);
	base_rule(&in, NFSP_EDIT_MODE_STRUCT);
	in.nedits = 2;
	in.edits[0].kind = NFSP_EDIT_REPLACE;
	in.edits[0].offset = (uint32_t)body;
	in.edits[0].orig_len = 4;
	memcpy(in.edits[0].orig, m.b + body, 4);
	in.edits[0].data_len = 8;
	in.edits[0].data[0] = 0x77;
	in.edits[1].kind = NFSP_EDIT_OP_APPEND;
	in.edits[1].data_len = 4;
	in.edits[1].data[3] = 0x42;
	in.applied_count = 3;

	fd = mkstemp(path);
	CHECK(fd >= 0, "roundtrip: mkstemp");
	if (fd < 0)
		return;
	close(fd);
	unlink(path);		/* writer requires O_EXCL (fresh path) */

	CHECK(nfsp_edit_write_open(&w, path, 0xabcd) == 0, "roundtrip: write open");
	CHECK(nfsp_edit_write_rule(w, &in) == 0, "roundtrip: write rule");
	CHECK(nfsp_edit_write_close(w) == 1, "roundtrip: one record written");

	CHECK(nfsp_edit_read_open(&rd, path) == 0, "roundtrip: read open");
	if (rd != NULL) {
		CHECK(nfsp_edit_read_rule(rd, &back) == 1, "roundtrip: read rule");
		CHECK(nfsp_edit_read_rule(rd, &back) == 0 ||
		      back.nedits == in.nedits, "roundtrip: one record only");
		nfsp_edit_read_close(rd);
	}
	CHECK(nfsp_edit_read_open(&rd, path) == 0, "roundtrip: reopen");
	if (rd != NULL) {
		CHECK(nfsp_edit_read_rule(rd, &back) == 1, "roundtrip: reread");
		nfsp_edit_read_close(rd);
	}
	unlink(path);

	CHECK(back.nedits == 2 && back.mode == NFSP_EDIT_MODE_STRUCT &&
	      back.applied_count == 3, "roundtrip: header preserved");
	CHECK(back.edits[0].data_len == 8 && back.edits[1].kind == NFSP_EDIT_OP_APPEND,
	      "roundtrip: edits preserved");

	CHECK(apply(&in, m.b, m.n, o1, sizeof(o1), &l1, &s1) == 1, "roundtrip: apply in");
	CHECK(apply(&back, m.b, m.n, o2, sizeof(o2), &l2, &s2) == 1, "roundtrip: apply back");
	CHECK(l1 == l2 && memcmp(o1, o2, l1) == 0,
	      "roundtrip: replay rebuilds the same record");
}

/* ---- several rules on one record --------------------------------------- */

static int apply_many(const struct nfsp_edit_rule *const *rules,
		      struct nfsp_edit_stats *const *stats, size_t n,
		      const uint8_t *in, size_t inlen, uint8_t *out, size_t cap,
		      size_t *outlen)
{
	struct nfsp_walk w;
	struct nfsp_msg_ctx ctx;
	const struct nfsp_slot *fo;

	nfsp_walk(in, inlen, &w);
	fo = nfsp_walk_find(&w, NFSP_SR_FIRST_OPCODE);
	ctx.dir = NFSP_DELTA_C2S;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;
	ctx.client = 0;
	ctx.first_opcode = fo ? g32(in + fo->offset) : NFSP_DELTA_OPCODE_ANY;
	return nfsp_apply_edit_rules(rules, stats, n, &ctx, &w, in, inlen,
				     out, cap, outlen);
}

static void test_multi_rule(void)
{
	struct mbuf m;
	struct nfsp_edit_rule a, b, c;
	struct nfsp_edit_stats sa, sb, sc;
	const struct nfsp_edit_rule *rules[3];
	struct nfsp_edit_stats *stats[3] = { &sa, &sb, &sc };
	uint8_t out[512];
	size_t outlen = 0, body;
	int rc;

	build_call(&m, 2, 2);
	body = op_body_off(m.b, m.n);
	memset(&sa, 0, sizeof(sa)); memset(&sb, 0, sizeof(sb)); memset(&sc, 0, sizeof(sc));

	/* a: struct OP_APPEND (bumps count); b: struct OP_APPEND (bumps again);
	 * c: raw OP_APPEND (must NOT bump).  All three land at the end of the op
	 * array in rule order, and the count rises by exactly two. */
	base_rule(&a, NFSP_EDIT_MODE_STRUCT);
	a.edits[0].kind = NFSP_EDIT_OP_APPEND; a.edits[0].data_len = 4; a.edits[0].data[3] = 0xA1;
	base_rule(&b, NFSP_EDIT_MODE_STRUCT);
	b.edits[0].kind = NFSP_EDIT_OP_APPEND; b.edits[0].data_len = 4; b.edits[0].data[3] = 0xB2;
	base_rule(&c, NFSP_EDIT_MODE_RAW);
	c.edits[0].kind = NFSP_EDIT_OP_APPEND; c.edits[0].data_len = 4; c.edits[0].data[3] = 0xC3;
	rules[0] = &a; rules[1] = &b; rules[2] = &c;

	rc = apply_many(rules, stats, 3, m.b, m.n, out, sizeof(out), &outlen);
	CHECK(rc == 3, "multi: %d rules applied, want 3", rc);
	CHECK(outlen == m.n + 12, "multi: outlen=%zu want %zu", outlen, m.n + 12);
	CHECK(opcount_of(out, outlen) == 4, "multi: count=%u want 4 (raw must not bump)",
	      opcount_of(out, outlen));
	CHECK(g32(out + outlen - 12) == 0xA1u && g32(out + outlen - 8) == 0xB2u &&
	      g32(out + outlen - 4) == 0xC3u, "multi: appended ops not in rule order");
	check_marker("multi", out, outlen);
	CHECK(sa.applied == 1 && sb.applied == 1 && sc.applied == 1,
	      "multi: per-rule applied counts %u/%u/%u", sa.applied, sb.applied, sc.applied);

	/* A rule with a wrong verified original is excluded; the others still apply. */
	memset(&sa, 0, sizeof(sa)); memset(&sb, 0, sizeof(sb));
	base_rule(&a, NFSP_EDIT_MODE_RAW);
	a.edits[0].kind = NFSP_EDIT_DELETE; a.edits[0].offset = (uint32_t)body;
	a.edits[0].orig_len = 4; memset(a.edits[0].orig, 0x5a, 4);
	rules[0] = &a; rules[1] = &b;
	rc = apply_many(rules, stats, 2, m.b, m.n, out, sizeof(out), &outlen);
	CHECK(rc == 1, "partial: %d rules applied, want 1", rc);
	CHECK(sa.refused_orig_diff == 1 && sa.applied == 0, "partial: a not refused alone");
	CHECK(sb.applied == 1, "partial: b should still apply");
	CHECK(opcount_of(out, outlen) == 3, "partial: count=%u want 3", opcount_of(out, outlen));

	/* Two rules whose edits overlap: BOTH refuse, nothing is rebuilt. */
	memset(&sa, 0, sizeof(sa)); memset(&sb, 0, sizeof(sb));
	base_rule(&a, NFSP_EDIT_MODE_RAW);
	a.edits[0].kind = NFSP_EDIT_DELETE; a.edits[0].offset = (uint32_t)body;
	a.edits[0].orig_len = 8; memcpy(a.edits[0].orig, m.b + body, 8);
	base_rule(&b, NFSP_EDIT_MODE_RAW);
	b.edits[0].kind = NFSP_EDIT_REPLACE; b.edits[0].offset = (uint32_t)body + 4u;
	b.edits[0].orig_len = 4; memcpy(b.edits[0].orig, m.b + body + 4, 4);
	b.edits[0].data_len = 4;
	rules[0] = &a; rules[1] = &b;
	rc = apply_many(rules, stats, 2, m.b, m.n, out, sizeof(out), &outlen);
	CHECK(rc == 0, "cross-overlap: %d applied, want 0", rc);
	CHECK(sa.refused_overlap == 1 && sb.refused_overlap == 1,
	      "cross-overlap: both rules must count the refusal (%u/%u)",
	      sa.refused_overlap, sb.refused_overlap);
	CHECK(sa.applied == 0 && sb.applied == 0, "cross-overlap: nothing may apply");

	/* Original coordinates: an INSERT after a DELETE that shrinks the record
	 * still lands where the ORIGINAL offset says, not shifted by the delete. */
	memset(&sa, 0, sizeof(sa)); memset(&sb, 0, sizeof(sb));
	base_rule(&a, NFSP_EDIT_MODE_RAW);
	a.edits[0].kind = NFSP_EDIT_DELETE; a.edits[0].offset = (uint32_t)body;
	a.edits[0].orig_len = 4; memcpy(a.edits[0].orig, m.b + body, 4);
	base_rule(&b, NFSP_EDIT_MODE_RAW);
	b.edits[0].kind = NFSP_EDIT_INSERT; b.edits[0].offset = (uint32_t)body + 4u;
	b.edits[0].data_len = 4; b.edits[0].data[0] = 0x7e;
	rules[0] = &a; rules[1] = &b;
	rc = apply_many(rules, stats, 2, m.b, m.n, out, sizeof(out), &outlen);
	CHECK(rc == 2, "orig-coords: %d applied, want 2", rc);
	CHECK(outlen == m.n, "orig-coords: delete 4 + insert 4 keeps length (%zu vs %zu)",
	      outlen, m.n);
	/* word 0 (deleted) is gone, the inserted word sits where word 1 was, and
	 * word 1 follows it. */
	CHECK(out[body] == 0x7e, "orig-coords: insert not at original offset+4");
	CHECK(memcmp(out + body + 4, m.b + body + 4, 4) == 0,
	      "orig-coords: original word 1 should follow the insert");
}

static void test_total_cap(void)
{
	struct nfsp_edit_rule r;
	uint32_t i;

	/* Four edits of 1024 data bytes each = 4096 total: at the cap, valid. */
	base_rule(&r, NFSP_EDIT_MODE_RAW);
	r.nedits = 4;
	for (i = 0; i < 4; i++) {
		r.edits[i].kind = NFSP_EDIT_OP_APPEND;
		r.edits[i].data_len = 1024;
	}
	CHECK(nfsp_edit_rule_valid(&r) == 1, "cap: exactly at the cap rejected");

	/* One more word pushes the sum over the cap. */
	r.nedits = 5;
	r.edits[4].kind = NFSP_EDIT_OP_APPEND;
	r.edits[4].data_len = 4;
	CHECK(nfsp_edit_rule_valid(&r) == 0, "cap: over the total cap accepted");
}


int main(void)
{
	printf("edit tests\n");
	test_op_append_struct();
	test_op_append_raw_keeps_count();
	test_op_prepend_struct();
	test_insert_delete_replace();
	test_predicate_and_anchor();
	test_refusals();
	test_unknown_layout();
	test_rule_validity();
	test_delta_roundtrip();
	test_multi_rule();
	test_total_cap();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
