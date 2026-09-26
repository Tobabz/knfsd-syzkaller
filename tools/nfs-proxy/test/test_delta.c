/* Tests for the mutation delta.
 *
 * The three properties this file exists to defend:
 *
 *   1. SELF-CONTAINMENT -- a delta read from disk applies with no other input.
 *      A record that referenced the observed-identifier pool would silently do
 *      nothing on replay, and that would read as a non-reproducing crash.
 *
 *   2. ORDER INDEPENDENCE -- the same rules applied to the same messages in a
 *      different order produce the same result.  This is what removes the
 *      ordinal-position problem that made "the Nth matching RPC" unusable.
 *
 *   3. LOUD REFUSAL -- a rule whose recorded originals do not match the bytes
 *      present must refuse and be counted, never patch.  Conflating that with
 *      "the crash did not reproduce" is the failure mode this whole design is
 *      arranged to prevent.
 */
#define _POSIX_C_SOURCE 200809L

#include "delta.h"

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

static const char *tmpfile_path(char *buf, size_t n, const char *tag)
{
	snprintf(buf, n, "/tmp/nfsp-delta-%s-%d.bin", tag, (int)getpid());
	return buf;
}

static void mkrule(struct nfsp_rule *r)
{
	memset(r, 0, sizeof(*r));
	r->dir = NFSP_DELTA_S2C;
	r->backend = NFSP_DELTA_BACKEND_KNFSD;
	r->client = 0;
	r->first_opcode = NFSP_DELTA_OPCODE_ANY;
	r->match_index = NFSP_DELTA_MATCH_ANY;
	r->patch_w = 4;
	r->patch_off = 8;
	r->orig[0] = 0x11; r->orig[1] = 0x22;
	r->orig[2] = 0x33; r->orig[3] = 0x44;
	r->repl[0] = 0xde; r->repl[1] = 0xad;
	r->repl[2] = 0xbe; r->repl[3] = 0xef;
}

static void test_rule_validity(void)
{
	struct nfsp_rule r;

	printf("rule validation rejects impossible rules\n");
	mkrule(&r);
	CHECK(nfsp_rule_valid(&r) == 1, "a sane rule must validate");

	mkrule(&r); r.patch_w = 0;
	CHECK(nfsp_rule_valid(&r) == 0, "zero patch width must be rejected");
	mkrule(&r); r.patch_w = NFSP_DELTA_PATCH_MAX + 1;
	CHECK(nfsp_rule_valid(&r) == 0, "over-wide patch must be rejected");
	mkrule(&r); r.anchor_len = NFSP_DELTA_ANCHOR_MAX + 1;
	CHECK(nfsp_rule_valid(&r) == 0, "over-long anchor must be rejected");
	mkrule(&r); r.dir = 7;
	CHECK(nfsp_rule_valid(&r) == 0, "unknown direction must be rejected");
	mkrule(&r); r.client = 2;
	CHECK(nfsp_rule_valid(&r) == 0, "client must be 0 or 1");
	mkrule(&r); r.patch_off = 0xffffffffu;
	CHECK(nfsp_rule_valid(&r) == 0, "overflowing patch offset must be rejected");
}

static void test_apply_and_verify(void)
{
	struct nfsp_rule r;
	struct nfsp_msg_ctx ctx;
	struct nfsp_apply_stats st;
	uint8_t buf[32];
	int rc;

	printf("apply: patches only when the recorded bytes are present\n");
	mkrule(&r);
	memset(buf, 0, sizeof(buf));
	buf[8] = 0x11; buf[9] = 0x22; buf[10] = 0x33; buf[11] = 0x44;

	memset(&ctx, 0, sizeof(ctx));
	ctx.dir = NFSP_DELTA_S2C;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;
	ctx.client = 0;
	ctx.first_opcode = 3;

	memset(&st, 0, sizeof(st));
	rc = nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st);
	CHECK(rc == 1, "expected apply, got %d", rc);
	CHECK(st.applied == 1, "applied %u", st.applied);
	CHECK(st.predicate_hits == 1, "hits %u", st.predicate_hits);
	CHECK(buf[8] == 0xde && buf[11] == 0xef, "bytes were not patched");

	/* Wrong bytes at the patch offset: refuse and count.  This is the
	 * distinction replay exists to make. */
	buf[8] = 0x77;
	memset(&st, 0, sizeof(st));
	rc = nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st);
	CHECK(rc == 0, "a byte mismatch must not apply, got %d", rc);
	CHECK(st.refused_orig_diff == 1, "refused_orig_diff %u",
	      st.refused_orig_diff);
	CHECK(st.applied == 0, "applied must stay 0 on refusal");
	CHECK(buf[8] == 0x77, "a refused rule must not modify the buffer");
}

static void test_predicate_matching(void)
{
	struct nfsp_rule r;
	struct nfsp_msg_ctx ctx;
	struct nfsp_apply_stats st;
	uint8_t buf[32];

	printf("predicate: direction, backend, client, opcode, anchor\n");
	mkrule(&r);
	memset(buf, 0, sizeof(buf));
	buf[8] = 0x11; buf[9] = 0x22; buf[10] = 0x33; buf[11] = 0x44;

	/* One field wrong at a time, each of which must stop the rule.  These
	 * are the fields that keep one executor's mutation off another client's
	 * or another backend's traffic. */
	struct {
		const char *what;
		void (*tweak)(struct nfsp_msg_ctx *);
	} cases[] = {
		{ "direction", NULL },
		{ "backend", NULL },
		{ "client", NULL },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.dir = NFSP_DELTA_S2C;
		ctx.backend = NFSP_DELTA_BACKEND_KNFSD;
		ctx.client = 0;
		if (i == 0) ctx.dir = NFSP_DELTA_C2S;
		if (i == 1) ctx.backend = NFSP_DELTA_BACKEND_GANESHA;
		if (i == 2) ctx.client = 1;
		memset(&st, 0, sizeof(st));
		buf[8] = 0x11;
		CHECK(nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st) == 0,
		      "a differing %s must not match", cases[i].what);
		CHECK(st.predicate_hits == 0, "%s: hits must be 0", cases[i].what);
	}

	printf("predicate: first_opcode\n");
	mkrule(&r);
	r.first_opcode = 22;	/* NFS4_OP_OPEN */
	memset(&ctx, 0, sizeof(ctx));
	ctx.dir = NFSP_DELTA_S2C;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;
	memset(&st, 0, sizeof(st));
	ctx.first_opcode = 3;
	CHECK(nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st) == 0,
	      "a different opcode must not match");
	ctx.first_opcode = 22;
	/* Reset the buffer: the first call did not apply, but being explicit
	 * here keeps this case independent of whatever ran before it. */
	memset(buf, 0, sizeof(buf));
	buf[8] = 0x11; buf[9] = 0x22; buf[10] = 0x33; buf[11] = 0x44;
	memset(&st, 0, sizeof(st));
	CHECK(nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st) == 1,
	      "the recorded opcode must match");
	CHECK(st.applied == 1, "opcode case: applied %u", st.applied);

	printf("predicate: literal anchor\n");
	mkrule(&r);
	r.first_opcode = NFSP_DELTA_OPCODE_ANY;
	r.anchor_off = 16;
	r.anchor_len = 4;
	memcpy(r.anchor, "OPEN", 4);
	memset(&ctx, 0, sizeof(ctx));
	ctx.dir = NFSP_DELTA_S2C;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;
	/* Restore the WHOLE buffer, not just buf[8].  The opcode case above
	 * applied a rule, so buf[8..11] now holds the replacement bytes; leaving
	 * three of them behind made the verify-before-patch guard refuse the
	 * next rule, and the test failed on a stale byte rather than on the
	 * anchor it was meant to exercise.  The guard was right and the test was
	 * wrong -- which is the useful direction for that to fail in. */
	memset(buf, 0, sizeof(buf));
	buf[8] = 0x11; buf[9] = 0x22; buf[10] = 0x33; buf[11] = 0x44;
	memcpy(buf + 16, "LOOK", 4);
	memset(&st, 0, sizeof(st));
	CHECK(nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st) == 0,
	      "a mismatching anchor must not match");
	memcpy(buf + 16, "OPEN", 4);
	CHECK(nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st) == 1,
	      "a matching anchor must match");
}

static void test_out_of_range_is_distinct(void)
{
	struct nfsp_rule r;
	struct nfsp_msg_ctx ctx;
	struct nfsp_apply_stats st;
	uint8_t buf[16];

	printf("out-of-range is reported as out-of-range, not as a byte mismatch\n");
	mkrule(&r);
	r.patch_off = 14;	/* 14 + 4 > 16 */
	memset(buf, 0, sizeof(buf));
	memset(&ctx, 0, sizeof(ctx));
	ctx.dir = NFSP_DELTA_S2C;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;

	memset(&st, 0, sizeof(st));
	CHECK(nfsp_apply_rule(&r, &ctx, buf, sizeof(buf), &st) == 0,
	      "must not apply outside the message");
	CHECK(st.refused_out_of_range == 1, "refused_out_of_range %u",
	      st.refused_out_of_range);
	/* A misleading diagnosis here would send someone hunting a byte
	 * mismatch that does not exist. */
	CHECK(st.refused_orig_diff == 0,
	      "must not be reported as a byte mismatch");
}

/* The shortest path to the format: write rules, read them back, compare every
 * field.  Any field lost in the round trip is a field replay cannot use. */
static void test_round_trip(void)
{
	char path[128];
	struct nfsp_delta_writer *w = NULL;
	struct nfsp_delta_reader *rd = NULL;
	struct nfsp_rule in, out;
	const uint64_t seed = 0x0123456789abcdefULL;
	long n;

	printf("round trip: every field survives\n");
	tmpfile_path(path, sizeof(path), "rt");
	CHECK(nfsp_delta_write_open(&w, path, seed) == 0, "open writer");

	mkrule(&in);
	in.first_opcode = 26;
	in.anchor_len = 6;
	memcpy(in.anchor, "abcdef", 6);
	in.anchor_off = 40;
	in.match_index = NFSP_DELTA_MATCH_ANY;
	in.applied_count = 3;
	CHECK(nfsp_delta_write_rule(w, &in) == 0, "write rule 1");

	{
		struct nfsp_rule second;

		mkrule(&second);
		second.dir = NFSP_DELTA_C2S;
		second.backend = NFSP_DELTA_BACKEND_GANESHA;
		second.client = 1;
		second.patch_w = 16;
		second.patch_off = 100;
		second.applied_count = 1;
		memset(second.orig, 0xaa, 16);
		memset(second.repl, 0x55, 16);
		CHECK(nfsp_delta_write_rule(w, &second) == 0, "write rule 2");
	}
	n = nfsp_delta_write_close(w);
	CHECK(n == 2, "writer counted %ld records, expected 2", n);

	CHECK(nfsp_delta_read_open(&rd, path) == 0, "open reader");
	CHECK(nfsp_delta_reader_seed(rd) == seed, "seed did not survive");

	CHECK(nfsp_delta_read_rule(rd, &out) == 1, "read rule 1");
	CHECK(out.dir == in.dir && out.backend == in.backend &&
	      out.client == in.client, "identity fields differ");
	CHECK(out.first_opcode == in.first_opcode, "first_opcode %u vs %u",
	      out.first_opcode, in.first_opcode);
	CHECK(out.match_index == in.match_index, "match_index differs");
	CHECK(out.anchor_off == in.anchor_off && out.anchor_len == in.anchor_len,
	      "anchor geometry differs");
	CHECK(memcmp(out.anchor, in.anchor, in.anchor_len) == 0,
	      "anchor bytes differ");
	CHECK(out.patch_off == in.patch_off && out.patch_w == in.patch_w,
	      "patch geometry differs");
	CHECK(memcmp(out.orig, in.orig, in.patch_w) == 0, "orig bytes differ");
	CHECK(memcmp(out.repl, in.repl, in.patch_w) == 0, "repl bytes differ");
	CHECK(out.applied_count == in.applied_count,
	      "applied_count %u vs %u -- the replay gate needs this",
	      out.applied_count, in.applied_count);

	CHECK(nfsp_delta_read_rule(rd, &out) == 1, "read rule 2");
	CHECK(out.patch_w == 16 && out.repl[0] == 0x55, "second rule differs");

	CHECK(nfsp_delta_read_rule(rd, &out) == 0, "expected clean EOF");
	nfsp_delta_read_close(rd);
	unlink(path);
}

/* THE property that replaces ordinal position: applying the same rules to the
 * same messages in a different order must produce the same result.  A rule tied
 * to "the Nth match" would fail here. */
static void test_order_independence(void)
{
	struct nfsp_rule rules[3];
	struct nfsp_msg_ctx ctx;
	uint8_t forward[3][32], backward[3][32], expect[32];
	struct nfsp_apply_stats st;
	int i;

	printf("order independence: same rules, reversed delivery\n");
	memset(&ctx, 0, sizeof(ctx));
	ctx.dir = NFSP_DELTA_S2C;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;

	for (i = 0; i < 3; i++) {
		mkrule(&rules[i]);
		rules[i].patch_off = 8;
		rules[i].patch_w = 4;
		/* Three rules with distinct replacement bytes so that applying
		 * the wrong one is visible. */
		rules[i].repl[0] = (uint8_t)(0xa0 + i);
		memset(forward[i], 0, sizeof(forward[i]));
		forward[i][8] = 0x11; forward[i][9] = 0x22;
		forward[i][10] = 0x33; forward[i][11] = 0x44;
		memcpy(backward[i], forward[i], sizeof(forward[i]));
	}

	/* Forward: rule i applied to message i. */
	for (i = 0; i < 3; i++) {
		memset(&st, 0, sizeof(st));
		CHECK(nfsp_apply_rule(&rules[i], &ctx, forward[i],
				      sizeof(forward[i]), &st) == 1,
		      "forward apply %d", i);
	}
	memcpy(expect, forward[0], sizeof(expect));

	/* Backward: the same three rules against the same messages in reverse.
	 * Because every rule matches by content and applies to all matches, the
	 * result must be identical per message. */
	for (i = 2; i >= 0; i--) {
		memset(&st, 0, sizeof(st));
		CHECK(nfsp_apply_rule(&rules[i], &ctx, backward[i],
				      sizeof(backward[i]), &st) == 1,
		      "backward apply %d", i);
	}
	CHECK(memcmp(forward[0], backward[0], sizeof(expect)) == 0,
	      "message 0 differs between forward and backward delivery");
	CHECK(memcmp(forward[1], backward[1], sizeof(expect)) == 0,
	      "message 1 differs between forward and backward delivery");
	CHECK(memcmp(forward[2], backward[2], sizeof(expect)) == 0,
	      "message 2 differs between forward and backward delivery");
}

/* Reproduce-identity: apply a rule, record it, then replay from the file alone
 * onto a fresh copy of the same message and require byte-identical output.
 * This is the end-to-end claim of the module. */
static void test_replay_identity(void)
{
	char path[128];
	struct nfsp_rule r;
	struct nfsp_rule loaded;
	struct nfsp_msg_ctx ctx;
	struct nfsp_apply_stats st;
	struct nfsp_delta_writer *w = NULL;
	struct nfsp_delta_reader *rd = NULL;
	uint8_t produced[48], replayed[48], original[48];

	printf("replay identity: file alone reproduces the mutation\n");
	mkrule(&r);
	r.first_opcode = 22;
	r.anchor_off = 20;
	r.anchor_len = 4;
	memcpy(r.anchor, "path", 4);
	r.patch_off = 40;
	r.patch_w = 8;
	memset(r.orig, 0x10, 8);
	memset(r.repl, 0xc7, 8);

	memset(original, 0, sizeof(original));
	memcpy(original + 20, "path", 4);
	memset(original + 40, 0x10, 8);

	memset(&ctx, 0, sizeof(ctx));
	ctx.dir = NFSP_DELTA_S2C;
	ctx.backend = NFSP_DELTA_BACKEND_KNFSD;
	ctx.first_opcode = 22;

	/* produce */
	memcpy(produced, original, sizeof(produced));
	memset(&st, 0, sizeof(st));
	CHECK(nfsp_apply_rule(&r, &ctx, produced, sizeof(produced), &st) == 1,
	      "produce apply failed");
	r.applied_count = st.applied;

	tmpfile_path(path, sizeof(path), "replay");
	CHECK(nfsp_delta_write_open(&w, path, 0) == 0, "open writer");
	CHECK(nfsp_delta_write_rule(w, &r) == 0, "write rule");
	nfsp_delta_write_close(w);

	/* replay: the file is the only input */
	CHECK(nfsp_delta_read_open(&rd, path) == 0, "open reader");
	CHECK(nfsp_delta_read_rule(rd, &loaded) == 1, "read rule");
	nfsp_delta_read_close(rd);

	memcpy(replayed, original, sizeof(replayed));
	memset(&st, 0, sizeof(st));
	CHECK(nfsp_apply_rule(&loaded, &ctx, replayed, sizeof(replayed),
			      &st) == 1, "replay apply failed");
	CHECK(st.applied == loaded.applied_count,
	      "replay applied %u but the record says %u -- a partial replay must "
	      "be loud", st.applied, loaded.applied_count);
	CHECK(memcmp(produced, replayed, sizeof(produced)) == 0,
	      "replay did not reproduce the produced bytes");
	unlink(path);
}

/* A corrupt file must be refused cleanly.  A length field is the obvious way an
 * attacker or a truncated write tries to drive a large read. */
static void test_corrupt_file_refused(void)
{
	char path[128];
	FILE *f;
	struct nfsp_delta_reader *rd = NULL;
	struct nfsp_rule r;

	printf("corrupt files are refused, not believed\n");

	/* bad magic */
	tmpfile_path(path, sizeof(path), "badmagic");
	f = fopen(path, "wb");
	CHECK(f != NULL, "create");
	fwrite("NOTDELTA", 1, 8, f);
	fwrite("\0\0\0\1", 1, 4, f);
	fwrite("\0\0\0\0\0\0\0\0", 1, 8, f);
	fclose(f);
	CHECK(nfsp_delta_read_open(&rd, path) == -1, "bad magic must be refused");
	unlink(path);

	/* truncated record header */
	tmpfile_path(path, sizeof(path), "trunc");
	{
		struct nfsp_delta_writer *w2 = NULL;
		struct nfsp_rule rr;

		/* Return values checked: an unchecked setup step is how a test
		 * ends up asserting nothing. */
		CHECK(nfsp_delta_write_open(&w2, path, 0) == 0,
		      "open writer for the truncation case");
		mkrule(&rr);
		CHECK(nfsp_delta_write_rule(w2, &rr) == 0, "write one rule");
		CHECK(nfsp_delta_write_close(w2) == 1, "one record written");
	}
	{
		long sz;
		FILE *rf = fopen(path, "rb");
		CHECK(rf != NULL, "reopen");
		CHECK(fseek(rf, 0, SEEK_END) == 0, "seek to end");
		sz = ftell(rf);
		CHECK(sz > 0, "empty file: the truncation case would be vacuous");
		CHECK(fclose(rf) == 0, "close probe");
		/* Chop the last byte so the final repl[] block is short.  The
		 * return value is checked because an unchecked setup step is how
		 * a test ends up asserting nothing: if the truncation silently
		 * failed, the following CHECK would pass for the wrong reason. */
		FILE *cf = fopen(path, "r+b");
		CHECK(cf != NULL, "open for truncation");
		CHECK(ftruncate(fileno(cf), (off_t)sz - 1) == 0,
		      "truncate by one byte");
		CHECK(fclose(cf) == 0, "close after truncation");
	}
	CHECK(nfsp_delta_read_open(&rd, path) == 0, "header still readable");
	CHECK(nfsp_delta_read_rule(rd, &r) == -1,
	      "a truncated record must be refused, not returned as valid");
	nfsp_delta_read_close(rd);
	unlink(path);
}

int main(void)
{
	printf("delta tests\n");
	test_rule_validity();
	test_apply_and_verify();
	test_predicate_matching();
	test_out_of_range_is_distinct();
	test_round_trip();
	test_order_independence();
	test_replay_identity();
	test_corrupt_file_refused();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
