/* Golden on-disk vectors for the legacy NFSPDLT1/NFSPDLT2 delta files (M0).
 *
 * WHY ROUND-TRIP TESTS ARE NOT ENOUGH
 *
 *   test_delta and test_edit write a file with the writer and read it back
 *   with the reader.  That proves the two halves agree with each other, not
 *   that either still matches the files already on disk: a change made to
 *   both halves in the same way -- two fields swapped, a width changed, the
 *   byte order flipped -- passes every round trip.  Legacy delta files are the
 *   reproduction contract of manual campaigns (docs/design/03-nfs-proxy/06
 *   §23, issue #19), so their bytes are pinned here independently of the code:
 *
 *     - the reader must decode each golden file to the fields spelled out in
 *       this file;
 *     - the writer must produce each golden file byte for byte, including the
 *       in-place applied_count update;
 *     - no test hands a writer's output to the reader.
 *
 *   The vectors are written by hand from the layout comments in delta.h,
 *   delta.c, edit.h and edit.c.  Changing one is a format change: delta files
 *   recorded earlier stop being replayable.
 *
 *   In each file, every pair of header fields differs in at least one record,
 *   so swapping any two fields changes the bytes.  The v2 file needs three
 *   records for that, and between them they use every edit kind.
 */
#define _POSIX_C_SOURCE 200809L

#include "delta.h"
#include "edit.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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

/* ---- NFSPDLT1 ------------------------------------------------------------
 *
 * Header: magic[8] "NFSPDLT1", version u32 = 1, seed u64.  Each record: ten
 * u32 words (dir, backend, client, first_opcode, match_index, anchor_off,
 * anchor_len, patch_off, patch_w, applied_count), then anchor[anchor_len],
 * orig[patch_w], repl[patch_w].  Every integer is big-endian. */
#define V1_HDR_LEN	20u
#define V1_REC_A_LEN	48u
#define V1_REC_B_LEN	48u

static const uint8_t golden_v1[] = {
	/* header */
	0x4e, 0x46, 0x53, 0x50, 0x44, 0x4c, 0x54, 0x31,	/* "NFSPDLT1" */
	0x00, 0x00, 0x00, 0x01,				/* version 1 */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	/* seed */
	/* record A: S2C, knfsd, client 0, no anchor, 4-byte patch at 28 */
	0x00, 0x00, 0x00, 0x01,				/* dir S2C */
	0x00, 0x00, 0x00, 0x00,				/* backend knfsd */
	0x00, 0x00, 0x00, 0x00,				/* client 0 */
	0xff, 0xff, 0xff, 0xff,				/* first_opcode any */
	0xff, 0xff, 0xff, 0xff,				/* match_index any */
	0x00, 0x00, 0x00, 0x00,				/* anchor_off */
	0x00, 0x00, 0x00, 0x00,				/* anchor_len */
	0x00, 0x00, 0x00, 0x1c,				/* patch_off 28 */
	0x00, 0x00, 0x00, 0x04,				/* patch_w 4 */
	0x00, 0x00, 0x00, 0x03,				/* applied_count 3 */
	0x00, 0x00, 0x27, 0x16,				/* orig */
	0x00, 0x00, 0x00, 0x00,				/* repl */
	/* record B: C2S, Ganesha, client 0, anchored, 2-byte patch at 44 */
	0x00, 0x00, 0x00, 0x00,				/* dir C2S */
	0x00, 0x00, 0x00, 0x01,				/* backend Ganesha */
	0x00, 0x00, 0x00, 0x00,				/* client 0 */
	0x00, 0x00, 0x00, 0x35,				/* first_opcode 53 */
	0xff, 0xff, 0xff, 0xff,				/* match_index any */
	0x00, 0x00, 0x00, 0x28,				/* anchor_off 40 */
	0x00, 0x00, 0x00, 0x04,				/* anchor_len 4 */
	0x00, 0x00, 0x00, 0x2c,				/* patch_off 44 */
	0x00, 0x00, 0x00, 0x02,				/* patch_w 2 */
	0x00, 0x01, 0x00, 0x02,				/* applied_count 65538 */
	0xde, 0xad, 0xbe, 0xef,				/* anchor */
	0xaa, 0xbb,					/* orig */
	0xcc, 0xdd,					/* repl */
};

#define V1_SEED	0x0102030405060708ull

static void v1_rule_a(struct nfsp_rule *r)
{
	static const uint8_t orig[4] = {0x00, 0x00, 0x27, 0x16};
	memset(r, 0, sizeof(*r));
	r->dir = NFSP_DELTA_S2C;
	r->backend = NFSP_DELTA_BACKEND_KNFSD;
	r->client = 0;
	r->first_opcode = NFSP_DELTA_OPCODE_ANY;
	r->match_index = NFSP_DELTA_MATCH_ANY;
	r->patch_off = 28;
	r->patch_w = 4;
	memcpy(r->orig, orig, sizeof(orig));
}

static void v1_rule_b(struct nfsp_rule *r)
{
	static const uint8_t anchor[4] = {0xde, 0xad, 0xbe, 0xef};
	memset(r, 0, sizeof(*r));
	r->dir = NFSP_DELTA_C2S;
	r->backend = NFSP_DELTA_BACKEND_GANESHA;
	r->client = 0;
	r->first_opcode = 53;
	r->match_index = NFSP_DELTA_MATCH_ANY;
	r->anchor_off = 40;
	r->anchor_len = 4;
	memcpy(r->anchor, anchor, sizeof(anchor));
	r->patch_off = 44;
	r->patch_w = 2;
	r->orig[0] = 0xaa; r->orig[1] = 0xbb;
	r->repl[0] = 0xcc; r->repl[1] = 0xdd;
}

/* ---- NFSPDLT2 ------------------------------------------------------------
 *
 * Header: magic[8] "NFSPDLT2", version u32 = 2, seed u64.  Each record: ten
 * u32 words (dir, backend, client, first_opcode, anchor_off, anchor_len, mode,
 * nedits, applied_count, reserved = 0), then anchor[anchor_len], then per edit
 * four u32 words (kind, offset, orig_len, data_len), orig[orig_len] and
 * data[data_len].  Every integer is big-endian. */
#define V2_HDR_LEN	20u
#define V2_REC_A_LEN	64u
#define V2_REC_B_LEN	90u
#define V2_REC_C_LEN	80u

static const uint8_t golden_v2[] = {
	/* header */
	0x4e, 0x46, 0x53, 0x50, 0x44, 0x4c, 0x54, 0x32,	/* "NFSPDLT2" */
	0x00, 0x00, 0x00, 0x02,				/* version 2 */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* seed */
	/* record A: C2S, knfsd, client 1, struct mode, one OP_APPEND */
	0x00, 0x00, 0x00, 0x00,				/* dir C2S */
	0x00, 0x00, 0x00, 0x00,				/* backend knfsd */
	0x00, 0x00, 0x00, 0x01,				/* client 1 */
	0xff, 0xff, 0xff, 0xff,				/* first_opcode any */
	0x00, 0x00, 0x00, 0x00,				/* anchor_off */
	0x00, 0x00, 0x00, 0x00,				/* anchor_len */
	0x00, 0x00, 0x00, 0x00,				/* mode struct */
	0x00, 0x00, 0x00, 0x01,				/* nedits 1 */
	0x00, 0x00, 0x00, 0x02,				/* applied_count 2 */
	0x00, 0x00, 0x00, 0x00,				/* reserved */
	0x00, 0x00, 0x00, 0x03,				/* kind OP_APPEND */
	0x00, 0x00, 0x00, 0x00,				/* offset (unused) */
	0x00, 0x00, 0x00, 0x00,				/* orig_len 0 */
	0x00, 0x00, 0x00, 0x08,				/* data_len 8 */
	0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x01,	/* data */
	/* record B: S2C, knfsd, client 0, raw mode, REPLACE grows + DELETE */
	0x00, 0x00, 0x00, 0x01,				/* dir S2C */
	0x00, 0x00, 0x00, 0x00,				/* backend knfsd */
	0x00, 0x00, 0x00, 0x00,				/* client 0 */
	0x00, 0x00, 0x00, 0x16,				/* first_opcode 22 */
	0x00, 0x00, 0x00, 0x24,				/* anchor_off 36 */
	0x00, 0x00, 0x00, 0x04,				/* anchor_len 4 */
	0x00, 0x00, 0x00, 0x01,				/* mode raw */
	0x00, 0x00, 0x00, 0x02,				/* nedits 2 */
	0x00, 0x01, 0x00, 0x02,				/* applied_count 65538 */
	0x00, 0x00, 0x00, 0x00,				/* reserved */
	0x01, 0x02, 0x03, 0x04,				/* anchor */
	0x00, 0x00, 0x00, 0x00,				/* kind REPLACE */
	0x00, 0x00, 0x00, 0x28,				/* offset 40 */
	0x00, 0x00, 0x00, 0x04,				/* orig_len 4 */
	0x00, 0x00, 0x00, 0x06,				/* data_len 6 */
	0x00, 0x00, 0x00, 0x04,				/* orig */
	0x00, 0x00, 0x00, 0x08, 0xab, 0xcd,		/* data */
	0x00, 0x00, 0x00, 0x02,				/* kind DELETE */
	0x00, 0x00, 0x00, 0x3c,				/* offset 60 */
	0x00, 0x00, 0x00, 0x04,				/* orig_len 4 */
	0x00, 0x00, 0x00, 0x00,				/* data_len 0 */
	0x11, 0x22, 0x33, 0x44,				/* orig */
	/* record C: S2C, Ganesha, client 1, struct mode, INSERT + OP_PREPEND */
	0x00, 0x00, 0x00, 0x01,				/* dir S2C */
	0x00, 0x00, 0x00, 0x01,				/* backend Ganesha */
	0x00, 0x00, 0x00, 0x01,				/* client 1 */
	0x00, 0x00, 0x00, 0x09,				/* first_opcode 9 */
	0x00, 0x00, 0x00, 0x00,				/* anchor_off */
	0x00, 0x00, 0x00, 0x00,				/* anchor_len */
	0x00, 0x00, 0x00, 0x00,				/* mode struct */
	0x00, 0x00, 0x00, 0x02,				/* nedits 2 */
	0x00, 0x00, 0x00, 0x05,				/* applied_count 5 */
	0x00, 0x00, 0x00, 0x00,				/* reserved */
	0x00, 0x00, 0x00, 0x01,				/* kind INSERT */
	0x00, 0x00, 0x00, 0x30,				/* offset 48 */
	0x00, 0x00, 0x00, 0x00,				/* orig_len 0 */
	0x00, 0x00, 0x00, 0x04,				/* data_len 4 */
	0x00, 0x00, 0x00, 0x2a,				/* data */
	0x00, 0x00, 0x00, 0x04,				/* kind OP_PREPEND */
	0x00, 0x00, 0x00, 0x00,				/* offset (unused) */
	0x00, 0x00, 0x00, 0x00,				/* orig_len 0 */
	0x00, 0x00, 0x00, 0x04,				/* data_len 4 */
	0x00, 0x00, 0x00, 0x09,				/* data */
};

#define V2_SEED	0x1122334455667788ull

static void v2_rule_a(struct nfsp_edit_rule *r)
{
	static const uint8_t data[8] = {0, 0, 0, 0x35, 0, 0, 0, 1};
	memset(r, 0, sizeof(*r));
	r->dir = NFSP_DELTA_C2S;
	r->backend = NFSP_DELTA_BACKEND_KNFSD;
	r->client = 1;
	r->first_opcode = NFSP_DELTA_OPCODE_ANY;
	r->mode = NFSP_EDIT_MODE_STRUCT;
	r->nedits = 1;
	r->edits[0].kind = NFSP_EDIT_OP_APPEND;
	r->edits[0].data_len = 8;
	memcpy(r->edits[0].data, data, sizeof(data));
}

static void v2_rule_b(struct nfsp_edit_rule *r)
{
	static const uint8_t anchor[4] = {1, 2, 3, 4};
	static const uint8_t orig0[4] = {0, 0, 0, 4};
	static const uint8_t data0[6] = {0, 0, 0, 8, 0xab, 0xcd};
	static const uint8_t orig1[4] = {0x11, 0x22, 0x33, 0x44};
	memset(r, 0, sizeof(*r));
	r->dir = NFSP_DELTA_S2C;
	r->backend = NFSP_DELTA_BACKEND_KNFSD;
	r->client = 0;
	r->first_opcode = 22;
	r->anchor_off = 36;
	r->anchor_len = 4;
	memcpy(r->anchor, anchor, sizeof(anchor));
	r->mode = NFSP_EDIT_MODE_RAW;
	r->nedits = 2;
	r->edits[0].kind = NFSP_EDIT_REPLACE;
	r->edits[0].offset = 40;
	r->edits[0].orig_len = 4;
	r->edits[0].data_len = 6;
	memcpy(r->edits[0].orig, orig0, sizeof(orig0));
	memcpy(r->edits[0].data, data0, sizeof(data0));
	r->edits[1].kind = NFSP_EDIT_DELETE;
	r->edits[1].offset = 60;
	r->edits[1].orig_len = 4;
	memcpy(r->edits[1].orig, orig1, sizeof(orig1));
}

static void v2_rule_c(struct nfsp_edit_rule *r)
{
	static const uint8_t data0[4] = {0, 0, 0, 0x2a};
	static const uint8_t data1[4] = {0, 0, 0, 9};
	memset(r, 0, sizeof(*r));
	r->dir = NFSP_DELTA_S2C;
	r->backend = NFSP_DELTA_BACKEND_GANESHA;
	r->client = 1;
	r->first_opcode = 9;
	r->mode = NFSP_EDIT_MODE_STRUCT;
	r->nedits = 2;
	r->edits[0].kind = NFSP_EDIT_INSERT;
	r->edits[0].offset = 48;
	r->edits[0].data_len = 4;
	memcpy(r->edits[0].data, data0, sizeof(data0));
	r->edits[1].kind = NFSP_EDIT_OP_PREPEND;
	r->edits[1].data_len = 4;
	memcpy(r->edits[1].data, data1, sizeof(data1));
}

/* ---- file helpers --------------------------------------------------------
 *
 * Plain open/write/read only: these must not depend on the code under test. */
static const char *tmp_path(char *buf, size_t n, const char *tag)
{
	snprintf(buf, n, "/tmp/nfsp-golden-%s-%d.bin", tag, (int)getpid());
	return buf;
}

static int put_file(const char *path, const uint8_t *bytes, size_t len)
{
	int fd, ok;

	unlink(path);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return -1;
	ok = write(fd, bytes, len) == (ssize_t)len;
	return close(fd) == 0 && ok ? 0 : -1;
}

/* Returns the file length, or -1.  Fails if the file is larger than `cap`. */
static long get_file(const char *path, uint8_t *buf, size_t cap)
{
	size_t got = 0;
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return -1;
	for (;;) {
		ssize_t n = read(fd, buf + got, cap - got);
		if (n < 0) {
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		got += (size_t)n;
		if (got == cap) {
			uint8_t extra;
			n = read(fd, &extra, 1);
			close(fd);
			return n == 0 ? (long)got : -1;
		}
	}
	close(fd);
	return (long)got;
}

/* ---- NFSPDLT1 tests ------------------------------------------------------- */

static int v1_rules_equal(const struct nfsp_rule *a, const struct nfsp_rule *b)
{
	return a->dir == b->dir && a->backend == b->backend &&
	       a->client == b->client && a->first_opcode == b->first_opcode &&
	       a->match_index == b->match_index &&
	       a->anchor_off == b->anchor_off &&
	       a->anchor_len == b->anchor_len &&
	       a->patch_off == b->patch_off && a->patch_w == b->patch_w &&
	       a->applied_count == b->applied_count &&
	       memcmp(a->anchor, b->anchor, a->anchor_len) == 0 &&
	       memcmp(a->orig, b->orig, a->patch_w) == 0 &&
	       memcmp(a->repl, b->repl, a->patch_w) == 0;
}

static void test_v1_reader_decodes_golden(void)
{
	char path[96];
	struct nfsp_delta_reader *rd = NULL;
	struct nfsp_rule got, want;

	printf("NFSPDLT1 reader decodes the golden file\n");
	CHECK(sizeof(golden_v1) == V1_HDR_LEN + V1_REC_A_LEN + V1_REC_B_LEN,
	      "golden v1 vector is %zu bytes", sizeof(golden_v1));
	tmp_path(path, sizeof(path), "v1-read");
	if (put_file(path, golden_v1, sizeof(golden_v1)) != 0) {
		CHECK(0, "write golden v1");
		return;
	}
	CHECK(nfsp_delta_read_open(&rd, path) == 0, "v1 golden opens");
	if (rd == NULL) {
		unlink(path);
		return;
	}
	CHECK(nfsp_delta_reader_seed(rd) == V1_SEED, "v1 seed byte order");
	v1_rule_a(&want);
	want.applied_count = 3;
	CHECK(nfsp_delta_read_rule(rd, &got) == 1 && v1_rules_equal(&got, &want),
	      "v1 record A fields");
	v1_rule_b(&want);
	want.applied_count = 0x00010002u;
	CHECK(nfsp_delta_read_rule(rd, &got) == 1 && v1_rules_equal(&got, &want),
	      "v1 record B fields");
	CHECK(nfsp_delta_read_rule(rd, &got) == 0, "v1 clean EOF after two records");
	nfsp_delta_read_close(rd);
	unlink(path);
}

static void test_v1_writer_produces_golden(void)
{
	char path[96];
	struct nfsp_delta_writer *w = NULL;
	struct nfsp_rule r;
	uint8_t buf[sizeof(golden_v1) + 16];
	long len;

	printf("NFSPDLT1 writer produces the golden file byte for byte\n");
	tmp_path(path, sizeof(path), "v1-write");
	unlink(path);
	CHECK(nfsp_delta_write_open(&w, path, V1_SEED) == 0, "v1 writer opens");
	if (w == NULL)
		return;
	/* Both records are written with applied_count 0 and then updated in
	 * place, as the live arm path does; the golden bytes therefore also pin
	 * where the in-place update lands. */
	v1_rule_a(&r);
	CHECK(nfsp_delta_write_rule(w, &r) == 0, "v1 write record A");
	v1_rule_b(&r);
	CHECK(nfsp_delta_write_rule(w, &r) == 0, "v1 write record B");
	CHECK(nfsp_delta_write_applied_count(w, 0, 3) == 0, "v1 update A count");
	CHECK(nfsp_delta_write_applied_count(w, 1, 0x00010002u) == 0,
	      "v1 update B count");
	CHECK(nfsp_delta_write_close(w) == 2, "v1 writer closes with two records");
	len = get_file(path, buf, sizeof(buf));
	CHECK(len == (long)sizeof(golden_v1), "v1 file is %ld bytes, want %zu",
	      len, sizeof(golden_v1));
	CHECK(len == (long)sizeof(golden_v1) &&
	      memcmp(buf, golden_v1, sizeof(golden_v1)) == 0,
	      "v1 writer bytes differ from the golden file");
	unlink(path);
}

/* Read every rule from `bytes`; return how many were read and set *status to
 * the last read result (0 clean EOF, -1 corrupt), or -2 if open failed. */
static int v1_read_all(const uint8_t *bytes, size_t len, int *status)
{
	char path[96];
	struct nfsp_delta_reader *rd = NULL;
	struct nfsp_rule rule;
	int n = 0, rc;

	tmp_path(path, sizeof(path), "v1-damage");
	if (put_file(path, bytes, len) != 0) {
		*status = -3;
		return 0;
	}
	if (nfsp_delta_read_open(&rd, path) != 0) {
		unlink(path);
		*status = -2;
		return 0;
	}
	while ((rc = nfsp_delta_read_rule(rd, &rule)) == 1)
		n++;
	*status = rc;
	nfsp_delta_read_close(rd);
	unlink(path);
	return n;
}

static void test_v1_reader_rejects_damage(void)
{
	static const size_t bounds[] = {
		V1_HDR_LEN, V1_HDR_LEN + V1_REC_A_LEN,
		V1_HDR_LEN + V1_REC_A_LEN + V1_REC_B_LEN,
	};
	uint8_t bad[sizeof(golden_v1)];
	int status, n;

	printf("NFSPDLT1 reader refuses truncation and corrupt fields\n");
	/* Every prefix: only whole records are returned, a cut on a record
	 * boundary is a clean EOF, and a cut inside a record is corrupt. */
	for (size_t len = 0; len < sizeof(golden_v1); len++) {
		int want_n = 0, want_status;
		if (len < V1_HDR_LEN) {
			want_status = -2;
		} else {
			want_status = 0;
			for (size_t b = 1; b < 3; b++)
				if (len >= bounds[b])
					want_n = (int)b;
			if (len != bounds[want_n])
				want_status = -1;
		}
		n = v1_read_all(golden_v1, len, &status);
		CHECK(n == want_n && status == want_status,
		      "v1 prefix %zu: read %d rules status %d, want %d status %d",
		      len, n, status, want_n, want_status);
	}

	memcpy(bad, golden_v1, sizeof(bad));
	bad[7] = '2';				/* magic "NFSPDLT2" */
	v1_read_all(bad, sizeof(bad), &status);
	CHECK(status == -2, "v1 reader opened a file with the v2 magic");

	memcpy(bad, golden_v1, sizeof(bad));
	bad[11] = 2;				/* version 2 */
	v1_read_all(bad, sizeof(bad), &status);
	CHECK(status == -2, "v1 reader opened a version-2 file");

	/* One field at a time, in record A (which starts at byte 20). */
	{
		static const struct { size_t off; uint8_t val; const char *what; } cases[] = {
			{V1_HDR_LEN + 3, 2, "dir 2"},
			{V1_HDR_LEN + 7, 2, "backend 2"},
			{V1_HDR_LEN + 11, 2, "client 2"},
			{V1_HDR_LEN + 27, 65, "anchor_len 65"},
			{V1_HDR_LEN + 35, 0, "patch_w 0"},
			{V1_HDR_LEN + 35, 17, "patch_w 17"},
		};
		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			memcpy(bad, golden_v1, sizeof(bad));
			bad[cases[i].off] = cases[i].val;
			n = v1_read_all(bad, sizeof(bad), &status);
			CHECK(n == 0 && status == -1, "v1 %s: read %d rules status %d",
			      cases[i].what, n, status);
		}
	}
}

/* ---- NFSPDLT2 tests ------------------------------------------------------- */

static int v2_rules_equal(const struct nfsp_edit_rule *a,
			  const struct nfsp_edit_rule *b)
{
	if (a->dir != b->dir || a->backend != b->backend ||
	    a->client != b->client || a->first_opcode != b->first_opcode ||
	    a->anchor_off != b->anchor_off || a->anchor_len != b->anchor_len ||
	    a->mode != b->mode || a->nedits != b->nedits ||
	    a->applied_count != b->applied_count ||
	    memcmp(a->anchor, b->anchor, a->anchor_len) != 0)
		return 0;
	for (uint32_t i = 0; i < a->nedits; i++) {
		const struct nfsp_edit *x = &a->edits[i], *y = &b->edits[i];
		if (x->kind != y->kind || x->offset != y->offset ||
		    x->orig_len != y->orig_len || x->data_len != y->data_len ||
		    memcmp(x->orig, y->orig, x->orig_len) != 0 ||
		    memcmp(x->data, y->data, x->data_len) != 0)
			return 0;
	}
	return 1;
}

static void test_v2_reader_decodes_golden(void)
{
	char path[96];
	struct nfsp_edit_reader *rd = NULL;
	/* An edit rule is about 16 KiB; keep these off the stack. */
	struct nfsp_edit_rule *got = calloc(1, sizeof(*got));
	struct nfsp_edit_rule *want = calloc(1, sizeof(*want));

	printf("NFSPDLT2 reader decodes the golden file\n");
	CHECK(sizeof(golden_v2) ==
	      V2_HDR_LEN + V2_REC_A_LEN + V2_REC_B_LEN + V2_REC_C_LEN,
	      "golden v2 vector is %zu bytes", sizeof(golden_v2));
	tmp_path(path, sizeof(path), "v2-read");
	if (got == NULL || want == NULL ||
	    put_file(path, golden_v2, sizeof(golden_v2)) != 0) {
		CHECK(0, "v2 read setup");
		goto out;
	}
	CHECK(nfsp_edit_read_open(&rd, path) == 0, "v2 golden opens");
	if (rd == NULL)
		goto out;
	v2_rule_a(want);
	want->applied_count = 2;
	CHECK(nfsp_edit_read_rule(rd, got) == 1 && v2_rules_equal(got, want),
	      "v2 record A fields");
	v2_rule_b(want);
	want->applied_count = 0x00010002u;
	CHECK(nfsp_edit_read_rule(rd, got) == 1 && v2_rules_equal(got, want),
	      "v2 record B fields");
	v2_rule_c(want);
	want->applied_count = 5;
	CHECK(nfsp_edit_read_rule(rd, got) == 1 && v2_rules_equal(got, want),
	      "v2 record C fields");
	CHECK(nfsp_edit_read_rule(rd, got) == 0, "v2 clean EOF after three records");
	nfsp_edit_read_close(rd);
out:
	unlink(path);
	free(got);
	free(want);
}

static void test_v2_writer_produces_golden(void)
{
	char path[96];
	struct nfsp_edit_writer *w = NULL;
	struct nfsp_edit_rule *r = calloc(1, sizeof(*r));
	uint8_t buf[sizeof(golden_v2) + 16];
	long len;

	printf("NFSPDLT2 writer produces the golden file byte for byte\n");
	tmp_path(path, sizeof(path), "v2-write");
	unlink(path);
	if (r == NULL) {
		CHECK(0, "v2 write setup");
		return;
	}
	CHECK(nfsp_edit_write_open(&w, path, V2_SEED) == 0, "v2 writer opens");
	if (w == NULL) {
		free(r);
		return;
	}
	v2_rule_a(r);
	CHECK(nfsp_edit_write_rule(w, r) == 0, "v2 write record A");
	v2_rule_b(r);
	CHECK(nfsp_edit_write_rule(w, r) == 0, "v2 write record B");
	v2_rule_c(r);
	CHECK(nfsp_edit_write_rule(w, r) == 0, "v2 write record C");
	CHECK(nfsp_edit_write_applied_count(w, 0, 2) == 0, "v2 update A count");
	CHECK(nfsp_edit_write_applied_count(w, 1, 0x00010002u) == 0,
	      "v2 update B count");
	CHECK(nfsp_edit_write_applied_count(w, 2, 5) == 0, "v2 update C count");
	CHECK(nfsp_edit_write_close(w) == 3, "v2 writer closes with three records");
	len = get_file(path, buf, sizeof(buf));
	CHECK(len == (long)sizeof(golden_v2), "v2 file is %ld bytes, want %zu",
	      len, sizeof(golden_v2));
	CHECK(len == (long)sizeof(golden_v2) &&
	      memcmp(buf, golden_v2, sizeof(golden_v2)) == 0,
	      "v2 writer bytes differ from the golden file");
	unlink(path);
	free(r);
}

static int v2_read_all(const uint8_t *bytes, size_t len, int *status)
{
	char path[96];
	struct nfsp_edit_reader *rd = NULL;
	struct nfsp_edit_rule *rule = calloc(1, sizeof(*rule));
	int n = 0, rc;

	tmp_path(path, sizeof(path), "v2-damage");
	if (rule == NULL || put_file(path, bytes, len) != 0) {
		free(rule);
		*status = -3;
		return 0;
	}
	if (nfsp_edit_read_open(&rd, path) != 0) {
		unlink(path);
		free(rule);
		*status = -2;
		return 0;
	}
	while ((rc = nfsp_edit_read_rule(rd, rule)) == 1)
		n++;
	*status = rc;
	nfsp_edit_read_close(rd);
	unlink(path);
	free(rule);
	return n;
}

static void test_v2_reader_rejects_damage(void)
{
	static const size_t bounds[] = {
		V2_HDR_LEN, V2_HDR_LEN + V2_REC_A_LEN,
		V2_HDR_LEN + V2_REC_A_LEN + V2_REC_B_LEN,
		V2_HDR_LEN + V2_REC_A_LEN + V2_REC_B_LEN + V2_REC_C_LEN,
	};
	/* Record B starts here; its edits follow its 40-byte header and anchor. */
	const size_t b0 = V2_HDR_LEN + V2_REC_A_LEN;
	uint8_t bad[sizeof(golden_v2)];
	int status, n;

	printf("NFSPDLT2 reader refuses truncation and corrupt fields\n");
	for (size_t len = 0; len < sizeof(golden_v2); len++) {
		int want_n = 0, want_status;
		if (len < V2_HDR_LEN) {
			want_status = -2;
		} else {
			want_status = 0;
			for (size_t b = 1; b < 4; b++)
				if (len >= bounds[b])
					want_n = (int)b;
			if (len != bounds[want_n])
				want_status = -1;
		}
		n = v2_read_all(golden_v2, len, &status);
		CHECK(n == want_n && status == want_status,
		      "v2 prefix %zu: read %d rules status %d, want %d status %d",
		      len, n, status, want_n, want_status);
	}

	memcpy(bad, golden_v2, sizeof(bad));
	bad[7] = '1';				/* magic "NFSPDLT1" */
	v2_read_all(bad, sizeof(bad), &status);
	CHECK(status == -2, "v2 reader opened a file with the v1 magic");

	memcpy(bad, golden_v2, sizeof(bad));
	bad[11] = 1;				/* version 1 */
	v2_read_all(bad, sizeof(bad), &status);
	CHECK(status == -2, "v2 reader opened a version-1 file");

	/* One field at a time in record B; record A must still be returned. */
	{
		static const struct { size_t off; uint8_t val; const char *what; } cases[] = {
			{3, 2, "dir 2"},
			{7, 2, "backend 2"},
			{11, 2, "client 2"},
			{23, 65, "anchor_len 65"},
			{27, 2, "mode 2"},
			{31, 0, "nedits 0"},
			{31, 9, "nedits 9"},
			{44 + 3, 5, "first edit kind 5"},
			{44 + 10, 0x04, "first edit orig_len 1028"},
			{44 + 26 + 3, 1, "second edit DELETE turned INSERT (orig_len must be 0)"},
		};
		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			memcpy(bad, golden_v2, sizeof(bad));
			bad[b0 + cases[i].off] = cases[i].val;
			n = v2_read_all(bad, sizeof(bad), &status);
			CHECK(n == 1 && status == -1, "v2 %s: read %d rules status %d",
			      cases[i].what, n, status);
		}
	}

	/* A file of one format is never read as the other: the replay loader
	 * tries the v1 reader first and relies on this to fall through to v2. */
	n = v1_read_all(golden_v2, sizeof(golden_v2), &status);
	CHECK(status == -2, "v1 reader opened the v2 golden file");
	n = v2_read_all(golden_v1, sizeof(golden_v1), &status);
	CHECK(status == -2, "v2 reader opened the v1 golden file");
	(void)n;
}

int main(void)
{
	test_v1_reader_decodes_golden();
	test_v1_writer_produces_golden();
	test_v1_reader_rejects_damage();
	test_v2_reader_decodes_golden();
	test_v2_writer_produces_golden();
	test_v2_reader_rejects_damage();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
