/* Tests for the structural walk.
 *
 * WHAT THESE CAN AND CANNOT PROVE
 *
 *   The offsets asserted here come from the same reading of RFC 5531 and
 *   RFC 5661 that the walker is built from, so a shared misreading would pass
 *   both.  That limitation is real and is stated in the header.  What these
 *   tests DO guarantee, independently of any RFC interpretation, is:
 *
 *     - no slot or region ever addresses a byte outside the message, for any
 *       input including deliberately hostile ones;
 *     - the walk never reports OK for a message that does not contain the
 *       fields it claims to have found;
 *     - truncation is reported as truncation, never as success.
 *
 *   The second and third are the properties that matter operationally: a
 *   mutation placed outside the message is a memory error, and a walk that
 *   reports success on garbage puts mutations at meaningless offsets.
 */
#include "walk.h"

#include <stdio.h>
#include <stdlib.h>
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

/* ---- a small big-endian message builder ---------------------------------- */

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

/* Finish a message: prepend the fragment header and shift the body up by four.
 * Building the body first and stamping the header last keeps the body offsets
 * in the builder identical to the offsets the walker will report minus four,
 * which is exactly the arithmetic worth testing. */
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

/* Build a COMPOUND4args CALL with `ops` payload words after the op count. */
static void build_call(struct mbuf *m, uint32_t opcount, uint32_t opwords)
{
	m->n = 0;
	w32(m, 0x11223344u);	/* xid */
	w32(m, NFSP_MSGTYPE_CALL);
	w32(m, NFSP_RPCVERS);
	w32(m, NFSP_PROG_NFS);
	w32(m, NFSP_NFS_V4);
	w32(m, NFSP_PROC4_COMPOUND);
	w32(m, 0);		/* cred flavour = AUTH_NULL */
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

static void build_reply(struct mbuf *m, uint32_t rescount, uint32_t opwords)
{
	m->n = 0;
	w32(m, 0x11223344u);	/* xid */
	w32(m, NFSP_MSGTYPE_REPLY);
	w32(m, NFSP_MSGP_ACCEPTED);
	w32(m, 0);		/* verf flavour */
	w32(m, 0);		/* verf len */
	w32(m, NFSP_MSGS_ACCEPTED);
	w32(m, 0);		/* nfsstat4 status = NFS4_OK */
	w32(m, 0);		/* tag len */
	w32(m, rescount);
	for (uint32_t i = 0; i < opwords; i++)
		w32(m, 0x0a0b0c00u + i);
	finish(m);
}

/* ---- the invariant that must hold for every input ------------------------ */

/* Every slot must be a 4-byte field fully inside the message, and every region
 * must lie fully inside the message.  Checked on every case below, including
 * the hostile ones, because this is the property that prevents a mutation from
 * being a memory error. */
static void check_bounds(const char *label, const struct nfsp_walk *w,
			 const uint8_t *buf, size_t len)
{
	size_t i;

	(void)buf;
	for (i = 0; i < w->nslots; i++) {
		CHECK(w->slots[i].offset + 4u <= len,
		      "%s: slot %zu (%s) at %u+4 exceeds msg len %zu", label, i,
		      nfsp_walk_role_name(w->slots[i].role),
		      w->slots[i].offset, len);
	}
	for (i = 0; i < w->nregions; i++) {
		CHECK((size_t)w->regions[i].offset + w->regions[i].len <= len,
		      "%s: region %zu (%s) at %u+%u exceeds msg len %zu", label,
		      i, nfsp_walk_region_name(w->regions[i].role),
		      w->regions[i].offset, w->regions[i].len, len);
		CHECK(w->regions[i].len > 0,
		      "%s: empty region emitted", label);
	}
}

#define RUN(label, buf, len)                                                   \
	do {                                                                   \
		struct nfsp_walk w_;                                           \
		nfsp_walk((buf), (len), &w_);                                  \
		check_bounds((label), &w_, (buf), (len));                      \
		last = w_;                                                     \
	} while (0)

static struct nfsp_walk last;

static void test_call_offsets(void)
{
	struct mbuf m;
	const struct nfsp_slot *s;

	printf("CALL: exact offsets of every certain field\n");
	build_call(&m, 3, 12);	/* 3 ops x 4 words each */
	RUN("call", m.b, m.n);

	CHECK(last.status == NFSP_WALK_OK, "status %s",
	      nfsp_walk_strerror(last.status));
	CHECK(last.is_call == 1, "is_call %d", last.is_call);
	CHECK(last.xid == 0x11223344u, "xid 0x%08x", last.xid);
	CHECK(last.prog == NFSP_PROG_NFS, "prog %u", last.prog);
	CHECK(last.vers == NFSP_NFS_V4, "vers %u", last.vers);
	CHECK(last.proc == NFSP_PROC4_COMPOUND, "proc %u", last.proc);
	CHECK(last.minorversion == 1, "minorversion %u", last.minorversion);
	CHECK(last.opcount == 3, "opcount %u", last.opcount);

	/* Offsets: 4-byte fragment header, then ten RPC-header words, then the
	 * three COMPOUND-header words.  Written out literally so that a change
	 * in the walker cannot silently move them. */
	s = nfsp_walk_find(&last, NFSP_SR_XID);
	CHECK(s != NULL && s->offset == 4, "xid at %u, expected 4",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_MTYPE);
	CHECK(s != NULL && s->offset == 8, "mtype at %u, expected 8",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_RPCVERS);
	CHECK(s != NULL && s->offset == 12, "rpcvers at %u, expected 12",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_PROG);
	CHECK(s != NULL && s->offset == 16, "prog at %u, expected 16",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_VERS);
	CHECK(s != NULL && s->offset == 20, "vers at %u, expected 20",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_PROC);
	CHECK(s != NULL && s->offset == 24, "proc at %u, expected 24",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_CRED_FLAVOR);
	CHECK(s != NULL && s->offset == 28, "cred_flavor at %u, expected 28",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_CRED_LEN);
	CHECK(s != NULL && s->offset == 32, "cred_len at %u, expected 32",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_VERF_FLAVOR);
	CHECK(s != NULL && s->offset == 36, "verf_flavor at %u, expected 36",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_VERF_LEN);
	CHECK(s != NULL && s->offset == 40, "verf_len at %u, expected 40",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_TAG_LEN);
	CHECK(s != NULL && s->offset == 44, "tag_len at %u, expected 44",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_MINORVERSION);
	CHECK(s != NULL && s->offset == 48, "minorversion at %u, expected 48",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_OPCOUNT);
	CHECK(s != NULL && s->offset == 52, "opcount at %u, expected 52",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_FIRST_OPCODE);
	CHECK(s != NULL && s->offset == 56, "first_opcode at %u, expected 56",
	      s ? s->offset : 0u);

	CHECK(last.header_end == 56, "header_end %zu, expected 56",
	      last.header_end);
	CHECK(last.nregions == 1, "expected 1 region, got %zu", last.nregions);
	CHECK(last.regions[0].role == NFSP_RR_OP_BODY, "region role %s",
	      nfsp_walk_region_name(last.regions[0].role));
	CHECK(last.regions[0].offset == 56 && last.regions[0].len == 48,
	      "op body region %u+%u, expected 56+48",
	      last.regions[0].offset, last.regions[0].len);
}

static void test_reply_offsets(void)
{
	struct mbuf m;
	const struct nfsp_slot *s;

	printf("REPLY: exact offsets, including the leading nfsstat4\n");
	build_reply(&m, 2, 8);
	RUN("reply", m.b, m.n);

	CHECK(last.status == NFSP_WALK_OK, "status %s",
	      nfsp_walk_strerror(last.status));
	CHECK(last.is_call == 0, "is_call %d", last.is_call);
	CHECK(last.nfs_status == 0, "nfs_status %u", last.nfs_status);
	CHECK(last.opcount == 2, "rescount %u", last.opcount);

	s = nfsp_walk_find(&last, NFSP_SR_REPLY_STAT);
	CHECK(s != NULL && s->offset == 12, "reply_stat at %u, expected 12",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_ACCEPT_STAT);
	CHECK(s != NULL && s->offset == 24, "accept_stat at %u, expected 24",
	      s ? s->offset : 0u);
	/* The reply's COMPOUND4res leads with nfsstat4, so the tag and the
	 * array count sit one word later than in a CALL.  This asymmetry is
	 * easy to get wrong and would silently shift every mutation. */
	s = nfsp_walk_find(&last, NFSP_SR_NFS_STATUS);
	CHECK(s != NULL && s->offset == 28, "nfs_status at %u, expected 28",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_TAG_LEN);
	CHECK(s != NULL && s->offset == 32, "tag_len at %u, expected 32",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_OPCOUNT);
	CHECK(s != NULL && s->offset == 36, "opcount at %u, expected 36",
	      s ? s->offset : 0u);
	s = nfsp_walk_find(&last, NFSP_SR_FIRST_OPCODE);
	CHECK(s != NULL && s->offset == 40, "first_opcode at %u, expected 40",
	      s ? s->offset : 0u);
	CHECK(nfsp_walk_find(&last, NFSP_SR_MINORVERSION) == NULL,
	      "a reply must not report minorversion");
}

/* Truncation at every length: the walk must never claim OK, and must never
 * address outside what was given.  This is the sweep that catches an off-by-one
 * in any single bounds check. */
static void test_truncation_sweep(void)
{
	struct mbuf m;
	size_t cut;
	/* A prefix shorter than the certain header must never report OK, and
	 * must never advertise a field it could not have read.  A prefix that
	 * contains the whole header MAY report OK even if the op body is short,
	 * because the op body is deliberately unclaimed: the walker does not
	 * parse ops and therefore cannot know how long they should be.  Asserting
	 * "no prefix is ever OK" would be asserting something false. */
	printf("truncation sweep over every length\n");
	build_call(&m, 2, 8);
	for (cut = 0; cut < m.n; cut++) {
		struct nfsp_walk w;

		nfsp_walk(m.b, cut, &w);
		check_bounds("trunc", &w, m.b, cut);
		if (cut < 56) {
			CHECK(w.status != NFSP_WALK_OK,
			      "a %zu-byte prefix reported OK although the header "
			      "needs 56", cut);
			CHECK(w.nslots == 0 || cut >= 4,
			      "phantom slots in a %zu-byte prefix", cut);
			CHECK(nfsp_walk_find(&w, NFSP_SR_OPCOUNT) == NULL,
			      "a %zu-byte prefix advertised an op count", cut);
		}
	}

	printf("truncation sweep, REPLY\n");
	build_reply(&m, 2, 8);
	for (cut = 0; cut < m.n; cut++) {
		struct nfsp_walk w;

		nfsp_walk(m.b, cut, &w);
		check_bounds("truncR", &w, m.b, cut);
		if (cut < 40) {
			CHECK(w.status != NFSP_WALK_OK,
			      "a %zu-byte reply prefix reported OK although the "
			      "header needs 40", cut);
			CHECK(nfsp_walk_find(&w, NFSP_SR_OPCOUNT) == NULL,
			      "a %zu-byte reply prefix advertised an op count",
			      cut);
		}
	}
}

/* A hostile opaque_auth length must not be believed. */
static void test_hostile_auth_len(void)
{
	struct mbuf m;
	struct nfsp_walk w;

	printf("hostile cred length\n");
	build_call(&m, 1, 2);
	/* cred_len sits at offset 32; claim far more than the message holds. */
	m.b[32] = 0x7f;
	m.b[33] = 0xff;
	m.b[34] = 0xff;
	m.b[35] = 0xff;
	nfsp_walk(m.b, m.n, &w);
	CHECK(w.status != NFSP_WALK_OK, "must not report OK, got %s",
	      nfsp_walk_strerror(w.status));
	check_bounds("authlen", &w, m.b, m.n);

	printf("hostile cred length that would wrap when padded\n");
	build_call(&m, 1, 2);
	m.b[32] = 0xff;
	m.b[33] = 0xff;
	m.b[34] = 0xff;
	m.b[35] = 0xff;
	nfsp_walk(m.b, m.n, &w);
	CHECK(w.status != NFSP_WALK_OK, "wrap must be refused, got %s",
	      nfsp_walk_strerror(w.status));
	check_bounds("authwrap", &w, m.b, m.n);
}

/* A tag length beyond the message must not be believed. */
static void test_hostile_tag_len(void)
{
	struct mbuf m;
	struct nfsp_walk w;

	printf("hostile compound tag length\n");
	build_call(&m, 1, 2);
	m.b[44] = 0x00;
	m.b[45] = 0x10;
	m.b[46] = 0x00;
	m.b[47] = 0x00;		/* 1 MiB tag in a 60-byte message */
	nfsp_walk(m.b, m.n, &w);
	CHECK(w.status == NFSP_WALK_BAD_TAG_LEN ||
	      w.status == NFSP_WALK_TRUNCATED,
	      "expected a tag-length refusal, got %s",
	      nfsp_walk_strerror(w.status));
	check_bounds("taglen", &w, m.b, m.n);
}

/* An op count larger than the remaining words cannot be honest: at minimum each
 * op is one u32.  Rejecting it keeps a hostile count from driving later work. */
static void test_hostile_opcount(void)
{
	struct mbuf m;
	struct nfsp_walk w;

	printf("hostile op count\n");
	build_call(&m, 1, 2);	/* 8 bytes of op body = 2 words available */
	m.b[52] = 0x00;
	m.b[53] = 0x00;
	m.b[54] = 0x10;
	m.b[55] = 0x00;		/* claim 4096 ops */
	nfsp_walk(m.b, m.n, &w);
	CHECK(w.status == NFSP_WALK_BAD_OPCOUNT,
	      "expected BAD_OPCOUNT, got %s", nfsp_walk_strerror(w.status));
	check_bounds("opcount", &w, m.b, m.n);
	/* The header fields found before the refusal must still be usable. */
	CHECK(nfsp_walk_find(&w, NFSP_SR_XID) != NULL,
	      "certain fields before the refusal must survive");
}

/* A non-COMPOUND call still has a certain header; the rest is explicitly
 * unclaimed.  This is the case that keeps the walker honest about what it does
 * not know. */
static void test_non_compound(void)
{
	struct mbuf m;
	struct nfsp_walk w;

	printf("non-COMPOUND call (NFSv3 proc)\n");
	m.n = 0;
	w32(&m, 0x99u);
	w32(&m, NFSP_MSGTYPE_CALL);
	w32(&m, NFSP_RPCVERS);
	w32(&m, NFSP_PROG_NFS);
	w32(&m, 3);		/* NFSv3 */
	w32(&m, 6);		/* NFSPROC3_READ */
	w32(&m, 0);
	w32(&m, 0);
	w32(&m, 0);
	w32(&m, 0);
	for (int i = 0; i < 8; i++)
		w32(&m, 0xdeadbeefu);
	finish(&m);
	nfsp_walk(m.b, m.n, &w);
	CHECK(w.status == NFSP_WALK_OK, "status %s",
	      nfsp_walk_strerror(w.status));
	CHECK(w.header_end == 44, "header_end %zu, expected 44", w.header_end);
	CHECK(nfsp_walk_find(&w, NFSP_SR_OPCOUNT) == NULL,
	      "must not invent a COMPOUND op count for a non-COMPOUND call");
	CHECK(w.nregions == 1 && w.regions[0].role == NFSP_RR_TRAILER,
	      "rest must be an unclaimed trailer region");
	check_bounds("noncompound", &w, m.b, m.n);
}

/* A fragmented RPC record must be refused rather than mis-addressed: a mutation
 * that lands on a fragment header is not the mutation anyone asked for. */
static void test_fragmented_record_refused(void)
{
	uint8_t two[64];
	struct nfsp_walk w;

	printf("fragmented record is refused\n");
	memset(two, 0, sizeof(two));
	two[0] = 0x00;		/* last-fragment bit clear */
	two[1] = 0x00;
	two[2] = 0x00;
	two[3] = 0x10;
	nfsp_walk(two, sizeof(two), &w);
	CHECK(w.status != NFSP_WALK_OK, "fragmented record must be refused");
	check_bounds("frag", &w, two, sizeof(two));
}

/* Certain fields must be found in order, and a later field must never be
 * reported when an earlier one was not. */
static void test_slot_ordering(void)
{
	struct mbuf m;
	struct nfsp_walk w;
	size_t i;
	uint32_t prev = 0;

	printf("slots are emitted in increasing offset order\n");
	build_call(&m, 4, 16);
	nfsp_walk(m.b, m.n, &w);
	for (i = 0; i < w.nslots; i++) {
		CHECK(w.slots[i].offset > prev,
		      "slot %zu (%s) at %u does not follow %u", i,
		      nfsp_walk_role_name(w.slots[i].role),
		      w.slots[i].offset, prev);
		prev = w.slots[i].offset;
	}
	CHECK(w.nslots > 0, "no slots emitted at all");
}

int main(void)
{
	printf("walk tests\n");
	test_call_offsets();
	test_reply_offsets();
	test_truncation_sweep();
	test_hostile_auth_len();
	test_hostile_tag_len();
	test_hostile_opcount();
	test_non_compound();
	test_fragmented_record_refused();
	test_slot_ordering();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
