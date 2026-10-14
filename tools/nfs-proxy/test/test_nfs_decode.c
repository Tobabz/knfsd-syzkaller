/* Tests for the NFS Semantic Decoder over the synthetic test schemas.
 *
 * test/schema/tproto-m{0,1}.x is a COMPOUND protocol with two minor
 * versions; test/schema/tflat.x is procedure-dispatched like NFSv3.  Neither
 * is NFS: they exist so every construct the normalizer accepts has a vector
 * whose offsets are written out below, word by word, independently of any
 * RFC.  The real NFSv4 schema gets its own vectors when its pinned XDR lands.
 *
 * Oracles (design 03-nfs-proxy/02 "검증 오라클"):
 *   1 golden      expected paths, values and every WireRef span
 *   2 truncation  every prefix of every golden message: not decoded, and no
 *                 field or operation survives
 *   3 malformed   oversized length, count beyond record, undeclared
 *                 discriminant, bad list link; lenient: undeclared enum and
 *                 bad bool outside a discriminant, non-zero padding and
 *                 trailing bytes decode and are flagged
 *   7 address     changing only one field's value bytes changes only that
 *                 field: no sibling, span or path moves
 *   F4            a REPLY is decoded only from reply_dispatch, never from a
 *                 shape its bytes happen to fit
 *   status        an operation's status is the status-typed value its result
 *                 starts with
 *   RPCSEC_GSS    a GSS-protected body is never decoded, even when its bytes
 *                 fit the procedure
 */
#include "nfs_decode.h"
#include "rpc_decode.h"
#include "schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct nfsp_schema_family nfsp_schema_family_tproto;
extern const struct nfsp_schema_family nfsp_schema_family_tflat;

static const struct nfsp_schema_family *const fams[] = {
	&nfsp_schema_family_tproto,
	&nfsp_schema_family_tflat,
};
#define NFAMS (sizeof(fams) / sizeof(fams[0]))

#define TPROTO_PROG	0x20000099u
#define TFLAT_PROG	0x2000009au

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

static void w64(struct msg *m, uint64_t v)
{
	w32(m, (uint32_t)(v >> 32));
	w32(m, (uint32_t)v);
}

static void wraw(struct msg *m, const char *s, size_t len)
{
	memcpy(m->b + m->n, s, len);
	m->n += len;
	while (m->n % 4u)
		m->b[m->n++] = 0;
}

static void wopaque(struct msg *m, const char *s)
{
	w32(m, (uint32_t)strlen(s));
	wraw(m, s, strlen(s));
}

static void call_header(struct msg *m, uint32_t prog, uint32_t vers,
			uint32_t proc)
{
	m->n = 0;
	w32(m, 0xc0ffee01);	/*  0 xid */
	w32(m, 0);		/*  4 CALL */
	w32(m, 2);		/*  8 rpcvers */
	w32(m, prog);		/* 12 */
	w32(m, vers);		/* 16 */
	w32(m, proc);		/* 20 */
	w32(m, 0);		/* 24 cred AUTH_NONE */
	w32(m, 0);		/* 28 */
	w32(m, 0);		/* 32 verf */
	w32(m, 0);		/* 36 */
}				/* 40 body */

static void reply_header(struct msg *m, uint32_t accept_stat)
{
	m->n = 0;
	w32(m, 0xc0ffee01);	/*  0 xid */
	w32(m, 1);		/*  4 REPLY */
	w32(m, 0);		/*  8 MSG_ACCEPTED */
	w32(m, 0);		/* 12 verf */
	w32(m, 0);		/* 16 */
	w32(m, accept_stat);	/* 20 */
}				/* 24 body */

/* tproto COMPOUND CALL with PING, WRITE, LOOKUP; offsets as in the
 * comments, total 184 bytes. */
static void build_compound_call(struct msg *m, uint32_t minor)
{
	call_header(m, TPROTO_PROG, 1, 1);
	wopaque(m, "ab");		/*  40 tag: len, 44..45, pad 46..47 */
	w32(m, minor);			/*  48 minorversion */
	w32(m, 3);			/*  52 argarray count */
	w32(m, 1);			/*  56 OP_PING, void */
	w32(m, 2);			/*  60 OP_WRITE */
	w32(m, 7);			/*  64 id.seq */
	wraw(m, "ID-ID-ID-ID!", 12);	/*  68 id.other[12] */
	w64(m, 0x0000000100000002ull);	/*  80 offset */
	w32(m, 0xfffffffbu);		/*  88 delta = -5 */
	w64(m, 0xfffffffffffffffeull);	/*  92 when = -2 */
	w32(m, 1);			/* 100 sync */
	wopaque(m, "hello");		/* 104 data: len, 108..112, pad ..115 */
	w32(m, 2);			/* 116 mask count */
	w32(m, 0xa);			/* 120 mask[0] */
	w32(m, 0xb);			/* 124 mask[1] */
	w32(m, 1);			/* 128 pair[0].seq */
	wraw(m, "pair-zero-00", 12);	/* 132 pair[0].other */
	w32(m, 2);			/* 144 pair[1].seq */
	wraw(m, "pair-one-111", 12);	/* 148 pair[1].other */
	w32(m, 2);			/* 160 target.kind = TK_LINK */
	wopaque(m, "x/y");		/* 164 link: len, 168..170, pad 171 */
	w32(m, 3);			/* 172 OP_LOOKUP */
	wopaque(m, "file");		/* 176 name: len, 180..183 */
}					/* 184 */

/* tproto COMPOUND REPLY to the call above plus two more WRITE results;
 * total 156 bytes. */
static void build_compound_reply(struct msg *m)
{
	reply_header(m, 0);
	w32(m, 0);			/*  24 status TP_OK */
	wopaque(m, "ab");		/*  28 tag */
	w32(m, 5);			/*  36 resarray count */
	w32(m, 1);			/*  40 OP_PING */
	w32(m, 0);			/*  44 PING_res.status */
	w32(m, 2);			/*  48 OP_WRITE */
	w32(m, 0);			/*  52 WRITE_res.status TP_OK */
	w32(m, 5);			/*  56 resok.count */
	w32(m, 9);			/*  60 resok.id.seq */
	wraw(m, "reply-id-xyz", 12);	/*  64 resok.id.other */
	w32(m, 3);			/*  76 OP_LOOKUP */
	w32(m, 0);			/*  80 LOOKUP_res.status TP_OK */
	w32(m, 1);			/*  84 entries present */
	w64(m, 100);			/*  88 entry[0].cookie */
	wopaque(m, "a");		/*  96 entry[0].name, 100, pad ..103 */
	w32(m, 1);			/* 104 entry[0] link: next present */
	w64(m, 200);			/* 108 entry[1].cookie */
	wopaque(m, "bb");		/* 116 entry[1].name, 120..121, pad */
	w32(m, 0);			/* 124 entry[1] link: end */
	w32(m, 1);			/* 128 eof */
	w32(m, 2);			/* 132 OP_WRITE */
	w32(m, 13);			/* 136 status TP_ERR_DENIED */
	wopaque(m, "own");		/* 140 owner: len, 144..146, pad 147 */
	w32(m, 2);			/* 148 OP_WRITE */
	w32(m, 5);			/* 152 status TP_ERR_IO: default, void */
}					/* 156 */

static enum nfsp_decode_status
run(const uint8_t *b, size_t n, const struct nfsp_reply_dispatch *rd,
    int allow_fixture, uint32_t max_fields, struct nfsp_decoded_msg *out)
{
	struct nfsp_rpc_envelope env;
	struct nfsp_decode_input in;

	memset(&in, 0, sizeof(in));
	in.payload = b;
	in.len = n;
	in.rpc = &env;
	in.reply_dispatch = rd;
	in.allow_test_fixture = allow_fixture;
	in.max_fields = max_fields;
	nfsp_rpc_decode(b, n, &env);
	return nfsp_nfs_decode(fams, NFAMS, &in, out);
}

static const struct nfsp_semantic_field *
field(const struct nfsp_decoded_msg *m, const char *path, unsigned nth)
{
	uint32_t i = 0;

	for (;;) {
		i = nfsp_field_find(m, path, i);
		if (i == NFSP_FIELD_NONE)
			return NULL;
		if (!nth--)
			return &m->fields[i];
		i++;
	}
}

#define SPAN(s, o, l) ((s).off == (o) && (s).len == (l))

static void expect(const struct nfsp_decoded_msg *m, const char *path,
		   unsigned nth, uint32_t eoff, uint32_t elen, uint32_t voff,
		   uint32_t vlen, uint64_t value, int line)
{
	const struct nfsp_semantic_field *f = field(m, path, nth);

	checks++;
	if (!f) {
		failures++;
		printf("  FAIL line %d: no field %s #%u\n", line, path, nth);
		return;
	}
	CHECK(SPAN(f->wire.encoded, eoff, elen) &&
	      SPAN(f->wire.value, voff, vlen),
	      "line %d %s: encoded %u+%u value %u+%u, want %u+%u %u+%u",
	      line, path, f->wire.encoded.off, f->wire.encoded.len,
	      f->wire.value.off, f->wire.value.len, eoff, elen, voff, vlen);
	CHECK(f->value == value, "line %d %s: value %llx, want %llx", line,
	      path, (unsigned long long)f->value, (unsigned long long)value);
}

#define EXPECT(m, path, nth, eo, el, vo, vl, v) \
	expect(m, path, nth, eo, el, vo, vl, v, __LINE__)

/* Structural invariants every decoded message must satisfy. */
static void check_invariants(const struct nfsp_decoded_msg *m, size_t len,
			     const char *what);

/* What a partial message must be: a CALL whose fields and ops all end where
 * the failed operation starts, with exactly the operations before it. */
static void check_partial(const struct nfsp_decoded_msg *m, size_t len,
			  const char *what)
{
	const struct nfsp_decode_failure *f = &m->failure;

	CHECK(m->status == NFSP_DECODE_PARTIAL && m->msg_type == 0 &&
	      (uint64_t)f->op_offset + 4 <= len && f->offset >= f->op_offset &&
	      m->nops == f->op_index && m->nfields > 0,
	      "%s: partial op %u at %u, %u ops, failure at %u", what,
	      f->op_index, f->op_offset, m->nops, f->offset);
	check_invariants(m, f->op_offset, what);
	for (uint32_t i = 0; i < m->nops; i++)
		CHECK(m->ops[i].sequence_index == i &&
		      m->ops[i].field < m->nfields, "%s: op %u", what, i);
}

static void check_invariants(const struct nfsp_decoded_msg *m, size_t len,
			     const char *what)
{
	char buf[1024];
	struct nfsp_schema_node node;
	enum nfsp_schema_resolve res;
	size_t n;

	for (uint32_t i = 0; i < m->nfields; i++) {
		const struct nfsp_semantic_field *f = &m->fields[i];
		const struct nfsp_wire_ref *w = &f->wire;
		uint64_t eend = (uint64_t)w->encoded.off + w->encoded.len;
		const struct nfsp_span *meta[4] = {
			&w->length, &w->count, &w->discriminant, &w->padding
		};

		CHECK(eend <= len, "%s field %u: encoded beyond payload", what,
		      i);
		CHECK(w->value.off >= w->encoded.off &&
		      (uint64_t)w->value.off + w->value.len <= eend,
		      "%s field %u: value outside encoded", what, i);
		for (unsigned r = 0; r < 4; r++) {
			if (!(w->meta & (1u << r)))
				continue;
			CHECK(meta[r]->off >= w->encoded.off &&
			      (uint64_t)meta[r]->off + meta[r]->len <= eend,
			      "%s field %u: metadata %u outside encoded", what,
			      i, r);
		}
		if (f->parent != NFSP_FIELD_NONE) {
			const struct nfsp_span *p =
				&m->fields[f->parent].wire.encoded;

			CHECK(f->parent < i, "%s field %u: parent after child",
			      what, i);
			CHECK(w->encoded.off >= p->off &&
			      eend <= (uint64_t)p->off + p->len,
			      "%s field %u: outside parent", what, i);
		}
		n = nfsp_field_path(m, i, buf, sizeof(buf));
		CHECK(n > 0 && n < sizeof(buf), "%s field %u: path length %zu",
		      what, i, n);
		/* A rule names this field by the same path before any
		 * message exists (schema.h): it must resolve to this node. */
		res = nfsp_schema_resolve(m->schema,
					  m->msg_type == NFSP_RPC_REPLY, buf,
					  &node);
		CHECK(res == NFSP_SCHEMA_FOUND && node.type == f->type &&
		      !(node.flags & NFSP_SN_OPERATION) ==
		      (f->op == NFSP_FIELD_NONE),
		      "%s field %u: %s resolves %d, type %u flags %#x; want "
		      "type %u", what, i, buf, res, res ? 0u : node.type,
		      res ? 0u : node.flags, f->type);
	}
}

static void test_call_golden(void)
{
	struct nfsp_decoded_msg m = {0};
	struct msg c;
	const struct nfsp_semantic_field *f;

	printf("CALL: COMPOUND minor 0, every construct, exact WireRefs\n");
	build_compound_call(&c, 0);
	CHECK(c.n == 184, "vector length %zu", c.n);
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) == NFSP_DECODE_DECODED, "%s at %u: %s",
	      nfsp_decode_strstatus(m.status), m.failure.offset,
	      m.failure.reason ? m.failure.reason : "");
	if (m.status != NFSP_DECODE_DECODED)
		return;
	CHECK(m.schema == nfsp_schema_family_tproto.schemas[0],
	      "schema is not tproto.0");
	CHECK(!strncmp(m.schema->schema_id, "tproto.0/sha256:", 16),
	      "schema_id %s", m.schema->schema_id);
	CHECK(m.has_minor && m.minor_version == 0, "minor");
	CHECK(m.procedure == 1 && !strcmp(m.procedure_name, "COMPOUND"),
	      "procedure");
	CHECK(m.request_context == 0, "request context must be absent in M2");
	check_invariants(&m, c.n, "call");

	EXPECT(&m, "tproto.request.COMPOUND.args", 0, 40, 144, 40, 144, 0);
	EXPECT(&m, "tproto.request.COMPOUND.args.tag", 0, 40, 8, 44, 2, 0);
	f = field(&m, "tproto.request.COMPOUND.args.tag", 0);
	CHECK(f && f->wire.meta == (NFSP_META_LENGTH | NFSP_META_PADDING) &&
	      SPAN(f->wire.length, 40, 4) && SPAN(f->wire.padding, 46, 2),
	      "tag metadata");
	EXPECT(&m, "tproto.request.COMPOUND.args.minorversion", 0, 48, 4, 48,
	       4, 0);
	EXPECT(&m, "tproto.request.COMPOUND.args.argarray", 0, 52, 132, 56,
	       128, 0);
	f = field(&m, "tproto.request.COMPOUND.args.argarray", 0);
	CHECK(f && f->wire.meta == NFSP_META_COUNT &&
	      SPAN(f->wire.count, 52, 4), "argarray count metadata");

	/* Operations: each is a path root, the array position is metadata. */
	CHECK(m.nops == 3, "nops %u", m.nops);
	if (m.nops == 3) {
		CHECK(m.ops[0].opcode == 1 && !strcmp(m.ops[0].name, "PING") &&
		      m.ops[0].sequence_index == 0, "op 0");
		CHECK(m.ops[1].opcode == 2 && !strcmp(m.ops[1].name, "WRITE") &&
		      m.ops[1].sequence_index == 1, "op 1");
		CHECK(m.ops[2].opcode == 3 &&
		      !strcmp(m.ops[2].name, "LOOKUP") &&
		      m.ops[2].sequence_index == 2, "op 2");
		CHECK(!m.ops[0].has_status && !m.ops[1].has_status,
		      "a request operation has no status");
		f = &m.fields[m.ops[1].field];
		CHECK(SPAN(f->wire.encoded, 60, 112) &&
		      SPAN(f->wire.discriminant, 56 + 4, 4) && f->index == 1,
		      "WRITE op node");
	}
	EXPECT(&m, "tproto.request.PING", 0, 56, 4, 60, 0, 0);
	EXPECT(&m, "tproto.request.PING.argop", 0, 56, 4, 56, 4, 1);
	CHECK(!field(&m, "tproto.request.PING.args", 0),
	      "a void arm has no value node");
	EXPECT(&m, "tproto.request.WRITE.argop", 0, 60, 4, 60, 4, 2);
	EXPECT(&m, "tproto.request.WRITE.args", 0, 64, 108, 64, 108, 0);
	EXPECT(&m, "tproto.request.WRITE.args.id", 0, 64, 16, 64, 16, 0);
	EXPECT(&m, "tproto.request.WRITE.args.id.seq", 0, 64, 4, 64, 4, 7);
	EXPECT(&m, "tproto.request.WRITE.args.id.other", 0, 68, 12, 68, 12,
	       0);
	EXPECT(&m, "tproto.request.WRITE.args.offset", 0, 80, 8, 80, 8,
	       0x0000000100000002ull);
	EXPECT(&m, "tproto.request.WRITE.args.delta", 0, 88, 4, 88, 4,
	       (uint64_t)-5);
	EXPECT(&m, "tproto.request.WRITE.args.when", 0, 92, 8, 92, 8,
	       (uint64_t)-2);
	EXPECT(&m, "tproto.request.WRITE.args.sync", 0, 100, 4, 100, 4, 1);
	EXPECT(&m, "tproto.request.WRITE.args.data", 0, 104, 12, 108, 5, 0);
	f = field(&m, "tproto.request.WRITE.args.data", 0);
	CHECK(f && SPAN(f->wire.length, 104, 4) &&
	      SPAN(f->wire.padding, 113, 3), "data metadata");
	EXPECT(&m, "tproto.request.WRITE.args.mask", 0, 116, 12, 120, 8, 0);
	EXPECT(&m, "tproto.request.WRITE.args.mask[]", 0, 120, 4, 120, 4, 0xa);
	EXPECT(&m, "tproto.request.WRITE.args.mask[]", 1, 124, 4, 124, 4, 0xb);
	f = field(&m, "tproto.request.WRITE.args.mask[]", 1);
	CHECK(f && f->index == 1, "element index is metadata");
	EXPECT(&m, "tproto.request.WRITE.args.pair", 0, 128, 32, 128, 32, 0);
	EXPECT(&m, "tproto.request.WRITE.args.pair[]", 1, 144, 16, 144, 16, 0);
	EXPECT(&m, "tproto.request.WRITE.args.pair[].seq", 1, 144, 4, 144, 4,
	       2);
	EXPECT(&m, "tproto.request.WRITE.args.target", 0, 160, 12, 164, 8, 0);
	f = field(&m, "tproto.request.WRITE.args.target", 0);
	CHECK(f && f->wire.meta == NFSP_META_DISCRIMINANT &&
	      SPAN(f->wire.discriminant, 160, 4), "target discriminant");
	EXPECT(&m, "tproto.request.WRITE.args.target.kind", 0, 160, 4, 160, 4,
	       2);
	/* A non-struct arm keeps its declaration name after the branch. */
	EXPECT(&m, "tproto.request.WRITE.args.target.tk_link.link", 0, 164, 8,
	       168, 3, 0);
	EXPECT(&m, "tproto.request.LOOKUP", 0, 172, 12, 176, 8, 0);
	EXPECT(&m, "tproto.request.LOOKUP.args.name", 0, 176, 8, 180, 4, 0);
	f = field(&m, "tproto.request.LOOKUP.args.name", 0);
	CHECK(f && !(f->wire.meta & NFSP_META_PADDING),
	      "aligned opaque has no padding span");
	CHECK(f && f->op == 2, "field belongs to operation 2");
	nfsp_decoded_msg_free(&m);
}

static const struct nfsp_reply_dispatch tproto_dispatch = {
	TPROTO_PROG, 1, 1, 1, 0, NFSP_DISPATCH_TEST_FIXTURE, NFSP_RPC_AUTH_NONE
};

static void test_reply_golden(void)
{
	struct nfsp_decoded_msg m = {0};
	struct msg r;
	const struct nfsp_semantic_field *f;

	printf("REPLY: COMPOUND minor 0 from reply_dispatch, list, arms\n");
	build_compound_reply(&r);
	CHECK(r.n == 156, "vector length %zu", r.n);
	CHECK(run(r.b, r.n, &tproto_dispatch, 1, 0, &m) == NFSP_DECODE_DECODED,
	      "%s at %u: %s", nfsp_decode_strstatus(m.status),
	      m.failure.offset, m.failure.reason ? m.failure.reason : "");
	if (m.status != NFSP_DECODE_DECODED)
		return;
	CHECK(m.dispatch_source == NFSP_DISPATCH_TEST_FIXTURE, "source");
	CHECK(m.schema == nfsp_schema_family_tproto.schemas[0], "schema");
	check_invariants(&m, r.n, "reply");

	EXPECT(&m, "tproto.response.COMPOUND.result.status", 0, 24, 4, 24, 4,
	       0);
	EXPECT(&m, "tproto.response.COMPOUND.result.resarray", 0, 36, 120, 40,
	       116, 0);
	CHECK(m.nops == 5, "nops %u", m.nops);
	if (m.nops == 5) {
		static const uint32_t want_status[5] = { 0, 0, 0, 13, 5 };

		for (unsigned i = 0; i < 5; i++)
			CHECK(m.ops[i].has_status &&
			      m.ops[i].status == want_status[i] &&
			      m.ops[i].sequence_index == i,
			      "op %u status %u/%u", i, m.ops[i].has_status,
			      m.ops[i].status);
	}
	EXPECT(&m, "tproto.response.PING.result.status", 0, 44, 4, 44, 4, 0);
	EXPECT(&m, "tproto.response.WRITE.result", 0, 52, 24, 56, 20, 0);
	EXPECT(&m, "tproto.response.WRITE.result.status", 0, 52, 4, 52, 4, 0);
	/* A struct arm is spliced: result.ok.count, not result.ok.resok.count */
	EXPECT(&m, "tproto.response.WRITE.result.ok", 0, 56, 20, 56, 20, 0);
	EXPECT(&m, "tproto.response.WRITE.result.ok.count", 0, 56, 4, 56, 4, 5);
	EXPECT(&m, "tproto.response.WRITE.result.ok.id.seq", 0, 60, 4, 60, 4,
	       9);
	CHECK(!field(&m, "tproto.response.WRITE.result.ok.resok", 0),
	      "spliced arm name must not appear");

	EXPECT(&m, "tproto.response.LOOKUP.result.ok.entries", 0, 84, 44, 88,
	       40, 0);
	f = field(&m, "tproto.response.LOOKUP.result.ok.entries", 0);
	CHECK(f && SPAN(f->wire.discriminant, 84, 4), "list head word");
	EXPECT(&m, "tproto.response.LOOKUP.result.ok.entries[]", 0, 88, 20, 88,
	       16, 0);
	EXPECT(&m, "tproto.response.LOOKUP.result.ok.entries[]", 1, 108, 20,
	       108, 16, 0);
	f = field(&m, "tproto.response.LOOKUP.result.ok.entries[]", 1);
	CHECK(f && f->index == 1 && SPAN(f->wire.discriminant, 124, 4),
	      "entry[1] index and link word");
	EXPECT(&m, "tproto.response.LOOKUP.result.ok.entries[].cookie", 1, 108,
	       8, 108, 8, 200);
	EXPECT(&m, "tproto.response.LOOKUP.result.ok.entries[].name", 0, 96, 8,
	       100, 1, 0);
	CHECK(!field(&m, "tproto.response.LOOKUP.result.ok.entries[].next", 0),
	      "the list link is not a member");
	EXPECT(&m, "tproto.response.LOOKUP.result.ok.eof", 0, 128, 4, 128, 4,
	       1);
	EXPECT(&m, "tproto.response.WRITE.result.status", 1, 136, 4, 136, 4,
	       13);
	EXPECT(&m, "tproto.response.WRITE.result.tp_err_denied.owner", 0, 140,
	       8, 144, 3, 0);
	/* default: void -- the union and its discriminant only */
	EXPECT(&m, "tproto.response.WRITE.result", 2, 152, 4, 156, 0, 0);
	EXPECT(&m, "tproto.response.WRITE.result.status", 2, 152, 4, 152, 4,
	       5);
	nfsp_decoded_msg_free(&m);
}

static void test_minor_selection(void)
{
	struct nfsp_decoded_msg m = {0};
	struct msg c;
	const char *id0 = nfsp_schema_family_tproto.schemas[0]->schema_id;
	const char *id1 = nfsp_schema_family_tproto.schemas[1]->schema_id;

	printf("CALL: minor version selects the schema; NULL has none\n");
	CHECK(strcmp(id0, id1), "minor schemas share a schema_id");

	/* OP_STAT (4) exists only in minor 1. */
	call_header(&c, TPROTO_PROG, 1, 1);
	wopaque(&c, "");
	w32(&c, 1);
	w32(&c, 1);
	w32(&c, 4);		/* OP_STAT */
	w32(&c, 42);		/* which */
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) == NFSP_DECODE_DECODED,
	      "minor 1 OP_STAT: %s", nfsp_decode_strstatus(m.status));
	CHECK(m.schema && !strcmp(m.schema->schema_id, id1), "schema minor 1");
	EXPECT(&m, "tproto.request.STAT.args.which", 0, 56, 4, 56, 4, 42);

	c.b[47] = 0;		/* minorversion = 0 */
	/* Not an operation of minor 0: knfsd answers it OP_ILLEGAL and stops
	 * there, so it is the failed operation of a partial CALL. */
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) == NFSP_DECODE_PARTIAL &&
	      m.nops == 0 && m.failure.op_index == 0 &&
	      m.failure.opcode == 4 && m.failure.op_offset == 52,
	      "minor 0 OP_STAT must be partial at op 0, got %s",
	      nfsp_decode_strstatus(m.status));
	CHECK(m.failure.offset == 52 && m.failure.reason &&
	      !strcmp(m.failure.reason, "enum value not declared"),
	      "failure %u %s", m.failure.offset,
	      m.failure.reason ? m.failure.reason : "");
	check_partial(&m, c.n, "minor 0 OP_STAT");

	c.b[47] = 7;		/* minorversion = 7 */
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA, "unknown minor: %s",
	      nfsp_decode_strstatus(m.status));
	CHECK(m.has_minor && m.minor_version == 7 && !m.schema,
	      "unknown minor is reported, no schema");

	call_header(&c, TPROTO_PROG, 1, 0);
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA,
	      "NULL of a minor-versioned family: %s",
	      nfsp_decode_strstatus(m.status));

	call_header(&c, TFLAT_PROG, 2, 0);
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) == NFSP_DECODE_DECODED &&
	      m.nfields == 0 && !strcmp(m.procedure_name, "NULL"),
	      "tflat NULL: %s", nfsp_decode_strstatus(m.status));

	call_header(&c, TFLAT_PROG, 3, 0);
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA, "unknown version");
	call_header(&c, TFLAT_PROG, 2, 99);
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA, "unknown procedure");
	nfsp_decoded_msg_free(&m);
}

/* F4: the reply schema comes from reply_dispatch and nothing else. */
static void test_reply_dispatch(void)
{
	struct nfsp_decoded_msg m = {0};
	struct nfsp_reply_dispatch rd;
	struct msg r, c;

	printf("REPLY: reply_dispatch rules (issue #18 F4)\n");
	reply_header(&r, 0);
	w32(&r, 0);		/* 24 status TF_OK */
	w32(&r, 1);		/* 28 eof */
	wopaque(&r, "DATA");	/* 32 len, 36..39 */

	CHECK(run(r.b, r.n, NULL, 1, 0, &m) ==
	      NFSP_DECODE_TRANSACTION_CONTEXT_MISSING && m.nfields == 0 &&
	      !m.schema, "no dispatch: %s", nfsp_decode_strstatus(m.status));

	rd = (struct nfsp_reply_dispatch){ TFLAT_PROG, 2, 6, 0, 0,
					   NFSP_DISPATCH_TEST_FIXTURE,
					   NFSP_RPC_AUTH_NONE };
	CHECK(run(r.b, r.n, &rd, 0, 0, &m) ==
	      NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
	      "fixture dispatch outside tests: %s",
	      nfsp_decode_strstatus(m.status));
	rd.source = NFSP_DISPATCH_NONE;
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) ==
	      NFSP_DECODE_TRANSACTION_CONTEXT_MISSING, "source none");

	rd.source = NFSP_DISPATCH_TRANSACTION_ENTRY;
	CHECK(run(r.b, r.n, &rd, 0, 0, &m) == NFSP_DECODE_DECODED,
	      "READ dispatch: %s", nfsp_decode_strstatus(m.status));
	EXPECT(&m, "tflat.response.READ.result.ok.data", 0, 32, 8, 36, 4, 0);
	CHECK(m.dispatch_source == NFSP_DISPATCH_TRANSACTION_ENTRY &&
	      m.procedure == 6, "dispatch echoed");
	check_invariants(&m, r.n, "tflat reply");

	/* Same bytes, GETSIZE dispatch: decoded as GETSIZE_res
	 * {status, unsigned hyper size} the bytes run out of shape. */
	rd.procedure = 7;
	CHECK(run(r.b, r.n, &rd, 0, 0, &m) == NFSP_DECODE_MALFORMED &&
	      m.failure.offset == 36 && m.nfields == 0,
	      "GETSIZE dispatch on READ bytes: %s at %u",
	      nfsp_decode_strstatus(m.status), m.failure.offset);

	/* A minor-versioned family needs the minor in the dispatch. */
	build_compound_reply(&r);
	rd = tproto_dispatch;
	rd.has_minor = 0;
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) ==
	      NFSP_DECODE_DISPATCH_INCOMPLETE && m.nfields == 0,
	      "no minor: %s", nfsp_decode_strstatus(m.status));
	rd.has_minor = 1;
	rd.minor_version = 3;
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA, "dispatch minor 3");
	rd.minor_version = 1;
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) == NFSP_DECODE_DECODED &&
	      !strcmp(m.schema->schema_id,
		      nfsp_schema_family_tproto.schemas[1]->schema_id),
	      "dispatch minor 1 picks tproto.1");
	rd.procedure = 5;
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA, "dispatch procedure 5");

	/* No result exists on a non-SUCCESS arm. */
	rd = (struct nfsp_reply_dispatch){ TFLAT_PROG, 2, 6, 0, 0,
					   NFSP_DISPATCH_TRANSACTION_ENTRY,
					   NFSP_RPC_AUTH_NONE };
	reply_header(&r, 3);	/* PROC_UNAVAIL */
	CHECK(run(r.b, r.n, &rd, 0, 0, &m) == NFSP_DECODE_DECODED &&
	      m.nfields == 0 && !strcmp(m.procedure_name, "READ"),
	      "PROC_UNAVAIL: %s", nfsp_decode_strstatus(m.status));
	w32(&r, 0);
	CHECK(run(r.b, r.n, &rd, 0, 0, &m) == NFSP_DECODE_MALFORMED,
	      "bytes after PROC_UNAVAIL");
	r.n = 0;
	w32(&r, 0xc0ffee01);
	w32(&r, 1);
	w32(&r, 1);		/* MSG_DENIED */
	w32(&r, 1);		/* AUTH_ERROR */
	w32(&r, 1);		/* AUTH_BADCRED */
	CHECK(run(r.b, r.n, &rd, 0, 0, &m) == NFSP_DECODE_DECODED &&
	      m.nfields == 0, "MSG_DENIED: %s",
	      nfsp_decode_strstatus(m.status));

	/* A CALL ignores any dispatch: it carries its own procedure. */
	call_header(&c, TFLAT_PROG, 2, 7);
	wopaque(&c, "fh");
	rd.procedure = 6;
	CHECK(run(c.b, c.n, &rd, 0, 0, &m) == NFSP_DECODE_DECODED,
	      "GETSIZE call: %s", nfsp_decode_strstatus(m.status));
	/* A non-struct argument is the args node itself. */
	EXPECT(&m, "tflat.request.GETSIZE.args", 0, 40, 8, 44, 2, 0);
	nfsp_decoded_msg_free(&m);
}

/* PR #25 review P2: an operation's status is the value its result starts
 * with.  STAT_res in minor 1 is { union on tp_status first; tp_status later;
 * }, so decoding the nested union must not let `later` overwrite the status.
 */
static void test_status_after_nested_union(void)
{
	struct nfsp_decoded_msg m = {0};
	struct nfsp_reply_dispatch rd = tproto_dispatch;
	struct msg r;

	printf("REPLY: operation status stays the result's first value past a "
	       "nested union\n");
	rd.minor_version = 1;
	reply_header(&r, 0);
	w32(&r, 0);		/* 24 COMPOUND status TP_OK */
	wopaque(&r, "");	/* 28 tag */
	w32(&r, 1);		/* 32 resarray count */
	w32(&r, 4);		/* 36 OP_STAT */
	w32(&r, 0);		/* 40 first.status TP_OK */
	w32(&r, 7);		/* 44 first.ok.value */
	w32(&r, 5);		/* 48 later TP_ERR_IO */
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) == NFSP_DECODE_DECODED,
	      "STAT reply: %s", nfsp_decode_strstatus(m.status));
	CHECK(m.nops == 1 && m.ops[0].has_status && m.ops[0].status == 0,
	      "op status %u/%u, want the value at the start, 0",
	      m.nops ? m.ops[0].has_status : 0, m.nops ? m.ops[0].status : 0);
	EXPECT(&m, "tproto.response.STAT.result.first.status", 0, 40, 4, 40, 4,
	       0);
	EXPECT(&m, "tproto.response.STAT.result.first.ok.value", 0, 44, 4, 44,
	       4, 7);
	EXPECT(&m, "tproto.response.STAT.result.later", 0, 48, 4, 48, 4, 5);
	nfsp_decoded_msg_free(&m);
}

/* PR #25 re-review: TAGS_res and NOTES_res (minor 1) start with a count and
 * a list link, not a tp_status.  So neither operation has a status, empty or
 * not; before, an empty array or list made the later member the status and a
 * non-empty one did not.  The status member still decodes at its own path. */
static void test_status_at_result_start(void)
{
	struct nfsp_decoded_msg m = {0};
	struct nfsp_reply_dispatch rd = tproto_dispatch;
	struct msg r;

	printf("REPLY: a result that starts with a count or a link has no "
	       "status\n");
	rd.minor_version = 1;
	reply_header(&r, 0);
	w32(&r, 0);		/* 24 COMPOUND status TP_OK */
	wopaque(&r, "");	/* 28 tag */
	w32(&r, 4);		/* 32 resarray count */
	w32(&r, 5);		/* 36 OP_TAGS */
	w32(&r, 0);		/* 40 tags count 0 */
	w32(&r, 5);		/* 44 status TP_ERR_IO */
	w32(&r, 5);		/* 48 OP_TAGS */
	w32(&r, 1);		/* 52 tags count 1 */
	w32(&r, 7);		/* 56 tags[0] */
	w32(&r, 5);		/* 60 status TP_ERR_IO */
	w32(&r, 6);		/* 64 OP_NOTES */
	w32(&r, 0);		/* 68 notes: none */
	w32(&r, 13);		/* 72 status TP_ERR_DENIED */
	w32(&r, 6);		/* 76 OP_NOTES */
	w32(&r, 1);		/* 80 notes present */
	w32(&r, 9);		/* 84 notes[0].n */
	w32(&r, 0);		/* 88 notes[0] link: end */
	w32(&r, 13);		/* 92 status TP_ERR_DENIED */
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) == NFSP_DECODE_DECODED &&
	      m.nops == 4, "TAGS/NOTES reply: %s, %u ops",
	      nfsp_decode_strstatus(m.status), m.nops);
	for (uint32_t i = 0; i < m.nops; i++)
		CHECK(!m.ops[i].has_status, "op %u (%s) has status %u", i,
		      m.ops[i].name, m.ops[i].status);
	EXPECT(&m, "tproto.response.TAGS.result.status", 0, 44, 4, 44, 4, 5);
	EXPECT(&m, "tproto.response.TAGS.result.status", 1, 60, 4, 60, 4, 5);
	EXPECT(&m, "tproto.response.NOTES.result.status", 0, 72, 4, 72, 4, 13);
	EXPECT(&m, "tproto.response.NOTES.result.status", 1, 92, 4, 92, 4, 13);
	check_invariants(&m, r.n, "tags/notes reply");
	nfsp_decoded_msg_free(&m);
}

/* A CALL with an RPCSEC_GSS credential (rpc_gss_cred_vers_1_t, RFC 2203
 * §5) and verifier; the body starts at 72. */
static void gss_call_header(struct msg *m, uint32_t prog, uint32_t vers,
			    uint32_t proc, uint32_t service)
{
	m->n = 0;
	w32(m, 0xc0ffee01);		/*  0 xid */
	w32(m, 0);			/*  4 CALL */
	w32(m, 2);			/*  8 rpcvers */
	w32(m, prog);			/* 12 */
	w32(m, vers);			/* 16 */
	w32(m, proc);			/* 20 */
	w32(m, NFSP_RPC_RPCSEC_GSS);	/* 24 cred flavor */
	w32(m, 24);			/* 28 cred length */
	w32(m, 1);			/* 32 version */
	w32(m, 0);			/* 36 gss_proc RPCSEC_GSS_DATA */
	w32(m, 1);			/* 40 seq_num */
	w32(m, service);		/* 44 none 1, integrity 2, privacy 3 */
	wopaque(m, "hndl");		/* 48 handle */
	w32(m, NFSP_RPC_RPCSEC_GSS);	/* 56 verf flavor */
	wopaque(m, "MIC-MIC!");		/* 60 checksum */
}					/* 72 body */

/* PR #25 re-review P2: under RPCSEC_GSS integrity or privacy the body is an
 * RFC 2203 wrapper.  Here rpc_gss_priv_data {opaque databody_priv<>} also
 * fits GETSIZE's tf_handle (opaque<8>), which used to decode as the file
 * handle.  Nothing GSS is decoded, whatever the service. */
static void test_rpcsec_gss(void)
{
	struct nfsp_decoded_msg m = {0};
	struct nfsp_reply_dispatch rd;
	struct msg c, body, r;

	printf("RPCSEC_GSS: a protected body is not decoded\n");
	for (uint32_t service = 1; service <= 3; service++) {
		gss_call_header(&c, TFLAT_PROG, 2, 7, service);
		wopaque(&c, "ciphertx");	/* 72 len, 76..83 */
		CHECK(run(c.b, c.n, NULL, 0, 0, &m) ==
		      NFSP_DECODE_UNSUPPORTED_SCHEMA && m.nfields == 0,
		      "GSS service %u CALL: %s", service,
		      nfsp_decode_strstatus(m.status));
	}
	call_header(&c, TFLAT_PROG, 2, 7);	/* the same body, AUTH_NONE */
	wopaque(&c, "ciphertx");
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) == NFSP_DECODE_DECODED,
	      "AUTH_NONE control: %s", nfsp_decode_strstatus(m.status));
	EXPECT(&m, "tflat.request.GETSIZE.args", 0, 40, 12, 44, 8, 0);

	/* A minor-versioned family refuses before reading the minor. */
	build_compound_call(&body, 0);
	gss_call_header(&c, TPROTO_PROG, 1, 1, 2);
	memcpy(c.b + c.n, body.b + 40, body.n - 40);
	c.n += body.n - 40;
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA && m.nfields == 0 &&
	      !m.has_minor, "GSS COMPOUND CALL: %s",
	      nfsp_decode_strstatus(m.status));

	/* REPLY: GETSIZE_res {status, unsigned hyper size}. */
	rd = (struct nfsp_reply_dispatch){ TFLAT_PROG, 2, 7, 0, 0,
					   NFSP_DISPATCH_TEST_FIXTURE,
					   NFSP_RPC_RPCSEC_GSS };
	reply_header(&r, 0);
	w32(&r, 0);		/* 24 status TF_OK */
	w64(&r, 4096);		/* 28 size */
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) == NFSP_DECODE_UNSUPPORTED_SCHEMA &&
	      m.nfields == 0, "REPLY to a GSS CALL: %s",
	      nfsp_decode_strstatus(m.status));
	rd.cred_flavor = NFSP_RPC_AUTH_SYS;
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) == NFSP_DECODE_DECODED,
	      "AUTH_SYS control: %s", nfsp_decode_strstatus(m.status));
	EXPECT(&m, "tflat.response.GETSIZE.result.size", 0, 28, 8, 28, 8,
	       4096);
	r.b[15] = (uint8_t)NFSP_RPC_RPCSEC_GSS;	/* 12 the REPLY's own verifier */
	CHECK(run(r.b, r.n, &rd, 1, 0, &m) == NFSP_DECODE_UNSUPPORTED_SCHEMA &&
	      m.nfields == 0, "GSS verifier on the REPLY: %s",
	      nfsp_decode_strstatus(m.status));
	nfsp_decoded_msg_free(&m);
}

/* PR #25 review P3: path lookup has no length limit of its own.  A message
 * is built by hand with components long enough to pass 512 characters. */
static void test_long_paths(void)
{
	static char longa[400], longb[400];
	struct nfsp_semantic_field f[3];
	struct nfsp_decoded_msg m;
	char small[10];
	char *full;
	size_t len;

	printf("paths: formatting and lookup beyond 512 characters\n");
	memset(longa, 'a', sizeof(longa) - 1);
	memset(longb, 'b', sizeof(longb) - 1);
	memset(f, 0, sizeof(f));
	memset(&m, 0, sizeof(m));
	f[0].parent = NFSP_FIELD_NONE;
	f[0].root = "LONG";
	f[0].component = longa;
	f[1].parent = 0;
	f[1].component = longb;
	f[2].parent = 1;
	f[2].component = "[]";
	m.schema = nfsp_schema_family_tproto.schemas[0];
	m.msg_type = NFSP_RPC_CALL;
	m.fields = f;
	m.nfields = 3;

	len = nfsp_field_path(&m, 2, NULL, 0);
	CHECK(len == strlen("tproto.request.LONG.") + 399 + 1 + 399 + 2,
	      "path length %zu", len);
	CHECK(nfsp_field_path(&m, 2, small, sizeof(small)) == len &&
	      strlen(small) == sizeof(small) - 1, "truncated formatting");
	full = malloc(len + 1);
	if (!full) {
		CHECK(0, "malloc");
		return;
	}
	nfsp_field_path(&m, 2, full, len + 1);
	CHECK(nfsp_field_find(&m, full, 0) == 2, "element path not found");
	full[len - 2] = '\0';		/* drop "[]": the parent's path */
	CHECK(nfsp_field_find(&m, full, 0) == 1, "member path not found");
	full[len - 3] = '\0';		/* a proper prefix matches nothing */
	CHECK(nfsp_field_find(&m, full, 0) == NFSP_FIELD_NONE,
	      "prefix matched");
	CHECK(nfsp_field_find(&m, "tproto.request.LONG", 0) ==
	      NFSP_FIELD_NONE, "root without its component matched");
	CHECK(nfsp_field_find(&m, NULL, 0) == NFSP_FIELD_NONE, "NULL path");
	free(full);
}

/* Oracle 2: every proper prefix fails.  It leaves nothing behind, except a
 * CALL cut inside an operation whose opcode word is present: that is
 * partial, with the operations before it (knfsd runs them). */
static void truncate_all(const struct msg *full,
			 const struct nfsp_reply_dispatch *rd, uint32_t body,
			 const char *what)
{
	struct nfsp_decoded_msg m = {0};
	unsigned bad = 0;

	for (size_t n = body; n < full->n; n++) {
		enum nfsp_decode_status st =
			run(full->b, n, rd, 1, 0, &m);

		if (st == NFSP_DECODE_PARTIAL && !rd) {
			check_partial(&m, n, what);
			continue;
		}
		if (st == NFSP_DECODE_DECODED || m.nfields || m.nops) {
			if (!bad++)
				printf("  first bad prefix %zu: %s\n", n,
				       nfsp_decode_strstatus(st));
		}
	}
	CHECK(bad == 0, "%s: %u prefixes decoded or kept fields", what, bad);
	nfsp_decoded_msg_free(&m);
}

static void test_truncation(void)
{
	struct msg c, r;

	printf("truncation: every prefix of every golden message\n");
	build_compound_call(&c, 0);
	truncate_all(&c, NULL, 40, "compound call");
	build_compound_reply(&r);
	truncate_all(&r, &tproto_dispatch, 24, "compound reply");
}

static enum nfsp_decode_status mutate_call(size_t at, uint32_t v,
					   struct nfsp_decoded_msg *m)
{
	struct msg c;

	build_compound_call(&c, 0);
	c.b[at] = (uint8_t)(v >> 24);
	c.b[at + 1] = (uint8_t)(v >> 16);
	c.b[at + 2] = (uint8_t)(v >> 8);
	c.b[at + 3] = (uint8_t)v;
	return run(c.b, c.n, NULL, 0, 0, m);
}

static void expect_refusal(size_t at, uint32_t v, enum nfsp_decode_status st,
			   uint32_t fail_off, const char *reason)
{
	struct nfsp_decoded_msg m = {0};

	CHECK(mutate_call(at, v, &m) == st && m.nfields == 0 && m.nops == 0 &&
	      m.failure.offset == fail_off && m.failure.reason &&
	      !strcmp(m.failure.reason, reason),
	      "word %zu = %#x: %s at %u (%s), want %s at %u (%s)", at, v,
	      nfsp_decode_strstatus(m.status), m.failure.offset,
	      m.failure.reason ? m.failure.reason : "",
	      nfsp_decode_strstatus(st), fail_off, reason);
	nfsp_decoded_msg_free(&m);
}

/* Word `at` of the golden CALL set to v fails operation op_index, which
 * starts at op_offset: partial, with the operations before it intact. */
static void expect_partial(size_t at, uint32_t v, uint32_t fail_off,
			   const char *reason, uint32_t op_index,
			   uint32_t op_offset)
{
	struct nfsp_decoded_msg m = {0}, full = {0};
	struct msg c;
	char what[64];

	snprintf(what, sizeof(what), "word %zu = %#x", at, v);
	CHECK(mutate_call(at, v, &m) == NFSP_DECODE_PARTIAL &&
	      m.failure.offset == fail_off && m.failure.reason &&
	      !strcmp(m.failure.reason, reason) &&
	      m.failure.op_index == op_index &&
	      m.failure.op_offset == op_offset,
	      "%s: %s at %u (%s), op %u at %u; want partial at %u (%s), "
	      "op %u at %u", what, nfsp_decode_strstatus(m.status),
	      m.failure.offset, m.failure.reason ? m.failure.reason : "",
	      m.failure.op_index, m.failure.op_offset, fail_off, reason,
	      op_index, op_offset);
	if (m.status != NFSP_DECODE_PARTIAL) {
		nfsp_decoded_msg_free(&m);
		return;
	}
	check_partial(&m, 184, what);
	/* The kept prefix is the golden decode's prefix, span for span. */
	build_compound_call(&c, 0);
	run(c.b, c.n, NULL, 0, 0, &full);
	for (uint32_t i = 0; i < m.nfields; i++) {
		const struct nfsp_semantic_field *a = &m.fields[i],
						 *b = &full.fields[i];

		if (a->wire.encoded.off + a->wire.encoded.len > op_offset ||
		    b->wire.encoded.off + b->wire.encoded.len <= op_offset)
			CHECK(!memcmp(&a->wire, &b->wire, sizeof(a->wire)) &&
			      a->value == b->value, "%s: field %u differs",
			      what, i);
	}
	CHECK(m.failure.opcode == (op_offset == at ? v :
				   full.ops[op_index].opcode),
	      "%s: opcode %u", what, m.failure.opcode);
	nfsp_decoded_msg_free(&full);
	nfsp_decoded_msg_free(&m);
}

static void test_malformed(void)
{
	struct nfsp_decoded_msg m = {0};
	struct msg c;

	printf("malformed: deterministic refusals with location\n");
	/* Outside any operation: the whole CALL is refused. */
	expect_refusal(40, 0x7fffffff, NFSP_DECODE_MALFORMED, 40,
		       "length exceeds remaining record");	/* tag */
	/* The operation count is not checked as a whole: three operations
	 * decode and the fourth opcode word is missing (knfsd refuses). */
	expect_refusal(52, 1000, NFSP_DECODE_TRUNCATED, 184,
		       "record ends here");
	/* Inside an operation: the operations before it stay (partial). */
	expect_partial(176, 17, 176, "length exceeds bound", 2, 172);
	expect_partial(176, 8, 176, "length exceeds remaining record", 2,
		       172);					/* tp_name<16> */
	expect_partial(104, 0x7fffffff, 104,
		       "length exceeds remaining record", 1, 60);
	expect_partial(116, 5, 116, "count exceeds bound", 1, 60);
	expect_partial(160, 9, 160, "enum value not declared", 1, 60);
	expect_partial(160, 0xffffffffu, 160, "enum value not declared", 1,
		       60);					/* tp_kind */
	expect_partial(60, 99, 60, "enum value not declared", 1, 60);
	expect_partial(56, 0, 56, "enum value not declared", 0, 56);

	build_compound_reply(&c);
	c.b[107] = 2;		/* entry[0] link = 2 */
	CHECK(run(c.b, c.n, &tproto_dispatch, 1, 0, &m) ==
	      NFSP_DECODE_MALFORMED && m.failure.offset == 104,
	      "list link 2: %s at %u", nfsp_decode_strstatus(m.status),
	      m.failure.offset);
	build_compound_reply(&c);
	c.b[87] = 3;		/* entries head = 3 */
	CHECK(run(c.b, c.n, &tproto_dispatch, 1, 0, &m) ==
	      NFSP_DECODE_MALFORMED && m.failure.offset == 84,
	      "list head 3: %s", nfsp_decode_strstatus(m.status));
	nfsp_decoded_msg_free(&m);
}

/* Where knfsd reads a word as a plain integer, skips padding unread or
 * ignores what follows the body, the decoder decodes and flags instead of
 * refusing (design 02 §15).  Spans are the same as without the oddity. */
static void expect_lenient(size_t at, uint32_t v, const char *path,
			   uint8_t flag, uint64_t value)
{
	struct nfsp_decoded_msg m = {0};
	const struct nfsp_semantic_field *f;

	if (mutate_call(at, v, &m) != NFSP_DECODE_DECODED) {
		CHECK(0, "word %zu = %#x: %s at %u (%s)", at, v,
		      nfsp_decode_strstatus(m.status), m.failure.offset,
		      m.failure.reason ? m.failure.reason : "");
		nfsp_decoded_msg_free(&m);
		return;
	}
	f = field(&m, path, 0);
	CHECK(f && f->flags == flag && f->value == value,
	      "%s: flags %#x value %llu", path, f ? f->flags : 0xffu,
	      f ? (unsigned long long)f->value : 0ull);
	for (uint32_t i = 0; i < m.nfields; i++)
		CHECK(&m.fields[i] == f || !m.fields[i].flags,
		      "field %u flagged too", i);
	CHECK(m.nops == 3 && m.trailing.len == 0, "ops %u trailing %u",
	      m.nops, m.trailing.len);
	nfsp_decoded_msg_free(&m);
}

static void test_lenient(void)
{
	struct nfsp_decoded_msg m = {0};
	const struct nfsp_semantic_field *f;
	struct msg c;

	printf("lenient CALL: out-of-domain words, padding, trailing bytes\n");
	expect_lenient(100, 2, "tproto.request.WRITE.args.sync",
		       NFSP_FF_UNDECLARED, 2);
	expect_lenient(100, 0xffffffffu, "tproto.request.WRITE.args.sync",
		       NFSP_FF_UNDECLARED, 0xffffffffu);
	expect_lenient(112, 0x6f000100u, "tproto.request.WRITE.args.data",
		       NFSP_FF_PAD_NONZERO, 0);
	expect_lenient(44, 0x61620001u, "tproto.request.COMPOUND.args.tag",
		       NFSP_FF_PAD_NONZERO, 0);

	build_compound_call(&c, 0);
	w32(&c, 0);
	w32(&c, 0xdeadbeef);
	if (run(c.b, c.n, NULL, 0, 0, &m) == NFSP_DECODE_DECODED) {
		CHECK(m.trailing.off == 184 && m.trailing.len == 8 &&
		      m.nops == 3, "trailing %u+%u, %u ops", m.trailing.off,
		      m.trailing.len, m.nops);
		f = field(&m, "tproto.request.COMPOUND.args", 0);
		CHECK(f && f->wire.encoded.off + f->wire.encoded.len == 184,
		      "the body still ends at 184");
	} else {
		CHECK(0, "trailing bytes: %s", nfsp_decode_strstatus(m.status));
	}

	/* A REPLY is never lenient (§14: a strict result keeps a wrong
	 * dispatch from decoding). */
	build_compound_reply(&c);
	c.b[27] = 1;		/* COMPOUND status 1: not a tp_status */
	CHECK(run(c.b, c.n, &tproto_dispatch, 1, 0, &m) ==
	      NFSP_DECODE_MALFORMED && m.failure.offset == 24,
	      "undeclared reply status: %s", nfsp_decode_strstatus(m.status));
	build_compound_reply(&c);
	w32(&c, 0);
	CHECK(run(c.b, c.n, &tproto_dispatch, 1, 0, &m) ==
	      NFSP_DECODE_MALFORMED && m.failure.offset == 156 &&
	      m.trailing.len == 0, "reply trailing bytes: %s",
	      nfsp_decode_strstatus(m.status));
	nfsp_decoded_msg_free(&m);
}

static void test_resource_limit(void)
{
	struct nfsp_decoded_msg m = {0};
	struct msg c;

	printf("resource limit: field cap fails closed\n");
	build_compound_call(&c, 0);
	CHECK(run(c.b, c.n, NULL, 0, 10, &m) == NFSP_DECODE_RESOURCE_LIMIT &&
	      m.nfields == 0 && m.nops == 0,
	      "max_fields 10: %s", nfsp_decode_strstatus(m.status));
	CHECK(run(c.b, c.n, NULL, 0, 0, &m) == NFSP_DECODE_DECODED,
	      "the reused message decodes again after a refusal");
	nfsp_decoded_msg_free(&m);
}

static int is_mutable_leaf(const struct nfsp_decoded_msg *m, uint32_t i)
{
	const struct nfsp_semantic_field *f = &m->fields[i];
	char buf[256];

	switch (f->kind) {
	case NFSP_XK_INT:
	case NFSP_XK_UINT:
	case NFSP_XK_HYPER:
	case NFSP_XK_UHYPER:
	case NFSP_XK_OPAQUE_FIXED:
	case NFSP_XK_OPAQUE_VAR:
	case NFSP_XK_STRING:
		break;
	default:
		return 0;	/* enum/bool/discriminant: validity changes */
	}
	if (!f->wire.value.len)
		return 0;
	nfsp_field_path(m, i, buf, sizeof(buf));
	/* The minor version selects the schema, so it is not a leaf value. */
	return !strstr(buf, ".minorversion");
}

/* Oracle 7: change one field's value bytes; nothing else may move. */
static void address_oracle(const struct msg *base,
			   const struct nfsp_reply_dispatch *rd,
			   unsigned leaves, const char *what)
{
	struct nfsp_decoded_msg a = {0}, b = {0};
	unsigned tried = 0;

	if (run(base->b, base->n, rd, 1, 0, &a) != NFSP_DECODE_DECODED) {
		CHECK(0, "%s: base does not decode", what);
		return;
	}
	for (uint32_t i = 0; i < a.nfields; i++) {
		struct msg mut = *base;
		const struct nfsp_span *v = &a.fields[i].wire.value;
		int same = 1;

		if (!is_mutable_leaf(&a, i))
			continue;
		tried++;
		for (uint32_t k = 0; k < v->len; k++)
			mut.b[v->off + k] ^= 0x5a;
		if (run(mut.b, mut.n, rd, 1, 0, &b) != NFSP_DECODE_DECODED ||
		    b.nfields != a.nfields) {
			CHECK(0, "%s field %u: mutated message %s", what, i,
			      nfsp_decode_strstatus(b.status));
			continue;
		}
		for (uint32_t j = 0; j < a.nfields; j++) {
			const struct nfsp_semantic_field *x = &a.fields[j];
			const struct nfsp_semantic_field *y = &b.fields[j];

			if (memcmp(&x->wire, &y->wire, sizeof(x->wire)) ||
			    x->parent != y->parent || x->type != y->type ||
			    x->component != y->component ||
			    x->root != y->root || x->index != y->index ||
			    (j != i && x->value != y->value))
				same = 0;
		}
		if (a.fields[i].kind != NFSP_XK_OPAQUE_FIXED &&
		    a.fields[i].kind != NFSP_XK_OPAQUE_VAR &&
		    a.fields[i].kind != NFSP_XK_STRING &&
		    a.fields[i].value == b.fields[i].value)
			same = 0;
		CHECK(same, "%s field %u: mutation moved another field", what,
		      i);
	}
	CHECK(tried == leaves, "%s: %u leaves tried, want %u", what, tried,
	      leaves);
	nfsp_decoded_msg_free(&a);
	nfsp_decoded_msg_free(&b);
}

static void test_address_oracle(void)
{
	struct msg c, r;

	printf("mutation-address oracle: one field changes, nothing moves\n");
	build_compound_call(&c, 0);
	address_oracle(&c, NULL, 15, "call");
	build_compound_reply(&r);
	address_oracle(&r, &tproto_dispatch, 9, "reply");
}

/* Hostile input smoke: random byte edits of the golden messages under the
 * sanitizer build.  Whatever the status, nothing may read out of bounds, and
 * any message that still decodes must satisfy the structural invariants. */
static void test_random_edits(void)
{
	struct nfsp_decoded_msg m = {0};
	uint64_t x = 0x9e3779b97f4a7c15ull;
	unsigned decoded = 0, partial = 0, refused = 0;
	enum nfsp_decode_status st;

	printf("random edits: 20000 mutated messages, invariants hold\n");
	for (unsigned it = 0; it < 20000; it++) {
		struct msg v;
		const struct nfsp_reply_dispatch *rd = NULL;
		unsigned edits;

		if (it & 1) {
			build_compound_reply(&v);
			rd = &tproto_dispatch;
		} else {
			build_compound_call(&v, (it >> 1) & 1);
		}
		x ^= x << 13, x ^= x >> 7, x ^= x << 17;
		edits = 1 + (unsigned)(x % 4);
		for (unsigned e = 0; e < edits; e++) {
			size_t at;

			x ^= x << 13, x ^= x >> 7, x ^= x << 17;
			/* Leave the RPC header alone: its decoder has its own
			 * tests, and an invalid one never reaches this one. */
			at = 24 + (size_t)(x % (v.n - 24));
			v.b[at] = (uint8_t)(x >> 32);
		}
		st = run(v.b, v.n, rd, 1, 0, &m);
		if (st == NFSP_DECODE_DECODED) {
			decoded++;
			check_invariants(&m, v.n, "random edit");
		} else if (st == NFSP_DECODE_PARTIAL) {
			partial++;
			CHECK(!rd, "partial REPLY");
			check_partial(&m, v.n, "random edit");
		} else {
			refused++;
			CHECK(m.nfields == 0 && m.nops == 0,
			      "refused message kept fields");
		}
	}
	printf("  %u decoded, %u partial, %u refused\n", decoded, partial,
	       refused);
	CHECK(decoded > 0 && refused > 0, "edits did not exercise both paths");
	nfsp_decoded_msg_free(&m);
}

/* A table whose CALL reaches a response operation union is refused, not
 * read as a second request operation list.  The normalizer never emits
 * one (test_normalize: test_operation_union_of_the_other_direction). */
/* Copy of tproto minor `k` whose COMPOUND arguments are {tag, argarray,
 * minorversion}: an operation array before the minor-version selector, a
 * layout the normalizer accepts.  Returns 0 on a table it cannot copy. */
static int reorder_selector(int k, struct nfsp_protocol_schema *sch,
			    struct nfsp_schema_field *fields, size_t cap)
{
	const struct nfsp_protocol_schema *o =
		nfsp_schema_family_tproto.schemas[k];
	const struct nfsp_schema_proc *pr = nfsp_schema_proc(o, 1);
	const struct nfsp_schema_type *args;
	size_t n = 0;
	struct nfsp_schema_field t;

	if (!pr || o->selector_field != 1)
		return 0;
	for (uint32_t i = 0; i < o->ntypes; i++)
		if (o->types[i].kind == NFSP_XK_STRUCT &&
		    o->types[i].first + o->types[i].count > n)
			n = o->types[i].first + o->types[i].count;
	if (n > cap)
		return 0;
	memcpy(fields, o->fields, n * sizeof(fields[0]));
	args = &o->types[pr->arg];
	t = fields[args->first + 1];
	fields[args->first + 1] = fields[args->first + 2];
	fields[args->first + 2] = t;
	*sch = *o;
	sch->fields = fields;
	sch->selector_field = 2;
	return 1;
}

/* A failure while reading the minor-version prefix is no partial: no
 * schema is chosen yet (PR #29 review).  The body decode, once a schema is
 * chosen, still is. */
static void test_ops_before_selector(void)
{
	static struct nfsp_schema_field f0[256], f1[256];
	static struct nfsp_protocol_schema s0, s1;
	const struct nfsp_protocol_schema *schs[2] = { &s0, &s1 };
	struct nfsp_schema_family fam = nfsp_schema_family_tproto;
	const struct nfsp_schema_family *f[1] = { &fam };
	struct nfsp_rpc_envelope env;
	struct nfsp_decode_input in;
	struct nfsp_decoded_msg m = {0};
	struct msg c;

	printf("tables: an operation array before the minor selector\n");
	CHECK(reorder_selector(0, &s0, f0, 256) &&
	      reorder_selector(1, &s1, f1, 256), "cannot copy tproto");
	fam.schemas = schs;
	fam.nschemas = 2;
	memset(&in, 0, sizeof(in));
	in.rpc = &env;

	call_header(&c, TPROTO_PROG, 1, 1);
	w32(&c, 0);		/* 40 tag */
	w32(&c, 1);		/* 44 argarray count */
	w32(&c, 1);		/* 48 OP_PING */
	w32(&c, 0);		/* 52 minorversion */
	in.payload = c.b, in.len = c.n;
	nfsp_rpc_decode(c.b, c.n, &env);
	CHECK(nfsp_nfs_decode(f, 1, &in, &m) == NFSP_DECODE_DECODED &&
	      m.schema == &s0 && m.nops == 1, "reordered PING: %s",
	      nfsp_decode_strstatus(m.status));

	call_header(&c, TPROTO_PROG, 1, 1);
	w32(&c, 0);		/* 40 tag */
	w32(&c, 2);		/* 44 argarray count */
	w32(&c, 1);		/* 48 OP_PING */
	w32(&c, 2);		/* 52 OP_WRITE, arguments missing */
	in.payload = c.b, in.len = c.n;
	nfsp_rpc_decode(c.b, c.n, &env);
	CHECK(nfsp_nfs_decode(f, 1, &in, &m) == NFSP_DECODE_TRUNCATED &&
	      !m.schema && m.nfields == 0 && m.nops == 0,
	      "probe cut in WRITE: %s, %u fields",
	      nfsp_decode_strstatus(m.status), m.nfields);
	c.b[55] = 99;		/* 52: undeclared opcode */
	nfsp_rpc_decode(c.b, c.n, &env);
	CHECK(nfsp_nfs_decode(f, 1, &in, &m) == NFSP_DECODE_MALFORMED &&
	      !m.schema && m.nfields == 0 && m.nops == 0,
	      "probe at opcode 99: %s, %u fields",
	      nfsp_decode_strstatus(m.status), m.nfields);
	nfsp_decoded_msg_free(&m);
}

static void test_other_direction_op_union(void)
{
	const struct nfsp_protocol_schema *orig =
		nfsp_schema_family_tproto.schemas[0];
	static struct nfsp_schema_type types[64];
	static struct nfsp_protocol_schema sch;
	const struct nfsp_protocol_schema *schs[1] = { &sch };
	struct nfsp_schema_family fam = nfsp_schema_family_tproto;
	const struct nfsp_schema_family *f[1] = { &fam };
	struct nfsp_rpc_envelope env;
	struct nfsp_decode_input in;
	struct nfsp_decoded_msg m = {0};
	struct msg c;
	uint32_t i, op = NFSP_SCHEMA_NONE;

	printf("tables: an operation union of the other direction\n");
	CHECK(orig->ntypes <= 64, "tproto.0 has %u types", orig->ntypes);
	if (orig->ntypes > 64)
		return;
	memcpy(types, orig->types, orig->ntypes * sizeof(types[0]));
	for (i = 0; i < orig->ntypes; i++)
		if (types[i].flags & NFSP_STF_OPS_REQUEST)
			op = i;
	CHECK(op != NFSP_SCHEMA_NONE, "no request operation union");
	if (op == NFSP_SCHEMA_NONE)
		return;
	types[op].flags = (uint8_t)((types[op].flags & ~NFSP_STF_OPS_REQUEST) |
				    NFSP_STF_OPS_RESPONSE);
	sch = *orig;
	sch.types = types;
	fam.schemas = schs;
	fam.nschemas = 1;

	build_compound_call(&c, 0);
	memset(&in, 0, sizeof(in));
	in.payload = c.b;
	in.len = c.n;
	in.rpc = &env;
	nfsp_rpc_decode(c.b, c.n, &env);
	CHECK(nfsp_nfs_decode(f, 1, &in, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA && m.nops == 0,
	      "%s, nops %u", nfsp_decode_strstatus(m.status), m.nops);
	nfsp_decoded_msg_free(&m);
}

static void test_bad_input(void)
{
	struct nfsp_decoded_msg m = {0};
	struct nfsp_rpc_envelope env;
	struct nfsp_decode_input in;
	struct msg c;

	printf("input contract: the envelope must describe this payload\n");
	build_compound_call(&c, 0);
	nfsp_rpc_decode(c.b, c.n, &env);
	memset(&in, 0, sizeof(in));
	in.payload = c.b;
	in.len = c.n - 4;	/* envelope was decoded for c.n */
	in.rpc = &env;
	CHECK(nfsp_nfs_decode(fams, NFAMS, &in, &m) == NFSP_DECODE_MALFORMED,
	      "stale envelope accepted");
	in.len = c.n;
	in.rpc = NULL;
	CHECK(nfsp_nfs_decode(fams, NFAMS, &in, &m) == NFSP_DECODE_MALFORMED,
	      "missing envelope accepted");
	CHECK(nfsp_nfs_decode(fams, NFAMS, NULL, &m) == NFSP_DECODE_MALFORMED,
	      "NULL input accepted");
	in.rpc = &env;
	CHECK(nfsp_nfs_decode(fams, 0, &in, &m) ==
	      NFSP_DECODE_UNSUPPORTED_SCHEMA, "empty schema set");
	nfsp_decoded_msg_free(&m);
}

int main(void)
{
	test_call_golden();
	test_reply_golden();
	test_minor_selection();
	test_reply_dispatch();
	test_status_after_nested_union();
	test_status_at_result_start();
	test_rpcsec_gss();
	test_long_paths();
	test_truncation();
	test_malformed();
	test_lenient();
	test_resource_limit();
	test_address_oracle();
	test_random_edits();
	test_other_direction_op_union();
	test_ops_before_selector();
	test_bad_input();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
