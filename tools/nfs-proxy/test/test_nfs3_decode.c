/* NFSv3 decoding over the schema assembled from RFC 1813.
 *
 * src/schema_nfs3.c comes from schema/nfs3/ (RFC 1813, assembled and pinned
 * by schema/nfs3/SOURCES).  test_nfs_decode.c proves the interpreter on
 * synthetic schemas; this file proves the real NFSv3 table: every golden
 * vector below has its offsets written out word by word, and every span the
 * decoder reports is checked against them.
 *
 * An NFSv3 REPLY names no procedure, so it is the case the Transaction
 * Context exists for (design 03-nfs-proxy/03 §8): the result schema comes
 * only from reply_dispatch.  test_dispatch() is the decoder's half of
 * oracle 11 (a WRITE reply decodes under its WRITE CALL, never under a READ
 * CALL); test_semantic.c drives the same through the Transaction Context.
 *
 * Oracles: golden spans, family selection by version next to NFSv4, reply
 * dispatch, every procedure of the program, every-prefix truncation, located
 * malformed refusals, random edits under the sanitizer.  The helpers mirror
 * test_nfs4_decode.c.
 */
#include "nfs_decode.h"
#include "rpc_decode.h"
#include "schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct nfsp_schema_family nfsp_schema_family_nfs3;
extern const struct nfsp_schema_family nfsp_schema_family_nfs4;

/* As the proxy registers them (main.c): both families share program
 * 100003 and are told apart by version. */
static const struct nfsp_schema_family *const fams[] = {
	&nfsp_schema_family_nfs4,
	&nfsp_schema_family_nfs3,
};
#define NFAMS (sizeof(fams) / sizeof(fams[0]))

#define NFS_PROG	100003u
#define NFS_V3		3u

/* RFC 1813 §3 procedure numbers */
#define PROC_NULL	0u
#define PROC_GETATTR	1u
#define PROC_READ	6u
#define PROC_WRITE	7u
#define PROC_READDIR	16u
#define PROC_COMMIT	21u

#define FH		"fh-00001"	/* nfs_fh3.data, 8 bytes */
#define VERF		"verf0001"	/* writeverf3, cookieverf3 */

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

/* `len` bytes of s, then XDR padding. */
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

static void put32(struct msg *m, size_t at, uint32_t v)
{
	m->b[at] = (uint8_t)(v >> 24);
	m->b[at + 1] = (uint8_t)(v >> 16);
	m->b[at + 2] = (uint8_t)(v >> 8);
	m->b[at + 3] = (uint8_t)v;
}

/* CALL with an AUTH_SYS credential, as the Linux client sends it, so the
 * body does not start at a convenient offset. */
static void call_header(struct msg *m, uint32_t vers, uint32_t proc)
{
	m->n = 0;
	w32(m, 0x5eed0003);	/*  0 xid */
	w32(m, 0);		/*  4 CALL */
	w32(m, 2);		/*  8 rpcvers */
	w32(m, NFS_PROG);	/* 12 */
	w32(m, vers);		/* 16 */
	w32(m, proc);		/* 20 */
	w32(m, 1);		/* 24 cred AUTH_SYS */
	w32(m, 24);		/* 28 cred length */
	w32(m, 0x5f000001);	/* 32 stamp */
	wopaque(m, "kvm");	/* 36 machinename: len, 40..42, pad 43 */
	w32(m, 0);		/* 44 uid */
	w32(m, 0);		/* 48 gid */
	w32(m, 0);		/* 52 gids count */
	w32(m, 0);		/* 56 verf AUTH_NONE */
	w32(m, 0);		/* 60 */
}				/* 64 body */

static void reply_header(struct msg *m)
{
	m->n = 0;
	w32(m, 0x5eed0003);	/*  0 xid */
	w32(m, 1);		/*  4 REPLY */
	w32(m, 0);		/*  8 MSG_ACCEPTED */
	w32(m, 0);		/* 12 verf AUTH_NONE */
	w32(m, 0);		/* 16 */
	w32(m, 0);		/* 20 SUCCESS */
}				/* 24 body */

/* WRITE3args, FILE_SYNC, five bytes.  104 bytes. */
static void build_write_call(struct msg *m)
{
	call_header(m, NFS_V3, PROC_WRITE);
	wopaque(m, FH);			/*  64 file.data: len, 68..75 */
	w64(m, 0x1000);			/*  76 offset */
	w32(m, 5);			/*  84 count */
	w32(m, 2);			/*  88 stable FILE_SYNC */
	wopaque(m, "hello");		/*  92 data: len, 96..100, pad */
}					/* 104 */

/* WRITE3res NFS3_OK: pre_op_attr present, post_op_attr absent.  76
 * bytes. */
static void build_write_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0);			/* 24 status NFS3_OK */
	w32(m, 1);			/* 28 before.attributes_follow */
	w64(m, 5);			/* 32 before.size */
	w32(m, 1);			/* 40 before.mtime.seconds */
	w32(m, 2);			/* 44 before.mtime.nseconds */
	w32(m, 3);			/* 48 before.ctime.seconds */
	w32(m, 4);			/* 52 before.ctime.nseconds */
	w32(m, 0);			/* 56 after.attributes_follow */
	w32(m, 5);			/* 60 count */
	w32(m, 2);			/* 64 committed FILE_SYNC */
	wraw(m, VERF, 8);		/* 68 verf */
}					/* 76 */

/* WRITE3res NFS3ERR_NOSPC: WRITE3resfail, the `default` arm.  36 bytes. */
static void build_write_reply_nospc(struct msg *m)
{
	reply_header(m);
	w32(m, 28);			/* 24 status NFS3ERR_NOSPC */
	w32(m, 0);			/* 28 before.attributes_follow */
	w32(m, 0);			/* 32 after.attributes_follow */
}					/* 36 */

/* READ3args.  88 bytes. */
static void build_read_call(struct msg *m)
{
	call_header(m, NFS_V3, PROC_READ);
	wopaque(m, FH);			/* 64 file.data */
	w64(m, 0);			/* 76 offset */
	w32(m, 5);			/* 84 count */
}					/* 88 */

/* READ3res NFS3_OK, eof, five bytes.  52 bytes. */
static void build_read_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0);			/* 24 status */
	w32(m, 0);			/* 28 file_attributes.attributes_follow */
	w32(m, 5);			/* 32 count */
	w32(m, 1);			/* 36 eof */
	wopaque(m, "hello");		/* 40 data: len, 44..48, pad */
}					/* 52 */

/* READDIR3res NFS3_OK: two entries, the XDR linked list.  104 bytes. */
static void build_readdir_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0);			/*  24 status */
	w32(m, 0);			/*  28 dir_attributes.attributes_follow */
	wraw(m, VERF, 8);		/*  32 cookieverf */
	w32(m, 1);			/*  40 reply.entries: present */
	w64(m, 2);			/*  44 fileid */
	wopaque(m, ".");		/*  52 name: len, 56, pad */
	w64(m, 1);			/*  60 cookie */
	w32(m, 1);			/*  68 nextentry: present */
	w64(m, 3);			/*  72 fileid */
	wopaque(m, "..");		/*  80 name: len, 84..85, pad */
	w64(m, 2);			/*  88 cookie */
	w32(m, 0);			/*  96 nextentry: end */
	w32(m, 1);			/* 100 reply.eof */
}					/* 104 */

static struct nfsp_reply_dispatch dispatch(uint32_t proc)
{
	/* The CALLs here carry AUTH_SYS, as the Linux client sends them.
	 * NFSv3 has no minor version. */
	return (struct nfsp_reply_dispatch){ NFS_PROG, NFS_V3, proc, 0, 0,
					     NFSP_DISPATCH_TEST_FIXTURE,
					     NFSP_RPC_AUTH_SYS };
}

static enum nfsp_decode_status
run(const struct msg *v, size_t n, const struct nfsp_reply_dispatch *rd,
    struct nfsp_decoded_msg *out)
{
	struct nfsp_rpc_envelope env;
	struct nfsp_decode_input in;

	memset(&in, 0, sizeof(in));
	in.payload = v->b;
	in.len = n;
	in.rpc = &env;
	in.reply_dispatch = rd;
	in.allow_test_fixture = 1;
	nfsp_rpc_decode(v->b, n, &env);
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

/* A metadata span of the field at `path`. */
static void expect_meta(const struct nfsp_decoded_msg *m, const char *path,
			unsigned nth, uint32_t role, uint32_t off,
			uint32_t len, int line)
{
	const struct nfsp_semantic_field *f = field(m, path, nth);
	const struct nfsp_span *s;

	checks++;
	if (!f) {
		failures++;
		printf("  FAIL line %d: no field %s #%u\n", line, path, nth);
		return;
	}
	s = role == NFSP_META_LENGTH ? &f->wire.length :
	    role == NFSP_META_COUNT ? &f->wire.count :
	    role == NFSP_META_DISCRIMINANT ? &f->wire.discriminant :
	    &f->wire.padding;
	CHECK((f->wire.meta & role) && SPAN(*s, off, len),
	      "line %d %s: meta %#x %u+%u, want %#x %u+%u", line, path,
	      f->wire.meta, s->off, s->len, role, off, len);
}

#define META(m, path, nth, role, o, l) \
	expect_meta(m, path, nth, role, o, l, __LINE__)

static void check_invariants(const struct nfsp_decoded_msg *m, size_t len,
			     const char *what)
{
	char buf[512];
	struct nfsp_schema_node node;
	enum nfsp_schema_resolve res;
	size_t n;

	CHECK(m->nops == 0, "%s: NFSv3 has no operations", what);
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
		CHECK(f->op == NFSP_FIELD_NONE, "%s field %u: under an op",
		      what, i);
		n = nfsp_field_path(m, i, buf, sizeof(buf));
		CHECK(n > 0 && n < sizeof(buf) && !strncmp(buf, "nfs3.", 5),
		      "%s field %u: path %s", what, i, buf);
		/* A rule names this field by the same path before any
		 * message exists (schema.h): it must resolve to this node. */
		res = nfsp_schema_resolve(m->schema,
					  m->msg_type == NFSP_RPC_REPLY, buf,
					  &node);
		CHECK(res == NFSP_SCHEMA_FOUND && node.type == f->type,
		      "%s field %u: %s resolves %d", what, i, buf, res);
	}
}

static int is_nfs3(const struct nfsp_decoded_msg *m)
{
	return m->schema == nfsp_schema_family_nfs3.schemas[0] &&
	       !m->has_minor && m->program == NFS_PROG &&
	       m->version == NFS_V3 &&
	       !strncmp(m->schema->schema_id, "nfs3/sha256:", 12);
}

static int decoded(const struct msg *v, const struct nfsp_reply_dispatch *rd,
		   struct nfsp_decoded_msg *m, const char *what)
{
	CHECK(run(v, v->n, rd, m) == NFSP_DECODE_DECODED, "%s: %s at %u: %s",
	      what, nfsp_decode_strstatus(m->status), m->failure.offset,
	      m->failure.reason ? m->failure.reason : "");
	if (m->status != NFSP_DECODE_DECODED)
		return 0;
	CHECK(is_nfs3(m), "%s: not the nfs3 schema", what);
	check_invariants(m, v->n, what);
	return 1;
}

static void test_write_call(void)
{
	struct nfsp_decoded_msg m = {0};
	struct msg c;

	printf("CALL: WRITE, exact WireRefs\n");
	build_write_call(&c);
	CHECK(c.n == 104, "vector length %zu", c.n);
	if (!decoded(&c, NULL, &m, "write call"))
		return;
	CHECK(m.procedure == PROC_WRITE && m.procedure_name &&
	      !strcmp(m.procedure_name, "WRITE") && m.trailing.len == 0,
	      "procedure %u %s", m.procedure,
	      m.procedure_name ? m.procedure_name : "");
	EXPECT(&m, "nfs3.request.WRITE.args", 0, 64, 40, 64, 40, 0);
	EXPECT(&m, "nfs3.request.WRITE.args.file", 0, 64, 12, 64, 12, 0);
	EXPECT(&m, "nfs3.request.WRITE.args.file.data", 0, 64, 12, 68, 8, 0);
	META(&m, "nfs3.request.WRITE.args.file.data", 0, NFSP_META_LENGTH,
	     64, 4);
	EXPECT(&m, "nfs3.request.WRITE.args.offset", 0, 76, 8, 76, 8, 0x1000);
	EXPECT(&m, "nfs3.request.WRITE.args.count", 0, 84, 4, 84, 4, 5);
	EXPECT(&m, "nfs3.request.WRITE.args.stable", 0, 88, 4, 88, 4, 2);
	EXPECT(&m, "nfs3.request.WRITE.args.data", 0, 92, 12, 96, 5, 0);
	META(&m, "nfs3.request.WRITE.args.data", 0, NFSP_META_LENGTH, 92, 4);
	META(&m, "nfs3.request.WRITE.args.data", 0, NFSP_META_PADDING, 101,
	     3);
	CHECK(m.nfields == 7, "nfields %u", m.nfields);
	nfsp_decoded_msg_free(&m);
}

static void test_write_reply(void)
{
	struct nfsp_reply_dispatch rd = dispatch(PROC_WRITE);
	struct nfsp_decoded_msg m = {0};
	struct msg r;
	const char *ok = "nfs3.response.WRITE.result.ok";

	printf("REPLY: WRITE ok and NFS3ERR_NOSPC, exact WireRefs\n");
	build_write_reply(&r);
	CHECK(r.n == 76, "vector length %zu", r.n);
	if (decoded(&r, &rd, &m, "write reply")) {
		char p[128];

		CHECK(m.procedure == PROC_WRITE &&
		      m.dispatch_source == NFSP_DISPATCH_TEST_FIXTURE,
		      "procedure %u", m.procedure);
		EXPECT(&m, "nfs3.response.WRITE.result", 0, 24, 52, 28, 48, 0);
		EXPECT(&m, "nfs3.response.WRITE.result.status", 0, 24, 4, 24,
		       4, 0);
		META(&m, "nfs3.response.WRITE.result", 0,
		     NFSP_META_DISCRIMINANT, 24, 4);
		snprintf(p, sizeof(p), "%s.file_wcc.before.attributes_follow",
			 ok);
		EXPECT(&m, p, 0, 28, 4, 28, 4, 1);
		snprintf(p, sizeof(p), "%s.file_wcc.before.true.size", ok);
		EXPECT(&m, p, 0, 32, 8, 32, 8, 5);
		snprintf(p, sizeof(p), "%s.file_wcc.before.true.ctime.nseconds",
			 ok);
		EXPECT(&m, p, 0, 52, 4, 52, 4, 4);
		snprintf(p, sizeof(p), "%s.file_wcc.after", ok);
		EXPECT(&m, p, 0, 56, 4, 60, 0, 0);
		snprintf(p, sizeof(p), "%s.count", ok);
		EXPECT(&m, p, 0, 60, 4, 60, 4, 5);
		snprintf(p, sizeof(p), "%s.committed", ok);
		EXPECT(&m, p, 0, 64, 4, 64, 4, 2);
		snprintf(p, sizeof(p), "%s.verf", ok);
		EXPECT(&m, p, 0, 68, 8, 68, 8, 0);
		CHECK(m.nfields == 19, "nfields %u", m.nfields);
	}
	build_write_reply_nospc(&r);
	if (decoded(&r, &rd, &m, "write reply nospc")) {
		EXPECT(&m, "nfs3.response.WRITE.result.status", 0, 24, 4, 24,
		       4, 28);
		EXPECT(&m, "nfs3.response.WRITE.result.default.file_wcc", 0,
		       28, 8, 28, 8, 0);
		CHECK(field(&m, "nfs3.response.WRITE.result.ok.count", 0) ==
		      NULL, "a failed WRITE has no ok arm");
		CHECK(m.nfields == 8, "nfields %u", m.nfields);
	}
	nfsp_decoded_msg_free(&m);
}

static void test_readdir_reply(void)
{
	struct nfsp_reply_dispatch rd = dispatch(PROC_READDIR);
	struct nfsp_decoded_msg m = {0};
	struct msg r;
	const char *e = "nfs3.response.READDIR.result.ok.reply.entries[]";
	char p[128];

	printf("REPLY: READDIR, the entry3 linked list\n");
	build_readdir_reply(&r);
	CHECK(r.n == 104, "vector length %zu", r.n);
	if (!decoded(&r, &rd, &m, "readdir reply"))
		return;
	EXPECT(&m, "nfs3.response.READDIR.result.ok.cookieverf", 0, 32, 8, 32,
	       8, 0);
	EXPECT(&m, "nfs3.response.READDIR.result.ok.reply.entries", 0, 40, 60,
	       44, 56, 0);
	EXPECT(&m, e, 0, 44, 28, 44, 24, 0);
	META(&m, e, 0, NFSP_META_DISCRIMINANT, 68, 4);
	EXPECT(&m, e, 1, 72, 28, 72, 24, 0);
	META(&m, e, 1, NFSP_META_DISCRIMINANT, 96, 4);
	snprintf(p, sizeof(p), "%s.fileid", e);
	EXPECT(&m, p, 0, 44, 8, 44, 8, 2);
	EXPECT(&m, p, 1, 72, 8, 72, 8, 3);
	snprintf(p, sizeof(p), "%s.name", e);
	EXPECT(&m, p, 1, 80, 8, 84, 2, 0);
	CHECK(field(&m, e, 0)->index == 0 && field(&m, e, 1)->index == 1,
	      "element indexes");
	EXPECT(&m, "nfs3.response.READDIR.result.ok.reply.eof", 0, 100, 4,
	       100, 4, 1);
	CHECK(m.nfields == 17, "nfields %u", m.nfields);
	nfsp_decoded_msg_free(&m);
}

/* The result schema comes only from reply_dispatch (design 03 §8, oracle
 * 11), and the version, not the program, picks the family. */
static void test_dispatch(void)
{
	struct nfsp_reply_dispatch wr = dispatch(PROC_WRITE);
	struct nfsp_reply_dispatch rd = dispatch(PROC_READ);
	struct nfsp_reply_dispatch bad = dispatch(22);
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	printf("dispatch: a REPLY decodes under its CALL's procedure only\n");
	build_write_reply(&v);
	CHECK(run(&v, v.n, NULL, &m) ==
	      NFSP_DECODE_TRANSACTION_CONTEXT_MISSING && m.nfields == 0,
	      "no dispatch: %s", nfsp_decode_strstatus(m.status));
	/* WRITE's reply bytes under READ's result schema: post_op_attr says
	 * attributes follow, and an fattr3 does not fit what is left. */
	CHECK(run(&v, v.n, &rd, &m) != NFSP_DECODE_DECODED &&
	      m.nfields == 0, "WRITE reply under READ: %s",
	      nfsp_decode_strstatus(m.status));
	CHECK(run(&v, v.n, &wr, &m) == NFSP_DECODE_DECODED &&
	      m.procedure == PROC_WRITE, "WRITE reply under WRITE: %s",
	      nfsp_decode_strstatus(m.status));
	build_read_reply(&v);
	if (decoded(&v, &rd, &m, "read reply")) {
		EXPECT(&m, "nfs3.response.READ.result.ok.data", 0, 40, 12, 44,
		       5, 0);
		EXPECT(&m, "nfs3.response.READ.result.ok.eof", 0, 36, 4, 36,
		       4, 1);
	}
	/* READ's reply under WRITE: a different, still well-formed shape
	 * would be a wrong decode, so it must be refused here. */
	CHECK(run(&v, v.n, &wr, &m) != NFSP_DECODE_DECODED &&
	      m.nfields == 0, "READ reply under WRITE: %s",
	      nfsp_decode_strstatus(m.status));
	CHECK(run(&v, v.n, &bad, &m) == NFSP_DECODE_UNSUPPORTED_SCHEMA &&
	      m.nfields == 0, "procedure 22: %s",
	      nfsp_decode_strstatus(m.status));
	build_read_call(&v);
	if (decoded(&v, NULL, &m, "read call"))
		EXPECT(&m, "nfs3.request.READ.args.count", 0, 84, 4, 84, 4, 5);
	call_header(&v, NFS_V3, 22);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_UNSUPPORTED_SCHEMA,
	      "CALL procedure 22: %s", nfsp_decode_strstatus(m.status));
	/* NFSv2 has no schema; NFSv4 still goes to its own family. */
	build_read_call(&v);
	put32(&v, 16, 2);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_UNSUPPORTED_SCHEMA,
	      "NFSv2: %s", nfsp_decode_strstatus(m.status));
	call_header(&v, 4, 1);
	w32(&v, 0);			/* tag */
	w32(&v, 0);			/* minorversion */
	w32(&v, 0);			/* no operations */
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_DECODED &&
	      m.schema == nfsp_schema_family_nfs4.schemas[0],
	      "NFSv4 next to NFSv3: %s", nfsp_decode_strstatus(m.status));
	nfsp_decoded_msg_free(&m);
}

/* The program as RFC 1813 §3 lists it: 22 procedures, NULL void. */
static void test_procedures(void)
{
	static const char *const names[] = {
		"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK",
		"READ", "WRITE", "CREATE", "MKDIR", "SYMLINK", "MKNOD",
		"REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS",
		"FSSTAT", "FSINFO", "PATHCONF", "COMMIT"
	};
	const struct nfsp_protocol_schema *s =
		nfsp_schema_family_nfs3.schemas[0];
	struct nfsp_reply_dispatch rd = dispatch(PROC_NULL);
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	printf("program: NFS_PROGRAM version 3, every procedure\n");
	CHECK(nfsp_schema_family_nfs3.nschemas == 1 &&
	      !nfsp_schema_family_nfs3.has_minor && s->program == NFS_PROG &&
	      s->version == NFS_V3 && s->nprocs == 22, "family shape");
	for (uint32_t i = 0; i < s->nprocs && i < 22; i++) {
		const struct nfsp_schema_proc *p = &s->procs[i];

		CHECK(p->number == i && !strcmp(p->name, names[i]),
		      "procedure %u: %u %s", i, p->number, p->name);
		CHECK(i == PROC_NULL ? p->arg == NFSP_SCHEMA_NONE &&
		      p->res == NFSP_SCHEMA_NONE :
		      p->arg != NFSP_SCHEMA_NONE &&
		      s->types[p->res].kind == NFSP_XK_UNION,
		      "procedure %s: arguments and a status union", p->name);
	}
	call_header(&v, NFS_V3, PROC_NULL);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_DECODED && is_nfs3(&m) &&
	      m.nfields == 0, "NULL call: %s",
	      nfsp_decode_strstatus(m.status));
	reply_header(&v);
	CHECK(run(&v, v.n, &rd, &m) == NFSP_DECODE_DECODED && m.nfields == 0,
	      "NULL reply: %s", nfsp_decode_strstatus(m.status));
	/* COMMIT, the last procedure: arguments decode to the end. */
	call_header(&v, NFS_V3, PROC_COMMIT);
	wopaque(&v, FH);		/* 64 */
	w64(&v, 0);			/* 76 offset */
	w32(&v, 0);			/* 84 count */
	if (decoded(&v, NULL, &m, "commit call"))
		EXPECT(&m, "nfs3.request.COMMIT.args.count", 0, 84, 4, 84, 4,
		       0);
	nfsp_decoded_msg_free(&m);
}

typedef void (*builder)(struct msg *);

static const struct golden {
	builder build;
	uint32_t proc;
	int reply;
	const char *what;
} goldens[] = {
	{ build_write_call, PROC_WRITE, 0, "write call" },
	{ build_write_reply, PROC_WRITE, 1, "write reply" },
	{ build_write_reply_nospc, PROC_WRITE, 1, "write reply nospc" },
	{ build_read_call, PROC_READ, 0, "read call" },
	{ build_read_reply, PROC_READ, 1, "read reply" },
	{ build_readdir_reply, PROC_READDIR, 1, "readdir reply" },
};
#define NGOLDEN (sizeof(goldens) / sizeof(goldens[0]))

static void test_truncation(void)
{
	struct nfsp_decoded_msg m = {0};

	printf("truncation: every prefix of every golden message\n");
	for (size_t g = 0; g < NGOLDEN; g++) {
		struct nfsp_reply_dispatch rd = dispatch(goldens[g].proc);
		struct msg v;
		unsigned bad = 0;

		goldens[g].build(&v);
		for (size_t n = goldens[g].reply ? 24 : 64; n < v.n; n++) {
			run(&v, n, goldens[g].reply ? &rd : NULL, &m);
			if (m.status == NFSP_DECODE_DECODED ||
			    m.status == NFSP_DECODE_PARTIAL || m.nfields)
				bad++;
		}
		CHECK(bad == 0, "%s: %u prefixes decoded or kept fields",
		      goldens[g].what, bad);
	}
	nfsp_decoded_msg_free(&m);
}

static void refused(builder build, const struct nfsp_reply_dispatch *rd,
		    size_t at, uint32_t word, enum nfsp_decode_status st,
		    uint32_t fail_off, const char *reason, int line)
{
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	build(&v);
	put32(&v, at, word);
	CHECK(run(&v, v.n, rd, &m) == st && m.nfields == 0 && m.nops == 0 &&
	      m.failure.offset == fail_off && m.failure.reason &&
	      !strcmp(m.failure.reason, reason),
	      "line %d: word %zu = %#x: %s at %u (%s), want %s at %u (%s)",
	      line, at, word, nfsp_decode_strstatus(m.status),
	      m.failure.offset, m.failure.reason ? m.failure.reason : "",
	      nfsp_decode_strstatus(st), fail_off, reason);
	nfsp_decoded_msg_free(&m);
}

#define REFUSED(b, rd, at, w, st, off, why) \
	refused(b, rd, at, w, st, off, why, __LINE__)

static void test_malformed(void)
{
	struct nfsp_reply_dispatch wr = dispatch(PROC_WRITE);
	struct nfsp_reply_dispatch rdd = dispatch(PROC_READDIR);
	const enum nfsp_decode_status bad = NFSP_DECODE_MALFORMED;
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	printf("malformed: located refusals on the NFSv3 bounds\n");
	/* nfs_fh3.data<NFS3_FHSIZE>: 64 is the bound. */
	REFUSED(build_write_call, NULL, 64, 65, bad, 64,
		"length exceeds bound");
	REFUSED(build_write_call, NULL, 92, 200, bad, 92,
		"length exceeds remaining record");
	REFUSED(build_write_reply, &wr, 28, 2, bad, 28,
		"bool is not 0 or 1");		/* a discriminant */
	REFUSED(build_write_reply, &wr, 24, 99999, bad, 24,
		"enum value not declared");	/* nfsstat3 */
	REFUSED(build_readdir_reply, &rdd, 68, 2, bad, 68,
		"list link is not 0 or 1");
	/* A REPLY is never lenient: an undeclared stable_how is refused. */
	REFUSED(build_write_reply, &wr, 64, 3, bad, 64,
		"enum value not declared");
	/* A CALL is, where knfsd reads the word as a plain integer. */
	build_write_call(&v);
	put32(&v, 88, 3);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_DECODED &&
	      (field(&m, "nfs3.request.WRITE.args.stable", 0)->flags &
	       NFSP_FF_UNDECLARED), "lenient stable_how: %s",
	      nfsp_decode_strstatus(m.status));
	nfsp_decoded_msg_free(&m);
}

static void test_random_edits(void)
{
	struct nfsp_decoded_msg m = {0};
	uint64_t x = 0x13198a2e03707344ull;
	unsigned ok = 0, refused_n = 0;
	enum nfsp_decode_status st;

	printf("random edits: 20000 mutated messages, invariants hold\n");
	for (unsigned it = 0; it < 20000; it++) {
		const struct golden *g = &goldens[it % NGOLDEN];
		struct nfsp_reply_dispatch rd = dispatch(g->proc);
		size_t hdr = g->reply ? 24 : 64;
		struct msg v;
		unsigned edits;

		g->build(&v);
		x ^= x << 13, x ^= x >> 7, x ^= x << 17;
		edits = 1 + (unsigned)(x % 4);
		for (unsigned e = 0; e < edits; e++) {
			x ^= x << 13, x ^= x >> 7, x ^= x << 17;
			v.b[hdr + (size_t)(x % (v.n - hdr))] =
				(uint8_t)(x >> 32);
		}
		st = run(&v, v.n, g->reply ? &rd : NULL, &m);
		if (st == NFSP_DECODE_DECODED) {
			ok++;
			CHECK(is_nfs3(&m), "random edit: not nfs3");
			check_invariants(&m, v.n, "random edit");
		} else {
			refused_n++;
			CHECK(st != NFSP_DECODE_PARTIAL && m.nfields == 0 &&
			      m.nops == 0, "refused message kept fields");
		}
	}
	printf("  %u decoded, %u refused\n", ok, refused_n);
	CHECK(ok > 0 && refused_n > 0, "edits did not exercise both paths");
	nfsp_decoded_msg_free(&m);
}

int main(void)
{
	test_write_call();
	test_write_reply();
	test_readdir_reply();
	test_dispatch();
	test_procedures();
	test_truncation();
	test_malformed();
	test_random_edits();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
