/* NFSPRUL1 rule sets and static path resolution (M4a).
 *
 * Oracles:
 *   - path resolution: every path the naming rules produce for the real
 *     NFSv4 tables and the synthetic test protocols resolves to exactly the
 *     node it was built from (the decode tests check the decoder's own
 *     paths the same way); a hand-made schema shows AMBIGUOUS;
 *   - format: a golden byte vector written out word by word, the builder
 *     reproducing it, every proper prefix refused, and one refusal per
 *     canonical-form rule;
 *   - validation: a valid rule of each supported shape loads, and each
 *     status is produced by a rule that differs from a valid one in one
 *     field, with the rule and predicate it names.
 */
#include "rule.h"
#include "schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct nfsp_schema_family nfsp_schema_family_nfs4;
extern const struct nfsp_schema_family nfsp_schema_family_tproto;
extern const struct nfsp_schema_family nfsp_schema_family_tflat;
extern const struct nfsp_schema_family nfsp_schema_family_tedge;

static const struct nfsp_schema_family *const fams[] = {
	&nfsp_schema_family_nfs4,
};
#define NFAMS (sizeof(fams) / sizeof(fams[0]))

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
#define NFS4_OK		0u
#define CLAIM_PREVIOUS	1u

static const struct nfsp_protocol_schema *v41(void)
{
	return nfsp_schema_family_nfs4.schemas[1];
}

/* ---- path resolution ---- */

struct gen {
	const struct nfsp_protocol_schema *s;
	int response;
	char path[1024];
	unsigned paths, found, ambiguous, other;
};

static int ops_union(const struct nfsp_protocol_schema *s, uint16_t t)
{
	return s->types[t].kind == NFSP_XK_UNION &&
	       (s->types[t].flags &
		(NFSP_STF_OPS_REQUEST | NFSP_STF_OPS_RESPONSE));
}

static void expect_node(struct gen *g, uint16_t t)
{
	struct nfsp_schema_node n;
	enum nfsp_schema_resolve r;

	g->paths++;
	r = nfsp_schema_resolve(g->s, g->response, g->path, &n);
	if (r == NFSP_SCHEMA_FOUND && n.type == t)
		g->found++;
	else if (r == NFSP_SCHEMA_AMBIGUOUS)
		g->ambiguous++;
	else
		g->other++;
	CHECK(r == NFSP_SCHEMA_FOUND && n.type == t,
	      "%s: %s %s, type %u want %u", g->s->schema_id,
	      g->response ? "response" : "request", g->path,
	      r == NFSP_SCHEMA_FOUND ? n.type : 0u, t);
}

/* The naming rules of schema.h, written out a second time: a node's path
 * is its parent's plus ".<component>", or "[]" for an element.  An
 * operation union has no path under its container: it is a root. */
static void gen_node(struct gen *g, size_t len, uint16_t t, unsigned depth)
{
	const struct nfsp_schema_type *ty = &g->s->types[t];
	int n;

	if (ops_union(g->s, t))
		return;
	expect_node(g, t);
	if (depth > 40 || len > 600)
		return;
	switch (ty->kind) {
	case NFSP_XK_STRUCT:
		for (uint32_t k = 0; k < ty->count; k++) {
			const struct nfsp_schema_field *f =
				&g->s->fields[ty->first + k];

			n = snprintf(g->path + len, sizeof(g->path) - len,
				     ".%s", f->name);
			gen_node(g, len + (size_t)n, f->type, depth + 1);
			g->path[len] = '\0';
		}
		break;
	case NFSP_XK_UNION:
		n = snprintf(g->path + len, sizeof(g->path) - len, ".%s",
			     ty->disc_name);
		gen_node(g, len + (size_t)n, ty->sub, depth + 1);
		g->path[len] = '\0';
		for (uint32_t k = 0; k < ty->count; k++) {
			const struct nfsp_schema_arm *a =
				&g->s->arms[ty->first + k];

			if (a->type == NFSP_SCHEMA_NONE)
				continue;
			n = snprintf(g->path + len, sizeof(g->path) - len,
				     ".%s", a->component);
			gen_node(g, len + (size_t)n, a->type, depth + 1);
			g->path[len] = '\0';
		}
		break;
	case NFSP_XK_ARRAY_FIXED:
	case NFSP_XK_ARRAY_VAR:
	case NFSP_XK_LIST:
		memcpy(g->path + len, "[]", 3);
		gen_node(g, len + 2, ty->sub, depth + 1);
		g->path[len] = '\0';
		break;
	default:
		break;
	}
}

static void gen_schema(const struct nfsp_protocol_schema *s,
		       unsigned *paths)
{
	struct gen g;

	memset(&g, 0, sizeof(g));
	g.s = s;
	for (g.response = 0; g.response < 2; g.response++) {
		const char *dir = g.response ? "response" : "request";
		uint8_t mine = g.response ? NFSP_STF_OPS_RESPONSE :
					    NFSP_STF_OPS_REQUEST;

		for (uint32_t i = 0; i < s->nprocs; i++) {
			uint16_t rt = g.response ? s->procs[i].res :
						   s->procs[i].arg;
			int n;

			if (rt == NFSP_SCHEMA_NONE)
				continue;
			n = snprintf(g.path, sizeof(g.path), "%s.%s.%s.%s",
				     s->family, dir, s->procs[i].name,
				     g.response ? s->response_leaf :
						  s->request_leaf);
			gen_node(&g, (size_t)n, rt, 0);
		}
		for (uint32_t t = 0; t < s->ntypes; t++) {
			const struct nfsp_schema_type *ty = &s->types[t];

			if (!ops_union(s, (uint16_t)t) || !(ty->flags & mine))
				continue;
			for (uint32_t k = 0; k < ty->count; k++) {
				const struct nfsp_schema_arm *a =
					&s->arms[ty->first + k];
				int n = snprintf(g.path, sizeof(g.path),
						 "%s.%s.%s", s->family, dir,
						 a->branch);
				int m;

				expect_node(&g, (uint16_t)t);
				m = snprintf(g.path + n, sizeof(g.path) -
					     (size_t)n, ".%s", ty->disc_name);
				gen_node(&g, (size_t)(n + m), ty->sub, 0);
				g.path[n] = '\0';
				if (a->type == NFSP_SCHEMA_NONE)
					continue;
				m = snprintf(g.path + n, sizeof(g.path) -
					     (size_t)n, ".%s", a->component);
				gen_node(&g, (size_t)(n + m), a->type, 0);
			}
		}
	}
	*paths += g.paths;
	CHECK(g.paths > 0 && g.found == g.paths, "%s: %u of %u paths "
	      "resolved, %u ambiguous", s->schema_id, g.found, g.paths,
	      g.ambiguous);
}

static void test_every_path(void)
{
	const struct nfsp_schema_family *all[] = {
		&nfsp_schema_family_nfs4, &nfsp_schema_family_tproto,
		&nfsp_schema_family_tflat, &nfsp_schema_family_tedge,
	};
	unsigned paths = 0;

	printf("resolve: every path of every schema\n");
	for (size_t f = 0; f < sizeof(all) / sizeof(all[0]); f++)
		for (uint32_t k = 0; k < all[f]->nschemas; k++)
			gen_schema(all[f]->schemas[k], &paths);
	printf("  %u paths\n", paths);
}

static void resolves(int response, const char *path, uint8_t kind,
		     uint8_t flags, const char *root, int line)
{
	struct nfsp_schema_node n;
	enum nfsp_schema_resolve r =
		nfsp_schema_resolve(v41(), response, path, &n);

	CHECK(r == NFSP_SCHEMA_FOUND &&
	      v41()->types[n.type].kind == kind && n.flags == flags &&
	      !strcmp(n.root, root),
	      "line %d: %s: %d kind %u flags 0x%x root %s", line, path, r,
	      r ? 0u : v41()->types[n.type].kind, r ? 0u : n.flags,
	      r ? "-" : n.root);
}

static void not_found(int response, const char *path, int line)
{
	struct nfsp_schema_node n;

	CHECK(nfsp_schema_resolve(v41(), response, path, &n) ==
	      NFSP_SCHEMA_NOT_FOUND, "line %d: %s resolved", line, path);
}

static void test_resolve_nodes(void)
{
	printf("resolve: node kinds and flags\n");
	resolves(0, "nfs4.request.COMPOUND.args", NFSP_XK_STRUCT,
		 NFSP_SN_ROOT, "COMPOUND", __LINE__);
	resolves(0, "nfs4.request.COMPOUND.args.argarray", NFSP_XK_ARRAY_VAR,
		 NFSP_SN_OPS_ARRAY, "COMPOUND", __LINE__);
	resolves(1, "nfs4.response.COMPOUND.result.resarray",
		 NFSP_XK_ARRAY_VAR, NFSP_SN_OPS_ARRAY, "COMPOUND", __LINE__);
	resolves(0, "nfs4.request.OPEN", NFSP_XK_UNION,
		 NFSP_SN_ROOT | NFSP_SN_OPERATION, "OPEN", __LINE__);
	resolves(0, "nfs4.request.OPEN.argop", NFSP_XK_ENUM,
		 NFSP_SN_OPERATION | NFSP_SN_DISCRIMINANT, "OPEN", __LINE__);
	/* An arm component that holds a dot. */
	resolves(0, "nfs4.request.OPEN.args.claim.claim_null.file",
		 NFSP_XK_OPAQUE_VAR, NFSP_SN_OPERATION, "OPEN", __LINE__);
	resolves(0, "nfs4.request.OPEN.args.claim.claim", NFSP_XK_ENUM,
		 NFSP_SN_OPERATION | NFSP_SN_DISCRIMINANT, "OPEN", __LINE__);
	resolves(1, "nfs4.response.OPEN.result.ok.stateid.other",
		 NFSP_XK_OPAQUE_FIXED, NFSP_SN_OPERATION, "OPEN", __LINE__);
	resolves(0, "nfs4.request.READDIR.args.attr_request[]", NFSP_XK_UINT,
		 NFSP_SN_OPERATION | NFSP_SN_REPEATED, "READDIR", __LINE__);
	resolves(1, "nfs4.response.READDIR.result.ok.reply.entries",
		 NFSP_XK_LIST, NFSP_SN_OPERATION, "READDIR", __LINE__);
	resolves(1, "nfs4.response.READDIR.result.ok.reply.entries[]",
		 NFSP_XK_STRUCT, NFSP_SN_OPERATION | NFSP_SN_REPEATED |
		 NFSP_SN_LIST_ELEMENT, "READDIR", __LINE__);
	resolves(1, "nfs4.response.READDIR.result.ok.reply.entries[].name",
		 NFSP_XK_OPAQUE_VAR, NFSP_SN_OPERATION | NFSP_SN_REPEATED,
		 "READDIR", __LINE__);

	/* An operation is a root, never an element of the array. */
	not_found(0, "nfs4.request.COMPOUND.args.argarray[]", __LINE__);
	not_found(0, "nfs4.request.COMPOUND.args.argarray[].argop", __LINE__);
	not_found(0, "nfs4.request.COMPOUND", __LINE__);
	not_found(0, "nfs4.response.COMPOUND.result", __LINE__);
	not_found(1, "nfs4.request.COMPOUND.args", __LINE__);
	not_found(0, "nfs4.request.OPEN.args.clai", __LINE__);
	not_found(0, "nfs4.request.OPEN.args.claim.claim_null", __LINE__);
	not_found(0, "nfs4.request.OPEN.args.claim.", __LINE__);
	not_found(0, "nfs4.request.OPEN.args.seqid.x", __LINE__);
	not_found(0, "nfs4.request.OPEN.args[]", __LINE__);
	not_found(0, "nfs4.request.OPENX", __LINE__);
	not_found(0, "nfs3.request.OPEN", __LINE__);
	not_found(0, "nfs4.request.", __LINE__);
	not_found(0, "", __LINE__);
	/* SEEK is an NFSv4.2 operation. */
	not_found(0, "nfs4.request.SEEK", __LINE__);
}

/* A schema whose union gives two arms the same component with different
 * types: the path cannot say which. */
static const struct nfsp_schema_type amb_types[] = {
	/* 0 */ { "args", NFSP_XK_STRUCT, 0, NFSP_SCHEMA_NONE, 0u, 0u, 1u,
		  NFSP_SCHEMA_NONE, NULL, 4u },
	/* 1 */ { "u", NFSP_XK_UNION, 0, 2, 0u, 0u, 3u, NFSP_SCHEMA_NONE,
		  "which", 4u },
	/* 2 */ { "which", NFSP_XK_ENUM, 0, NFSP_SCHEMA_NONE, 0u, 0u, 3u,
		  NFSP_SCHEMA_NONE, NULL, 4u },
	/* 3 */ { "unsigned int", NFSP_XK_UINT, 0, NFSP_SCHEMA_NONE, 0u, 0u,
		  0u, NFSP_SCHEMA_NONE, NULL, 4u },
	/* 4 */ { "string", NFSP_XK_STRING, 0, NFSP_SCHEMA_NONE,
		  NFSP_XDR_UNBOUNDED, 0u, 0u, NFSP_SCHEMA_NONE, NULL, 4u },
};
static const struct nfsp_schema_field amb_fields[] = { { "u", 1 } };
static const struct nfsp_schema_arm amb_arms[] = {
	{ 0u, "A", "x", "x", 3 },
	{ 1u, "B", "x", "x", 4 },
	{ 2u, "C", "y", "y", 3 },
};
static const struct nfsp_schema_enumval amb_enums[] = {
	{ 0u, "A" }, { 1u, "B" }, { 2u, "C" },
};
static const struct nfsp_schema_proc amb_procs[] = {
	{ 1u, "P", 0, NFSP_SCHEMA_NONE },
};
static const struct nfsp_protocol_schema amb_schema = {
	.schema_id = "amb/test", .family = "amb", .program = 1u, .version = 1u,
	.request_leaf = "args", .response_leaf = "result",
	.types = amb_types, .ntypes = 5u, .fields = amb_fields,
	.arms = amb_arms, .enums = amb_enums, .procs = amb_procs,
	.nprocs = 1u, .max_depth = 3u,
};

static void test_resolve_ambiguous(void)
{
	struct nfsp_schema_node n;

	printf("resolve: ambiguous arms\n");
	CHECK(nfsp_schema_resolve(&amb_schema, 0, "amb.request.P.args.u.x",
				  &n) == NFSP_SCHEMA_AMBIGUOUS,
	      "two arms named x");
	CHECK(nfsp_schema_resolve(&amb_schema, 0, "amb.request.P.args.u.y",
				  &n) == NFSP_SCHEMA_FOUND && n.type == 3,
	      "one arm named y");
	CHECK(nfsp_schema_resolve(&amb_schema, 0,
				  "amb.request.P.args.u.which", &n) ==
	      NFSP_SCHEMA_FOUND && (n.flags & NFSP_SN_DISCRIMINANT),
	      "discriminant");
}

static void test_reaches(void)
{
	const struct nfsp_protocol_schema *s = v41();
	const struct nfsp_schema_proc *compound = nfsp_schema_proc(s, 1);
	struct nfsp_schema_node op;

	printf("resolve: reachability\n");
	CHECK(nfsp_schema_resolve(s, 0, "nfs4.request.OPEN", &op) ==
	      NFSP_SCHEMA_FOUND, "OPEN");
	CHECK(nfsp_schema_reaches(s, compound->arg, op.root_type) == 1,
	      "COMPOUND args reach the operation union");
	CHECK(nfsp_schema_reaches(s, op.root_type, compound->arg) == 0,
	      "the operation union does not reach COMPOUND args");
	CHECK(nfsp_schema_reaches(s, compound->arg, compound->arg) == 1,
	      "a type reaches itself");
}

/* ---- the format ---- */

struct w {
	uint8_t b[32768];
	size_t n;
};

static void w32(struct w *w, uint32_t v)
{
	w->b[w->n++] = (uint8_t)(v >> 24);
	w->b[w->n++] = (uint8_t)(v >> 16);
	w->b[w->n++] = (uint8_t)(v >> 8);
	w->b[w->n++] = (uint8_t)v;
}

static void w64(struct w *w, uint64_t v)
{
	w32(w, (uint32_t)(v >> 32));
	w32(w, (uint32_t)v);
}

static void wbytes(struct w *w, const void *p, uint32_t n)
{
	w32(w, n);
	memcpy(w->b + w->n, p, n);
	w->n += n;
	while (w->n & 3u)
		w->b[w->n++] = 0;
}

static void wstr(struct w *w, const char *s)
{
	wbytes(w, s, (uint32_t)strlen(s));
}

struct lit {
	uint32_t kind;
	uint64_t num;
	const char *bytes;
	uint32_t len;
};

struct ref {
	uint32_t source;
	const char *path;
};

struct pred {
	struct ref lhs;
	uint32_t op;
	int is_ref;
	struct lit lit;
	struct ref ref;
};

struct deps {
	int proc, opseq;
	const char *fields[4];
	uint32_t n;
};

struct spec {
	const char *rule_id, *intent_id;
	uint32_t dir, backend, client;
	uint32_t msg, prog, vers;
	int has_proc;
	uint32_t proc;
	const char *family;
	int has_nfsv, has_minor;
	uint32_t nfsv, minor;
	const char *operation;
	uint32_t tkind;
	const char *path;
	uint32_t part;
	struct pred preds[4];
	uint32_t npreds;
	uint32_t mkind;
	int has_xf;
	uint32_t xkind;
	struct lit xlit;
	struct ref xsrc;
	const char *builtin;
	uint32_t policy;
	struct deps fwd, orig;
	uint32_t app;
};

static void wlit(struct w *w, const struct lit *l)
{
	w32(w, l->kind);
	switch (l->kind) {
	case NFSP_LIT_HYPER:
	case NFSP_LIT_UHYPER:
		w64(w, l->num);
		break;
	case NFSP_LIT_OPAQUE:
	case NFSP_LIT_STRING:
		wbytes(w, l->bytes, l->len);
		break;
	default:
		w32(w, (uint32_t)l->num);
		break;
	}
}

static void wref(struct w *w, const struct ref *r)
{
	w32(w, r->source);
	wstr(w, r->path ? r->path : "");
}

static void wdeps(struct w *w, const struct deps *d)
{
	w32(w, (uint32_t)d->proc);
	w32(w, (uint32_t)d->opseq);
	w32(w, d->n);
	for (uint32_t i = 0; i < d->n; i++)
		wstr(w, d->fields[i]);
}

static void wrule(struct w *w, const struct spec *sp)
{
	wstr(w, sp->rule_id);
	wstr(w, sp->intent_id);
	w32(w, sp->dir);
	w32(w, sp->backend);
	w32(w, sp->client);
	w32(w, sp->msg);
	w32(w, sp->prog);
	w32(w, sp->vers);
	w32(w, (uint32_t)sp->has_proc);
	if (sp->has_proc)
		w32(w, sp->proc);
	wstr(w, sp->family);
	w32(w, (uint32_t)sp->has_nfsv);
	if (sp->has_nfsv)
		w32(w, sp->nfsv);
	w32(w, (uint32_t)sp->has_minor);
	if (sp->has_minor)
		w32(w, sp->minor);
	w32(w, sp->operation ? 1u : 0u);
	if (sp->operation)
		wstr(w, sp->operation);
	w32(w, sp->tkind);
	wstr(w, sp->path);
	w32(w, sp->part);
	w32(w, sp->npreds);
	for (uint32_t i = 0; i < sp->npreds; i++) {
		const struct pred *p = &sp->preds[i];

		wref(w, &p->lhs);
		w32(w, p->op);
		w32(w, p->is_ref ? 1u : 0u);
		if (p->is_ref)
			wref(w, &p->ref);
		else
			wlit(w, &p->lit);
	}
	w32(w, sp->mkind);
	w32(w, (uint32_t)sp->has_xf);
	if (sp->has_xf) {
		w32(w, sp->xkind);
		if (sp->xkind == NFSP_XF_LITERAL) {
			wlit(w, &sp->xlit);
		} else if (sp->xkind == NFSP_XF_COPY) {
			wref(w, &sp->xsrc);
		} else {
			wstr(w, sp->builtin);
			w32(w, 1);
			wlit(w, &sp->xlit);
		}
	}
	w32(w, sp->policy);
	wdeps(w, &sp->fwd);
	wdeps(w, &sp->orig);
	w32(w, sp->app);
}

static void wset(struct w *w, const char *schema_id, const struct spec *sp,
		 uint32_t n)
{
	w->n = 0;
	memcpy(w->b, NFSP_RULESET_MAGIC, 8);
	w->n = 8;
	w32(w, NFSP_SEMANTIC_RUNTIME_VERSION);
	wstr(w, schema_id);
	wstr(w, "VC-1");
	w32(w, n);
	for (uint32_t i = 0; i < n; i++)
		wrule(w, &sp[i]);
}

/* The golden set, word by word: one CALL rule that raises
 * SEQUENCE.args.sa_slotid to 7 when it is above 3. */
static const uint8_t golden[] = {
	'N', 'F', 'S', 'P', 'R', 'U', 'L', '1',
	0, 0, 0, 1,				/* semantic_runtime_version */
	0, 0, 0, 8, 'n', 'f', 's', '4', '.', '1', '/', 'x',	/* schema_id */
	0, 0, 0, 4, 'V', 'C', '-', '1',		/* candidate_id */
	0, 0, 0, 1,				/* rules<> count */
	0, 0, 0, 2, 'r', '1', 0, 0,		/* rule_id, padded */
	0, 0, 0, 2, 'i', '1', 0, 0,		/* intent_id */
	0, 0, 0, 0,				/* direction C2S */
	0, 0, 0, 1,				/* backend */
	0, 0, 0, 2,				/* client */
	0, 0, 0, 0,				/* message_type call */
	0, 0x01, 0x86, 0xa3,			/* program 100003 */
	0, 0, 0, 4,				/* version */
	0, 0, 0, 1, 0, 0, 0, 1,			/* *procedure = 1 */
	0, 0, 0, 4, 'n', 'f', 's', '4',		/* family */
	0, 0, 0, 1, 0, 0, 0, 4,			/* *nfs_version = 4 */
	0, 0, 0, 1, 0, 0, 0, 1,			/* *minor_version = 1 */
	0, 0, 0, 1,				/* *operation */
	0, 0, 0, 8, 'S', 'E', 'Q', 'U', 'E', 'N', 'C', 'E',
	0, 0, 0, 0,				/* target kind field */
	0, 0, 0, 36,				/* target path */
	'n', 'f', 's', '4', '.', 'r', 'e', 'q', 'u', 'e', 's', 't',
	'.', 'S', 'E', 'Q', 'U', 'E', 'N', 'C', 'E', '.', 'a', 'r',
	'g', 's', '.', 's', 'a', '_', 's', 'l', 'o', 't', 'i', 'd',
	0, 0, 0, 0,				/* part value */
	0, 0, 0, 1,				/* predicates<> count */
	0, 0, 0, 0, 0, 0, 0, 0,			/* lhs: target, "" */
	0, 0, 0, 4,				/* gt */
	0, 0, 0, 0,				/* rhs: literal */
	0, 0, 0, 1, 0, 0, 0, 3,			/* unsigned 3 */
	0, 0, 0, 0,				/* replace */
	0, 0, 0, 1,				/* *transform */
	0, 0, 0, 0,				/* literal */
	0, 0, 0, 1, 0, 0, 0, 7,			/* unsigned 7 */
	0, 0, 0, 0,				/* preserve */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* forwarded: none */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* original: none */
	0, 0, 0, 0,				/* all_matches */
};

#define SEQ_SLOTID "nfs4.request.SEQUENCE.args.sa_slotid"

static struct spec golden_spec(void)
{
	struct spec sp;

	memset(&sp, 0, sizeof(sp));
	sp.rule_id = "r1";
	sp.intent_id = "i1";
	sp.dir = NFSP_RULE_C2S;
	sp.backend = 1;
	sp.client = 2;
	sp.msg = NFSP_RULE_CALL;
	sp.prog = NFS4_PROG;
	sp.vers = 4;
	sp.has_proc = 1;
	sp.proc = 1;
	sp.family = "nfs4";
	sp.has_nfsv = 1;
	sp.nfsv = 4;
	sp.has_minor = 1;
	sp.minor = 1;
	sp.operation = "SEQUENCE";
	sp.tkind = NFSP_RULE_FIELD;
	sp.path = SEQ_SLOTID;
	sp.part = NFSP_PART_VALUE;
	sp.npreds = 1;
	sp.preds[0].lhs.source = NFSP_SRC_TARGET;
	sp.preds[0].op = NFSP_CMP_GT;
	sp.preds[0].lit.kind = NFSP_LIT_UINT;
	sp.preds[0].lit.num = 3;
	sp.mkind = NFSP_MUT_REPLACE;
	sp.has_xf = 1;
	sp.xkind = NFSP_XF_LITERAL;
	sp.xlit.kind = NFSP_LIT_UINT;
	sp.xlit.num = 7;
	sp.policy = NFSP_POLICY_PRESERVE;
	sp.app = NFSP_APPLY_ALL_MATCHES;
	return sp;
}

static void test_golden(void)
{
	struct nfsp_ruleset rs;
	struct nfsp_rule_error err;
	struct spec sp = golden_spec();
	const struct nfsp_rule *r;
	struct w w;

	printf("format: golden vector\n");
	CHECK(nfsp_ruleset_parse(golden, sizeof(golden), &rs, &err) ==
	      NFSP_RULE_OK, "golden: %s at %u: %s",
	      nfsp_rule_strstatus(err.status), err.offset, err.detail);
	if (err.status)
		return;
	CHECK(rs.semantic_runtime_version == 1 &&
	      !strcmp(rs.schema_id, "nfs4.1/x") &&
	      !strcmp(rs.candidate_id, "VC-1") && rs.nrules == 1, "header");
	r = &rs.rules[0];
	CHECK(!strcmp(r->rule_id, "r1") && !strcmp(r->intent_id, "i1") &&
	      r->direction == NFSP_RULE_C2S && r->backend == 1 &&
	      r->client == 2, "identity and scope");
	CHECK(r->message_type == NFSP_RULE_CALL && r->program == NFS4_PROG &&
	      r->version == 4 && r->has_procedure && r->procedure == 1 &&
	      !strcmp(r->family, "nfs4") && r->has_nfs_version &&
	      r->nfs_version == 4 && r->has_minor_version &&
	      r->minor_version == 1 && !strcmp(r->operation, "SEQUENCE"),
	      "selector");
	CHECK(r->target_kind == NFSP_RULE_FIELD &&
	      !strcmp(r->target_path, SEQ_SLOTID) &&
	      r->part == NFSP_PART_VALUE, "target");
	CHECK(r->npredicates == 1 &&
	      r->predicates[0].lhs.source == NFSP_SRC_TARGET &&
	      !strcmp(r->predicates[0].lhs.path, "") &&
	      r->predicates[0].op == NFSP_CMP_GT &&
	      r->predicates[0].rhs_kind == NFSP_OPND_LITERAL &&
	      r->predicates[0].rhs_literal.kind == NFSP_LIT_UINT &&
	      r->predicates[0].rhs_literal.num == 3, "predicate");
	CHECK(r->kind == NFSP_MUT_REPLACE && r->has_transform &&
	      r->transform.kind == NFSP_XF_LITERAL &&
	      r->transform.value.kind == NFSP_LIT_UINT &&
	      r->transform.value.num == 7 &&
	      r->policy == NFSP_POLICY_PRESERVE, "mutation");
	CHECK(!r->forwarded.rpc_procedure &&
	      !r->forwarded.request_operation_sequence &&
	      !r->forwarded.nfields && !r->original.nfields &&
	      r->application == NFSP_APPLY_ALL_MATCHES, "dependencies");
	nfsp_ruleset_free(&rs);

	/* The builder the other tests use writes exactly these bytes. */
	wset(&w, "nfs4.1/x", &sp, 1);
	CHECK(w.n == sizeof(golden) && !memcmp(w.b, golden, w.n),
	      "builder differs from the golden vector");

	/* Valid against the real 4.1 schema too. */
	wset(&w, v41()->schema_id, &sp, 1);
	CHECK(nfsp_ruleset_load(w.b, w.n, fams, NFAMS, &rs, &err) ==
	      NFSP_RULE_OK, "golden rule on 4.1: %s rule %u: %s",
	      nfsp_rule_strstatus(err.status), err.rule,
	      err.detail ? err.detail : "");
	CHECK(rs.schema == v41() && rs.rules[0].target.type < v41()->ntypes,
	      "validation binds the schema and the target");
	nfsp_ruleset_free(&rs);
}

static void test_prefixes(void)
{
	struct nfsp_ruleset rs;
	struct nfsp_rule_error err;
	unsigned bad = 0;

	printf("format: every proper prefix is refused\n");
	for (size_t n = 0; n < sizeof(golden); n++) {
		enum nfsp_rule_status st =
			nfsp_ruleset_parse(golden, n, &rs, &err);

		if (st != NFSP_RULE_MALFORMED || rs.rules || rs.arena)
			bad++;
	}
	CHECK(bad == 0, "%u prefixes were not refused cleanly", bad);
}

static void put_word(uint8_t *b, size_t at, uint32_t v)
{
	b[at] = (uint8_t)(v >> 24);
	b[at + 1] = (uint8_t)(v >> 16);
	b[at + 2] = (uint8_t)(v >> 8);
	b[at + 3] = (uint8_t)v;
}

/* The golden vector with the word at `at` replaced. */
static void malformed_word(size_t at, uint32_t v, enum nfsp_rule_status want,
			   size_t want_off, const char *what)
{
	uint8_t b[sizeof(golden)];
	struct nfsp_ruleset rs;
	struct nfsp_rule_error err;

	memcpy(b, golden, sizeof(b));
	put_word(b, at, v);
	CHECK(nfsp_ruleset_parse(b, sizeof(b), &rs, &err) == want &&
	      err.offset == want_off, "%s: %s at %u (%s), want %s at %zu",
	      what, nfsp_rule_strstatus(err.status), err.offset,
	      err.detail ? err.detail : "", nfsp_rule_strstatus(want),
	      want_off);
}

static enum nfsp_rule_status parse_spec(const struct spec *sp, uint32_t n,
					struct nfsp_rule_error *err)
{
	struct nfsp_ruleset rs;
	struct w w;
	enum nfsp_rule_status st;

	wset(&w, "s", sp, n);
	st = nfsp_ruleset_parse(w.b, w.n, &rs, err);
	nfsp_ruleset_free(&rs);
	return st;
}

static void test_canonical(void)
{
	struct nfsp_ruleset rs;
	struct nfsp_rule_error err;
	struct spec two[2];
	struct spec sp;

	printf("format: canonical form\n");
	malformed_word(0, 0x4e465351u, NFSP_RULE_MALFORMED, 0, "magic NFSQ");
	malformed_word(8, 2, NFSP_RULE_UNSUPPORTED_VERSION, 8, "version 2");
	malformed_word(12, 240, NFSP_RULE_MALFORMED, 12,
		       "schema_id length beyond the input");
	malformed_word(12, NFSP_RULE_SCHEMA_ID_MAX + 1u, NFSP_RULE_MALFORMED, 12,
		       "schema_id length beyond its bound");
	malformed_word(32, NFSP_RULES_MAX + 1u, NFSP_RULE_MALFORMED, 32,
		       "rule count beyond its bound");
	malformed_word(32, 2, NFSP_RULE_MALFORMED, sizeof(golden),
		       "a rule count the input does not hold");
	malformed_word(32, 0, NFSP_RULE_MALFORMED, 36,
		       "a rule the count does not cover");
	malformed_word(32, 100, NFSP_RULE_MALFORMED, 32,
		       "more rules than the input can hold");
	malformed_word(52, 2, NFSP_RULE_MALFORMED, 52, "direction 2");
	malformed_word(64, 2, NFSP_RULE_MALFORMED, 64, "message type 2");
	malformed_word(76, 2, NFSP_RULE_MALFORMED, 76, "optional flag 2");
	malformed_word(48, 0x69310100u, NFSP_RULE_MALFORMED, 50,
		       "non-zero padding");
	malformed_word(40, 0x72000000u, NFSP_RULE_MALFORMED, 41,
		       "a NUL in a name");
	malformed_word(168, 6, NFSP_RULE_MALFORMED, 168, "part 6");
	malformed_word(172, NFSP_RULE_PREDICATES_MAX + 1u, NFSP_RULE_MALFORMED,
		       172, "17 predicates");
	malformed_word(172, NFSP_RULE_PREDICATES_MAX, NFSP_RULE_MALFORMED,
		       172, "more predicates than the input can hold");
	malformed_word(204, 2, NFSP_RULE_MALFORMED, 204, "transform flag 2");
	malformed_word(220, 2, NFSP_RULE_MALFORMED, 220, "policy 2");
	malformed_word(224, 2, NFSP_RULE_MALFORMED, 224,
		       "rpc_procedure dependency 2");

	/* One byte too many. */
	{
		uint8_t b[sizeof(golden) + 4];

		memcpy(b, golden, sizeof(golden));
		memset(b + sizeof(golden), 0, 4);
		CHECK(nfsp_ruleset_parse(b, sizeof(b), &rs, &err) ==
		      NFSP_RULE_MALFORMED && err.offset == sizeof(golden),
		      "trailing bytes: %s at %u",
		      nfsp_rule_strstatus(err.status), err.offset);
	}
	CHECK(nfsp_ruleset_parse(golden, NFSP_RULESET_MAX_LEN + 1u, &rs,
				 &err) == NFSP_RULE_MALFORMED,
	      "a set beyond the size bound");
	CHECK(nfsp_ruleset_parse(NULL, 0, &rs, &err) == NFSP_RULE_MALFORMED &&
	      !strcmp(err.detail, "no buffer"), "no buffer: %s", err.detail);

	/* Rules in rule_id order, each id once: one encoding per set. */
	two[0] = golden_spec();
	two[1] = golden_spec();
	two[1].rule_id = "r2";
	CHECK(parse_spec(two, 2, &err) == NFSP_RULE_OK, "two rules: %s",
	      nfsp_rule_strstatus(err.status));
	two[0].rule_id = "r3";
	CHECK(parse_spec(two, 2, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 1, "descending rule ids: %s",
	      nfsp_rule_strstatus(err.status));
	two[0].rule_id = "r2";
	CHECK(parse_spec(two, 2, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 1, "duplicate rule ids");

	sp = golden_spec();
	sp.fwd.n = 2;
	sp.fwd.fields[0] = "nfs4.request.b";
	sp.fwd.fields[1] = "nfs4.request.a";
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "request fields out of order");
	sp.fwd.fields[1] = "nfs4.request.b";
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "a request field twice");

	sp = golden_spec();
	sp.preds[0].lhs.path = SEQ_SLOTID;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 0, "a target ValueRef with a path");
	sp = golden_spec();
	sp.preds[0].lhs.source = NFSP_SRC_CURRENT_MESSAGE;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "a message ValueRef without a path");
	sp = golden_spec();
	sp.npreds = 4;
	for (uint32_t i = 1; i < 4; i++)
		sp.preds[i] = sp.preds[0];
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_OK, "four predicates");

	/* A malformed predicate names itself, as a type error does (PR #33
	 * review); a fault after the predicates names none. */
	sp = golden_spec();
	sp.npreds = 2;
	sp.preds[1] = sp.preds[0];
	sp.preds[1].op = NFSP_CMP_GE + 1u;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 0 && err.predicate == 1,
	      "second comparison out of range: %s rule %u predicate %u",
	      nfsp_rule_strstatus(err.status), err.rule, err.predicate);
	sp.preds[1] = sp.preds[0];
	sp.preds[1].lit.kind = NFSP_LIT_BOOL;
	sp.preds[1].lit.num = 2;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 0 && err.predicate == 1,
	      "second predicate bool 2: predicate %u", err.predicate);
	sp.preds[1] = sp.preds[0];
	sp.preds[1].lhs.path = SEQ_SLOTID;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 0 && err.predicate == 1,
	      "second predicate target with a path: predicate %u",
	      err.predicate);
	sp.preds[0].op = NFSP_CMP_GE + 1u;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED &&
	      err.predicate == 0, "first predicate: predicate %u",
	      err.predicate);
	sp = golden_spec();
	sp.npreds = 2;
	sp.preds[1] = sp.preds[0];
	sp.mkind = NFSP_MUT_OP_PREPEND + 1u;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 0 && err.predicate == NFSP_RULE_NONE,
	      "mutation kind after two predicates: predicate %u",
	      err.predicate);
	two[0] = golden_spec();
	two[1] = golden_spec();
	two[1].rule_id = "r2";
	two[1].preds[0].op = NFSP_CMP_GE + 1u;
	CHECK(parse_spec(two, 2, &err) == NFSP_RULE_MALFORMED &&
	      err.rule == 1 && err.predicate == 0,
	      "second rule's predicate: rule %u predicate %u", err.rule,
	      err.predicate);
	CHECK(nfsp_ruleset_parse(golden, sizeof(golden) - 1u, &rs, &err) ==
	      NFSP_RULE_MALFORMED && err.rule == 0 &&
	      err.predicate == NFSP_RULE_NONE,
	      "a cut after the predicates: predicate %u", err.predicate);
	sp = golden_spec();
	sp.preds[0].lit.kind = NFSP_LIT_BOOL;
	sp.preds[0].lit.num = 2;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "a bool literal of 2");
	sp = golden_spec();
	sp.preds[0].lit.kind = 8;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "literal kind 8");
	sp = golden_spec();
	sp.app = 1;
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "an application mode other than all_matches");
	sp = golden_spec();
	sp.family = "";
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "an empty family");
	sp = golden_spec();
	sp.path = "nfs4.request.SEQUENCE args";
	CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
	      "a space in a path");

	/* Bounds: a literal of 4097 bytes. */
	sp = golden_spec();
	{
		static char lot[NFSP_RULE_LITERAL_MAX + 1u];

		memset(lot, 'a', sizeof(lot));
		sp.xlit.kind = NFSP_LIT_OPAQUE;
		sp.xlit.bytes = lot;
		sp.xlit.len = NFSP_RULE_LITERAL_MAX;
		CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_OK,
		      "a literal at the bound");
		sp.xlit.len = NFSP_RULE_LITERAL_MAX + 1u;
		CHECK(parse_spec(&sp, 1, &err) == NFSP_RULE_MALFORMED,
		      "a literal beyond the bound");
	}
}

/* Operation unions outside an operation array (PR #33 review): tedge has
 * one as the whole argument of DIRECT and one as a member of EMBEDDED's.
 * The decoder emits each operation only as its own root, so the container
 * paths name nothing, and a rule on one is refused (test_nfs_decode checks
 * the decoder side). */
static void test_resolve_op_containers(void)
{
	const struct nfsp_protocol_schema *s = nfsp_schema_family_tedge.schemas[0];
	static const char *const none[][2] = {
		{ "0", "tedge.request.DIRECT.args" },
		{ "0", "tedge.request.DIRECT.args.argop" },
		{ "0", "tedge.request.DIRECT.args.args.value" },
		{ "0", "tedge.request.EMBEDDED.args.operation" },
		{ "0", "tedge.request.EMBEDDED.args.operation.argop" },
		{ "1", "tedge.response.DIRECT.result" },
		{ "1", "tedge.response.EMBEDDED.result.operation" },
		{ "1", "tedge.response.EMBEDDED.result.operation.result" },
	};
	struct nfsp_schema_node n;
	struct nfsp_ruleset rs;
	struct nfsp_rule_error err;
	const struct nfsp_schema_family *const tf[] = {
		&nfsp_schema_family_tedge,
	};
	struct spec sp;
	struct w w;

	printf("resolve: operation unions outside an operation array\n");
	for (size_t i = 0; i < sizeof(none) / sizeof(none[0]); i++)
		CHECK(nfsp_schema_resolve(s, none[i][0][0] == '1', none[i][1],
					  &n) == NFSP_SCHEMA_NOT_FOUND,
		      "%s resolved", none[i][1]);
	CHECK(nfsp_schema_resolve(s, 0, "tedge.request.EMBEDDED.args", &n) ==
	      NFSP_SCHEMA_FOUND && n.flags == NFSP_SN_ROOT,
	      "EMBEDDED args");
	CHECK(nfsp_schema_resolve(s, 0, "tedge.request.EMBEDDED.args.tag",
				  &n) == NFSP_SCHEMA_FOUND && n.flags == 0,
	      "EMBEDDED args.tag");
	CHECK(nfsp_schema_resolve(s, 0, "tedge.request.ECHO", &n) ==
	      NFSP_SCHEMA_FOUND &&
	      n.flags == (NFSP_SN_ROOT | NFSP_SN_OPERATION) && !n.proc,
	      "ECHO root");
	CHECK(nfsp_schema_resolve(s, 1, "tedge.response.ECHO.result.value",
				  &n) == NFSP_SCHEMA_FOUND &&
	      n.flags == NFSP_SN_OPERATION, "ECHO result value");

	/* The reviewer's rule: a raw edit of the discriminant word at the
	 * DIRECT argument path loaded; it names no node the decoder emits. */
	memset(&sp, 0, sizeof(sp));
	sp.rule_id = "r1";
	sp.intent_id = "i1";
	sp.msg = NFSP_RULE_CALL;
	sp.prog = 0x2000009bu;
	sp.vers = 1;
	sp.has_proc = 1;
	sp.proc = 1;
	sp.family = "tedge";
	sp.tkind = NFSP_RULE_FIELD;
	sp.path = "tedge.request.DIRECT.args";
	sp.part = NFSP_PART_DISCRIMINANT;
	sp.mkind = NFSP_MUT_REPLACE;
	sp.has_xf = 1;
	sp.xkind = NFSP_XF_LITERAL;
	sp.xlit.kind = NFSP_LIT_UINT;
	sp.xlit.num = 2;
	sp.policy = NFSP_POLICY_RAW;
	wset(&w, s->schema_id, &sp, 1);
	CHECK(nfsp_ruleset_load(w.b, w.n, tf, 1, &rs, &err) ==
	      NFSP_RULE_UNKNOWN_PATH && err.rule == 0,
	      "DIRECT args discriminant: %s", nfsp_rule_strstatus(err.status));
	nfsp_ruleset_free(&rs);
	sp.path = "tedge.request.EMBEDDED.args.operation";
	sp.proc = 2;
	wset(&w, s->schema_id, &sp, 1);
	CHECK(nfsp_ruleset_load(w.b, w.n, tf, 1, &rs, &err) ==
	      NFSP_RULE_UNKNOWN_PATH && err.rule == 0,
	      "EMBEDDED operation discriminant: %s",
	      nfsp_rule_strstatus(err.status));
	nfsp_ruleset_free(&rs);

	/* The same edit named by the operation's own root loads, in both
	 * procedures. */
	sp.path = "tedge.request.ECHO";
	sp.operation = "ECHO";
	for (sp.proc = 1; sp.proc <= 2; sp.proc++) {
		wset(&w, s->schema_id, &sp, 1);
		CHECK(nfsp_ruleset_load(w.b, w.n, tf, 1, &rs, &err) ==
		      NFSP_RULE_OK, "ECHO discriminant in procedure %u: %s",
		      sp.proc, nfsp_rule_strstatus(err.status));
		nfsp_ruleset_free(&rs);
	}
}

/* ---- validation ---- */

#define OPEN_OTHER	"nfs4.response.OPEN.result.ok.stateid.other"
#define OPEN_STATUS	"nfs4.response.OPEN.result.status"
#define OPEN_FILE	"nfs4.request.OPEN.args.claim.claim_null.file"

/* A valid REPLY rule (design 08 §8): forge the stateid of a successful
 * OPEN of "scenario-file". */
static struct spec open_spec(void)
{
	struct spec sp;

	memset(&sp, 0, sizeof(sp));
	sp.rule_id = "r-open";
	sp.intent_id = "forge-open-stateid";
	sp.dir = NFSP_RULE_S2C;
	sp.msg = NFSP_RULE_REPLY;
	sp.prog = NFS4_PROG;
	sp.vers = 4;
	sp.has_proc = 1;
	sp.proc = 1;
	sp.family = "nfs4";
	sp.has_minor = 1;
	sp.minor = 1;
	sp.operation = "OPEN";
	sp.tkind = NFSP_RULE_FIELD;
	sp.path = OPEN_OTHER;
	sp.part = NFSP_PART_VALUE;
	sp.npreds = 2;
	sp.preds[0].lhs.source = NFSP_SRC_CURRENT_MESSAGE;
	sp.preds[0].lhs.path = OPEN_STATUS;
	sp.preds[0].op = NFSP_CMP_EQ;
	sp.preds[0].lit.kind = NFSP_LIT_ENUM;
	sp.preds[0].lit.num = NFS4_OK;
	sp.preds[1].lhs.source = NFSP_SRC_REQUEST_FORWARDED;
	sp.preds[1].lhs.path = OPEN_FILE;
	sp.preds[1].op = NFSP_CMP_EQ;
	sp.preds[1].lit.kind = NFSP_LIT_OPAQUE;
	sp.preds[1].lit.bytes = "scenario-file";
	sp.preds[1].lit.len = 13;
	sp.mkind = NFSP_MUT_REPLACE;
	sp.has_xf = 1;
	sp.xkind = NFSP_XF_LITERAL;
	sp.xlit.kind = NFSP_LIT_OPAQUE;
	sp.xlit.bytes = "forged-other";
	sp.xlit.len = 12;
	sp.policy = NFSP_POLICY_PRESERVE;
	sp.fwd.proc = 1;
	sp.fwd.opseq = 1;
	sp.fwd.n = 1;
	sp.fwd.fields[0] = OPEN_FILE;
	sp.app = NFSP_APPLY_ALL_MATCHES;
	return sp;
}

static enum nfsp_rule_status load(const struct spec *sp, uint32_t n,
				  struct nfsp_rule_error *err)
{
	struct nfsp_ruleset rs;
	struct w w;
	enum nfsp_rule_status st;

	wset(&w, v41()->schema_id, sp, n);
	st = nfsp_ruleset_load(w.b, w.n, fams, NFAMS, &rs, err);
	CHECK(st == NFSP_RULE_OK || (!rs.rules && !rs.arena && !rs.schema),
	      "a refused set left storage behind");
	nfsp_ruleset_free(&rs);
	return st;
}

static void expect(const struct spec *sp, enum nfsp_rule_status want,
		   uint32_t pred, int line)
{
	struct nfsp_rule_error err;
	enum nfsp_rule_status st = load(sp, 1, &err);

	CHECK(st == want && (want == NFSP_RULE_OK ||
			     (err.rule == 0 && err.predicate == pred)),
	      "line %d: %s (rule %u predicate %u: %s), want %s", line,
	      nfsp_rule_strstatus(st), err.rule, err.predicate,
	      err.detail ? err.detail : "", nfsp_rule_strstatus(want));
}

#define OK(sp)			expect(&(sp), NFSP_RULE_OK, 0, __LINE__)
#define REFUSED(sp, st)		expect(&(sp), st, NFSP_RULE_NONE, __LINE__)
#define REFUSED_AT(sp, st, p)	expect(&(sp), st, p, __LINE__)

static void test_valid(void)
{
	struct nfsp_ruleset rs;
	struct nfsp_rule_error err;
	struct spec sp = open_spec();
	const struct nfsp_rule *r;
	struct w w;

	printf("validate: supported rule shapes\n");
	wset(&w, v41()->schema_id, &sp, 1);
	CHECK(nfsp_ruleset_load(w.b, w.n, fams, NFAMS, &rs, &err) ==
	      NFSP_RULE_OK, "open rule: %s rule %u predicate %u: %s",
	      nfsp_rule_strstatus(err.status), err.rule, err.predicate,
	      err.detail ? err.detail : "");
	if (!err.status) {
		const struct nfsp_protocol_schema *s = v41();

		r = &rs.rules[0];
		CHECK(s->types[r->target.type].kind == NFSP_XK_OPAQUE_FIXED &&
		      s->types[r->target.type].bound == 12 &&
		      (r->target.flags & NFSP_SN_OPERATION) &&
		      !strcmp(r->target.root, "OPEN"), "target node");
		CHECK(s->types[r->predicates[0].lhs.node.type].kind ==
		      NFSP_XK_ENUM && (r->predicates[0].lhs.node.flags &
				       NFSP_SN_DISCRIMINANT),
		      "status node");
		CHECK(s->types[r->predicates[1].lhs.node.type].kind ==
		      NFSP_XK_OPAQUE_VAR, "request field node");
	}
	nfsp_ruleset_free(&rs);

	/* No procedure, no minor: the dependencies follow. */
	sp = open_spec();
	sp.has_proc = 0;
	sp.has_minor = 0;
	sp.fwd.proc = 0;
	OK(sp);

	/* Copy one uint into another of the same CALL. */
	sp = golden_spec();
	sp.npreds = 0;
	sp.path = "nfs4.request.SEQUENCE.args.sa_sequenceid";
	sp.xkind = NFSP_XF_COPY;
	sp.xsrc.source = NFSP_SRC_CURRENT_MESSAGE;
	sp.xsrc.path = SEQ_SLOTID;
	OK(sp);

	/* A request field compared with a response field. */
	sp = open_spec();
	sp.preds[1].op = NFSP_CMP_NE;
	OK(sp);

	/* Raw metadata: an opaque's length word, the operation count, a
	 * union's discriminant word, padding bytes. */
	sp = golden_spec();
	sp.npreds = 0;
	sp.operation = "OPEN";
	sp.path = "nfs4.request.OPEN.args.owner.owner";
	sp.part = NFSP_PART_LENGTH;
	sp.policy = NFSP_POLICY_RAW;
	OK(sp);
	sp.part = NFSP_PART_PADDING;
	sp.xlit.kind = NFSP_LIT_OPAQUE;
	sp.xlit.bytes = "\1\2";
	sp.xlit.len = 2;
	OK(sp);
	sp = golden_spec();
	sp.npreds = 0;
	sp.operation = NULL;
	sp.path = "nfs4.request.COMPOUND.args.argarray";
	sp.part = NFSP_PART_COUNT;
	sp.policy = NFSP_POLICY_RAW;
	OK(sp);
	sp = golden_spec();
	sp.npreds = 0;
	sp.operation = "OPEN";
	sp.path = "nfs4.request.OPEN.args.claim";
	sp.part = NFSP_PART_DISCRIMINANT;
	sp.policy = NFSP_POLICY_RAW;
	OK(sp);

	/* The discriminant node itself, raw: a declared value of its type. */
	sp.path = "nfs4.request.OPEN.args.claim.claim";
	sp.part = NFSP_PART_VALUE;
	sp.xlit.kind = NFSP_LIT_ENUM;
	sp.xlit.num = CLAIM_PREVIOUS;
	OK(sp);

	/* An ordered comparison on a hyper; a bool. */
	sp = golden_spec();
	sp.operation = "READDIR";
	sp.path = "nfs4.request.READDIR.args.cookie";
	sp.preds[0].lit.kind = NFSP_LIT_UHYPER;
	sp.preds[0].lit.num = 1ull << 40;
	sp.xlit.kind = NFSP_LIT_UHYPER;
	sp.xlit.num = ~0ull;
	OK(sp);
	sp = golden_spec();
	sp.npreds = 0;
	sp.path = "nfs4.request.SEQUENCE.args.sa_cachethis";
	sp.xlit.kind = NFSP_LIT_BOOL;
	sp.xlit.num = 1;
	OK(sp);
}

static void test_refusals(void)
{
	struct nfsp_rule_error err;
	struct nfsp_ruleset rs;
	struct spec sp, two[2];
	struct w w;

	printf("validate: one refusal per status\n");

	wset(&w, "nfs4.1/sha256:0000", &sp, 0);
	CHECK(nfsp_ruleset_load(w.b, w.n, fams, NFAMS, &rs, &err) ==
	      NFSP_RULE_UNKNOWN_SCHEMA && !rs.arena, "unknown schema_id");

	sp = open_spec(); sp.family = "nfs3";
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);
	sp = open_spec(); sp.prog = 100005;
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);
	sp = open_spec(); sp.has_nfsv = 1; sp.nfsv = 3;
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);
	sp = open_spec(); sp.minor = 2;
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);
	sp = open_spec(); sp.proc = 7;
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);
	sp = open_spec(); sp.proc = 0; sp.fwd.proc = 1;
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);	/* NULL has no OPEN */
	sp = open_spec(); sp.operation = NULL;
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);
	sp = open_spec(); sp.operation = "CLOSE";
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);
	sp = golden_spec(); sp.path = "nfs4.request.COMPOUND.args.tag";
	REFUSED(sp, NFSP_RULE_SELECTOR_MISMATCH);	/* operation given */

	sp = open_spec(); sp.msg = NFSP_RULE_CALL;
	REFUSED(sp, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT);
	sp = golden_spec(); sp.msg = NFSP_RULE_REPLY;
	REFUSED(sp, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT);
	sp = golden_spec();
	sp.preds[0].lhs.source = NFSP_SRC_REQUEST_FORWARDED;
	sp.preds[0].lhs.path = SEQ_SLOTID;
	REFUSED_AT(sp, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT, 0);
	sp = open_spec(); sp.preds[1].lhs.path = OPEN_OTHER;
	REFUSED_AT(sp, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT, 1);
	load(&sp, 1, &err);
	CHECK(!strcmp(err.detail, "a response path in a request view"),
	      "request view detail: %s", err.detail);
	sp = open_spec(); sp.has_xf = 1; sp.xkind = NFSP_XF_COPY;
	sp.xsrc.source = NFSP_SRC_REQUEST_FORWARDED; sp.xsrc.path = OPEN_OTHER;
	REFUSED(sp, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT);
	load(&sp, 1, &err);
	CHECK(!strcmp(err.detail, "a response path in a request view"),
	      "copy from a request view detail: %s", err.detail);
	sp = open_spec();
	sp.preds[0].lhs.path = "nfs4.request.OPEN.args.seqid";
	REFUSED_AT(sp, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT, 0);

	sp = open_spec(); sp.path = "nfs4.response.OPEN.result.ok.stateid.x";
	REFUSED(sp, NFSP_RULE_UNKNOWN_PATH);
	sp = open_spec(); sp.path = "nfs4.response.SEEK.result.status";
	REFUSED(sp, NFSP_RULE_UNKNOWN_PATH);	/* a 4.2 operation */
	sp = open_spec(); sp.preds[0].lhs.path = "nfs4.response.OPEN.x";
	REFUSED_AT(sp, NFSP_RULE_UNKNOWN_PATH, 0);

	sp = open_spec(); sp.part = NFSP_PART_LENGTH;
	REFUSED(sp, NFSP_RULE_PART_UNAVAILABLE);
	sp.part = NFSP_PART_PADDING;			/* opaque[12] */
	REFUSED(sp, NFSP_RULE_PART_UNAVAILABLE);
	sp.part = NFSP_PART_COUNT;
	REFUSED(sp, NFSP_RULE_PART_UNAVAILABLE);
	sp.part = NFSP_PART_DISCRIMINANT;
	REFUSED(sp, NFSP_RULE_PART_UNAVAILABLE);
	sp = golden_spec(); sp.npreds = 0; sp.operation = NULL;
	sp.path = "nfs4.request.COMPOUND.args.argarray";
	sp.tkind = NFSP_RULE_OPERATION_ARRAY; sp.part = NFSP_PART_COUNT;
	sp.mkind = NFSP_MUT_OP_APPEND; sp.has_xf = 0;
	REFUSED(sp, NFSP_RULE_PART_UNAVAILABLE);

	sp = open_spec(); sp.preds[0].lit.kind = NFSP_LIT_UINT;
	REFUSED_AT(sp, NFSP_RULE_TYPE_MISMATCH, 0);	/* enum vs uint */
	sp = open_spec(); sp.preds[0].lit.num = 99999;
	REFUSED_AT(sp, NFSP_RULE_TYPE_MISMATCH, 0);	/* undeclared */
	sp = open_spec(); sp.preds[0].op = NFSP_CMP_LT;
	REFUSED_AT(sp, NFSP_RULE_TYPE_MISMATCH, 0);	/* enums: no order */
	sp = open_spec(); sp.preds[1].lit.kind = NFSP_LIT_STRING;
	REFUSED_AT(sp, NFSP_RULE_TYPE_MISMATCH, 1);	/* opaque<> field */
	sp = open_spec();
	sp.preds[1].lhs.path = "nfs4.request.OPEN.args.owner";
	REFUSED_AT(sp, NFSP_RULE_TYPE_MISMATCH, 1);	/* a struct */
	sp = open_spec();
	sp.preds[0].is_ref = 1;
	sp.preds[0].ref.source = NFSP_SRC_CURRENT_MESSAGE;
	sp.preds[0].ref.path = "nfs4.response.OPEN.result.ok.rflags";
	REFUSED_AT(sp, NFSP_RULE_TYPE_MISMATCH, 0);	/* enum vs uint */
	sp = open_spec(); sp.xlit.len = 11;
	REFUSED(sp, NFSP_RULE_TYPE_MISMATCH);		/* opaque[12] */
	sp = open_spec(); sp.xlit.kind = NFSP_LIT_STRING;
	REFUSED(sp, NFSP_RULE_TYPE_MISMATCH);
	sp = golden_spec(); sp.xlit.kind = NFSP_LIT_INT;
	REFUSED(sp, NFSP_RULE_TYPE_MISMATCH);		/* no reinterpretation */
	sp = golden_spec(); sp.npreds = 0; sp.xkind = NFSP_XF_COPY;
	sp.xsrc.source = NFSP_SRC_CURRENT_MESSAGE;
	sp.xsrc.path = "nfs4.request.SEQUENCE.args.sa_cachethis";
	REFUSED(sp, NFSP_RULE_TYPE_MISMATCH);		/* bool into uint */
	sp = golden_spec(); sp.npreds = 0; sp.operation = NULL;
	sp.path = "nfs4.request.COMPOUND.args.tag";
	sp.tkind = NFSP_RULE_OPERATION_ARRAY; sp.mkind = NFSP_MUT_OP_APPEND;
	sp.has_xf = 0;
	REFUSED(sp, NFSP_RULE_TYPE_MISMATCH);	/* not an operation array */
	sp = golden_spec(); sp.npreds = 0; sp.operation = "OPEN";
	sp.path = "nfs4.request.OPEN.args.owner.owner";
	sp.part = NFSP_PART_LENGTH; sp.policy = NFSP_POLICY_RAW;
	sp.xlit.kind = NFSP_LIT_INT;
	REFUSED(sp, NFSP_RULE_TYPE_MISMATCH);	/* a length is unsigned */

	sp = open_spec(); sp.has_xf = 0;
	REFUSED(sp, NFSP_RULE_MUTATION_INVALID);
	sp = open_spec(); sp.mkind = NFSP_MUT_DELETE;
	REFUSED(sp, NFSP_RULE_MUTATION_INVALID);	/* with a transform */
	sp = open_spec(); sp.mkind = NFSP_MUT_OP_APPEND;
	REFUSED(sp, NFSP_RULE_MUTATION_INVALID);	/* on a field */
	sp = golden_spec(); sp.npreds = 0; sp.operation = NULL;
	sp.path = "nfs4.request.COMPOUND.args.argarray";
	sp.tkind = NFSP_RULE_OPERATION_ARRAY;
	REFUSED(sp, NFSP_RULE_MUTATION_INVALID);	/* replace an array */
	sp = golden_spec(); sp.npreds = 0; sp.operation = "OPEN";
	sp.path = "nfs4.request.OPEN.args.owner.owner";
	sp.part = NFSP_PART_LENGTH;
	REFUSED(sp, NFSP_RULE_MUTATION_INVALID);	/* preserve metadata */

	sp = open_spec(); sp.fwd.n = 0;
	REFUSED(sp, NFSP_RULE_DEPENDENCIES_MISMATCH);
	sp = open_spec(); sp.fwd.opseq = 0;
	REFUSED(sp, NFSP_RULE_DEPENDENCIES_MISMATCH);
	sp = open_spec(); sp.fwd.proc = 0;
	REFUSED(sp, NFSP_RULE_DEPENDENCIES_MISMATCH);
	sp = open_spec(); sp.orig = sp.fwd; sp.orig.proc = 0;
	REFUSED(sp, NFSP_RULE_DEPENDENCIES_MISMATCH);	/* wrong view */
	sp = open_spec(); sp.fwd.n = 2;
	sp.fwd.fields[1] = "nfs4.request.OPEN.args.seqid";
	REFUSED(sp, NFSP_RULE_DEPENDENCIES_MISMATCH);	/* one extra */
	/* The original view: its own sequence and the forwarded one. */
	sp = open_spec();
	sp.preds[1].lhs.source = NFSP_SRC_REQUEST_ORIGINAL;
	REFUSED(sp, NFSP_RULE_DEPENDENCIES_MISMATCH);
	sp.orig.opseq = 1;
	sp.orig.n = 1;
	sp.orig.fields[0] = OPEN_FILE;
	sp.fwd.n = 0;
	OK(sp);
	/* A request field outside an operation needs no sequence. */
	sp = open_spec();
	sp.preds[1].lhs.path = "nfs4.request.COMPOUND.args.tag";
	sp.preds[1].lit.kind = NFSP_LIT_OPAQUE;
	sp.fwd.fields[0] = "nfs4.request.COMPOUND.args.tag";
	REFUSED(sp, NFSP_RULE_DEPENDENCIES_MISMATCH);
	sp.fwd.opseq = 0;
	OK(sp);

	sp = open_spec(); sp.mkind = NFSP_MUT_INSERT;
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);
	sp = open_spec(); sp.mkind = NFSP_MUT_DELETE; sp.has_xf = 0;
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);
	sp = golden_spec(); sp.npreds = 0; sp.operation = NULL;
	sp.path = "nfs4.request.COMPOUND.args.argarray";
	sp.tkind = NFSP_RULE_OPERATION_ARRAY; sp.mkind = NFSP_MUT_OP_PREPEND;
	sp.has_xf = 0;
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);
	sp = golden_spec(); sp.xkind = NFSP_XF_BUILTIN;
	sp.builtin = "integer_add";
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);
	sp = open_spec(); sp.part = NFSP_PART_ENCODED;
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);
	sp = open_spec(); sp.path = "nfs4.response.OPEN.result.ok.stateid";
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);	/* a struct value */
	sp = golden_spec(); sp.npreds = 0; sp.operation = "OPEN";
	sp.path = "nfs4.request.OPEN.args.claim.claim";
	sp.xlit.kind = NFSP_LIT_ENUM; sp.xlit.num = CLAIM_PREVIOUS;
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);	/* preserve */
	sp = golden_spec(); sp.npreds = 0; sp.operation = "OPEN";
	sp.path = "nfs4.request.OPEN.args.owner.owner";
	sp.part = NFSP_PART_LENGTH; sp.policy = NFSP_POLICY_RAW;
	sp.xkind = NFSP_XF_COPY; sp.xsrc.source = NFSP_SRC_CURRENT_MESSAGE;
	sp.xsrc.path = SEQ_SLOTID;
	REFUSED(sp, NFSP_RULE_UNSUPPORTED_CAPABILITY);	/* copy metadata */

	/* All or nothing: a bad second rule refuses the set, and names
	 * itself. */
	two[0] = open_spec();
	two[1] = open_spec();
	two[1].rule_id = "r-open2";
	two[1].preds[0].lit.num = 99999;
	CHECK(load(two, 2, &err) == NFSP_RULE_TYPE_MISMATCH &&
	      err.rule == 1 && err.predicate == 0,
	      "second rule: %s rule %u predicate %u",
	      nfsp_rule_strstatus(err.status), err.rule, err.predicate);
}

int main(void)
{
	test_every_path();
	test_resolve_nodes();
	test_resolve_ambiguous();
	test_reaches();
	test_resolve_op_containers();
	test_golden();
	test_prefixes();
	test_canonical();
	test_valid();
	test_refusals();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
