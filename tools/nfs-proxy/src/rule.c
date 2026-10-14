/* CompiledMutationRule set: NFSPRUL1 reader and validator.  See rule.h.
 *
 * The reader trusts nothing: every count and length is checked against its
 * bound and against the bytes left before anything is allocated or copied,
 * and storage is sized from the input length up front, so no pointer handed
 * out during the parse is ever moved.
 */
#include "rule.h"

#include <stdlib.h>
#include <string.h>

/* ---- reading ---- */

struct rd {
	const uint8_t *p;
	size_t len, off;
	struct nfsp_ruleset *rs;
	struct nfsp_rule_error *err;
	size_t npreds, preds_cap;
	size_t nargs, args_cap;
	size_t nfields, fields_cap;
};

static int bad(struct rd *r, const char *detail)
{
	if (r->err->status == NFSP_RULE_OK) {
		r->err->status = NFSP_RULE_MALFORMED;
		r->err->offset = r->off > UINT32_MAX ? UINT32_MAX :
							(uint32_t)r->off;
		r->err->detail = detail;
	}
	return -1;
}

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static int u32(struct rd *r, uint32_t *v)
{
	if (r->len - r->off < 4)
		return bad(r, "ends inside a word");
	*v = get32(r->p + r->off);
	r->off += 4;
	return 0;
}

static int u64(struct rd *r, uint64_t *v)
{
	uint32_t hi, lo;

	if (u32(r, &hi) || u32(r, &lo))
		return -1;
	*v = (uint64_t)hi << 32 | lo;
	return 0;
}

/* An enum of the format: a word in 0..max. */
static int word_in(struct rd *r, uint32_t max, uint32_t *v,
		   const char *detail)
{
	size_t at = r->off;

	if (u32(r, v))
		return -1;
	if (*v > max) {
		r->off = at;
		return bad(r, detail);
	}
	return 0;
}

static int boolean(struct rd *r, int *v)
{
	uint32_t w;

	if (word_in(r, 1, &w, "bool or optional flag is not 0 or 1"))
		return -1;
	*v = (int)w;
	return 0;
}

/* opaque<bound> / string<bound>: length, bytes, zero padding. */
static int counted(struct rd *r, uint32_t bound, const uint8_t **bytes,
		   uint32_t *n)
{
	size_t at = r->off;
	uint32_t pad;

	if (u32(r, n))
		return -1;
	if (*n > bound) {
		r->off = at;
		return bad(r, "length exceeds its bound");
	}
	pad = (4u - (*n & 3u)) & 3u;
	if ((size_t)*n + pad > r->len - r->off) {
		r->off = at;
		return bad(r, "length exceeds the bytes left");
	}
	*bytes = r->p + r->off;
	for (uint32_t i = 0; i < pad; i++)
		if (r->p[r->off + *n + i]) {
			r->off += *n + i;
			return bad(r, "non-zero padding");
		}
	r->off += *n + pad;
	return 0;
}

static char *keep(struct rd *r, const uint8_t *bytes, uint32_t n)
{
	struct nfsp_ruleset *rs = r->rs;
	char *s;

	/* Sized in parse(): every string is in the input and takes at least
	 * its own length word, so this cannot run out. */
	if (rs->arena_cap - rs->arena_len < (size_t)n + 1)
		return NULL;
	s = rs->arena + rs->arena_len;
	if (n)
		memcpy(s, bytes, n);
	s[n] = '\0';
	rs->arena_len += (size_t)n + 1;
	return s;
}

/* A name in the format (id, path, family, operation): visible ASCII. */
static int name(struct rd *r, uint32_t bound, int may_be_empty,
		const char **out)
{
	const uint8_t *b;
	uint32_t n;
	size_t at = r->off;

	if (counted(r, bound, &b, &n))
		return -1;
	if (!n && !may_be_empty) {
		r->off = at;
		return bad(r, "empty name");
	}
	for (uint32_t i = 0; i < n; i++)
		if (b[i] < 0x21 || b[i] > 0x7e) {
			r->off = at + 4 + i;
			return bad(r, "name byte outside visible ASCII");
		}
	*out = keep(r, b, n);
	return *out ? 0 : bad(r, "string storage");
}

static int optional_word(struct rd *r, int *has, uint32_t *v)
{
	if (boolean(r, has))
		return -1;
	return *has ? u32(r, v) : 0;
}

/* An array count: within its bound and within `room`, what the input can
 * hold.  Either refusal names the count word. */
static int count_in(struct rd *r, uint32_t max, size_t room, uint32_t *n,
		    const char *too_many, const char *exceeds)
{
	size_t at = r->off;

	if (word_in(r, max, n, too_many))
		return -1;
	if (*n > room) {
		r->off = at;
		return bad(r, exceeds);
	}
	return 0;
}

static int literal(struct rd *r, struct nfsp_rule_literal *l)
{
	uint32_t k, w;

	memset(l, 0, sizeof(*l));
	if (word_in(r, NFSP_LIT_STRING, &k, "literal kind out of range"))
		return -1;
	l->kind = (enum nfsp_rule_literal_kind)k;
	switch (l->kind) {
	case NFSP_LIT_INT:
		if (u32(r, &w))
			return -1;
		l->num = (uint64_t)(int64_t)(int32_t)w;
		return 0;
	case NFSP_LIT_UINT:
	case NFSP_LIT_ENUM:
		if (u32(r, &w))
			return -1;
		l->num = w;
		return 0;
	case NFSP_LIT_HYPER:
	case NFSP_LIT_UHYPER:
		return u64(r, &l->num);
	case NFSP_LIT_BOOL: {
		int b;

		if (boolean(r, &b))
			return -1;
		l->num = (uint64_t)b;
		return 0;
	}
	case NFSP_LIT_OPAQUE:
	case NFSP_LIT_STRING: {
		const uint8_t *b;

		if (counted(r, NFSP_RULE_LITERAL_MAX, &b, &l->len))
			return -1;
		l->bytes = (const uint8_t *)keep(r, b, l->len);
		return l->bytes ? 0 : bad(r, "string storage");
	}
	}
	return bad(r, "literal kind out of range");
}

static int value_ref(struct rd *r, struct nfsp_rule_value_ref *v)
{
	uint32_t src;
	size_t at;

	memset(v, 0, sizeof(*v));
	if (word_in(r, NFSP_SRC_REQUEST_ORIGINAL, &src,
		    "value source out of range"))
		return -1;
	v->source = (enum nfsp_rule_source)src;
	at = r->off;
	if (name(r, NFSP_RULE_PATH_MAX, 1, &v->path))
		return -1;
	/* The target occurrence has no path; every other source needs one. */
	if ((v->source == NFSP_SRC_TARGET) != (v->path[0] == '\0')) {
		r->off = at;
		return bad(r, v->source == NFSP_SRC_TARGET ?
			   "a target value has no path" :
			   "a value source needs a path");
	}
	return 0;
}

static int predicate(struct rd *r, struct nfsp_rule_predicate *p)
{
	uint32_t w;

	memset(p, 0, sizeof(*p));
	if (value_ref(r, &p->lhs) ||
	    word_in(r, NFSP_CMP_GE, &w, "comparison out of range"))
		return -1;
	p->op = (enum nfsp_rule_compare)w;
	if (word_in(r, NFSP_OPND_REF, &w, "operand kind out of range"))
		return -1;
	p->rhs_kind = (enum nfsp_rule_operand_kind)w;
	return p->rhs_kind == NFSP_OPND_LITERAL ?
		literal(r, &p->rhs_literal) : value_ref(r, &p->rhs_ref);
}

static int transform(struct rd *r, struct nfsp_rule_transform *t)
{
	uint32_t w;

	memset(t, 0, sizeof(*t));
	if (word_in(r, NFSP_XF_BUILTIN, &w, "transform kind out of range"))
		return -1;
	t->kind = (enum nfsp_rule_transform_kind)w;
	switch (t->kind) {
	case NFSP_XF_LITERAL:
		return literal(r, &t->value);
	case NFSP_XF_COPY:
		return value_ref(r, &t->source);
	case NFSP_XF_BUILTIN:
		if (name(r, NFSP_RULE_ID_MAX, 0, &t->transform_id) ||
		    count_in(r, NFSP_RULE_BUILTIN_ARGS_MAX,
			     r->args_cap - r->nargs, &t->nargs,
			     "too many builtin arguments",
			     "builtin arguments exceed the input"))
			return -1;
		t->args = &r->rs->arg_pool[r->nargs];
		r->nargs += t->nargs;
		for (uint32_t i = 0; i < t->nargs; i++)
			if (literal(r, &t->args[i]))
				return -1;
		return 0;
	}
	return bad(r, "transform kind out of range");
}

static int view_deps(struct rd *r, struct nfsp_rule_view_deps *d)
{
	memset(d, 0, sizeof(*d));
	if (boolean(r, &d->rpc_procedure) ||
	    boolean(r, &d->request_operation_sequence) ||
	    count_in(r, NFSP_RULE_REQUEST_FIELDS_MAX,
		     r->fields_cap - r->nfields, &d->nfields,
		     "too many request fields",
		     "request fields exceed the input"))
		return -1;
	d->request_fields = &r->rs->field_pool[r->nfields];
	r->nfields += d->nfields;
	for (uint32_t i = 0; i < d->nfields; i++) {
		size_t at = r->off;

		if (name(r, NFSP_RULE_PATH_MAX, 0, &d->request_fields[i]))
			return -1;
		if (i && strcmp(d->request_fields[i - 1],
				d->request_fields[i]) >= 0) {
			r->off = at;
			return bad(r, "request fields not strictly ascending");
		}
	}
	return 0;
}

static int rule(struct rd *r, struct nfsp_rule *ru)
{
	uint32_t w;
	int has;

	memset(ru, 0, sizeof(*ru));
	if (name(r, NFSP_RULE_ID_MAX, 0, &ru->rule_id) ||
	    name(r, NFSP_RULE_ID_MAX, 0, &ru->intent_id) ||
	    word_in(r, NFSP_RULE_S2C, &w, "direction out of range"))
		return -1;
	ru->direction = (enum nfsp_rule_direction)w;
	if (u32(r, &ru->backend) || u32(r, &ru->client) ||
	    word_in(r, NFSP_RULE_REPLY, &w, "message type out of range"))
		return -1;
	ru->message_type = (enum nfsp_rule_msg_type)w;
	if (u32(r, &ru->program) || u32(r, &ru->version) ||
	    optional_word(r, &ru->has_procedure, &ru->procedure) ||
	    name(r, NFSP_RULE_FAMILY_MAX, 0, &ru->family) ||
	    optional_word(r, &ru->has_nfs_version, &ru->nfs_version) ||
	    optional_word(r, &ru->has_minor_version, &ru->minor_version) ||
	    boolean(r, &has))
		return -1;
	if (has && name(r, NFSP_RULE_OPERATION_MAX, 0, &ru->operation))
		return -1;
	if (word_in(r, NFSP_RULE_OPERATION_ARRAY, &w,
		    "target kind out of range"))
		return -1;
	ru->target_kind = (enum nfsp_rule_target_kind)w;
	if (name(r, NFSP_RULE_PATH_MAX, 0, &ru->target_path) ||
	    word_in(r, NFSP_PART_PADDING, &w, "part out of range"))
		return -1;
	ru->part = (enum nfsp_rule_part)w;

	if (count_in(r, NFSP_RULE_PREDICATES_MAX, r->preds_cap - r->npreds,
		     &ru->npredicates, "too many predicates",
		     "predicates exceed the input"))
		return -1;
	ru->predicates = &r->rs->pred_pool[r->npreds];
	r->npreds += ru->npredicates;
	for (uint32_t i = 0; i < ru->npredicates; i++) {
		r->err->predicate = i;
		if (predicate(r, &ru->predicates[i]))
			return -1;
	}
	r->err->predicate = NFSP_RULE_NONE;

	if (word_in(r, NFSP_MUT_OP_PREPEND, &w, "mutation kind out of range"))
		return -1;
	ru->kind = (enum nfsp_rule_mutation_kind)w;
	if (boolean(r, &ru->has_transform) ||
	    (ru->has_transform && transform(r, &ru->transform)) ||
	    word_in(r, NFSP_POLICY_RAW, &w, "structure policy out of range"))
		return -1;
	ru->policy = (enum nfsp_rule_policy)w;
	if (view_deps(r, &ru->forwarded) || view_deps(r, &ru->original) ||
	    word_in(r, NFSP_APPLY_ALL_MATCHES, &w,
		    "application mode is not all_matches"))
		return -1;
	ru->application = (enum nfsp_rule_application)w;
	return 0;
}

void nfsp_ruleset_free(struct nfsp_ruleset *rs)
{
	if (!rs)
		return;
	free(rs->rules);
	free(rs->arena);
	free(rs->pred_pool);
	free(rs->arg_pool);
	free(rs->field_pool);
	memset(rs, 0, sizeof(*rs));
}

static enum nfsp_rule_status fail_free(struct nfsp_ruleset *rs,
				       struct nfsp_rule_error *err)
{
	nfsp_ruleset_free(rs);
	return err->status;
}

static size_t min_size(size_t a, size_t b)
{
	return a < b ? a : b;
}

enum nfsp_rule_status nfsp_ruleset_parse(const uint8_t *buf, size_t len,
					 struct nfsp_ruleset *rs,
					 struct nfsp_rule_error *err)
{
	struct rd r;
	uint32_t n;

	memset(rs, 0, sizeof(*rs));
	memset(err, 0, sizeof(*err));
	err->rule = err->predicate = NFSP_RULE_NONE;
	memset(&r, 0, sizeof(r));
	r.p = buf;
	r.len = len;
	r.rs = rs;
	r.err = err;
	if (!buf || len > NFSP_RULESET_MAX_LEN) {
		bad(&r, buf ? "larger than NFSP_RULESET_MAX_LEN" : "no buffer");
		return fail_free(rs, err);
	}
	if (len < 8 || memcmp(buf, NFSP_RULESET_MAGIC, 8)) {
		bad(&r, "not an NFSPRUL1 rule set");
		return fail_free(rs, err);
	}
	r.off = 8;
	if (u32(&r, &rs->semantic_runtime_version))
		return fail_free(rs, err);
	if (rs->semantic_runtime_version != NFSP_SEMANTIC_RUNTIME_VERSION) {
		err->status = NFSP_RULE_UNSUPPORTED_VERSION;
		err->offset = 8;
		err->detail = "semantic_runtime_version is not 1";
		return fail_free(rs, err);
	}

	/* Storage from the input length: every string and literal byte is in
	 * the input once and costs at least one 4-byte length word, which
	 * also covers its NUL; a predicate takes at least 24 bytes, a builtin
	 * argument 8, a request field 4. */
	rs->arena_cap = len + len / 4 + 1;
	r.preds_cap = min_size(len / 24, (size_t)NFSP_RULES_MAX *
					 NFSP_RULE_PREDICATES_MAX);
	r.args_cap = min_size(len / 8, (size_t)NFSP_RULES_MAX *
				       NFSP_RULE_BUILTIN_ARGS_MAX);
	r.fields_cap = min_size(len / 4, (size_t)NFSP_RULES_MAX * 2u *
					 NFSP_RULE_REQUEST_FIELDS_MAX);
	rs->arena = malloc(rs->arena_cap);
	rs->pred_pool = calloc(r.preds_cap + 1, sizeof(*rs->pred_pool));
	rs->arg_pool = calloc(r.args_cap + 1, sizeof(*rs->arg_pool));
	rs->field_pool = calloc(r.fields_cap + 1, sizeof(*rs->field_pool));
	if (!rs->arena || !rs->pred_pool || !rs->arg_pool || !rs->field_pool) {
		err->status = NFSP_RULE_NO_MEMORY;
		err->detail = "rule set storage";
		return fail_free(rs, err);
	}

	if (name(&r, NFSP_RULE_SCHEMA_ID_MAX, 0, &rs->schema_id) ||
	    name(&r, NFSP_RULE_ID_MAX, 0, &rs->candidate_id))
		return fail_free(rs, err);
	/* A rule takes far more than 4 bytes; this only bounds the array. */
	if (count_in(&r, NFSP_RULES_MAX, (len - r.off) / 4, &n,
		     "too many rules", "rules exceed the input"))
		return fail_free(rs, err);
	if (n) {
		rs->rules = calloc(n, sizeof(*rs->rules));
		if (!rs->rules) {
			err->status = NFSP_RULE_NO_MEMORY;
			err->detail = "rule array";
			return fail_free(rs, err);
		}
	}
	for (uint32_t i = 0; i < n; i++) {
		size_t at = r.off;

		err->rule = i;
		if (rule(&r, &rs->rules[i]))
			return fail_free(rs, err);
		if (i && strcmp(rs->rules[i - 1].rule_id,
				rs->rules[i].rule_id) >= 0) {
			r.off = at;
			bad(&r, "rule ids not strictly ascending");
			return fail_free(rs, err);
		}
		rs->nrules = i + 1;
	}
	err->rule = NFSP_RULE_NONE;
	if (r.off != len) {
		bad(&r, "bytes after the rule set");
		return fail_free(rs, err);
	}
	return NFSP_RULE_OK;
}

/* ---- validation ---- */

struct val {
	const struct nfsp_protocol_schema *s;
	struct nfsp_rule *ru;
	struct nfsp_rule_error *err;
	uint32_t pred;
};

static enum nfsp_rule_status refuse(struct val *v, enum nfsp_rule_status st,
				    const char *detail)
{
	if (v->err->status == NFSP_RULE_OK) {
		v->err->status = st;
		v->err->predicate = v->pred;
		v->err->detail = detail;
	}
	return st;
}

static uint8_t kind_of(const struct nfsp_protocol_schema *s, uint16_t t)
{
	return t < s->ntypes ? s->types[t].kind : NFSP_XK_VOID;
}

/* A leaf whose value a predicate can compare and a literal can be. */
static int comparable(uint8_t k)
{
	switch (k) {
	case NFSP_XK_INT:
	case NFSP_XK_UINT:
	case NFSP_XK_HYPER:
	case NFSP_XK_UHYPER:
	case NFSP_XK_BOOL:
	case NFSP_XK_ENUM:
	case NFSP_XK_OPAQUE_FIXED:
	case NFSP_XK_OPAQUE_VAR:
	case NFSP_XK_STRING:
		return 1;
	default:
		return 0;
	}
}

static int ordered(uint8_t k)
{
	return k == NFSP_XK_INT || k == NFSP_XK_UINT || k == NFSP_XK_HYPER ||
	       k == NFSP_XK_UHYPER;
}

/* A literal is a value of the node's own type: no reinterpretation (design
 * 04 §9, §13).  An enum literal must be a value the type declares. */
static int literal_fits(const struct nfsp_protocol_schema *s, uint16_t t,
			const struct nfsp_rule_literal *l)
{
	const struct nfsp_schema_type *ty;

	if (t >= s->ntypes)
		return 0;
	ty = &s->types[t];
	switch (ty->kind) {
	case NFSP_XK_INT: return l->kind == NFSP_LIT_INT;
	case NFSP_XK_UINT: return l->kind == NFSP_LIT_UINT;
	case NFSP_XK_HYPER: return l->kind == NFSP_LIT_HYPER;
	case NFSP_XK_UHYPER: return l->kind == NFSP_LIT_UHYPER;
	case NFSP_XK_BOOL: return l->kind == NFSP_LIT_BOOL;
	case NFSP_XK_ENUM:
		return l->kind == NFSP_LIT_ENUM &&
		       nfsp_schema_enum_has(s, t, (uint32_t)l->num);
	case NFSP_XK_OPAQUE_FIXED:
		return l->kind == NFSP_LIT_OPAQUE && l->len == ty->bound;
	case NFSP_XK_OPAQUE_VAR:
		return l->kind == NFSP_LIT_OPAQUE && l->len <= ty->bound;
	case NFSP_XK_STRING:
		return l->kind == NFSP_LIT_STRING && l->len <= ty->bound;
	default:
		return 0;
	}
}

static int same_enum(const struct nfsp_protocol_schema *s, uint16_t a,
		     uint16_t b)
{
	return a == b || (s->types[a].name && s->types[b].name &&
			  !strcmp(s->types[a].name, s->types[b].name));
}

/* Two values a predicate may compare: the same logical type (design 04
 * §9).  Lengths of variable opaques may differ. */
static int comparable_pair(const struct nfsp_protocol_schema *s, uint16_t a,
			   uint16_t b)
{
	uint8_t ka = kind_of(s, a), kb = kind_of(s, b);

	if (ka != kb || !comparable(ka))
		return 0;
	if (ka == NFSP_XK_ENUM)
		return same_enum(s, a, b);
	if (ka == NFSP_XK_OPAQUE_FIXED)
		return s->types[a].bound == s->types[b].bound;
	return 1;
}

/* A copied value always fits where it goes (design 04 §14). */
static int copy_fits(const struct nfsp_protocol_schema *s, uint16_t from,
		     uint16_t to)
{
	uint8_t k = kind_of(s, to);

	if (!comparable_pair(s, from, to))
		return 0;
	if (k == NFSP_XK_OPAQUE_VAR || k == NFSP_XK_STRING)
		return s->types[from].bound <= s->types[to].bound;
	return 1;
}

static int in_message(const struct nfsp_protocol_schema *s,
		      const char *path, int response)
{
	const char *dir = response ? ".response." : ".request.";
	size_t n = strlen(s->family);

	return !strncmp(path, s->family, n) &&
	       !strncmp(path + n, dir, strlen(dir));
}

/* Resolve a path of the request (response 0) or response message. */
static enum nfsp_rule_status resolve(struct val *v, int response,
				     const char *path,
				     struct nfsp_schema_node *node)
{
	if (in_message(v->s, path, !response))
		return refuse(v, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT,
			      response ? "a request path in a reply rule" :
					 "a response path in a call rule");
	switch (nfsp_schema_resolve(v->s, response, path, node)) {
	case NFSP_SCHEMA_FOUND:
		return NFSP_RULE_OK;
	case NFSP_SCHEMA_AMBIGUOUS:
		return refuse(v, NFSP_RULE_AMBIGUOUS_PATH,
			      "path names more than one schema node");
	default:
		return refuse(v, NFSP_RULE_UNKNOWN_PATH,
			      "path names no schema node");
	}
}

static enum nfsp_rule_status resolve_ref(struct val *v,
					 struct nfsp_rule_value_ref *ref)
{
	int reply = v->ru->message_type == NFSP_RULE_REPLY;

	switch (ref->source) {
	case NFSP_SRC_TARGET:
		ref->node = v->ru->target;
		return NFSP_RULE_OK;
	case NFSP_SRC_CURRENT_MESSAGE:
		return resolve(v, reply, ref->path, &ref->node);
	case NFSP_SRC_REQUEST_FORWARDED:
	case NFSP_SRC_REQUEST_ORIGINAL:
		/* A request view is the CALL a REPLY answers (design 04 §8). */
		if (!reply)
			return refuse(v, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT,
				      "a request view in a call rule");
		if (in_message(v->s, ref->path, 1))
			return refuse(v, NFSP_RULE_MESSAGE_TYPE_INCONSISTENT,
				      "a response path in a request view");
		return resolve(v, 0, ref->path, &ref->node);
	}
	return refuse(v, NFSP_RULE_MALFORMED, "value source");
}

static enum nfsp_rule_status check_selector(struct val *v)
{
	const struct nfsp_protocol_schema *s = v->s;
	const struct nfsp_rule *ru = v->ru;

	if (strcmp(ru->family, s->family))
		return refuse(v, NFSP_RULE_SELECTOR_MISMATCH,
			      "family is not the schema's");
	if (ru->program != s->program || ru->version != s->version ||
	    (ru->has_nfs_version && ru->nfs_version != s->version))
		return refuse(v, NFSP_RULE_SELECTOR_MISMATCH,
			      "program or version is not the schema's");
	if (ru->has_minor_version &&
	    (!s->has_minor || ru->minor_version != s->minor))
		return refuse(v, NFSP_RULE_SELECTOR_MISMATCH,
			      "minor version is not the schema's");
	if (ru->has_procedure && !nfsp_schema_proc(s, ru->procedure))
		return refuse(v, NFSP_RULE_SELECTOR_MISMATCH,
			      "procedure not in the schema");
	return NFSP_RULE_OK;
}

static int has_meta(const struct nfsp_protocol_schema *s,
		    const struct nfsp_schema_node *n, enum nfsp_rule_part part)
{
	const struct nfsp_schema_type *ty = &s->types[n->type];

	switch (part) {
	case NFSP_PART_VALUE:
	case NFSP_PART_ENCODED:
		return 1;
	case NFSP_PART_LENGTH:
		return ty->kind == NFSP_XK_OPAQUE_VAR ||
		       ty->kind == NFSP_XK_STRING;
	case NFSP_PART_COUNT:
		return ty->kind == NFSP_XK_ARRAY_VAR;
	case NFSP_PART_DISCRIMINANT:
		return ty->kind == NFSP_XK_UNION || ty->kind == NFSP_XK_LIST ||
		       (n->flags & NFSP_SN_LIST_ELEMENT);
	case NFSP_PART_PADDING:
		return (ty->kind == NFSP_XK_OPAQUE_FIXED && (ty->bound & 3u)) ||
		       ty->kind == NFSP_XK_OPAQUE_VAR ||
		       ty->kind == NFSP_XK_STRING;
	}
	return 0;
}

static enum nfsp_rule_status check_target(struct val *v)
{
	const struct nfsp_protocol_schema *s = v->s;
	struct nfsp_rule *ru = v->ru;
	struct nfsp_schema_node *n = &ru->target;
	enum nfsp_rule_status st;

	st = resolve(v, ru->message_type == NFSP_RULE_REPLY, ru->target_path,
		     n);
	if (st)
		return st;
	/* The operation selector names the target's operation, and only
	 * that: a field outside an operation has none. */
	if (n->flags & NFSP_SN_OPERATION) {
		if (!ru->operation || strcmp(ru->operation, n->root))
			return refuse(v, NFSP_RULE_SELECTOR_MISMATCH,
				      "operation is not the target's");
	} else if (ru->operation) {
		return refuse(v, NFSP_RULE_SELECTOR_MISMATCH,
			      "operation given for a target outside one");
	}
	if (ru->has_procedure) {
		const struct nfsp_schema_proc *pr =
			nfsp_schema_proc(s, ru->procedure);
		uint16_t rt = ru->message_type == NFSP_RULE_REPLY ? pr->res :
								    pr->arg;
		int in;

		if (n->proc)
			in = n->proc == pr;
		else if (rt == NFSP_SCHEMA_NONE)
			in = 0;
		else
			in = nfsp_schema_reaches(s, rt, n->root_type);
		if (in < 0)
			return refuse(v, NFSP_RULE_NO_MEMORY, "reachability");
		if (!in)
			return refuse(v, NFSP_RULE_SELECTOR_MISMATCH,
				      "target is not in the procedure");
	}
	if (ru->target_kind == NFSP_RULE_OPERATION_ARRAY) {
		if (!(n->flags & NFSP_SN_OPS_ARRAY))
			return refuse(v, NFSP_RULE_TYPE_MISMATCH,
				      "target is not an operation array");
		if (ru->part != NFSP_PART_VALUE)
			return refuse(v, NFSP_RULE_PART_UNAVAILABLE,
				      "an operation array target is its value");
		return NFSP_RULE_OK;
	}
	if (!has_meta(s, n, ru->part))
		return refuse(v, NFSP_RULE_PART_UNAVAILABLE,
			      "target has no such part");
	return NFSP_RULE_OK;
}

static enum nfsp_rule_status check_predicates(struct val *v)
{
	const struct nfsp_protocol_schema *s = v->s;
	struct nfsp_rule *ru = v->ru;
	enum nfsp_rule_status st;

	for (v->pred = 0; v->pred < ru->npredicates; v->pred++) {
		struct nfsp_rule_predicate *p = &ru->predicates[v->pred];
		uint16_t lt;

		if ((st = resolve_ref(v, &p->lhs)))
			return st;
		lt = p->lhs.node.type;
		if (!comparable(kind_of(s, lt)))
			return refuse(v, NFSP_RULE_TYPE_MISMATCH,
				      "left side is not a comparable value");
		if (p->op >= NFSP_CMP_LT && !ordered(kind_of(s, lt)))
			return refuse(v, NFSP_RULE_TYPE_MISMATCH,
				      "ordering needs a numeric type");
		if (p->rhs_kind == NFSP_OPND_LITERAL) {
			if (!literal_fits(s, lt, &p->rhs_literal))
				return refuse(v, NFSP_RULE_TYPE_MISMATCH,
					      "literal is not of the left "
					      "side's type");
			continue;
		}
		if ((st = resolve_ref(v, &p->rhs_ref)))
			return st;
		if (!comparable_pair(s, lt, p->rhs_ref.node.type))
			return refuse(v, NFSP_RULE_TYPE_MISMATCH,
				      "the two sides are not one type");
	}
	v->pred = NFSP_RULE_NONE;
	return NFSP_RULE_OK;
}

/* ---- context dependencies (design 04 §10, rules in §35) ---- */

struct deps {
	int rpc_procedure, opseq;
	const char *fields[2u * NFSP_RULE_PREDICATES_MAX + 1u];
	uint32_t n;
};

static void add_field(struct deps *d, const char *path)
{
	for (uint32_t i = 0; i < d->n; i++)
		if (!strcmp(d->fields[i], path))
			return;
	d->fields[d->n++] = path;
}

static void add_ref(const struct nfsp_rule *ru,
		    const struct nfsp_rule_value_ref *ref, struct deps *fwd,
		    struct deps *orig)
{
	/* A request field bound to a field of a response operation needs
	 * the operation sequence to prove which request operation answers
	 * it: the forwarded one always, the original one too when the field
	 * is the original's (design 04 §23). */
	int bind = (ref->node.flags & NFSP_SN_OPERATION) &&
		   (ru->target.flags & NFSP_SN_OPERATION);

	if (ref->source == NFSP_SRC_REQUEST_FORWARDED) {
		add_field(fwd, ref->path);
		fwd->opseq |= bind;
	} else if (ref->source == NFSP_SRC_REQUEST_ORIGINAL) {
		add_field(orig, ref->path);
		orig->opseq |= bind;
		fwd->opseq |= bind;
	}
}

static int by_name(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int deps_equal(struct deps *want, const struct nfsp_rule_view_deps *got)
{
	if (want->rpc_procedure != got->rpc_procedure ||
	    want->opseq != got->request_operation_sequence ||
	    want->n != got->nfields)
		return 0;
	qsort(want->fields, want->n, sizeof(want->fields[0]), by_name);
	for (uint32_t i = 0; i < want->n; i++)
		if (strcmp(want->fields[i], got->request_fields[i]))
			return 0;
	return 1;
}

static enum nfsp_rule_status check_deps(struct val *v)
{
	const struct nfsp_rule *ru = v->ru;
	struct deps fwd, orig;

	memset(&fwd, 0, sizeof(fwd));
	memset(&orig, 0, sizeof(orig));
	for (uint32_t i = 0; i < ru->npredicates; i++) {
		add_ref(ru, &ru->predicates[i].lhs, &fwd, &orig);
		if (ru->predicates[i].rhs_kind == NFSP_OPND_REF)
			add_ref(ru, &ru->predicates[i].rhs_ref, &fwd, &orig);
	}
	if (ru->has_transform && ru->transform.kind == NFSP_XF_COPY)
		add_ref(ru, &ru->transform.source, &fwd, &orig);
	/* A REPLY rule that names a procedure needs it from the CALL the
	 * server answered (design 04 §4). */
	fwd.rpc_procedure = ru->message_type == NFSP_RULE_REPLY &&
			    ru->has_procedure;
	if (!deps_equal(&fwd, &ru->forwarded))
		return refuse(v, NFSP_RULE_DEPENDENCIES_MISMATCH,
			      "forwarded view dependencies differ from the "
			      "rule's references");
	if (!deps_equal(&orig, &ru->original))
		return refuse(v, NFSP_RULE_DEPENDENCIES_MISMATCH,
			      "original view dependencies differ from the "
			      "rule's references");
	return NFSP_RULE_OK;
}

/* ---- mutation ---- */

static enum nfsp_rule_status unsupported(struct val *v, const char *what)
{
	return refuse(v, NFSP_RULE_UNSUPPORTED_CAPABILITY, what);
}

/* A metadata word or padding written as itself: raw only, and a literal of
 * the word (or the padding bytes). */
static enum nfsp_rule_status check_metadata_edit(struct val *v)
{
	const struct nfsp_rule *ru = v->ru;
	const struct nfsp_rule_literal *l = &ru->transform.value;

	if (ru->policy != NFSP_POLICY_RAW)
		return refuse(v, NFSP_RULE_MUTATION_INVALID,
			      "a metadata target is a raw edit; preserve "
			      "would recompute it");
	if (ru->transform.kind != NFSP_XF_LITERAL)
		return unsupported(v, "only a literal writes metadata");
	if (ru->part == NFSP_PART_PADDING) {
		if (l->kind != NFSP_LIT_OPAQUE || l->len < 1 || l->len > 3)
			return refuse(v, NFSP_RULE_TYPE_MISMATCH,
				      "padding is written as 1 to 3 opaque "
				      "bytes");
	} else if (l->kind != NFSP_LIT_UINT) {
		return refuse(v, NFSP_RULE_TYPE_MISMATCH,
			      "a metadata word is written as unsigned int");
	}
	return NFSP_RULE_OK;
}

static enum nfsp_rule_status check_replace(struct val *v)
{
	const struct nfsp_protocol_schema *s = v->s;
	struct nfsp_rule *ru = v->ru;
	uint16_t t = ru->target.type;

	if (ru->target_kind != NFSP_RULE_FIELD)
		return refuse(v, NFSP_RULE_MUTATION_INVALID,
			      "replace needs a field target");
	if (!ru->has_transform)
		return refuse(v, NFSP_RULE_MUTATION_INVALID,
			      "replace needs a transform");
	switch (ru->part) {
	case NFSP_PART_VALUE:
		break;
	case NFSP_PART_ENCODED:
		return unsupported(v, "replacing a whole encoding");
	default:
		return check_metadata_edit(v);
	}
	if (!comparable(kind_of(s, t)))
		return unsupported(v, "replacing a value that is not a leaf");
	switch (ru->transform.kind) {
	case NFSP_XF_LITERAL:
		if (!literal_fits(s, t, &ru->transform.value))
			return refuse(v, NFSP_RULE_TYPE_MISMATCH,
				      "literal is not of the target's type");
		break;
	case NFSP_XF_COPY:
		/* Resolved by check_rule(), before the dependencies. */
		if (!copy_fits(s, ru->transform.source.node.type, t))
			return refuse(v, NFSP_RULE_TYPE_MISMATCH,
				      "copied value does not fit the target");
		break;
	case NFSP_XF_BUILTIN:
		return unsupported(v, "no builtin transform is registered");
	}
	/* A new discriminant picks a different layout for what follows;
	 * preserve would have to re-encode that arm. */
	if ((ru->target.flags & NFSP_SN_DISCRIMINANT) &&
	    ru->policy == NFSP_POLICY_PRESERVE)
		return unsupported(v, "preserving the layout behind a new "
				      "discriminant");
	return NFSP_RULE_OK;
}

static enum nfsp_rule_status check_mutation(struct val *v)
{
	const struct nfsp_rule *ru = v->ru;
	int field = ru->target_kind == NFSP_RULE_FIELD;

	switch (ru->kind) {
	case NFSP_MUT_REPLACE:
		return check_replace(v);
	case NFSP_MUT_INSERT:
		if (!field || !ru->has_transform)
			return refuse(v, NFSP_RULE_MUTATION_INVALID,
				      "insert needs a field target and a "
				      "transform");
		return unsupported(v, "insert");
	case NFSP_MUT_DELETE:
		if (!field || ru->has_transform)
			return refuse(v, NFSP_RULE_MUTATION_INVALID,
				      "delete needs a field target and no "
				      "transform");
		return unsupported(v, "delete");
	case NFSP_MUT_OP_APPEND:
	case NFSP_MUT_OP_PREPEND:
		if (field)
			return refuse(v, NFSP_RULE_MUTATION_INVALID,
				      "an operation edit needs an operation "
				      "array target");
		return unsupported(v, "typed operation values");
	}
	return refuse(v, NFSP_RULE_MALFORMED, "mutation kind");
}

static enum nfsp_rule_status check_rule(struct val *v)
{
	enum nfsp_rule_status st;
	struct nfsp_rule *ru = v->ru;

	v->pred = NFSP_RULE_NONE;
	if ((st = check_selector(v)) || (st = check_target(v)) ||
	    (st = check_predicates(v)))
		return st;
	if (ru->has_transform && ru->transform.kind == NFSP_XF_COPY &&
	    (st = resolve_ref(v, &ru->transform.source)))
		return st;
	if ((st = check_deps(v)))
		return st;
	return check_mutation(v);
}

static const struct nfsp_protocol_schema *
find_schema(const struct nfsp_schema_family *const *families, size_t n,
	    const char *id)
{
	for (size_t i = 0; i < n; i++)
		for (uint32_t k = 0; families[i] && k < families[i]->nschemas;
		     k++)
			if (!strcmp(families[i]->schemas[k]->schema_id, id))
				return families[i]->schemas[k];
	return NULL;
}

enum nfsp_rule_status
nfsp_ruleset_validate(struct nfsp_ruleset *rs,
		      const struct nfsp_schema_family *const *families,
		      size_t nfamilies, struct nfsp_rule_error *err)
{
	struct val v;

	memset(err, 0, sizeof(*err));
	err->rule = err->predicate = NFSP_RULE_NONE;
	rs->schema = find_schema(families, nfamilies, rs->schema_id);
	if (!rs->schema) {
		err->status = NFSP_RULE_UNKNOWN_SCHEMA;
		err->detail = "no ProtocolSchema has this schema_id";
		return err->status;
	}
	memset(&v, 0, sizeof(v));
	v.s = rs->schema;
	v.err = err;
	for (uint32_t i = 0; i < rs->nrules; i++) {
		v.ru = &rs->rules[i];
		if (check_rule(&v)) {
			err->rule = i;
			rs->schema = NULL;
			return err->status;
		}
	}
	return NFSP_RULE_OK;
}

enum nfsp_rule_status
nfsp_ruleset_load(const uint8_t *buf, size_t len,
		  const struct nfsp_schema_family *const *families,
		  size_t nfamilies, struct nfsp_ruleset *rs,
		  struct nfsp_rule_error *err)
{
	if (nfsp_ruleset_parse(buf, len, rs, err))
		return err->status;
	if (nfsp_ruleset_validate(rs, families, nfamilies, err))
		return fail_free(rs, err);
	return NFSP_RULE_OK;
}

const char *nfsp_rule_strstatus(enum nfsp_rule_status status)
{
	switch (status) {
	case NFSP_RULE_OK: return "ok";
	case NFSP_RULE_MALFORMED: return "malformed";
	case NFSP_RULE_UNSUPPORTED_VERSION: return "unsupported_version";
	case NFSP_RULE_NO_MEMORY: return "no_memory";
	case NFSP_RULE_UNKNOWN_SCHEMA: return "unknown_schema";
	case NFSP_RULE_SELECTOR_MISMATCH: return "selector_mismatch";
	case NFSP_RULE_MESSAGE_TYPE_INCONSISTENT:
		return "message_type_inconsistent";
	case NFSP_RULE_UNKNOWN_PATH: return "unknown_path";
	case NFSP_RULE_AMBIGUOUS_PATH: return "ambiguous_path";
	case NFSP_RULE_PART_UNAVAILABLE: return "part_unavailable";
	case NFSP_RULE_TYPE_MISMATCH: return "type_mismatch";
	case NFSP_RULE_MUTATION_INVALID: return "mutation_invalid";
	case NFSP_RULE_DEPENDENCIES_MISMATCH:
		return "dependencies_mismatch";
	case NFSP_RULE_UNSUPPORTED_CAPABILITY:
		return "unsupported_capability";
	}
	return "unknown";
}
