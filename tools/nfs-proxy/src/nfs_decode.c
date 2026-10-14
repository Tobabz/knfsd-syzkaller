/* NFS Semantic Decoder: a generic interpreter over generated schema tables.
 *
 * WHY AN INTERPRETER AND NOT GENERATED CODE
 *
 *   Design 02 §4 leaves the choice open.  One interpreter means one checked
 *   cursor and one copy of every bounds check, reviewed once, instead of a
 *   copy per XDR type in generated code.  The tables are data, so a schema
 *   change cannot introduce an unchecked read.
 *
 * SHAPE OF THE WALK
 *
 *   decode() handles one node.  It emits the node before its children, so
 *   field indices are pre-order and every child's parent is already in the
 *   array.  Each item is checked before the cursor advances, so on failure
 *   d->off is the offset of the refused item.  Recursion depth is bounded by
 *   the schema's max_depth (checked by the normalizer and again here); the
 *   XDR linked list is decoded by a loop, so a long READDIR reply does not
 *   deepen the stack.
 *
 *   The output arrays are indexed, never held by pointer across emit(),
 *   because emit() may move them.
 */
#include "nfs_decode.h"

#include <stdlib.h>
#include <string.h>

struct dec {
	const struct nfsp_protocol_schema *s;
	struct nfsp_decoded_msg *m;
	const uint8_t *p;
	uint32_t len;
	uint32_t off;
	uint32_t max_fields;
	unsigned depth;
	int response;
	uint32_t op;		/* current operation, or NFSP_FIELD_NONE */
	uint32_t op_start;	/* payload offset where its result begins */
	enum nfsp_decode_status st;
	uint32_t stop_field;	/* partial: the operation array node */
	int probing;		/* reading the minor-version prefix: no schema
				 * is chosen yet, so nothing is partial */
};

static const char *kind_name(uint8_t kind)
{
	static const char *const names[] = {
		"void", "int", "unsigned int", "hyper", "unsigned hyper", "bool",
		"enum", "opaque[]", "opaque<>", "string<>", "array[]",
		"array<>", "list", "struct", "union"
	};
	return kind < sizeof(names) / sizeof(names[0]) ? names[kind] : "?";
}

static const char *node_name(const struct dec *d, uint16_t t)
{
	if (!d->s || t >= d->s->ntypes)
		return "?";
	if (d->s->types[t].name)
		return d->s->types[t].name;
	return kind_name(d->s->types[t].kind);
}

static int fail(struct dec *d, enum nfsp_decode_status st, uint16_t t,
		const char *reason)
{
	if (d->st == NFSP_DECODE_DECODED) {
		d->st = st;
		d->m->failure.offset = d->off;
		d->m->failure.schema_node = node_name(d, t);
		d->m->failure.reason = reason;
	}
	return -1;
}

static uint32_t remaining(const struct dec *d)
{
	return d->len - d->off;
}

static uint32_t rd32(const struct dec *d, uint32_t at)
{
	return (uint32_t)d->p[at] << 24 | (uint32_t)d->p[at + 1] << 16 |
	       (uint32_t)d->p[at + 2] << 8 | (uint32_t)d->p[at + 3];
}

static struct nfsp_semantic_field *F(struct dec *d, uint32_t i)
{
	return &d->m->fields[i];
}

static int emit(struct dec *d, uint16_t t, uint32_t parent, const char *root,
		const char *component, uint32_t index, uint32_t *out)
{
	struct nfsp_decoded_msg *m = d->m;
	struct nfsp_semantic_field *f;

	if (m->nfields >= d->max_fields)
		return fail(d, NFSP_DECODE_RESOURCE_LIMIT, t, "field limit");
	if (m->nfields == m->fields_cap) {
		uint32_t cap = m->fields_cap ? m->fields_cap * 2u : 64u;
		void *n;

		if (cap > d->max_fields || cap < m->fields_cap)
			cap = d->max_fields;
		n = realloc(m->fields, (size_t)cap * sizeof(*m->fields));
		if (!n)
			return fail(d, NFSP_DECODE_RESOURCE_LIMIT, t,
				    "out of memory");
		m->fields = n;
		m->fields_cap = cap;
	}
	f = &m->fields[m->nfields];
	memset(f, 0, sizeof(*f));
	f->parent = parent;
	f->op = d->op;
	f->index = index;
	f->root = root;
	f->component = component;
	f->type = t;
	f->kind = d->s->types[t].kind;
	f->wire.encoded.off = d->off;
	f->wire.value.off = d->off;
	*out = m->nfields++;
	return 0;
}

static void finish(struct dec *d, uint32_t me, uint32_t start)
{
	F(d, me)->wire.encoded.len = d->off - start;
}

static void meta(struct dec *d, uint32_t me, uint32_t role, uint32_t off,
		 uint32_t len)
{
	struct nfsp_wire_ref *w = &F(d, me)->wire;
	struct nfsp_span *sp = role == NFSP_META_LENGTH ? &w->length :
			       role == NFSP_META_COUNT ? &w->count :
			       role == NFSP_META_DISCRIMINANT ?
			       &w->discriminant : &w->padding;

	w->meta |= role;
	sp->off = off;
	sp->len = len;
}

/* A response operation's status is the value of the annotated status type
 * that its result starts with (every NFSv4 resop arm starts with nfsstat4).
 * It is decided by offset, not by reading order: a count or link word at the
 * start means no status whatever the element count, and a later status-typed
 * member can never take the status's place (PR #25 reviews). */
static void status_at(struct dec *d, uint16_t t, uint32_t at, uint64_t value)
{
	struct nfsp_decoded_op *op;

	if (d->op == NFSP_FIELD_NONE || !d->response || at != d->op_start ||
	    !(d->s->types[t].flags & NFSP_STF_STATUS))
		return;
	op = &d->m->ops[d->op];
	op->has_status = 1;
	op->status = (uint32_t)value;
}

static int enum_has(const struct nfsp_protocol_schema *s,
		    const struct nfsp_schema_type *ty, uint32_t v)
{
	for (uint32_t i = 0; i < ty->count; i++)
		if (s->enums[ty->first + i].value == v)
			return 1;
	return 0;
}

/* Validate a discriminant word against its type.  0 when allowed. */
static int check_word(struct dec *d, uint16_t t, uint32_t w)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];

	if (ty->kind == NFSP_XK_BOOL && w > 1)
		return fail(d, NFSP_DECODE_MALFORMED, t, "bool is not 0 or 1");
	if (ty->kind == NFSP_XK_ENUM && !enum_has(d->s, ty, w))
		return fail(d, NFSP_DECODE_MALFORMED, t,
			    "enum value not declared");
	return 0;
}

/* A 4-byte value of a field that is not a discriminant.  In a CALL the
 * server reads it as a plain word, so an out-of-domain value is decoded and
 * flagged.  A REPLY stays strict: its reader is the client, and a strict
 * result is what keeps a wrong reply_dispatch from decoding (§14). */
static int check_leaf(struct dec *d, uint16_t t, uint32_t me, uint32_t w)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];

	if ((ty->kind == NFSP_XK_BOOL && w > 1) ||
	    (ty->kind == NFSP_XK_ENUM && !enum_has(d->s, ty, w))) {
		if (d->response)
			return check_word(d, t, w);
		F(d, me)->flags |= NFSP_FF_UNDECLARED;
	}
	return 0;
}

static int decode(struct dec *d, uint16_t t, uint32_t parent,
		  const char *root, const char *component, uint32_t index);

static int dec_scalar(struct dec *d, uint16_t t, uint32_t me)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];
	uint32_t size = ty->kind == NFSP_XK_HYPER ||
			ty->kind == NFSP_XK_UHYPER ? 8u : 4u;
	uint32_t at = d->off;
	uint64_t v;

	if (remaining(d) < size)
		return fail(d, NFSP_DECODE_TRUNCATED, t, "record ends here");
	if (size == 8) {
		v = (uint64_t)rd32(d, d->off) << 32 | rd32(d, d->off + 4);
	} else {
		uint32_t w = rd32(d, d->off);

		if (check_leaf(d, t, me, w))
			return -1;
		v = ty->kind == NFSP_XK_INT ?
			(uint64_t)(int64_t)(int32_t)w : w;
	}
	F(d, me)->value = v;
	F(d, me)->wire.value.len = size;
	d->off += size;
	status_at(d, t, at, v);
	return 0;
}

/* opaque[n], opaque<n>, string<n>. */
static int dec_bytes(struct dec *d, uint16_t t, uint32_t me)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];
	uint32_t n, pad, at;

	if (ty->kind == NFSP_XK_OPAQUE_FIXED) {
		n = ty->bound;
		pad = (4u - (n & 3u)) & 3u;
		if ((uint64_t)n + pad > remaining(d))
			return fail(d, NFSP_DECODE_TRUNCATED, t,
				    "record ends inside fixed opaque");
	} else {
		if (remaining(d) < 4)
			return fail(d, NFSP_DECODE_TRUNCATED, t,
				    "record ends here");
		n = rd32(d, d->off);
		if (n > ty->bound)
			return fail(d, NFSP_DECODE_MALFORMED, t,
				    "length exceeds bound");
		pad = (4u - (n & 3u)) & 3u;
		if ((uint64_t)n + pad > remaining(d) - 4u)
			return fail(d, NFSP_DECODE_MALFORMED, t,
				    "length exceeds remaining record");
		meta(d, me, NFSP_META_LENGTH, d->off, 4);
		d->off += 4;
	}
	at = d->off + n;
	for (uint32_t i = 0; i < pad; i++)
		if (d->p[at + i]) {
			if (d->response) {
				d->off = at;
				return fail(d, NFSP_DECODE_MALFORMED, t,
					    "non-zero padding");
			}
			F(d, me)->flags |= NFSP_FF_PAD_NONZERO;
		}
	F(d, me)->wire.value.off = d->off;
	F(d, me)->wire.value.len = n;
	if (pad)
		meta(d, me, NFSP_META_PADDING, at, pad);
	d->off = at + pad;
	return 0;
}

/* A CALL's operation array: knfsd decodes its operations one by one and
 * stops at the first that fails (nfsd4_decode_compound). */
static int ops_array(const struct dec *d, const struct nfsp_schema_type *ty)
{
	return !d->response && !d->probing && d->len >= 4u &&
	       (d->s->types[ty->sub].flags & NFSP_STF_OPS_REQUEST);
}

/* Keep the operations before element i of array `arr` and drop the rest:
 * the fields and ops the failed element added go, and `failure` keeps why
 * it failed.  The containing nodes are cut at `at` by the caller of
 * decode() once the walk has unwound (finish_partial). */
static void stop_at_op(struct dec *d, uint32_t arr, uint32_t i, uint32_t at,
		       uint32_t nf, uint32_t no)
{
	d->m->nfields = nf;
	d->m->nops = no;
	d->m->failure.op_index = i;
	d->m->failure.opcode = rd32(d, at);
	d->m->failure.op_offset = at;
	d->stop_field = arr;
	d->st = NFSP_DECODE_PARTIAL;
}

/* After a partial walk: the operation array and every node containing it
 * end where the failed operation starts. */
static void finish_partial(struct dec *d)
{
	uint32_t stop = d->m->failure.op_offset;

	for (uint32_t i = d->stop_field; i != NFSP_FIELD_NONE;
	     i = F(d, i)->parent) {
		struct nfsp_wire_ref *w = &F(d, i)->wire;

		w->encoded.len = stop - w->encoded.off;
		w->value.len = w->value.off <= stop ? stop - w->value.off : 0;
	}
}

static int dec_array(struct dec *d, uint16_t t, uint32_t me)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];
	uint32_t count = ty->bound;

	if (ty->kind == NFSP_XK_ARRAY_VAR) {
		uint32_t min = d->s->types[ty->sub].min_size;

		if (remaining(d) < 4)
			return fail(d, NFSP_DECODE_TRUNCATED, t,
				    "record ends here");
		count = rd32(d, d->off);
		if (count > ty->bound)
			return fail(d, NFSP_DECODE_MALFORMED, t,
				    "count exceeds bound");
		/* min_size > 0 is a normalizer guarantee; this check bounds
		 * the loop below by the bytes actually present.  A CALL's
		 * operation array is not checked as a whole: knfsd reads
		 * operations until one fails and never looks at the count of
		 * those after it, and each element is checked as it is read
		 * (an element needs at least its opcode word, so the loop
		 * still ends with the record). */
		if (!ops_array(d, ty) &&
		    (uint64_t)count * min > remaining(d) - 4u)
			return fail(d, NFSP_DECODE_MALFORMED, t,
				    "count exceeds remaining record");
		meta(d, me, NFSP_META_COUNT, d->off, 4);
		d->off += 4;
		F(d, me)->wire.value.off = d->off;
	}
	for (uint32_t i = 0; i < count; i++) {
		uint32_t nf = d->m->nfields, no = d->m->nops, at = d->off;

		if (!decode(d, ty->sub, me, NULL, "[]", i))
			continue;
		if (ops_array(d, ty) && at <= d->len - 4u &&
		    (d->st == NFSP_DECODE_MALFORMED ||
		     d->st == NFSP_DECODE_TRUNCATED))
			stop_at_op(d, me, i, at, nf, no);
		return -1;
	}
	F(d, me)->wire.value.len = d->off - F(d, me)->wire.value.off;
	return 0;
}

/* T *head, where T ends in `T *next`: elements become siblings head[] with
 * indices, each owning the link word after it. */
static int dec_list(struct dec *d, uint16_t t, uint32_t me)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];
	const struct nfsp_schema_type *el = &d->s->types[ty->sub];
	uint32_t present, i = 0;

	if (remaining(d) < 4)
		return fail(d, NFSP_DECODE_TRUNCATED, t, "record ends here");
	present = rd32(d, d->off);
	if (present > 1)
		return fail(d, NFSP_DECODE_MALFORMED, t,
			    "list link is not 0 or 1");
	meta(d, me, NFSP_META_DISCRIMINANT, d->off, 4);
	d->off += 4;
	F(d, me)->wire.value.off = d->off;
	while (present) {
		uint32_t e, start = d->off;

		if (++d->depth > NFSP_DECODE_MAX_DEPTH)
			return fail(d, NFSP_DECODE_RESOURCE_LIMIT, t,
				    "nesting depth");
		if (emit(d, ty->sub, me, NULL, "[]", i, &e))
			return -1;
		for (uint32_t k = 0; k < el->count; k++) {
			const struct nfsp_schema_field *f =
				&d->s->fields[el->first + k];

			if (decode(d, f->type, e, NULL, f->name,
				   NFSP_FIELD_NONE))
				return -1;
		}
		d->depth--;
		F(d, e)->wire.value.len = d->off - start;
		if (remaining(d) < 4)
			return fail(d, NFSP_DECODE_TRUNCATED, ty->sub,
				    "record ends here");
		present = rd32(d, d->off);
		if (present > 1)
			return fail(d, NFSP_DECODE_MALFORMED, ty->sub,
				    "list link is not 0 or 1");
		meta(d, e, NFSP_META_DISCRIMINANT, d->off, 4);
		d->off += 4;
		finish(d, e, start);
		i++;
	}
	F(d, me)->wire.value.len = d->off - F(d, me)->wire.value.off;
	return 0;
}

static int dec_struct(struct dec *d, uint16_t t, uint32_t me)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];

	for (uint32_t k = 0; k < ty->count; k++) {
		const struct nfsp_schema_field *f = &d->s->fields[ty->first + k];

		if (decode(d, f->type, me, NULL, f->name, NFSP_FIELD_NONE))
			return -1;
	}
	F(d, me)->wire.value.len = d->off - F(d, me)->wire.value.off;
	return 0;
}

static int new_op(struct dec *d, uint16_t t, uint32_t opcode,
		  const char *name, uint32_t seq)
{
	struct nfsp_decoded_msg *m = d->m;

	if (m->nops == m->ops_cap) {
		uint32_t cap = m->ops_cap ? m->ops_cap * 2u : 16u;
		void *n;

		if (cap > d->max_fields || cap < m->ops_cap)
			cap = d->max_fields;
		if (m->nops >= cap)
			return fail(d, NFSP_DECODE_RESOURCE_LIMIT, t,
				    "operation limit");
		n = realloc(m->ops, (size_t)cap * sizeof(*m->ops));
		if (!n)
			return fail(d, NFSP_DECODE_RESOURCE_LIMIT, t,
				    "out of memory");
		m->ops = n;
		m->ops_cap = cap;
	}
	memset(&m->ops[m->nops], 0, sizeof(m->ops[0]));
	m->ops[m->nops].opcode = opcode;
	m->ops[m->nops].name = name;
	m->ops[m->nops].sequence_index = seq;
	m->ops[m->nops].field = NFSP_FIELD_NONE;
	m->nops++;
	return 0;
}

static int dec_union(struct dec *d, uint16_t t, uint32_t parent,
		     const char *root, const char *component, uint32_t index)
{
	const struct nfsp_schema_type *ty = &d->s->types[t];
	const struct nfsp_schema_arm *arm = NULL;
	uint8_t mine = d->response ? NFSP_STF_OPS_RESPONSE :
				     NFSP_STF_OPS_REQUEST;
	int is_op = (ty->flags & mine) != 0;
	uint32_t start = d->off, w, me, dn, saved_op = d->op;
	uint32_t saved_start = d->op_start;
	int rc = 0;

	/* An operation boundary sets op/op_start for its arm and restores the
	 * enclosing ones after it.  An ordinary union changes neither. */

	/* The normalizer refuses an operation union of the other direction
	 * in a message; a table that has one was not made by it. */
	if (ty->flags & (NFSP_STF_OPS_REQUEST | NFSP_STF_OPS_RESPONSE) & ~mine)
		return fail(d, NFSP_DECODE_UNSUPPORTED_SCHEMA, t,
			    "operation union of the other direction");
	if (remaining(d) < 4)
		return fail(d, NFSP_DECODE_TRUNCATED, t, "record ends here");
	w = rd32(d, d->off);
	if (check_word(d, ty->sub, w))
		return -1;
	for (uint32_t i = 0; i < ty->count; i++) {
		if (i == ty->default_arm)
			continue;
		if (d->s->arms[ty->first + i].value == w) {
			arm = &d->s->arms[ty->first + i];
			break;
		}
	}
	if (!arm && ty->default_arm != NFSP_SCHEMA_NONE)
		arm = &d->s->arms[ty->first + ty->default_arm];
	if (!arm)
		return fail(d, NFSP_DECODE_MALFORMED, t,
			    "no union arm for discriminant");

	if (is_op) {
		/* An operation is a path root of its own: <family>.<dir>.<OP>.
		 * The array position stays as `index`, metadata only. */
		if (new_op(d, t, w, arm->branch, index))
			return -1;
		d->op = d->m->nops - 1;
		root = arm->branch;
		component = NULL;
	}
	if (emit(d, t, parent, root, component, index, &me))
		goto out_fail;
	if (is_op)
		d->m->ops[d->op].field = me;
	meta(d, me, NFSP_META_DISCRIMINANT, d->off, 4);

	/* The discriminant is a node of its own: `result.status` is a path. */
	if (emit(d, ty->sub, me, NULL, ty->disc_name, NFSP_FIELD_NONE, &dn))
		goto out_fail;
	F(d, dn)->value = d->s->types[ty->sub].kind == NFSP_XK_INT ?
		(uint64_t)(int64_t)(int32_t)w : w;
	F(d, dn)->wire.value.len = 4;
	d->off += 4;
	F(d, dn)->wire.encoded.len = 4;
	if (is_op)
		d->op_start = d->off;	/* the result follows the opcode */
	else
		status_at(d, ty->sub, start, w);

	F(d, me)->wire.value.off = d->off;
	if (arm->type != NFSP_SCHEMA_NONE &&
	    decode(d, arm->type, me, NULL, arm->component, NFSP_FIELD_NONE))
		goto out_fail;
	F(d, me)->wire.value.len = d->off - F(d, me)->wire.value.off;
	finish(d, me, start);
	goto out;
out_fail:
	rc = -1;
out:
	if (is_op) {
		d->op = saved_op;
		d->op_start = saved_start;
	}
	return rc;
}

static int decode(struct dec *d, uint16_t t, uint32_t parent,
		  const char *root, const char *component, uint32_t index)
{
	const struct nfsp_schema_type *ty;
	uint32_t me, start = d->off;
	int rc;

	if (t >= d->s->ntypes)
		return fail(d, NFSP_DECODE_UNSUPPORTED_SCHEMA, t,
			    "type index outside the schema");
	ty = &d->s->types[t];
	if (++d->depth > NFSP_DECODE_MAX_DEPTH) {
		d->depth--;
		return fail(d, NFSP_DECODE_RESOURCE_LIMIT, t, "nesting depth");
	}
	if (ty->kind == NFSP_XK_UNION) {
		rc = dec_union(d, t, parent, root, component, index);
		d->depth--;
		return rc;
	}
	if (emit(d, t, parent, root, component, index, &me)) {
		d->depth--;
		return -1;
	}
	switch (ty->kind) {
	case NFSP_XK_INT:
	case NFSP_XK_UINT:
	case NFSP_XK_HYPER:
	case NFSP_XK_UHYPER:
	case NFSP_XK_BOOL:
	case NFSP_XK_ENUM:
		rc = dec_scalar(d, t, me);
		break;
	case NFSP_XK_OPAQUE_FIXED:
	case NFSP_XK_OPAQUE_VAR:
	case NFSP_XK_STRING:
		rc = dec_bytes(d, t, me);
		break;
	case NFSP_XK_ARRAY_FIXED:
	case NFSP_XK_ARRAY_VAR:
		rc = dec_array(d, t, me);
		break;
	case NFSP_XK_LIST:
		rc = dec_list(d, t, me);
		break;
	case NFSP_XK_STRUCT:
		rc = dec_struct(d, t, me);
		break;
	default:
		rc = fail(d, NFSP_DECODE_UNSUPPORTED_SCHEMA, t,
			  "type kind without a decoder");
		break;
	}
	d->depth--;
	if (rc)
		return -1;
	finish(d, me, start);
	return 0;
}

static const struct nfsp_schema_family *
find_family(const struct nfsp_schema_family *const *fams, size_t n,
	    uint32_t prog, uint32_t vers)
{
	for (size_t i = 0; i < n; i++)
		if (fams[i] && fams[i]->program == prog &&
		    fams[i]->version == vers && fams[i]->nschemas > 0)
			return fams[i];
	return NULL;
}

static void reset(struct nfsp_decoded_msg *m)
{
	struct nfsp_semantic_field *fields = m->fields;
	struct nfsp_decoded_op *ops = m->ops;
	uint32_t fcap = m->fields_cap, ocap = m->ops_cap;

	memset(m, 0, sizeof(*m));
	m->fields = fields;
	m->ops = ops;
	m->fields_cap = fcap;
	m->ops_cap = ocap;
}

static enum nfsp_decode_status refuse(struct dec *d,
				      enum nfsp_decode_status st,
				      const char *reason)
{
	d->st = st;
	d->m->failure.offset = d->off;
	d->m->failure.schema_node = NULL;
	d->m->failure.reason = reason;
	return st;
}

/* Read the minor version of a CALL from the members its argument struct
 * shares across the family (normalize.py proves the layout identical up to
 * and including that member, so any schema of the family reads it right). */
static int probe_minor(struct dec *d, const struct nfsp_schema_family *fam,
		       const struct nfsp_schema_proc *pr, uint32_t *minor)
{
	const struct nfsp_protocol_schema *s0 = fam->schemas[0];
	const struct nfsp_schema_type *ty;
	uint32_t idx = 0;

	if (pr->arg >= s0->ntypes)
		return refuse(d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
			      "minor-version selector has no argument"), -1;
	ty = &s0->types[pr->arg];
	d->s = s0;
	d->probing = 1;
	for (uint32_t k = 0; k <= s0->selector_field && k < ty->count; k++) {
		const struct nfsp_schema_field *f = &s0->fields[ty->first + k];

		idx = d->m->nfields;
		if (decode(d, f->type, NFSP_FIELD_NONE, pr->name, f->name,
			   NFSP_FIELD_NONE)) {
			d->probing = 0;
			return -1;
		}
	}
	d->probing = 0;
	*minor = (uint32_t)d->m->fields[idx].value;
	return 0;
}

enum nfsp_decode_status
nfsp_nfs_decode(const struct nfsp_schema_family *const *families,
		size_t nfamilies, const struct nfsp_decode_input *in,
		struct nfsp_decoded_msg *out)
{
	const struct nfsp_schema_family *fam;
	const struct nfsp_protocol_schema *s;
	const struct nfsp_schema_proc *pr;
	const struct nfsp_rpc_envelope *rpc;
	struct dec d;
	uint16_t root_type;
	const char *leaf;

	reset(out);
	memset(&d, 0, sizeof(d));
	d.m = out;
	d.op = NFSP_FIELD_NONE;
	d.st = NFSP_DECODE_DECODED;

	if (!in || !in->rpc || in->rpc->status != NFSP_RPC_OK ||
	    (!in->payload && in->len) || in->len > UINT32_MAX ||
	    in->rpc->body.off > in->len ||
	    in->rpc->body.len != in->len - in->rpc->body.off) {
		refuse(&d, NFSP_DECODE_MALFORMED,
		       "input is not a decoded RPC envelope of this payload");
		goto done;
	}
	rpc = in->rpc;
	d.p = in->payload;
	d.len = (uint32_t)in->len;
	d.max_fields = in->max_fields ? in->max_fields :
			NFSP_DECODE_DEFAULT_MAX_FIELDS;
	out->msg_type = rpc->msg_type;
	out->xid = rpc->xid;
	d.off = rpc->body.off;

	if (rpc->msg_type == NFSP_RPC_CALL) {
		uint32_t minor = 0;

		out->program = rpc->prog;
		out->version = rpc->vers;
		out->procedure = rpc->proc;
		fam = find_family(families, nfamilies, rpc->prog, rpc->vers);
		if (!fam) {
			refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
			       "no schema for this program and version");
			goto done;
		}
		if (rpc->cred.flavor == NFSP_RPC_RPCSEC_GSS) {
			/* Before the minor-version probe, which already reads
			 * the body as arguments. */
			refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
			       "RPCSEC_GSS body is not decoded");
			goto done;
		}
		s = fam->schemas[0];
		if (fam->has_minor) {
			if (rpc->proc != s->selector_proc ||
			    !(pr = nfsp_schema_proc(s, rpc->proc))) {
				/* e.g. NFSv4 NULL: no COMPOUND, so no minor
				 * version, so no single schema applies. */
				refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
				       "procedure carries no minor version");
				goto done;
			}
			if (probe_minor(&d, fam, pr, &minor))
				goto done;
			reset(out);
			out->msg_type = rpc->msg_type;
			out->xid = rpc->xid;
			out->program = rpc->prog;
			out->version = rpc->vers;
			out->procedure = rpc->proc;
			d.off = rpc->body.off;
			s = nfsp_schema_minor(fam, minor);
			out->has_minor = 1;
			out->minor_version = minor;
			if (!s) {
				refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
				       "minor version not in the schema");
				goto done;
			}
		}
		out->schema = s;
		d.s = s;
		pr = nfsp_schema_proc(s, rpc->proc);
		if (!pr) {
			refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
			       "procedure not in the schema");
			goto done;
		}
		root_type = pr->arg;
		leaf = s->request_leaf;
	} else {
		const struct nfsp_reply_dispatch *rd = in->reply_dispatch;

		d.response = 1;
		if (!rd || (rd->source != NFSP_DISPATCH_TRANSACTION_ENTRY &&
			    rd->source != NFSP_DISPATCH_TEST_FIXTURE)) {
			refuse(&d, NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
			       "no reply_dispatch");
			goto done;
		}
		if (rd->source == NFSP_DISPATCH_TEST_FIXTURE &&
		    !in->allow_test_fixture) {
			refuse(&d, NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
			       "test_fixture dispatch outside host tests");
			goto done;
		}
		out->dispatch_source = rd->source;
		out->program = rd->program;
		out->version = rd->version;
		out->procedure = rd->procedure;
		fam = find_family(families, nfamilies, rd->program,
				  rd->version);
		if (!fam) {
			refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
			       "no schema for this program and version");
			goto done;
		}
		if (rd->cred_flavor == NFSP_RPC_RPCSEC_GSS ||
		    (rpc->reply_stat == NFSP_RPC_MSG_ACCEPTED &&
		     rpc->verf.flavor == NFSP_RPC_RPCSEC_GSS)) {
			refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
			       "RPCSEC_GSS body is not decoded");
			goto done;
		}
		s = fam->schemas[0];
		if (fam->has_minor) {
			if (!rd->has_minor) {
				refuse(&d, NFSP_DECODE_DISPATCH_INCOMPLETE,
				       "reply_dispatch has no minor version");
				goto done;
			}
			out->has_minor = 1;
			out->minor_version = rd->minor_version;
			s = nfsp_schema_minor(fam, rd->minor_version);
			if (!s) {
				refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
				       "minor version not in the schema");
				goto done;
			}
		}
		out->schema = s;
		d.s = s;
		pr = nfsp_schema_proc(s, rd->procedure);
		if (!pr) {
			refuse(&d, NFSP_DECODE_UNSUPPORTED_SCHEMA,
			       "procedure not in the schema");
			goto done;
		}
		root_type = pr->res;
		leaf = s->response_leaf;
		if (rpc->reply_stat != NFSP_RPC_MSG_ACCEPTED ||
		    rpc->accept_stat != NFSP_RPC_SUCCESS) {
			/* No procedure result exists on this arm (RFC 5531
			 * §9).  Nothing to decode, and nothing may follow. */
			out->procedure_name = pr->name;
			if (rpc->body.len)
				refuse(&d, NFSP_DECODE_MALFORMED,
				       "bytes after a reply without results");
			goto done;
		}
	}
	out->procedure_name = pr->name;
	if (root_type != NFSP_SCHEMA_NONE &&
	    decode(&d, root_type, NFSP_FIELD_NONE, pr->name, leaf,
		   NFSP_FIELD_NONE)) {
		if (d.st == NFSP_DECODE_PARTIAL)
			finish_partial(&d);
		goto done;
	}
	if (d.off != d.len) {
		if (d.response) {
			fail(&d, NFSP_DECODE_MALFORMED, root_type,
			     "bytes after the procedure body");
		} else {
			out->trailing.off = d.off;
			out->trailing.len = d.len - d.off;
		}
	}
done:
	out->status = d.st;
	if (out->status != NFSP_DECODE_DECODED &&
	    out->status != NFSP_DECODE_PARTIAL) {
		out->nfields = 0;
		out->nops = 0;
	}
	return out->status;
}

void nfsp_decoded_msg_free(struct nfsp_decoded_msg *m)
{
	if (!m)
		return;
	free(m->fields);
	free(m->ops);
	memset(m, 0, sizeof(*m));
}

static size_t put(char *buf, size_t cap, size_t at, const char *s)
{
	size_t n = strlen(s);

	if (at < cap) {
		size_t room = cap - at - 1;

		memcpy(buf + at, s, n < room ? n : room);
		buf[at + (n < room ? n : room)] = '\0';
	}
	return at + n;
}

/* A path is never materialised in the message: it is the concatenation of
 * static pieces (family, direction, root, components).  Both the formatter
 * and the matcher walk the same pieces, so neither has a length limit of its
 * own (PR #25 review: a fixed buffer made long valid paths unfindable). */
#define CHAIN_MAX	(2u * NFSP_DECODE_MAX_DEPTH + 2u)
#define SEGS_MAX	(3u + 2u * CHAIN_MAX)

static size_t path_segments(const struct nfsp_decoded_msg *m, uint32_t idx,
			    const char **seg)
{
	uint32_t chain[CHAIN_MAX];
	size_t n = 0, k = 0;
	uint32_t i = idx;

	if (!m || !m->schema || idx >= m->nfields)
		return 0;
	for (;;) {
		if (n == CHAIN_MAX || i >= m->nfields)
			return 0;
		chain[n++] = i;
		if (m->fields[i].root)
			break;
		i = m->fields[i].parent;
	}
	seg[k++] = m->schema->family;
	seg[k++] = m->msg_type == NFSP_RPC_CALL ? ".request." : ".response.";
	seg[k++] = m->fields[chain[n - 1]].root;
	while (n--) {
		const char *c = m->fields[chain[n]].component;

		if (!c)
			continue;
		if (strcmp(c, "[]"))
			seg[k++] = ".";
		seg[k++] = c;
	}
	return k;
}

size_t nfsp_field_path(const struct nfsp_decoded_msg *m, uint32_t idx,
		       char *buf, size_t cap)
{
	const char *seg[SEGS_MAX];
	size_t n, at = 0;

	if (cap)
		buf[0] = '\0';
	n = path_segments(m, idx, seg);
	for (size_t k = 0; k < n; k++)
		at = put(buf, cap, at, seg[k]);
	return at;
}

uint32_t nfsp_field_find(const struct nfsp_decoded_msg *m, const char *path,
			 uint32_t from)
{
	const char *seg[SEGS_MAX];

	for (uint32_t i = from; m && path && i < m->nfields; i++) {
		size_t n = path_segments(m, i, seg);
		const char *p = path;
		size_t k;

		for (k = 0; k < n; k++) {
			size_t len = strlen(seg[k]);

			if (strncmp(p, seg[k], len))
				break;
			p += len;
		}
		if (n && k == n && !*p)
			return i;
	}
	return NFSP_FIELD_NONE;
}

const char *nfsp_decode_strstatus(enum nfsp_decode_status status)
{
	switch (status) {
	case NFSP_DECODE_DECODED: return "decoded";
	case NFSP_DECODE_UNSUPPORTED_SCHEMA: return "unsupported_schema";
	case NFSP_DECODE_MALFORMED: return "malformed";
	case NFSP_DECODE_TRUNCATED: return "truncated";
	case NFSP_DECODE_TRANSACTION_CONTEXT_MISSING:
		return "transaction_context_missing";
	case NFSP_DECODE_DISPATCH_INCOMPLETE: return "dispatch_incomplete";
	case NFSP_DECODE_RESOURCE_LIMIT: return "resource_limit";
	case NFSP_DECODE_PARTIAL: return "partial";
	}
	return "unknown";
}
