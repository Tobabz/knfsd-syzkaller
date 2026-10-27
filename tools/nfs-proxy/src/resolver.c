/* M4b semantic rule resolver.  See resolver.h and design 04 sections 21-31. */
#include "resolver.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct live_value {
	enum nfsp_rule_literal_kind kind;
	uint64_t number;
	const uint8_t *bytes;
	uint32_t len;
};

enum ref_result {
	REF_OK = 0,
	REF_MISSING,
	REF_AMBIGUOUS,
	REF_UNUSABLE
};

enum mutation_result {
	MUTATION_OK = 0,
	MUTATION_UNSUPPORTED,
	MUTATION_FAILED,
	MUTATION_STRUCTURE,
	MUTATION_NOMEM
};

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get64(const uint8_t *p)
{
	return ((uint64_t)get32(p) << 32) | (uint64_t)get32(p + 4);
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)(v >> 32));
	put32(p + 4, (uint32_t)v);
}

static int span_valid(struct nfsp_span s, size_t len)
{
	return (uint64_t)s.off + s.len <= len;
}

static int decoded(const struct nfsp_decoded_msg *m)
{
	return m != NULL && (m->status == NFSP_DECODE_DECODED ||
			     m->status == NFSP_DECODE_PARTIAL);
}

static enum nfsp_rule_literal_kind value_kind(uint8_t kind)
{
	switch (kind) {
	case NFSP_XK_INT: return NFSP_LIT_INT;
	case NFSP_XK_UINT: return NFSP_LIT_UINT;
	case NFSP_XK_HYPER: return NFSP_LIT_HYPER;
	case NFSP_XK_UHYPER: return NFSP_LIT_UHYPER;
	case NFSP_XK_BOOL: return NFSP_LIT_BOOL;
	case NFSP_XK_ENUM: return NFSP_LIT_ENUM;
	case NFSP_XK_OPAQUE_FIXED:
	case NFSP_XK_OPAQUE_VAR: return NFSP_LIT_OPAQUE;
	case NFSP_XK_STRING: return NFSP_LIT_STRING;
	default: return (enum nfsp_rule_literal_kind)-1;
	}
}

static int field_value(const struct nfsp_decoded_msg *m,
		       const uint8_t *payload, size_t payload_len, uint32_t field,
		       struct live_value *out)
{
	const struct nfsp_semantic_field *f;
	const struct nfsp_schema_type *ty;
	enum nfsp_rule_literal_kind kind;

	if (!decoded(m) || m->schema == NULL || field >= m->nfields)
		return -1;
	f = &m->fields[field];
	if (f->type >= m->schema->ntypes ||
	    !span_valid(f->wire.value, payload_len))
		return -1;
	ty = &m->schema->types[f->type];
	kind = value_kind(ty->kind);
	if ((int)kind < 0)
		return -1;
	memset(out, 0, sizeof(*out));
	out->kind = kind;
	out->bytes = payload + f->wire.value.off;
	out->len = f->wire.value.len;
	switch (ty->kind) {
	case NFSP_XK_INT:
	case NFSP_XK_UINT:
	case NFSP_XK_BOOL:
	case NFSP_XK_ENUM:
		if (out->len != 4u)
			return -1;
		out->number = ty->kind == NFSP_XK_INT ?
			(uint64_t)(int64_t)(int32_t)get32(out->bytes) :
			(uint64_t)get32(out->bytes);
		break;
	case NFSP_XK_HYPER:
	case NFSP_XK_UHYPER:
		if (out->len != 8u)
			return -1;
		out->number = get64(out->bytes);
		break;
	default:
		break;
	}
	return 0;
}

static struct live_value literal_value(const struct nfsp_rule_literal *l)
{
	struct live_value v;

	memset(&v, 0, sizeof(v));
	v.kind = l->kind;
	v.number = l->num;
	v.bytes = l->bytes;
	v.len = l->len;
	return v;
}

/* Find exactly one path occurrence.  When bind_op is true it must belong to
 * that operation occurrence; otherwise it is message-wide. */
static enum ref_result select_path(const struct nfsp_decoded_msg *m,
				   const char *path, int bind_op,
				   uint32_t wanted_op, uint32_t *field)
{
	uint32_t from = 0, found = NFSP_FIELD_NONE, count = 0;

	while (from < m->nfields) {
		uint32_t at = nfsp_field_find(m, path, from);

		if (at == NFSP_FIELD_NONE)
			break;
		from = at + 1u;
		if (bind_op && m->fields[at].op != wanted_op)
			continue;
		found = at;
		count++;
	}
	if (count == 0)
		return REF_MISSING;
	if (count != 1u)
		return REF_AMBIGUOUS;
	*field = found;
	return REF_OK;
}

static uint32_t op_by_sequence(const struct nfsp_decoded_msg *m, uint32_t seq)
{
	for (uint32_t i = 0; i < m->nops; i++)
		if (m->ops[i].sequence_index == seq)
			return i;
	return NFSP_FIELD_NONE;
}

static int same_operations(const struct nfsp_decoded_msg *a,
			   const struct nfsp_decoded_msg *b)
{
	if (a->nops != b->nops)
		return 0;
	for (uint32_t i = 0; i < a->nops; i++)
		if (a->ops[i].sequence_index != b->ops[i].sequence_index ||
		    a->ops[i].opcode != b->ops[i].opcode)
			return 0;
	return 1;
}

static int view_valid(const struct nfsp_resolver_view *v,
		      const struct nfsp_protocol_schema *schema)
{
	return v != NULL && v->payload != NULL && decoded(v->message) &&
	       v->message->msg_type == NFSP_RPC_CALL &&
	       v->message->schema != NULL &&
	       !strcmp(v->message->schema->schema_id, schema->schema_id);
}

static enum ref_result
resolve_ref(const struct nfsp_rule_value_ref *ref,
	    const struct nfsp_rule *rule, uint32_t target,
	    const struct nfsp_resolver_record *record, uint32_t *field,
	    const uint8_t **payload, size_t *payload_len,
	    const struct nfsp_decoded_msg **message)
{
	const struct nfsp_decoded_msg *current = record->message;
	const struct nfsp_semantic_field *tf = &current->fields[target];
	const struct nfsp_resolver_transaction *tx = record->transaction;
	const struct nfsp_resolver_view *view;
	uint32_t wanted_op = NFSP_FIELD_NONE;
	int bind_op = 0;
	int same_operation;

	(void)rule;
	if (ref->source == NFSP_SRC_TARGET) {
		*field = target;
		*payload = record->payload;
		*payload_len = record->payload_len;
		*message = current;
		return REF_OK;
	}
	/* Only references to this operation type share the target occurrence.
	 * Other operation types must be unique across the selected message. */
	same_operation = (ref->node.flags & NFSP_SN_OPERATION) &&
		ref->node.root != NULL && tf->op < current->nops &&
		!strcmp(ref->node.root, current->ops[tf->op].name);
	if (ref->source == NFSP_SRC_CURRENT_MESSAGE) {
		if (same_operation) {
			bind_op = 1;
			wanted_op = tf->op;
		}
		*payload = record->payload;
		*payload_len = record->payload_len;
		*message = current;
		return select_path(current, ref->path, bind_op, wanted_op,
				   field);
	}
	if (tx == NULL || tx->state != NFSP_RESOLVER_TXN_FOUND)
		return REF_UNUSABLE;
	view = ref->source == NFSP_SRC_REQUEST_FORWARDED ?
		&tx->forwarded : &tx->original;
	if (!view_valid(view, current->schema))
		return REF_UNUSABLE;
	if ((ref->node.flags & NFSP_SN_OPERATION) &&
	    tf->op != NFSP_FIELD_NONE) {
		uint32_t seq, cur_op, req_op;

		if (tf->op >= current->nops)
			return REF_UNUSABLE;
		seq = current->ops[tf->op].sequence_index;
		cur_op = current->ops[tf->op].opcode;
		req_op = op_by_sequence(view->message, seq);
		if (req_op == NFSP_FIELD_NONE ||
		    view->message->ops[req_op].opcode != cur_op)
			return REF_AMBIGUOUS;
		/* request_original may bind only when its operation sequence is
		 * demonstrably the one forwarded to the server. */
		if (ref->source == NFSP_SRC_REQUEST_ORIGINAL) {
			uint32_t fwd_op;

			if (!view_valid(&tx->forwarded, current->schema) ||
			    !same_operations(tx->original.message,
					     tx->forwarded.message))
				return REF_AMBIGUOUS;
			fwd_op = op_by_sequence(tx->forwarded.message, seq);
			if (fwd_op == NFSP_FIELD_NONE ||
			    tx->forwarded.message->ops[fwd_op].opcode != cur_op)
				return REF_AMBIGUOUS;
		}
		/* Even a message-wide cross-operation reference must not bypass
		 * the request/result correspondence checks above.  Only a
		 * same-type reference is narrowed to that proven occurrence. */
		bind_op = same_operation;
		wanted_op = req_op;
	}
	*payload = view->payload;
	*payload_len = view->payload_len;
	*message = view->message;
	return select_path(view->message, ref->path, bind_op, wanted_op, field);
}

static enum ref_result
value_ref(const struct nfsp_rule_value_ref *ref, const struct nfsp_rule *rule,
	  uint32_t target, const struct nfsp_resolver_record *record,
	  struct live_value *value)
{
	const struct nfsp_decoded_msg *m;
	const uint8_t *payload;
	size_t payload_len;
	uint32_t field;
	enum ref_result rr = resolve_ref(ref, rule, target, record, &field,
					&payload, &payload_len, &m);

	if (rr != REF_OK)
		return rr;
	return field_value(m, payload, payload_len, field, value) == 0 ?
		REF_OK : REF_UNUSABLE;
}

static int equal_value(const struct live_value *a,
		       const struct live_value *b)
{
	if (a->kind != b->kind)
		return 0;
	if (a->kind == NFSP_LIT_OPAQUE || a->kind == NFSP_LIT_STRING)
		return a->len == b->len &&
		       (a->len == 0u || !memcmp(a->bytes, b->bytes, a->len));
	return a->number == b->number;
}

static int compare_value(const struct live_value *a,
			 const struct live_value *b, enum nfsp_rule_compare op)
{
	int cmp;

	if (op == NFSP_CMP_EQ || op == NFSP_CMP_NE) {
		int eq = equal_value(a, b);

		return op == NFSP_CMP_EQ ? eq : !eq;
	}
	if (a->kind == NFSP_LIT_INT || a->kind == NFSP_LIT_HYPER) {
		int64_t av = (int64_t)a->number;
		int64_t bv = (int64_t)b->number;

		cmp = av < bv ? -1 : av > bv;
	} else {
		cmp = a->number < b->number ? -1 : a->number > b->number;
	}
	switch (op) {
	case NFSP_CMP_LT: return cmp < 0;
	case NFSP_CMP_LE: return cmp <= 0;
	case NFSP_CMP_GT: return cmp > 0;
	case NFSP_CMP_GE: return cmp >= 0;
	default: return 0;
	}
}

/* Evaluate every conjunct so an ambiguous reference is not hidden by an
 * earlier false conjunct. */
static enum nfsp_resolve_status
predicates(const struct nfsp_rule *rule, uint32_t target,
	   const struct nfsp_resolver_record *record)
{
	int false_seen = 0, ambiguous = 0, unusable = 0;

	for (uint32_t i = 0; i < rule->npredicates; i++) {
		const struct nfsp_rule_predicate *p = &rule->predicates[i];
		struct live_value lhs, rhs;
		enum ref_result lr, rr = REF_OK;

		lr = value_ref(&p->lhs, rule, target, record, &lhs);
		if (p->rhs_kind == NFSP_OPND_LITERAL)
			rhs = literal_value(&p->rhs_literal);
		else
			rr = value_ref(&p->rhs_ref, rule, target, record, &rhs);
		if (lr == REF_AMBIGUOUS || rr == REF_AMBIGUOUS) {
			ambiguous = 1;
			continue;
		}
		if (lr == REF_UNUSABLE || rr == REF_UNUSABLE) {
			unusable = 1;
			continue;
		}
		if (lr == REF_MISSING || rr == REF_MISSING) {
			false_seen = 1;
			continue;
		}
		if (!compare_value(&lhs, &rhs, p->op))
			false_seen = 1;
	}
	if (unusable)
		return NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE;
	if (ambiguous)
		return NFSP_RESOLVE_PREDICATE_REFERENCE_AMBIGUOUS;
	if (false_seen)
		return NFSP_RESOLVE_PREDICATE_FALSE;
	return NFSP_RESOLVE_RESOLVED;
}

static int needs_context(const struct nfsp_rule *rule)
{
	return rule->forwarded.rpc_procedure ||
	       rule->forwarded.request_operation_sequence ||
	       rule->forwarded.nfields || rule->original.rpc_procedure ||
	       rule->original.request_operation_sequence ||
	       rule->original.nfields;
}

static enum nfsp_resolve_status
check_context(const struct nfsp_rule *rule,
	      const struct nfsp_resolver_record *record,
	      const struct nfsp_protocol_schema *schema)
{
	const struct nfsp_resolver_transaction *tx = record->transaction;

	if (!needs_context(rule))
		return NFSP_RESOLVE_RESOLVED;
	if (tx == NULL || tx->state == NFSP_RESOLVER_TXN_MISSING)
		return NFSP_RESOLVE_TRANSACTION_CONTEXT_MISSING;
	if (tx->state != NFSP_RESOLVER_TXN_FOUND ||
	    tx->program != rule->program || tx->version != rule->version ||
	    (rule->has_procedure && tx->procedure != rule->procedure))
		return NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE;
	if (rule->forwarded.nfields && !view_valid(&tx->forwarded, schema))
		return NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE;
	if (rule->original.nfields && !view_valid(&tx->original, schema))
		return NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE;
	return NFSP_RESOLVE_RESOLVED;
}

static int span_for_part(const struct nfsp_semantic_field *f,
			 enum nfsp_rule_part part, struct nfsp_span *span)
{
	switch (part) {
	case NFSP_PART_VALUE: *span = f->wire.value; return 0;
	case NFSP_PART_ENCODED: *span = f->wire.encoded; return 0;
	case NFSP_PART_LENGTH:
		if (!(f->wire.meta & NFSP_META_LENGTH)) return -1;
		*span = f->wire.length; return 0;
	case NFSP_PART_COUNT:
		if (!(f->wire.meta & NFSP_META_COUNT)) return -1;
		*span = f->wire.count; return 0;
	case NFSP_PART_DISCRIMINANT:
		if (!(f->wire.meta & NFSP_META_DISCRIMINANT)) return -1;
		*span = f->wire.discriminant; return 0;
	case NFSP_PART_PADDING:
		if (!(f->wire.meta & NFSP_META_PADDING)) return -1;
		*span = f->wire.padding; return 0;
	}
	return -1;
}

static int snapshot(struct nfsp_resolution *out, uint8_t **owned,
		    const uint8_t *bytes, uint32_t len)
{
	uint8_t *p;

	*owned = NULL;
	if (len == 0u)
		return 0;
	if (len > NFSP_RESOLVED_SNAPSHOT_MAX ||
	    out->snapshot_bytes > NFSP_RESOLVED_SNAPSHOT_MAX - len)
		return 1;
	p = malloc(len);
	if (p == NULL)
		return -1;
	memcpy(p, bytes, len);
	out->snapshot_bytes += len;
	*owned = p;
	return 0;
}

static int encode_value(const struct live_value *value, uint8_t scalar[8],
			const uint8_t **bytes, uint32_t *len)
{
	switch (value->kind) {
	case NFSP_LIT_INT:
	case NFSP_LIT_UINT:
	case NFSP_LIT_BOOL:
	case NFSP_LIT_ENUM:
		put32(scalar, (uint32_t)value->number);
		*bytes = scalar;
		*len = 4;
		return 0;
	case NFSP_LIT_HYPER:
	case NFSP_LIT_UHYPER:
		put64(scalar, value->number);
		*bytes = scalar;
		*len = 8;
		return 0;
	case NFSP_LIT_OPAQUE:
	case NFSP_LIT_STRING:
		*bytes = value->bytes;
		*len = value->len;
		return 0;
	}
	return -1;
}

static int target_current(const struct nfsp_rule *rule,
			  const struct nfsp_resolver_record *record,
			  uint32_t target, struct nfsp_span selected,
			  struct live_value *value)
{
	if (rule->part == NFSP_PART_VALUE)
		return field_value(record->message, record->payload,
				   record->payload_len, target, value);
	memset(value, 0, sizeof(*value));
	value->bytes = record->payload + selected.off;
	value->len = selected.len;
	if (rule->part == NFSP_PART_PADDING) {
		value->kind = NFSP_LIT_OPAQUE;
		return 0;
	}
	if (selected.len != 4u)
		return -1;
	value->kind = NFSP_LIT_UINT;
	value->number = get32(value->bytes);
	return 0;
}

static enum mutation_result
make_mutation(const struct nfsp_rule *rule, uint32_t target,
	      const struct nfsp_resolver_record *record,
	      struct nfsp_resolution *out, struct nfsp_resolved_mutation *m)
{
	const struct nfsp_semantic_field *f = &record->message->fields[target];
	const struct nfsp_schema_type *ty =
		&record->message->schema->types[f->type];
	struct live_value current, output;
	const uint8_t *out_bytes;
	uint8_t scalar[8];
	uint32_t out_len;
	int sr;

	if (rule->kind != NFSP_MUT_REPLACE || !rule->has_transform ||
	    rule->part == NFSP_PART_ENCODED ||
	    rule->transform.kind == NFSP_XF_BUILTIN ||
	    (rule->part != NFSP_PART_VALUE &&
	     rule->transform.kind != NFSP_XF_LITERAL))
		return MUTATION_UNSUPPORTED;
	memset(m, 0, sizeof(*m));
	m->operation_index = NFSP_FIELD_NONE;
	if (span_for_part(f, rule->part, &m->selected) != 0 ||
	    !span_valid(m->selected, record->payload_len))
		return MUTATION_STRUCTURE;
	if (target_current(rule, record, target, m->selected, &current) != 0)
		return MUTATION_STRUCTURE;
	if (rule->transform.kind == NFSP_XF_LITERAL) {
		output = literal_value(&rule->transform.value);
	} else if (rule->transform.kind == NFSP_XF_COPY) {
		enum ref_result rr = value_ref(&rule->transform.source, rule,
					       target, record, &output);

		if (rr != REF_OK)
			return MUTATION_FAILED;
	} else {
		return MUTATION_UNSUPPORTED;
	}
	if (encode_value(&output, scalar, &out_bytes, &out_len) != 0)
		return MUTATION_FAILED;
	m->rule_id = rule->rule_id;
	m->semantic_path = rule->target_path;
	m->field_index = target;
	m->operation_index = f->op;
	m->part = rule->part;
	m->policy = rule->policy;
	m->wire = f->wire;
	m->footprint = m->selected;
	if (rule->policy == NFSP_POLICY_PRESERVE &&
	    rule->part == NFSP_PART_VALUE &&
	    (ty->kind == NFSP_XK_OPAQUE_VAR || ty->kind == NFSP_XK_STRING))
		m->footprint = f->wire.encoded;
	if (!span_valid(m->footprint, record->payload_len))
		return MUTATION_STRUCTURE;
	m->current.kind = current.kind;
	m->current.number = current.number;
	m->current.len = current.len;
	sr = snapshot(out, &m->current_storage, current.bytes, current.len);
	if (sr != 0)
		return sr < 0 ? MUTATION_NOMEM : MUTATION_STRUCTURE;
	m->current.bytes = m->current_storage;
	m->output.kind = output.kind;
	m->output.number = output.number;
	m->output.len = out_len;
	sr = snapshot(out, &m->output_storage, out_bytes, out_len);
	if (sr != 0) {
		free(m->current_storage);
		m->current_storage = NULL;
		out->snapshot_bytes -= current.len;
		return sr < 0 ? MUTATION_NOMEM : MUTATION_STRUCTURE;
	}
	m->output.bytes = m->output_storage;
	return MUTATION_OK;
}

static void count(struct nfsp_rule_resolution *r,
		  enum nfsp_resolve_status status)
{
	if (r->count[status] != UINT32_MAX)
		r->count[status]++;
}

static int rule_scope(const struct nfsp_rule *rule,
		      const struct nfsp_resolver_record *record)
{
	return rule->direction == record->direction &&
	       rule->backend == record->backend && rule->client == record->client;
}

static int rpc_selector(const struct nfsp_rule *rule,
			const struct nfsp_decoded_msg *m)
{
	return (uint32_t)rule->message_type == m->msg_type &&
	       rule->program == m->program && rule->version == m->version &&
	       (!rule->has_procedure || rule->procedure == m->procedure);
}

static int protocol_selector(const struct nfsp_rule *rule,
			     const struct nfsp_decoded_msg *m)
{
	return !strcmp(rule->family, m->schema->family) &&
	       (!rule->has_nfs_version || rule->nfs_version == m->version) &&
	       (!rule->has_minor_version ||
		(m->has_minor && rule->minor_version == m->minor_version));
}

static int target_is_operation(const struct nfsp_rule *rule,
			       const struct nfsp_decoded_msg *m,
			       uint32_t field)
{
	uint32_t op = m->fields[field].op;

	if (rule->operation == NULL)
		return op == NFSP_FIELD_NONE;
	return op < m->nops && !strcmp(rule->operation, m->ops[op].name);
}

static int footprints_conflict(const struct nfsp_resolved_mutation *a,
			       const struct nfsp_resolved_mutation *b)
{
	uint64_t ae = (uint64_t)a->footprint.off + a->footprint.len;
	uint64_t be = (uint64_t)b->footprint.off + b->footprint.len;

	/* Two rules own the same semantic field even when its current value is
	 * empty and therefore has a zero-byte value span. */
	if (a->field_index == b->field_index && a->part == b->part)
		return 1;
	return a->footprint.off < be && b->footprint.off < ae;
}

static int mutation_order(const void *ap, const void *bp)
{
	const struct nfsp_resolved_mutation *a = ap, *b = bp;
	int c = strcmp(a->rule_id, b->rule_id);

	if (c)
		return c;
	if (a->field_index != b->field_index)
		return a->field_index < b->field_index ? -1 : 1;
	if (a->part != b->part)
		return a->part < b->part ? -1 : 1;
	return 0;
}

void nfsp_resolution_free(struct nfsp_resolution *out)
{
	if (out == NULL)
		return;
	for (uint32_t i = 0; i < out->nmutations; i++) {
		free(out->mutations[i].current_storage);
		free(out->mutations[i].output_storage);
	}
	free(out->mutations);
	free(out->rules);
	memset(out, 0, sizeof(*out));
}

int nfsp_resolve_rules(const struct nfsp_ruleset *ruleset,
		       const struct nfsp_resolver_record *record,
		       struct nfsp_resolution *out)
{
	uint32_t *order;
	int structure = 0, conflict = 0;

	if (out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));
	if (ruleset == NULL || record == NULL || ruleset->schema == NULL ||
	    (ruleset->nrules != 0u && ruleset->rules == NULL) ||
	    ruleset->nrules > NFSP_RULES_MAX || record->activation_generation == 0u ||
	    record->message == NULL || record->payload == NULL)
		return -1;
	out->activation_generation = record->activation_generation;
	out->nrules = ruleset->nrules;
	/* An empty, validated rule set is target mode's identity transform.  It
	 * still observes and accounts the record, but has nothing to allocate or
	 * resolve. */
	if (out->nrules == 0u) {
		out->preflight = NFSP_PREFLIGHT_EMPTY;
		return 0;
	}
	out->rules = calloc(out->nrules, sizeof(*out->rules));
	out->mutations = calloc(NFSP_RESOLVED_MAX, sizeof(*out->mutations));
	order = malloc((size_t)out->nrules * sizeof(*order));
	if (out->rules == NULL || out->mutations == NULL || order == NULL) {
		free(order);
		nfsp_resolution_free(out);
		return -1;
	}
	for (uint32_t i = 0; i < out->nrules; i++) {
		order[i] = i;
		for (uint32_t j = i; j > 0; j--) {
			const char *a = ruleset->rules[order[j - 1u]].rule_id;
			const char *b = ruleset->rules[order[j]].rule_id;
			uint32_t tmp;

			if (strcmp(a, b) <= 0)
				break;
			tmp = order[j - 1u];
			order[j - 1u] = order[j];
			order[j] = tmp;
		}
	}
	for (uint32_t i = 1; i < out->nrules; i++)
		if (!strcmp(ruleset->rules[order[i - 1u]].rule_id,
			    ruleset->rules[order[i]].rule_id)) {
			free(order);
			nfsp_resolution_free(out);
			return -1;
		}

	for (uint32_t ri = 0; ri < out->nrules; ri++) {
		const struct nfsp_rule *rule = &ruleset->rules[order[ri]];
		struct nfsp_rule_resolution *result = &out->rules[ri];
		const struct nfsp_decoded_msg *m = record->message;
		enum nfsp_resolve_status cs;
		uint32_t from = 0, targets = 0;

		result->rule_id = rule->rule_id;
		if (!rule_scope(rule, record)) {
			count(result, NFSP_RESOLVE_SCOPE_MISS);
			continue;
		}
		if (!rpc_selector(rule, m)) {
			count(result, NFSP_RESOLVE_RPC_SELECTOR_MISS);
			continue;
		}
		if (!decoded(m) || m->schema == NULL) {
			count(result, NFSP_RESOLVE_DECODE_UNAVAILABLE);
			continue;
		}
		if (strcmp(ruleset->schema_id, m->schema->schema_id)) {
			count(result, NFSP_RESOLVE_SCHEMA_MISMATCH);
			continue;
		}
		if (!protocol_selector(rule, m)) {
			count(result, NFSP_RESOLVE_RPC_SELECTOR_MISS);
			continue;
		}
		cs = check_context(rule, record, ruleset->schema);
		if (cs != NFSP_RESOLVE_RESOLVED) {
			count(result, cs);
			continue;
		}
		while (from < m->nfields) {
			uint32_t target = nfsp_field_find(m, rule->target_path, from);
			struct nfsp_resolved_mutation mutation;
			enum mutation_result mr;

			if (target == NFSP_FIELD_NONE)
				break;
			from = target + 1u;
			if (m->fields[target].type != rule->target.type ||
			    !target_is_operation(rule, m, target))
				continue;
			targets++;
			cs = predicates(rule, target, record);
			if (cs != NFSP_RESOLVE_RESOLVED) {
				count(result, cs);
				continue;
			}
			mr = make_mutation(rule, target, record, out, &mutation);
			if (mr == MUTATION_UNSUPPORTED) {
				count(result, NFSP_RESOLVE_TRANSFORM_UNSUPPORTED);
				continue;
			}
			if (mr == MUTATION_FAILED) {
				count(result, NFSP_RESOLVE_TRANSFORM_FAILED);
				continue;
			}
			if (mr == MUTATION_NOMEM) {
				free(order);
				nfsp_resolution_free(out);
				return -1;
			}
			result->eligible++;
			if (mr == MUTATION_STRUCTURE || structure ||
			    out->nmutations == NFSP_RESOLVED_MAX) {
				if (mr == MUTATION_OK) {
					free(mutation.current_storage);
					free(mutation.output_storage);
					out->snapshot_bytes -=
						(size_t)mutation.current.len +
						mutation.output.len;
				}
				structure = 1;
				continue;
			}
			out->mutations[out->nmutations++] = mutation;
		}
		if (targets == 0u)
			count(result, NFSP_RESOLVE_TARGET_NOT_FOUND);
	}
	free(order);

	if (structure) {
		out->preflight = NFSP_PREFLIGHT_STRUCTURE_CONSTRAINT_FAILED;
		for (uint32_t i = 0; i < out->nrules; i++)
			for (uint32_t n = 0; n < out->rules[i].eligible; n++)
				count(&out->rules[i],
				      NFSP_RESOLVE_STRUCTURE_CONSTRAINT_FAILED);
		/* A bounded-prefix is not a ResolvedMutation set.  Keep only the
		 * rule summaries and expose no partial semantic output. */
		for (uint32_t i = 0; i < out->nmutations; i++) {
			free(out->mutations[i].current_storage);
			free(out->mutations[i].output_storage);
			memset(&out->mutations[i], 0,
			       sizeof(out->mutations[i]));
		}
		out->nmutations = 0;
		out->snapshot_bytes = 0;
		return 0;
	}
	qsort(out->mutations, out->nmutations, sizeof(*out->mutations),
	      mutation_order);
	for (uint32_t i = 0; i < out->nmutations; i++)
		for (uint32_t j = i + 1u; j < out->nmutations; j++)
			if (footprints_conflict(&out->mutations[i],
						&out->mutations[j]))
				conflict = 1;
	if (conflict) {
		out->preflight = NFSP_PREFLIGHT_CONFLICT;
		for (uint32_t i = 0; i < out->nrules; i++)
			for (uint32_t n = 0; n < out->rules[i].eligible; n++)
				count(&out->rules[i], NFSP_RESOLVE_CONFLICT);
	} else if (out->nmutations != 0u) {
		out->preflight = NFSP_PREFLIGHT_READY;
		for (uint32_t i = 0; i < out->nrules; i++)
			for (uint32_t n = 0; n < out->rules[i].eligible; n++)
				count(&out->rules[i], NFSP_RESOLVE_RESOLVED);
	} else {
		out->preflight = NFSP_PREFLIGHT_EMPTY;
	}
	return 0;
}

const char *nfsp_resolve_strstatus(enum nfsp_resolve_status status)
{
	switch (status) {
	case NFSP_RESOLVE_SCOPE_MISS: return "scope_miss";
	case NFSP_RESOLVE_RPC_SELECTOR_MISS: return "rpc_selector_miss";
	case NFSP_RESOLVE_SCHEMA_MISMATCH: return "schema_mismatch";
	case NFSP_RESOLVE_DECODE_UNAVAILABLE: return "decode_unavailable";
	case NFSP_RESOLVE_TRANSACTION_CONTEXT_MISSING:
		return "transaction_context_missing";
	case NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE:
		return "transaction_context_unusable";
	case NFSP_RESOLVE_TARGET_NOT_FOUND: return "target_not_found";
	case NFSP_RESOLVE_TARGET_AMBIGUOUS: return "target_ambiguous";
	case NFSP_RESOLVE_PREDICATE_FALSE: return "predicate_false";
	case NFSP_RESOLVE_PREDICATE_REFERENCE_AMBIGUOUS:
		return "predicate_reference_ambiguous";
	case NFSP_RESOLVE_TRANSFORM_UNSUPPORTED:
		return "transform_unsupported";
	case NFSP_RESOLVE_TRANSFORM_FAILED: return "transform_failed";
	case NFSP_RESOLVE_RESOLVED: return "resolved";
	case NFSP_RESOLVE_CONFLICT: return "conflict";
	case NFSP_RESOLVE_STRUCTURE_CONSTRAINT_FAILED:
		return "structure_constraint_failed";
	case NFSP_RESOLVE_STATUS_COUNT: break;
	}
	return "unknown";
}
