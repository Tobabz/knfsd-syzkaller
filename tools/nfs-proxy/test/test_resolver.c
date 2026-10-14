/* M4b Semantic Rule Resolver tests.
 *
 * The synthetic tproto messages give exact, independently written offsets.
 * Oracles here are typed predicate/copy behavior, request-view binding,
 * all_matches, raw/preserve ownership, explicit ambiguity/conflict, and byte-
 * for-byte identical resolution after permuting the rules array.
 */
#include "resolver.h"
#include "rpc_decode.h"
#include "schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct nfsp_schema_family nfsp_schema_family_tproto;

#define TPROTO_PROG 0x20000099u

static const struct nfsp_schema_family *const fams[] = {
	&nfsp_schema_family_tproto,
};

static int checks;
static int failures;

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

static void call_header(struct msg *m)
{
	m->n = 0;
	w32(m, 0xc0ffee01u);
	w32(m, NFSP_RPC_CALL);
	w32(m, NFSP_RPC_VERSION);
	w32(m, TPROTO_PROG);
	w32(m, 1);
	w32(m, 1);
	w32(m, NFSP_RPC_AUTH_NONE); w32(m, 0);
	w32(m, NFSP_RPC_AUTH_NONE); w32(m, 0);
}

static void reply_header(struct msg *m)
{
	m->n = 0;
	w32(m, 0xc0ffee01u);
	w32(m, NFSP_RPC_REPLY);
	w32(m, NFSP_RPC_MSG_ACCEPTED);
	w32(m, NFSP_RPC_AUTH_NONE); w32(m, 0);
	w32(m, NFSP_RPC_SUCCESS);
}

/* The decoder golden CALL: PING, WRITE, LOOKUP. */
static void build_call(struct msg *m, uint32_t seq)
{
	call_header(m);
	wopaque(m, "ab");
	w32(m, 0);			/* minor */
	w32(m, 3);
	w32(m, 1);			/* PING */
	w32(m, 2);			/* WRITE */
	w32(m, seq);
	wraw(m, "ID-ID-ID-ID!", 12);
	w64(m, 0x0000000100000002ull);
	w32(m, 0xfffffffbu);		/* delta -5 */
	w64(m, 0xfffffffffffffffeull);
	w32(m, 1);
	wopaque(m, "hello");
	w32(m, 2); w32(m, 0xau); w32(m, 0xbu);
	w32(m, 1); wraw(m, "pair-zero-00", 12);
	w32(m, 2); wraw(m, "pair-one-111", 12);
	w32(m, 2); wopaque(m, "x/y");
	w32(m, 3); wopaque(m, "file");
}

/* The decoder golden REPLY.  The first WRITE result is at sequence 1. */
static void build_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0); wopaque(m, "ab");
	w32(m, 5);
	w32(m, 1); w32(m, 0);
	w32(m, 2); w32(m, 0); w32(m, 5); w32(m, 9);
	wraw(m, "reply-id-xyz", 12);
	w32(m, 3); w32(m, 0); w32(m, 1);
	w64(m, 100); wopaque(m, "a"); w32(m, 1);
	w64(m, 200); wopaque(m, "bb"); w32(m, 0); w32(m, 1);
	w32(m, 2); w32(m, 13); wopaque(m, "own");
	w32(m, 2); w32(m, 5);
}

static const struct nfsp_reply_dispatch dispatch = {
	TPROTO_PROG, 1, 1, 1, 0, NFSP_DISPATCH_TEST_FIXTURE,
	NFSP_RPC_AUTH_NONE
};

static int decode_msg(const struct msg *wire,
		      const struct nfsp_reply_dispatch *rd,
		      struct nfsp_decoded_msg *m)
{
	struct nfsp_rpc_envelope rpc;
	struct nfsp_decode_input in;

	memset(&in, 0, sizeof(in));
	if (nfsp_rpc_decode(wire->b, wire->n, &rpc) != NFSP_RPC_OK)
		return -1;
	in.payload = wire->b;
	in.len = wire->n;
	in.rpc = &rpc;
	in.reply_dispatch = rd;
	in.allow_test_fixture = rd != NULL;
	return nfsp_nfs_decode(fams, sizeof(fams) / sizeof(fams[0]), &in, m) ==
	       NFSP_DECODE_DECODED ? 0 : -1;
}

static const struct nfsp_protocol_schema *schema(void)
{
	return nfsp_schema_family_tproto.schemas[0];
}

static void bind_node(struct nfsp_schema_node *node, int reply,
		      const char *path)
{
	CHECK(nfsp_schema_resolve(schema(), reply, path, node) ==
	      NFSP_SCHEMA_FOUND, "cannot bind %s", path);
}

static void base_rule(struct nfsp_rule *r, const char *id, int reply,
		      const char *operation, const char *path)
{
	memset(r, 0, sizeof(*r));
	r->rule_id = id;
	r->intent_id = "intent";
	r->direction = reply ? NFSP_RULE_S2C : NFSP_RULE_C2S;
	r->backend = 3;
	r->client = 4;
	r->message_type = reply ? NFSP_RULE_REPLY : NFSP_RULE_CALL;
	r->program = TPROTO_PROG;
	r->version = 1;
	r->has_procedure = 1;
	r->procedure = 1;
	r->family = "tproto";
	r->has_minor_version = 1;
	r->minor_version = 0;
	r->operation = operation;
	r->target_kind = NFSP_RULE_FIELD;
	r->target_path = path;
	r->part = NFSP_PART_VALUE;
	bind_node(&r->target, reply, path);
	r->kind = NFSP_MUT_REPLACE;
	r->has_transform = 1;
	r->transform.kind = NFSP_XF_LITERAL;
	r->policy = NFSP_POLICY_PRESERVE;
	r->application = NFSP_APPLY_ALL_MATCHES;
}

static void literal_uint(struct nfsp_rule *r, uint32_t value)
{
	r->transform.kind = NFSP_XF_LITERAL;
	r->transform.value.kind = NFSP_LIT_UINT;
	r->transform.value.num = value;
}

static void literal_int(struct nfsp_rule *r, int32_t value)
{
	r->transform.kind = NFSP_XF_LITERAL;
	r->transform.value.kind = NFSP_LIT_INT;
	r->transform.value.num = (uint64_t)(int64_t)value;
}

static void literal_opaque(struct nfsp_rule *r, const char *bytes,
			   uint32_t len)
{
	r->transform.kind = NFSP_XF_LITERAL;
	r->transform.value.kind = NFSP_LIT_OPAQUE;
	r->transform.value.bytes = (const uint8_t *)bytes;
	r->transform.value.len = len;
}

static void target_predicate(struct nfsp_rule *r,
			     struct nfsp_rule_predicate *p,
			     enum nfsp_rule_compare op,
			     enum nfsp_rule_literal_kind kind, uint64_t value)
{
	memset(p, 0, sizeof(*p));
	p->lhs.source = NFSP_SRC_TARGET;
	p->lhs.node = r->target;
	p->op = op;
	p->rhs_kind = NFSP_OPND_LITERAL;
	p->rhs_literal.kind = kind;
	p->rhs_literal.num = value;
}

static void current_ref(struct nfsp_rule_value_ref *ref, int reply,
			const char *path)
{
	memset(ref, 0, sizeof(*ref));
	ref->source = NFSP_SRC_CURRENT_MESSAGE;
	ref->path = path;
	bind_node(&ref->node, reply, path);
}

static void request_ref(struct nfsp_rule_value_ref *ref,
			enum nfsp_rule_source source, const char *path)
{
	memset(ref, 0, sizeof(*ref));
	ref->source = source;
	ref->path = path;
	bind_node(&ref->node, 0, path);
}

static struct nfsp_ruleset rule_set(struct nfsp_rule *rules, uint32_t nrules)
{
	struct nfsp_ruleset rs;

	memset(&rs, 0, sizeof(rs));
	rs.semantic_runtime_version = NFSP_SEMANTIC_RUNTIME_VERSION;
	rs.schema_id = schema()->schema_id;
	rs.candidate_id = "candidate";
	rs.rules = rules;
	rs.nrules = nrules;
	rs.schema = schema();
	return rs;
}

static struct nfsp_resolver_record call_record(const struct msg *wire,
					const struct nfsp_decoded_msg *m)
{
	struct nfsp_resolver_record record;

	memset(&record, 0, sizeof(record));
	record.activation_generation = 17;
	record.direction = NFSP_RULE_C2S;
	record.backend = 3;
	record.client = 4;
	record.payload = wire->b;
	record.payload_len = wire->n;
	record.message = m;
	return record;
}

static void test_typed_current_and_all_matches(void)
{
	static const char pair_seq[] = "tproto.request.WRITE.args.pair[].seq";
	static const char minor[] =
		"tproto.request.COMPOUND.args.minorversion";
	struct nfsp_decoded_msg decoded_call = {0};
	struct nfsp_rule_predicate predicate;
	struct nfsp_resolver_record record;
	struct nfsp_resolution result;
	struct nfsp_ruleset rs;
	struct nfsp_rule rule;
	struct msg call;

	printf("resolver: typed current view and all_matches\n");
	build_call(&call, 7);
	CHECK(decode_msg(&call, NULL, &decoded_call) == 0, "decode call");
	base_rule(&rule, "r-pairs", 0, "WRITE", pair_seq);
	target_predicate(&rule, &predicate, NFSP_CMP_GE, NFSP_LIT_UINT, 1);
	rule.predicates = &predicate;
	rule.npredicates = 1;
	rule.transform.kind = NFSP_XF_COPY;
	current_ref(&rule.transform.source, 0, minor);
	rs = rule_set(&rule, 1);
	record = call_record(&call, &decoded_call);
	CHECK(nfsp_resolve_rules(&rs, &record, &result) == 0, "resolve");
	CHECK(result.preflight == NFSP_PREFLIGHT_READY &&
	      result.nmutations == 2 && result.rules[0].eligible == 2 &&
	      result.rules[0].count[NFSP_RESOLVE_RESOLVED] == 2,
	      "all_matches: preflight %d mutations %u eligible %u resolved %u",
	      result.preflight, result.nmutations, result.rules[0].eligible,
	      result.rules[0].count[NFSP_RESOLVE_RESOLVED]);
	for (uint32_t i = 0; i < result.nmutations; i++) {
		CHECK(result.mutations[i].current.number == i + 1u,
		      "pair %u current %llu", i,
		      (unsigned long long)result.mutations[i].current.number);
		CHECK(result.mutations[i].output.number == 0 &&
		      result.mutations[i].output.len == 4,
		      "pair %u copied output", i);
	}
	nfsp_resolution_free(&result);
	nfsp_decoded_msg_free(&decoded_call);
}

static void test_reference_ambiguity(void)
{
	static const char target[] = "tproto.request.WRITE.args.id.seq";
	static const char masks[] = "tproto.request.WRITE.args.mask[]";
	struct nfsp_decoded_msg decoded_call = {0};
	struct nfsp_rule_predicate predicate;
	struct nfsp_resolver_record record;
	struct nfsp_resolution result;
	struct nfsp_ruleset rs;
	struct nfsp_rule rule;
	struct msg call;

	printf("resolver: same-operation ambiguous reference\n");
	build_call(&call, 7);
	CHECK(decode_msg(&call, NULL, &decoded_call) == 0, "decode call");
	base_rule(&rule, "r-ambiguous", 0, "WRITE", target);
	literal_uint(&rule, 9);
	memset(&predicate, 0, sizeof(predicate));
	current_ref(&predicate.lhs, 0, masks);
	predicate.op = NFSP_CMP_EQ;
	predicate.rhs_kind = NFSP_OPND_LITERAL;
	predicate.rhs_literal.kind = NFSP_LIT_UINT;
	predicate.rhs_literal.num = 0xau;
	rule.predicates = &predicate;
	rule.npredicates = 1;
	rs = rule_set(&rule, 1);
	record = call_record(&call, &decoded_call);
	CHECK(nfsp_resolve_rules(&rs, &record, &result) == 0, "resolve");
	CHECK(result.preflight == NFSP_PREFLIGHT_EMPTY &&
	      result.nmutations == 0 &&
	      result.rules[0].count[
		      NFSP_RESOLVE_PREDICATE_REFERENCE_AMBIGUOUS] == 1,
	      "ambiguity was not explicit");
	nfsp_resolution_free(&result);
	nfsp_decoded_msg_free(&decoded_call);
}

static void test_request_original_and_forwarded(void)
{
	static const char count_path[] =
		"tproto.response.WRITE.result.ok.count";
	static const char status_path[] =
		"tproto.response.WRITE.result.status";
	static const char request_seq[] = "tproto.request.WRITE.args.id.seq";
	const char *forwarded_fields[] = { request_seq };
	const char *original_fields[] = { request_seq };
	struct nfsp_decoded_msg original_decoded = {0}, forwarded_decoded = {0};
	struct nfsp_decoded_msg reply_decoded = {0};
	struct nfsp_rule_predicate predicates[2];
	struct nfsp_resolver_transaction transaction;
	struct nfsp_resolver_record record;
	struct nfsp_resolution result;
	struct nfsp_ruleset rs;
	struct nfsp_rule rule;
	struct msg original, forwarded, reply;

	printf("resolver: dynamic original and forwarded request views\n");
	build_call(&original, 7);
	build_call(&forwarded, 8);
	build_reply(&reply);
	CHECK(decode_msg(&original, NULL, &original_decoded) == 0,
	      "decode original");
	CHECK(decode_msg(&forwarded, NULL, &forwarded_decoded) == 0,
	      "decode forwarded");
	CHECK(decode_msg(&reply, &dispatch, &reply_decoded) == 0,
	      "decode reply");
	base_rule(&rule, "r-request-views", 1, "WRITE", count_path);
	memset(predicates, 0, sizeof(predicates));
	current_ref(&predicates[0].lhs, 1, status_path);
	predicates[0].op = NFSP_CMP_EQ;
	predicates[0].rhs_kind = NFSP_OPND_LITERAL;
	predicates[0].rhs_literal.kind = NFSP_LIT_ENUM;
	predicates[0].rhs_literal.num = 0;
	request_ref(&predicates[1].lhs, NFSP_SRC_REQUEST_FORWARDED,
		    request_seq);
	predicates[1].op = NFSP_CMP_EQ;
	predicates[1].rhs_kind = NFSP_OPND_LITERAL;
	predicates[1].rhs_literal.kind = NFSP_LIT_UINT;
	predicates[1].rhs_literal.num = 8;
	rule.predicates = predicates;
	rule.npredicates = 2;
	rule.transform.kind = NFSP_XF_COPY;
	request_ref(&rule.transform.source, NFSP_SRC_REQUEST_ORIGINAL,
		    request_seq);
	rule.forwarded.rpc_procedure = 1;
	rule.forwarded.request_operation_sequence = 1;
	rule.forwarded.request_fields = forwarded_fields;
	rule.forwarded.nfields = 1;
	rule.original.request_operation_sequence = 1;
	rule.original.request_fields = original_fields;
	rule.original.nfields = 1;
	rs = rule_set(&rule, 1);
	memset(&transaction, 0, sizeof(transaction));
	transaction.state = NFSP_RESOLVER_TXN_FOUND;
	transaction.program = TPROTO_PROG;
	transaction.version = 1;
	transaction.procedure = 1;
	transaction.forwarded.payload = forwarded.b;
	transaction.forwarded.payload_len = forwarded.n;
	transaction.forwarded.message = &forwarded_decoded;
	transaction.original.payload = original.b;
	transaction.original.payload_len = original.n;
	transaction.original.message = &original_decoded;
	record = call_record(&reply, &reply_decoded);
	record.direction = NFSP_RULE_S2C;
	record.transaction = &transaction;
	CHECK(nfsp_resolve_rules(&rs, &record, &result) == 0, "resolve reply");
	CHECK(result.preflight == NFSP_PREFLIGHT_READY &&
	      result.nmutations == 1 && result.mutations[0].current.number == 5 &&
	      result.mutations[0].output.number == 7,
	      "request views: preflight %d n=%u current=%llu output=%llu",
	      result.preflight, result.nmutations,
	      result.nmutations ? (unsigned long long)
		result.mutations[0].current.number : 0ull,
	      result.nmutations ? (unsigned long long)
		result.mutations[0].output.number : 0ull);
	nfsp_resolution_free(&result);

	transaction.original.message = NULL;
	CHECK(nfsp_resolve_rules(&rs, &record, &result) == 0,
	      "resolve unusable view");
	CHECK(result.rules[0].count[
		      NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE] == 1 &&
	      result.preflight == NFSP_PREFLIGHT_EMPTY,
	      "missing original view was not refused");
	nfsp_resolution_free(&result);
	nfsp_decoded_msg_free(&original_decoded);
	nfsp_decoded_msg_free(&forwarded_decoded);
	nfsp_decoded_msg_free(&reply_decoded);
}

static void make_structure_rules(struct nfsp_rule rules[2])
{
	static const char data[] = "tproto.request.WRITE.args.data";

	base_rule(&rules[0], "a-preserve", 0, "WRITE", data);
	literal_opaque(&rules[0], "xy", 2);
	rules[0].policy = NFSP_POLICY_PRESERVE;
	base_rule(&rules[1], "b-raw-length", 0, "WRITE", data);
	rules[1].part = NFSP_PART_LENGTH;
	rules[1].policy = NFSP_POLICY_RAW;
	literal_uint(&rules[1], 2);
}

static int same_resolution(const struct nfsp_resolution *a,
			   const struct nfsp_resolution *b)
{
	if (a->preflight != b->preflight || a->nrules != b->nrules ||
	    a->nmutations != b->nmutations)
		return 0;
	for (uint32_t i = 0; i < a->nrules; i++)
		if (strcmp(a->rules[i].rule_id, b->rules[i].rule_id) ||
		    a->rules[i].eligible != b->rules[i].eligible ||
		    memcmp(a->rules[i].count, b->rules[i].count,
			   sizeof(a->rules[i].count)))
			return 0;
	for (uint32_t i = 0; i < a->nmutations; i++) {
		const struct nfsp_resolved_mutation *x = &a->mutations[i];
		const struct nfsp_resolved_mutation *y = &b->mutations[i];

		if (strcmp(x->rule_id, y->rule_id) ||
		    x->field_index != y->field_index || x->part != y->part ||
		    memcmp(&x->selected, &y->selected, sizeof(x->selected)) ||
		    memcmp(&x->footprint, &y->footprint, sizeof(x->footprint)) ||
		    x->current.kind != y->current.kind ||
		    x->current.number != y->current.number ||
		    x->current.len != y->current.len ||
		    x->output.kind != y->output.kind ||
		    x->output.number != y->output.number ||
		    x->output.len != y->output.len ||
		    (x->current.len && memcmp(x->current.bytes, y->current.bytes,
				       x->current.len)) ||
		    (x->output.len && memcmp(x->output.bytes, y->output.bytes,
				      x->output.len)))
			return 0;
	}
	return 1;
}

static void test_structure_conflict_and_order(void)
{
	struct nfsp_decoded_msg decoded_call = {0};
	struct nfsp_resolver_record record;
	struct nfsp_resolution first, second, preserve_only, raw_only;
	struct nfsp_ruleset rs;
	struct nfsp_rule rules[2], reversed[2];
	struct msg call;

	printf("resolver: preserve/raw footprints, conflict, registration order\n");
	build_call(&call, 7);
	CHECK(decode_msg(&call, NULL, &decoded_call) == 0, "decode call");
	make_structure_rules(rules);
	reversed[0] = rules[1];
	reversed[1] = rules[0];
	record = call_record(&call, &decoded_call);

	rs = rule_set(&rules[0], 1);
	CHECK(nfsp_resolve_rules(&rs, &record, &preserve_only) == 0,
	      "resolve preserve");
	CHECK(preserve_only.preflight == NFSP_PREFLIGHT_READY &&
	      preserve_only.mutations[0].selected.off == 108 &&
	      preserve_only.mutations[0].selected.len == 5 &&
	      preserve_only.mutations[0].footprint.off == 104 &&
	      preserve_only.mutations[0].footprint.len == 12,
	      "preserve footprint");
	nfsp_resolution_free(&preserve_only);

	rs = rule_set(&rules[1], 1);
	CHECK(nfsp_resolve_rules(&rs, &record, &raw_only) == 0,
	      "resolve raw metadata");
	CHECK(raw_only.preflight == NFSP_PREFLIGHT_READY &&
	      raw_only.mutations[0].selected.off == 104 &&
	      raw_only.mutations[0].selected.len == 4 &&
	      !memcmp(&raw_only.mutations[0].selected,
		      &raw_only.mutations[0].footprint,
		      sizeof(raw_only.mutations[0].selected)),
	      "raw footprint");
	nfsp_resolution_free(&raw_only);

	rs = rule_set(rules, 2);
	CHECK(nfsp_resolve_rules(&rs, &record, &first) == 0,
	      "resolve conflict first");
	rs = rule_set(reversed, 2);
	CHECK(nfsp_resolve_rules(&rs, &record, &second) == 0,
	      "resolve conflict reversed");
	CHECK(first.preflight == NFSP_PREFLIGHT_CONFLICT &&
	      first.rules[0].count[NFSP_RESOLVE_CONFLICT] == 1 &&
	      first.rules[1].count[NFSP_RESOLVE_CONFLICT] == 1,
	      "global conflict classification");
	CHECK(same_resolution(&first, &second),
	      "registration permutation changed conflict resolution");
	nfsp_resolution_free(&first);
	nfsp_resolution_free(&second);
	nfsp_decoded_msg_free(&decoded_call);
}

static void make_independent_rules(struct nfsp_rule rules[2])
{
	base_rule(&rules[0], "z-seq", 0, "WRITE",
		  "tproto.request.WRITE.args.id.seq");
	literal_uint(&rules[0], 11);
	base_rule(&rules[1], "a-delta", 0, "WRITE",
		  "tproto.request.WRITE.args.delta");
	literal_int(&rules[1], -9);
}

static void test_ready_order_invariance(void)
{
	struct nfsp_decoded_msg decoded_call = {0};
	struct nfsp_resolver_record record;
	struct nfsp_resolution first, second;
	struct nfsp_ruleset rs;
	struct nfsp_rule rules[2], reversed[2];
	struct msg call;

	printf("resolver: registration order invariant ready set\n");
	build_call(&call, 7);
	CHECK(decode_msg(&call, NULL, &decoded_call) == 0, "decode call");
	make_independent_rules(rules);
	reversed[0] = rules[1];
	reversed[1] = rules[0];
	record = call_record(&call, &decoded_call);
	rs = rule_set(rules, 2);
	CHECK(nfsp_resolve_rules(&rs, &record, &first) == 0, "resolve first");
	rs = rule_set(reversed, 2);
	CHECK(nfsp_resolve_rules(&rs, &record, &second) == 0,
	      "resolve reversed");
	CHECK(first.preflight == NFSP_PREFLIGHT_READY &&
	      first.nmutations == 2 && same_resolution(&first, &second),
	      "registration permutation changed ready resolution");
	CHECK(!strcmp(first.rules[0].rule_id, "a-delta") &&
	      !strcmp(first.rules[1].rule_id, "z-seq"),
	      "results are not canonical by rule_id");
	nfsp_resolution_free(&first);
	nfsp_resolution_free(&second);
	nfsp_decoded_msg_free(&decoded_call);
}

static void test_typed_misses_and_unsupported(void)
{
	struct nfsp_decoded_msg decoded_call = {0};
	struct nfsp_resolver_record record;
	struct nfsp_resolution result;
	struct nfsp_ruleset rs;
	struct nfsp_rule rule;
	struct msg call;

	printf("resolver: typed stage misses and unsupported transform\n");
	build_call(&call, 7);
	CHECK(decode_msg(&call, NULL, &decoded_call) == 0, "decode call");
	base_rule(&rule, "r-stages", 0, "WRITE",
		  "tproto.request.WRITE.args.id.seq");
	literal_uint(&rule, 9);
	rs = rule_set(&rule, 1);
	record = call_record(&call, &decoded_call);
	record.client = 99;
	CHECK(nfsp_resolve_rules(&rs, &record, &result) == 0 &&
	      result.rules[0].count[NFSP_RESOLVE_SCOPE_MISS] == 1,
	      "scope miss");
	nfsp_resolution_free(&result);
	record.client = 4;
	rule.transform.kind = NFSP_XF_BUILTIN;
	rule.transform.transform_id = "integer_add";
	CHECK(nfsp_resolve_rules(&rs, &record, &result) == 0 &&
	      result.rules[0].count[NFSP_RESOLVE_TRANSFORM_UNSUPPORTED] == 1,
	      "unsupported transform");
	nfsp_resolution_free(&result);
	nfsp_decoded_msg_free(&decoded_call);
}

int main(void)
{
	test_typed_current_and_all_matches();
	test_reference_ambiguity();
	test_request_original_and_forwarded();
	test_structure_conflict_and_order();
	test_ready_order_invariance();
	test_typed_misses_and_unsupported();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
