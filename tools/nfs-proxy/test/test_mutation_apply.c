/* M4c semantic mutation lowering/application tests.
 *
 * These tests use the generated tproto schema so offsets come only from the
 * live decoder.  They pin the properties the component boundary promises:
 * derived XDR repairs, one original-coordinate batch, typed all-or-nothing
 * refusals, dynamic originals, semantic verification and final wire bytes
 * independent of registration order.
 */
#include "mutation_apply.h"

#include "framing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TPROTO_PROG 536871065u

extern const struct nfsp_schema_family nfsp_schema_family_tproto;

static const struct nfsp_schema_family *const fams[] = {
	&nfsp_schema_family_tproto,
};

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

static uint32_t g32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

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

static void build_call(struct msg *m, uint32_t seq, const char *tag,
		       const char *data)
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
	wopaque(m, tag);
	w32(m, 0);
	w32(m, 3);
	w32(m, 1);
	w32(m, 2);
	w32(m, seq);
	wraw(m, "ID-ID-ID-ID!", 12);
	w64(m, 0x0000000100000002ull);
	w32(m, 0xfffffffbu);
	w64(m, 0xfffffffffffffffeull);
	w32(m, 1);
	wopaque(m, data);
	w32(m, 2); w32(m, 0xau); w32(m, 0xbu);
	w32(m, 1); wraw(m, "pair-zero-00", 12);
	w32(m, 2); wraw(m, "pair-one-111", 12);
	w32(m, 2); wopaque(m, "x/y");
	w32(m, 3); wopaque(m, "file");
}

static int decode_call(const struct msg *wire, struct nfsp_decoded_msg *out)
{
	struct nfsp_rpc_envelope rpc;
	struct nfsp_decode_input input;

	memset(&input, 0, sizeof(input));
	if (nfsp_rpc_decode(wire->b, wire->n, &rpc) != NFSP_RPC_OK)
		return -1;
	input.payload = wire->b;
	input.len = wire->n;
	input.rpc = &rpc;
	return nfsp_nfs_decode(fams, sizeof(fams) / sizeof(fams[0]), &input,
			       out) == NFSP_DECODE_DECODED ? 0 : -1;
}

static int decode_payload(const uint8_t *payload, size_t len,
			  struct nfsp_decoded_msg *out)
{
	struct nfsp_rpc_envelope rpc;
	struct nfsp_decode_input input;

	memset(&input, 0, sizeof(input));
	if (nfsp_rpc_decode(payload, len, &rpc) != NFSP_RPC_OK)
		return -1;
	input.payload = payload;
	input.len = len;
	input.rpc = &rpc;
	return nfsp_nfs_decode(fams, sizeof(fams) / sizeof(fams[0]), &input,
			       out) == NFSP_DECODE_DECODED ? 0 : -1;
}

static const struct nfsp_protocol_schema *schema(void)
{
	return nfsp_schema_family_tproto.schemas[0];
}

static void bind_node(struct nfsp_schema_node *node, const char *path)
{
	CHECK(nfsp_schema_resolve(schema(), 0, path, node) == NFSP_SCHEMA_FOUND,
	      "cannot bind %s", path);
}

static void base_rule(struct nfsp_rule *rule, const char *id,
		      const char *operation, const char *path)
{
	memset(rule, 0, sizeof(*rule));
	rule->rule_id = id;
	rule->intent_id = "intent";
	rule->direction = NFSP_RULE_C2S;
	rule->backend = 3;
	rule->client = 4;
	rule->message_type = NFSP_RULE_CALL;
	rule->program = TPROTO_PROG;
	rule->version = 1;
	rule->has_procedure = 1;
	rule->procedure = 1;
	rule->family = "tproto";
	rule->has_minor_version = 1;
	rule->minor_version = 0;
	rule->operation = operation;
	rule->target_kind = NFSP_RULE_FIELD;
	rule->target_path = path;
	rule->part = NFSP_PART_VALUE;
	bind_node(&rule->target, path);
	rule->kind = NFSP_MUT_REPLACE;
	rule->has_transform = 1;
	rule->transform.kind = NFSP_XF_LITERAL;
	rule->policy = NFSP_POLICY_PRESERVE;
	rule->application = NFSP_APPLY_ALL_MATCHES;
}

static void literal_uint(struct nfsp_rule *rule, uint32_t value)
{
	rule->transform.value.kind = NFSP_LIT_UINT;
	rule->transform.value.num = value;
}

static void literal_opaque(struct nfsp_rule *rule, const char *bytes)
{
	rule->transform.value.kind = NFSP_LIT_OPAQUE;
	rule->transform.value.bytes = (const uint8_t *)bytes;
	rule->transform.value.len = (uint32_t)strlen(bytes);
}

static void literal_string(struct nfsp_rule *rule, const char *bytes)
{
	rule->transform.value.kind = NFSP_LIT_STRING;
	rule->transform.value.bytes = (const uint8_t *)bytes;
	rule->transform.value.len = (uint32_t)strlen(bytes);
}

static struct nfsp_ruleset rule_set(struct nfsp_rule *rules, uint32_t nrules)
{
	struct nfsp_ruleset set;

	memset(&set, 0, sizeof(set));
	set.semantic_runtime_version = NFSP_SEMANTIC_RUNTIME_VERSION;
	set.schema_id = schema()->schema_id;
	set.candidate_id = "candidate";
	set.rules = rules;
	set.nrules = nrules;
	set.schema = schema();
	return set;
}

static struct nfsp_resolver_record record_for(
		const struct msg *wire, const struct nfsp_decoded_msg *message)
{
	struct nfsp_resolver_record record;

	memset(&record, 0, sizeof(record));
	record.activation_generation = 23;
	record.direction = NFSP_RULE_C2S;
	record.backend = 3;
	record.client = 4;
	record.payload = wire->b;
	record.payload_len = wire->n;
	record.message = message;
	return record;
}

static struct nfsp_mutation_verify verify_context(void)
{
	struct nfsp_mutation_verify verify;

	memset(&verify, 0, sizeof(verify));
	verify.families = fams;
	verify.nfamilies = sizeof(fams) / sizeof(fams[0]);
	return verify;
}

static void make_three_rules(struct nfsp_rule rules[3])
{
	base_rule(&rules[0], "c-data", "WRITE",
		  "tproto.request.WRITE.args.data");
	literal_opaque(&rules[0], "abcdefghij");
	base_rule(&rules[1], "a-tag", NULL,
		  "tproto.request.COMPOUND.args.tag");
	literal_string(&rules[1], "proxy");
	base_rule(&rules[2], "b-seq", "WRITE",
		  "tproto.request.WRITE.args.id.seq");
	literal_uint(&rules[2], 11);
}

static void check_frame(const struct nfsp_mutation_output *out)
{
	uint32_t marker;

	CHECK(out->framed_bytes == out->framed.p && out->framed_len >= 4u,
	      "framed output ownership");
	marker = out->framed_len >= 4u ? g32(out->framed_bytes) : 0;
	CHECK((marker & NFSP_LAST_FRAGMENT) != 0u,
	      "last-fragment bit absent");
	CHECK((marker & NFSP_FRAG_LEN_MASK) == out->rpc_payload_len &&
	      out->framed_len == out->rpc_payload_len + 4u,
	      "marker/payload lengths %u/%zu/%zu", marker,
	      out->rpc_payload_len, out->framed_len);
	CHECK(out->rpc_payload == out->framed_bytes + 4,
	      "canonical payload is not after marker");
}

static void check_value(const struct nfsp_mutation_output *out,
			const char *path, const uint8_t *want, uint32_t want_len)
{
	struct nfsp_decoded_msg decoded = {0};
	uint32_t field;

	CHECK(decode_payload(out->rpc_payload, out->rpc_payload_len, &decoded) == 0,
	      "decode output for %s", path);
	field = nfsp_field_find(&decoded, path, 0);
	CHECK(field != NFSP_FIELD_NONE, "missing output field %s", path);
	if (field != NFSP_FIELD_NONE) {
		struct nfsp_span value = decoded.fields[field].wire.value;

		CHECK(value.len == want_len &&
		      (want_len == 0u ||
		       !memcmp(out->rpc_payload + value.off, want, want_len)),
		      "%s value differs", path);
		if (decoded.fields[field].wire.meta & NFSP_META_PADDING) {
			struct nfsp_span padding = decoded.fields[field].wire.padding;
			int zero = 1;

			for (uint32_t i = 0; i < padding.len; i++)
				if (out->rpc_payload[padding.off + i] != 0u)
					zero = 0;
			CHECK(zero, "%s derived padding is non-zero", path);
		}
	}
	nfsp_decoded_msg_free(&decoded);
}

static void test_preserve_variables_and_batch(void)
{
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_mutation_output output = {0};
	struct nfsp_mutation_batch batch = {0};
	struct nfsp_resolver_record record;
	struct nfsp_resolution resolution;
	struct nfsp_ruleset set;
	struct nfsp_rule rules[3];
	struct msg call;
	uint8_t seq[4] = {0, 0, 0, 11};
	uint32_t length_fixups = 0, padding_fixups = 0, targets = 0;

	printf("mutation apply: preserve opaque/string and one concrete batch\n");
	build_call(&call, 7, "ab", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode call");
	make_three_rules(rules);
	set = rule_set(rules, 3);
	record = record_for(&call, &decoded);
	CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
	      resolution.preflight == NFSP_PREFLIGHT_READY &&
	      resolution.nmutations == 3u,
	      "resolve three mutations");
	CHECK(nfsp_mutation_lower(&record, &resolution, &batch) ==
	      NFSP_MUTATION_OK, "lower ready batch");
	CHECK(batch.concrete.nedits == 5u && batch.output_len == call.n + 8u,
	      "batch edits/length %zu/%zu", batch.concrete.nedits,
	      batch.output_len);
	for (size_t i = 0; i < batch.concrete.nedits; i++) {
		if (batch.edit_flags[i] & NFSP_MUTATION_EDIT_DERIVED_LENGTH)
			length_fixups++;
		if (batch.edit_flags[i] & NFSP_MUTATION_EDIT_DERIVED_PADDING)
			padding_fixups++;
		if (batch.edit_flags[i] & NFSP_MUTATION_EDIT_TARGET)
			targets++;
	}
	CHECK(length_fixups == 2u && padding_fixups == 2u && targets == 3u,
	      "derived edits length=%u padding=%u targets=%u", length_fixups,
	      padding_fixups, targets);
	nfsp_mutation_batch_free(&batch);
	CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
	      NFSP_MUTATION_OK, "apply preserve batch");
	check_frame(&output);
	check_value(&output, "tproto.request.COMPOUND.args.tag",
		    (const uint8_t *)"proxy", 5);
	check_value(&output, "tproto.request.WRITE.args.data",
		    (const uint8_t *)"abcdefghij", 10);
	check_value(&output, "tproto.request.WRITE.args.id.seq", seq, 4);
	nfsp_mutation_output_free(&output);
	nfsp_resolution_free(&resolution);
	nfsp_decoded_msg_free(&decoded);
}

static void test_preserve_shrink_and_empty_input(void)
{
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_mutation_output output = {0};
	struct nfsp_resolver_record record;
	struct nfsp_resolution resolution;
	struct nfsp_ruleset set;
	struct nfsp_rule rules[2];
	struct msg call;

	printf("mutation apply: preserve shrink and empty-value insertion\n");
	build_call(&call, 7, "", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode empty-tag call");
	base_rule(&rules[0], "a-tag", NULL,
		  "tproto.request.COMPOUND.args.tag");
	literal_string(&rules[0], "z");
	base_rule(&rules[1], "b-data", "WRITE",
		  "tproto.request.WRITE.args.data");
	literal_opaque(&rules[1], "xy");
	set = rule_set(rules, 2);
	record = record_for(&call, &decoded);
	CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
	      resolution.preflight == NFSP_PREFLIGHT_READY,
	      "resolve shrink/empty preserve");
	CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
	      NFSP_MUTATION_OK, "apply shrink/empty preserve");
	CHECK(output.rpc_payload_len == call.n,
	      "balanced grow/shrink length %zu/%zu", output.rpc_payload_len,
	      call.n);
	check_frame(&output);
	check_value(&output, "tproto.request.COMPOUND.args.tag",
		    (const uint8_t *)"z", 1);
	check_value(&output, "tproto.request.WRITE.args.data",
		    (const uint8_t *)"xy", 2);
	nfsp_mutation_output_free(&output);
	nfsp_resolution_free(&resolution);
	nfsp_decoded_msg_free(&decoded);
}

static void test_raw_scalar_and_metadata(void)
{
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_mutation_output output = {0};
	struct nfsp_resolver_record record;
	struct nfsp_resolution resolution;
	struct nfsp_ruleset set;
	struct nfsp_rule rules[3];
	struct msg call;
	uint32_t seq_field, data_field;

	printf("mutation apply: raw scalar and schema-proven metadata\n");
	build_call(&call, 7, "ab", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode call");
	base_rule(&rules[0], "a-seq", "WRITE",
		  "tproto.request.WRITE.args.id.seq");
	rules[0].policy = NFSP_POLICY_RAW;
	literal_uint(&rules[0], 99);
	base_rule(&rules[1], "b-length", "WRITE",
		  "tproto.request.WRITE.args.data");
	rules[1].part = NFSP_PART_LENGTH;
	rules[1].policy = NFSP_POLICY_RAW;
	literal_uint(&rules[1], 2);
	base_rule(&rules[2], "c-data", "WRITE",
		  "tproto.request.WRITE.args.data");
	rules[2].policy = NFSP_POLICY_RAW;
	literal_opaque(&rules[2], "ABCDEFGHI");
	set = rule_set(rules, 3);
	record = record_for(&call, &decoded);
	CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
	      resolution.preflight == NFSP_PREFLIGHT_READY,
	      "resolve raw edits");
	CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
	      NFSP_MUTATION_OK, "apply raw edits");
	check_frame(&output);
	seq_field = nfsp_field_find(&decoded,
		"tproto.request.WRITE.args.id.seq", 0);
	data_field = nfsp_field_find(&decoded,
		"tproto.request.WRITE.args.data", 0);
	CHECK(seq_field != NFSP_FIELD_NONE &&
	      g32(output.rpc_payload + decoded.fields[seq_field].wire.value.off) ==
		99u, "raw scalar output");
	CHECK(data_field != NFSP_FIELD_NONE &&
	      g32(output.rpc_payload +
		  decoded.fields[data_field].wire.length.off) == 2u,
	      "raw length metadata output");
	CHECK(data_field != NFSP_FIELD_NONE &&
	      !memcmp(output.rpc_payload +
		      decoded.fields[data_field].wire.value.off, "ABCDEFGHI", 9),
	      "raw variable value output");
	CHECK(output.rpc_payload_len == call.n + 4u,
	      "raw value growth did not update outer framing");
	nfsp_mutation_output_free(&output);
	nfsp_resolution_free(&resolution);
	nfsp_decoded_msg_free(&decoded);
}

static int same_batch(const struct nfsp_mutation_batch *a,
		      const struct nfsp_mutation_batch *b)
{
	if (a->activation_generation != b->activation_generation ||
	    a->concrete.nedits != b->concrete.nedits ||
	    a->output_len != b->output_len ||
	    a->storage_len != b->storage_len ||
	    (a->storage_len != 0u &&
	     memcmp(a->storage, b->storage, a->storage_len)))
		return 0;
	for (size_t i = 0; i < a->concrete.nedits; i++) {
		const struct nfsp_concrete_edit *x = &a->edits[i];
		const struct nfsp_concrete_edit *y = &b->edits[i];

		if (x->offset != y->offset || x->remove_len != y->remove_len ||
		    x->data_len != y->data_len ||
		    a->mutation_index[i] != b->mutation_index[i] ||
		    a->edit_flags[i] != b->edit_flags[i] ||
		    (x->remove_len != 0u &&
		     memcmp(x->original, y->original, x->remove_len)) ||
		    (x->data_len != 0u && memcmp(x->data, y->data, x->data_len)))
			return 0;
	}
	return 1;
}

static void test_empty_value_adjacent_edit(void)
{
	static const char tag[] = "tproto.request.COMPOUND.args.tag";
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_mutation_batch baseline = {0};
	struct nfsp_resolver_record record;
	struct nfsp_rule canonical[2];
	struct msg call, expected;

	printf("mutation apply: empty preserve value and adjacent field ownership\n");
	build_call(&call, 7, "", "hello");
	build_call(&expected, 7, "old", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode adjacent fixture");
	record = record_for(&call, &decoded);
	base_rule(&canonical[0], "z-tag", NULL, tag);
	literal_string(&canonical[0], "old");
	base_rule(&canonical[1], "a-minor", NULL,
		  "tproto.request.COMPOUND.args.minorversion");
	literal_uint(&canonical[1], 0);
	for (uint32_t p = 0; p < 2; p++) {
		struct nfsp_mutation_batch batch = {0};
		struct nfsp_mutation_output output = {0};
		struct nfsp_resolution resolution;
		struct nfsp_rule rules[2] = {canonical[p], canonical[1u - p]};
		struct nfsp_ruleset set = rule_set(rules, 2);

		CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
		      resolution.preflight == NFSP_PREFLIGHT_READY,
		      "adjacent footprints must resolve");
		CHECK(nfsp_mutation_lower(&record, &resolution, &batch) ==
		      NFSP_MUTATION_OK, "lower adjacent empty field");
		CHECK(batch.concrete.nedits == 2u && batch.edits[0].offset == 40u &&
		      batch.edits[0].remove_len == 4u && batch.edits[0].data_len == 8u &&
		      g32(batch.edits[0].original) == 0u &&
		      g32(batch.edits[0].data) == 3u &&
		      !memcmp(batch.edits[0].data + 4, "old\0", 4) &&
		      batch.edits[1].offset == 44u &&
		      batch.edit_flags[0] == (NFSP_MUTATION_EDIT_TARGET |
			NFSP_MUTATION_EDIT_DERIVED_LENGTH |
			NFSP_MUTATION_EDIT_DERIVED_PADDING) &&
		      batch.mutation_index[0] == 1u,
		      "coalesced edit lost original bytes, derived flags or owner");
		if (p == 0u)
			CHECK(nfsp_mutation_lower(&record, &resolution, &baseline) ==
			      NFSP_MUTATION_OK, "lower permutation baseline");
		else
			CHECK(same_batch(&baseline, &batch),
			      "adjacent edit permutation changed signed batch inputs");
		CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
		      NFSP_MUTATION_OK, "apply adjacent edits");
		CHECK(output.rpc_payload_len == expected.n &&
		      !memcmp(output.rpc_payload, expected.b, expected.n),
		      "adjacent edits changed unintended bytes");
		if (output.framed_bytes != NULL) {
			check_frame(&output);
			check_value(&output, tag, (const uint8_t *)"old", 3);
		}
		nfsp_mutation_output_free(&output);
		call.b[43] = 1; /* Stale original length, despite an empty value. */
		CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
		      NFSP_MUTATION_ORIGINAL_MISMATCH && output.framed_bytes == NULL,
		      "coalescing must retain exact original length precondition");
		call.b[43] = 0;
		resolution.mutations[1].output.len = UINT32_MAX - 3u;
		CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
		      NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED && output.framed_bytes == NULL,
		      "coalesced encoding size must not wrap around");
		resolution.mutations[1].output.len = 3;
		nfsp_resolution_free(&resolution);
		nfsp_mutation_batch_free(&batch);
	}
	nfsp_mutation_batch_free(&baseline);

	/* Coalescing must not hide a real owner overlap, including an empty field. */
	for (uint32_t p = 0; p < 2; p++) {
		struct nfsp_mutation_output output = {0};
		struct nfsp_resolution resolution;
		struct nfsp_ruleset set = rule_set(canonical, 2);

		base_rule(&canonical[1], "a-overlap", NULL, tag);
		canonical[1].policy = NFSP_POLICY_RAW;
		if (p == 0u) {
			canonical[1].part = NFSP_PART_LENGTH;
			literal_uint(&canonical[1], 3);
		} else {
			literal_string(&canonical[1], "other");
		}
		CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
		      resolution.preflight == NFSP_PREFLIGHT_CONFLICT,
		      "empty field overlap must conflict");
		resolution.preflight = NFSP_PREFLIGHT_READY;
		CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
		      NFSP_MUTATION_CONFLICT && output.framed_bytes == NULL,
		      "lowering must independently reject owner overlap");
		nfsp_resolution_free(&resolution);
	}
	nfsp_decoded_msg_free(&decoded);
}

static void test_raw_schema_dispatch_and_safe_controls(void)
{
	static const char minor[] = "tproto.request.COMPOUND.args.minorversion";
	static const uint32_t values[] = {1u, 99u};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_resolver_record record;
	struct nfsp_rule rule;
	struct msg call;

	printf("mutation apply: raw schema selector, discriminant and safe controls\n");
	build_call(&call, 7, "ab", "hello");
	/* PING's encoding is the same in both supported minor versions. */
	call.n = 60;
	call.b[55] = 1;
	CHECK(decode_call(&call, &decoded) == 0, "decode schema-dispatch fixture");
	record = record_for(&call, &decoded);
	for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		struct nfsp_mutation_output output = {0};
		struct nfsp_resolution resolution;
		struct nfsp_decoded_msg changed = {0};
		struct nfsp_ruleset set;
		struct msg expected = call;

		base_rule(&rule, "minor", NULL, minor);
		rule.policy = NFSP_POLICY_RAW;
		literal_uint(&rule, values[i]);
		set = rule_set(&rule, 1);
		CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
		      resolution.preflight == NFSP_PREFLIGHT_READY,
		      "resolve raw schema selector");
		CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
		      NFSP_MUTATION_OK, "apply raw minor %u", values[i]);
		expected.b[51] = (uint8_t)values[i];
		CHECK(output.rpc_payload_len == expected.n &&
		      !memcmp(output.rpc_payload, expected.b, expected.n),
		      "raw minor output differs from exact intended bytes");
		if (output.framed_bytes != NULL) {
			check_frame(&output);
			if (values[i] == 1u)
				CHECK(decode_payload(output.rpc_payload, output.rpc_payload_len,
						     &changed) == 0 && changed.minor_version == 1u &&
				      strcmp(changed.schema->schema_id, decoded.schema->schema_id),
				      "supported changed minor must independently decode");
			else
				CHECK(decode_payload(output.rpc_payload, output.rpc_payload_len,
						     &changed) != 0 &&
				      changed.status == NFSP_DECODE_UNSUPPORTED_SCHEMA,
				      "unknown raw minor must retain raw semantics");
		}
		nfsp_decoded_msg_free(&changed);
		nfsp_mutation_output_free(&output);
		nfsp_resolution_free(&resolution);
	}
	nfsp_decoded_msg_free(&decoded);
	build_call(&call, 7, "ab", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode safe controls");
	record = record_for(&call, &decoded);
	for (uint32_t i = 0; i < 4; i++) {
		struct nfsp_mutation_output output = {0};
		struct nfsp_resolution resolution;
		struct nfsp_ruleset set;

		base_rule(&rule, "control", i == 0u || i == 3u ? NULL : "WRITE",
			  i == 0u || i == 3u ? minor : i == 1u ?
			  "tproto.request.WRITE.args.id.seq" :
			  "tproto.request.WRITE.args.target.kind");
		rule.policy = i == 3u ? NFSP_POLICY_PRESERVE : NFSP_POLICY_RAW;
		literal_uint(&rule, i == 0u ? 0u : i == 1u ? 9u : 1u);
		if (i == 2u)
			rule.transform.value.kind = NFSP_LIT_ENUM;
		set = rule_set(&rule, 1);
		CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
		      resolution.preflight == NFSP_PREFLIGHT_READY, "resolve control %u", i);
		/* A no-op selector and an ordinary raw scalar still need a decoder.
		 * Raw discriminants may change layout; preserve selectors may not. */
		CHECK(nfsp_mutation_apply(&record, &resolution, NULL, &output) ==
		      (i == 2u ? NFSP_MUTATION_OK : NFSP_MUTATION_VERIFY_FAILED),
		      "raw verification classification %u", i);
		nfsp_mutation_output_free(&output);
		CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
		      (i == 3u ? NFSP_MUTATION_VERIFY_FAILED : NFSP_MUTATION_OK),
		      "verified control %u", i);
		if (i == 1u && output.framed_bytes != NULL) {
			const uint8_t seq[4] = {0, 0, 0, 9};

			check_value(&output, rule.target_path, seq, 4);
		}
		nfsp_mutation_output_free(&output);
		if (i <= 1u) {
			struct nfsp_mutation_batch batch = {0};

			/* Break an unrelated operation after resolution.  Concrete
			 * preconditions still match, so only a real semantic decode
			 * can reject the output, using the normal verifier context. */
			call.b[59] = 99;
			CHECK(nfsp_mutation_lower(&record, &resolution, &batch) ==
			      NFSP_MUTATION_OK, "negative decode control must lower");
			CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
			      NFSP_MUTATION_VERIFY_FAILED && output.framed_bytes == NULL,
			      "safe raw field %u skipped independent semantic verification", i);
			call.b[59] = 1;
			nfsp_mutation_batch_free(&batch);
		}
		nfsp_resolution_free(&resolution);
	}
	nfsp_decoded_msg_free(&decoded);
}

static void test_permutation_final_bytes(void)
{
	static const uint32_t permutations[6][3] = {
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2},
		{1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	};
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_mutation_batch baseline_batch = {0};
	struct nfsp_resolver_record record;
	struct nfsp_rule canonical[3];
	struct msg call;
	uint8_t baseline[1024];
	size_t baseline_len = 0;

	printf("mutation apply: every registration permutation has final-byte identity\n");
	build_call(&call, 7, "ab", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode call");
	make_three_rules(canonical);
	record = record_for(&call, &decoded);
	for (size_t p = 0; p < 6u; p++) {
		struct nfsp_mutation_batch batch = {0};
		struct nfsp_mutation_output output = {0};
		struct nfsp_resolution resolution;
		struct nfsp_rule rules[3];
		struct nfsp_ruleset set;

		for (size_t i = 0; i < 3u; i++)
			rules[i] = canonical[permutations[p][i]];
		set = rule_set(rules, 3);
		CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
		      resolution.preflight == NFSP_PREFLIGHT_READY,
		      "permutation %zu resolve", p);
		if (p == 0u) {
			CHECK(nfsp_mutation_lower(&record, &resolution,
					  &baseline_batch) == NFSP_MUTATION_OK,
			      "baseline batch lower");
		} else {
			CHECK(nfsp_mutation_lower(&record, &resolution, &batch) ==
			      NFSP_MUTATION_OK && same_batch(&baseline_batch, &batch),
			      "permutation %zu changed concrete batch", p);
		}
		CHECK(nfsp_mutation_apply(&record, &resolution, &verify, &output) ==
		      NFSP_MUTATION_OK, "permutation %zu apply", p);
		if (p == 0u) {
			baseline_len = output.framed_len;
			CHECK(baseline_len <= sizeof(baseline), "baseline capacity");
			if (baseline_len <= sizeof(baseline))
				memcpy(baseline, output.framed_bytes, baseline_len);
		} else {
			CHECK(output.framed_len == baseline_len &&
			      !memcmp(output.framed_bytes, baseline, baseline_len),
			      "permutation %zu changed final bytes", p);
		}
		nfsp_mutation_batch_free(&batch);
		nfsp_mutation_output_free(&output);
		nfsp_resolution_free(&resolution);
	}
	nfsp_mutation_batch_free(&baseline_batch);
	nfsp_decoded_msg_free(&decoded);
}

static void make_conflict_rules(struct nfsp_rule rules[2])
{
	base_rule(&rules[0], "a-preserve", "WRITE",
		  "tproto.request.WRITE.args.data");
	literal_opaque(&rules[0], "xy");
	base_rule(&rules[1], "b-raw-length", "WRITE",
		  "tproto.request.WRITE.args.data");
	rules[1].part = NFSP_PART_LENGTH;
	rules[1].policy = NFSP_POLICY_RAW;
	literal_uint(&rules[1], 2);
}

static void test_overlap_and_structure_refusal(void)
{
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_resolver_record record;
	struct nfsp_rule canonical[2], reversed[2];
	struct nfsp_resolution first, second, ready;
	struct nfsp_mutation_output output = {0};
	struct nfsp_ruleset set;
	struct nfsp_rule lookup;
	struct msg call;

	printf("mutation apply: overlap and structure refuse the whole batch\n");
	build_call(&call, 7, "ab", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode call");
	record = record_for(&call, &decoded);
	make_conflict_rules(canonical);
	reversed[0] = canonical[1];
	reversed[1] = canonical[0];
	set = rule_set(canonical, 2);
	CHECK(nfsp_resolve_rules(&set, &record, &first) == 0,
	      "resolve conflict");
	set = rule_set(reversed, 2);
	CHECK(nfsp_resolve_rules(&set, &record, &second) == 0,
	      "resolve reversed conflict");
	CHECK(nfsp_mutation_apply(&record, &first, &verify, &output) ==
	      NFSP_MUTATION_CONFLICT && output.framed_bytes == NULL,
	      "first conflict status/output");
	CHECK(nfsp_mutation_apply(&record, &second, &verify, &output) ==
	      NFSP_MUTATION_CONFLICT && output.framed_bytes == NULL,
	      "reversed conflict status/output");
	CHECK(!strcmp(nfsp_mutation_strstatus(NFSP_MUTATION_CONFLICT),
		      "conflict"), "typed conflict name");
	nfsp_resolution_free(&first);
	nfsp_resolution_free(&second);

	base_rule(&lookup, "lookup-name", "LOOKUP",
		  "tproto.request.LOOKUP.args.name");
	literal_opaque(&lookup, "longer-name");
	set = rule_set(&lookup, 1);
	CHECK(nfsp_resolve_rules(&set, &record, &ready) == 0 &&
	      ready.preflight == NFSP_PREFLIGHT_READY,
	      "resolve structure fixture");
	ready.mutations[0].wire.encoded.len++;
	CHECK(nfsp_mutation_apply(&record, &ready, &verify, &output) ==
	      NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED &&
	      output.framed_bytes == NULL,
	      "inconsistent WireRef was not refused");
	nfsp_resolution_free(&ready);
	nfsp_decoded_msg_free(&decoded);
}

static void test_dynamic_originals(void)
{
	struct nfsp_decoded_msg decoded_a = {0}, decoded_b = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_mutation_output output = {0};
	struct nfsp_mutation_batch batch_a = {0}, batch_b = {0};
	struct nfsp_resolver_record record_a, record_b;
	struct nfsp_resolution resolution_a, resolution_b;
	struct nfsp_ruleset set;
	struct nfsp_rule rule;
	struct msg call_a, call_b;

	printf("mutation apply: originals are captured from each live payload\n");
	build_call(&call_a, 7, "ab", "hello");
	build_call(&call_b, 8, "ab", "hello");
	CHECK(decode_call(&call_a, &decoded_a) == 0, "decode call A");
	CHECK(decode_call(&call_b, &decoded_b) == 0, "decode call B");
	base_rule(&rule, "seq", "WRITE",
		  "tproto.request.WRITE.args.id.seq");
	literal_uint(&rule, 11);
	set = rule_set(&rule, 1);
	record_a = record_for(&call_a, &decoded_a);
	record_b = record_for(&call_b, &decoded_b);
	CHECK(nfsp_resolve_rules(&set, &record_a, &resolution_a) == 0,
	      "resolve A");
	CHECK(nfsp_resolve_rules(&set, &record_b, &resolution_b) == 0,
	      "resolve B");
	CHECK(nfsp_mutation_lower(&record_a, &resolution_a, &batch_a) ==
	      NFSP_MUTATION_OK &&
	      nfsp_mutation_lower(&record_b, &resolution_b, &batch_b) ==
	      NFSP_MUTATION_OK, "lower dynamic originals");
	CHECK(batch_a.concrete.nedits == 1u && batch_b.concrete.nedits == 1u &&
	      g32(batch_a.edits[0].original) == 7u &&
	      g32(batch_b.edits[0].original) == 8u,
	      "original snapshots are not live values");
	nfsp_mutation_batch_free(&batch_a);
	nfsp_mutation_batch_free(&batch_b);
	CHECK(nfsp_mutation_apply(&record_a, &resolution_a, &verify, &output) ==
	      NFSP_MUTATION_OK, "apply A");
	nfsp_mutation_output_free(&output);
	CHECK(nfsp_mutation_apply(&record_b, &resolution_b, &verify, &output) ==
	      NFSP_MUTATION_OK, "apply B");
	nfsp_mutation_output_free(&output);
	CHECK(nfsp_mutation_apply(&record_b, &resolution_a, &verify, &output) ==
	      NFSP_MUTATION_ORIGINAL_MISMATCH &&
	      output.framed_bytes == NULL,
	      "stale resolution was not refused");
	nfsp_resolution_free(&resolution_a);
	nfsp_resolution_free(&resolution_b);
	nfsp_decoded_msg_free(&decoded_a);
	nfsp_decoded_msg_free(&decoded_b);
}

static void test_concrete_preflight_order(void)
{
	uint8_t input[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	uint8_t output[20];
	uint8_t replacement[4] = {9, 9, 9, 9};
	uint8_t wrong[6] = {0};
	struct nfsp_concrete_edit edits[2], reversed[2];
	struct nfsp_concrete_edit_batch batch;
	size_t final_len = 0, output_len = 99;

	printf("mutation apply: concrete refusal priority is order independent\n");
	memset(edits, 0, sizeof(edits));
	edits[0].offset = 2;
	edits[0].remove_len = 6;
	edits[0].original = wrong;
	edits[0].data_len = 4;
	edits[0].data = replacement;
	edits[1].offset = 4;
	edits[1].remove_len = 2;
	edits[1].original = input + 4;
	edits[1].data_len = 4;
	edits[1].data = replacement;
	reversed[0] = edits[1];
	reversed[1] = edits[0];
	batch.edits = edits;
	batch.nedits = 2;
	CHECK(nfsp_concrete_preflight(&batch, input, sizeof(input), 64,
				      &final_len) == NFSP_CONCRETE_CONFLICT,
	      "overlap must precede original mismatch");
	memset(output, 0xa5, sizeof(output));
	CHECK(nfsp_apply_concrete_batch(&batch, input, sizeof(input), output,
				       sizeof(output), &output_len) ==
	      NFSP_CONCRETE_CONFLICT && output_len == 0u,
	      "conflicting apply did not refuse before rebuild");
	for (size_t i = 0; i < sizeof(output); i++)
		CHECK(output[i] == 0xa5, "refusal wrote output byte %zu", i);
	batch.edits = reversed;
	CHECK(nfsp_concrete_preflight(&batch, input, sizeof(input), 64,
				      &final_len) == NFSP_CONCRETE_CONFLICT,
	      "reversed overlap changed refusal");
	edits[0].offset = 20;
	batch.edits = edits;
	CHECK(nfsp_concrete_preflight(&batch, input, sizeof(input), 64,
				      &final_len) == NFSP_CONCRETE_BOUNDS,
	      "bounds must precede overlap/original checks");
	edits[0].offset = edits[1].offset = 2;
	edits[0].remove_len = 0;
	edits[0].original = NULL;
	edits[1].original = input + 2;
	CHECK(nfsp_concrete_preflight(&batch, input, sizeof(input), 64,
				      &final_len) == NFSP_CONCRETE_CONFLICT,
	      "independent insert and replacement at one boundary still conflict");
	reversed[0] = edits[1];
	reversed[1] = edits[0];
	batch.edits = reversed;
	CHECK(nfsp_concrete_preflight(&batch, input, sizeof(input), 64,
				      &final_len) == NFSP_CONCRETE_CONFLICT,
	      "reordering must not permit a boundary collision");
	edits[1].remove_len = 0;
	edits[1].original = NULL;
	batch.edits = edits;
	CHECK(nfsp_concrete_preflight(&batch, input, sizeof(input), 64,
				      &final_len) == NFSP_CONCRETE_CONFLICT,
	      "independent inserts at one boundary still conflict");
}

/* A raw no-op (empty value replaced by empty bytes) edits nothing and must
 * not refuse an independent edit in the same batch (PR #34 review). */
static void test_raw_noop_keeps_batch(void)
{
	static const char tag[] = "tproto.request.COMPOUND.args.tag";
	struct nfsp_decoded_msg decoded = {0};
	struct nfsp_mutation_verify verify = verify_context();
	struct nfsp_resolver_record record;
	struct nfsp_rule rules[2];
	struct msg call;

	printf("mutation apply: raw no-op beside a real edit\n");
	build_call(&call, 7, "", "hello");
	CHECK(decode_call(&call, &decoded) == 0, "decode no-op fixture");
	record = record_for(&call, &decoded);
	base_rule(&rules[0], "a-noop", NULL, tag);
	rules[0].policy = NFSP_POLICY_RAW;
	literal_string(&rules[0], "");
	base_rule(&rules[1], "b-seq", "WRITE",
		  "tproto.request.WRITE.args.id.seq");
	literal_uint(&rules[1], 11);
	for (uint32_t n = 1; n <= 2; n++) {
		struct nfsp_mutation_batch batch = {0};
		struct nfsp_mutation_output output = {0};
		struct nfsp_resolution resolution;
		struct nfsp_ruleset set = rule_set(rules, n);
		enum nfsp_mutation_status st;

		CHECK(nfsp_resolve_rules(&set, &record, &resolution) == 0 &&
		      resolution.preflight == NFSP_PREFLIGHT_READY,
		      "no-op batch of %u resolves", n);
		st = nfsp_mutation_lower(&record, &resolution, &batch);
		if (n == 1u) {
			CHECK(st == NFSP_MUTATION_EMPTY,
			      "a lone raw no-op lowers to nothing (%s)",
			      nfsp_mutation_strstatus(st));
		} else {
			const uint8_t seq[4] = {0, 0, 0, 11};

			CHECK(st == NFSP_MUTATION_OK && batch.concrete.nedits == 1u,
			      "raw no-op is skipped, the other edit stays");
			CHECK(nfsp_mutation_apply(&record, &resolution, &verify,
						  &output) == NFSP_MUTATION_OK,
			      "batch with a raw no-op applies");
			if (output.framed_bytes != NULL)
				check_value(&output, rules[1].target_path, seq, 4);
		}
		nfsp_mutation_output_free(&output);
		nfsp_mutation_batch_free(&batch);
		nfsp_resolution_free(&resolution);
	}
	nfsp_decoded_msg_free(&decoded);
}

int main(void)
{
	test_preserve_variables_and_batch();
	test_preserve_shrink_and_empty_input();
	test_raw_scalar_and_metadata();
	test_empty_value_adjacent_edit();
	test_raw_schema_dispatch_and_safe_controls();
	test_permutation_final_bytes();
	test_overlap_and_structure_refusal();
	test_dynamic_originals();
	test_concrete_preflight_order();
	test_raw_noop_keeps_batch();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
