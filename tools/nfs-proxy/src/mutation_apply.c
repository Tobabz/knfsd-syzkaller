/* M4c ConcreteEditBatch adapter.  See mutation_apply.h. */
#include "mutation_apply.h"

#include "framing.h"

#include <stdlib.h>
#include <string.h>

#define MUTATION_STORAGE_MAX \
	(NFSP_RESOLVED_SNAPSHOT_MAX + NFSP_CONCRETE_EDIT_MAX * 8u)

_Static_assert(NFSP_CONCRETE_EDIT_MAX >= NFSP_RESOLVED_MAX * 2u,
	       "one preserve mutation may need two concrete edits");

enum plan_form {
	PLAN_SIMPLE = 0,
	PLAN_LENGTH,
	PLAN_VALUE_PADDING
};

struct edit_plan {
	uint32_t offset, remove_len, data_len;
	uint32_t mutation, flags;
	enum plan_form form;
	const uint8_t *original;
	const uint8_t *data;
	uint32_t old_value_len, new_value_len;
	uint32_t old_padding, new_padding;
	uint8_t original_word[4], data_word[4];
};

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get64(const uint8_t *p)
{
	return ((uint64_t)get32(p) << 32) | get32(p + 4);
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static int span_equal(struct nfsp_span a, struct nfsp_span b)
{
	return a.off == b.off && a.len == b.len;
}

static int span_valid(struct nfsp_span span, size_t len)
{
	return (uint64_t)span.off + span.len <= len;
}

static int wire_equal(const struct nfsp_wire_ref *a,
		      const struct nfsp_wire_ref *b)
{
	return span_equal(a->encoded, b->encoded) &&
	       span_equal(a->value, b->value) && a->meta == b->meta &&
	       span_equal(a->length, b->length) &&
	       span_equal(a->count, b->count) &&
	       span_equal(a->discriminant, b->discriminant) &&
	       span_equal(a->padding, b->padding);
}

static int wire_valid(const struct nfsp_wire_ref *wire, size_t len)
{
	if (!span_valid(wire->encoded, len) || !span_valid(wire->value, len))
		return 0;
	if ((wire->meta & NFSP_META_LENGTH) &&
	    !span_valid(wire->length, len))
		return 0;
	if ((wire->meta & NFSP_META_COUNT) &&
	    !span_valid(wire->count, len))
		return 0;
	if ((wire->meta & NFSP_META_DISCRIMINANT) &&
	    !span_valid(wire->discriminant, len))
		return 0;
	if ((wire->meta & NFSP_META_PADDING) &&
	    !span_valid(wire->padding, len))
		return 0;
	return 1;
}

static int part_span(const struct nfsp_wire_ref *wire,
		     enum nfsp_rule_part part, struct nfsp_span *out)
{
	switch (part) {
	case NFSP_PART_VALUE:
		*out = wire->value;
		return 0;
	case NFSP_PART_ENCODED:
		*out = wire->encoded;
		return 0;
	case NFSP_PART_LENGTH:
		if (!(wire->meta & NFSP_META_LENGTH))
			return -1;
		*out = wire->length;
		return 0;
	case NFSP_PART_COUNT:
		if (!(wire->meta & NFSP_META_COUNT))
			return -1;
		*out = wire->count;
		return 0;
	case NFSP_PART_DISCRIMINANT:
		if (!(wire->meta & NFSP_META_DISCRIMINANT))
			return -1;
		*out = wire->discriminant;
		return 0;
	case NFSP_PART_PADDING:
		if (!(wire->meta & NFSP_META_PADDING))
			return -1;
		*out = wire->padding;
		return 0;
	}
	return -1;
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

static int value_encoding_valid(const struct nfsp_resolved_value *value)
{
	if (value->len != 0u && value->bytes == NULL)
		return 0;
	switch (value->kind) {
	case NFSP_LIT_INT:
		return value->len == 4u &&
		       value->number ==
			(uint64_t)(int64_t)(int32_t)get32(value->bytes);
	case NFSP_LIT_UINT:
	case NFSP_LIT_BOOL:
	case NFSP_LIT_ENUM:
		return value->len == 4u && value->number == get32(value->bytes);
	case NFSP_LIT_HYPER:
	case NFSP_LIT_UHYPER:
		return value->len == 8u && value->number == get64(value->bytes);
	case NFSP_LIT_OPAQUE:
	case NFSP_LIT_STRING:
		return 1;
	}
	return 0;
}

static int footprint_conflict(const struct nfsp_resolved_mutation *a,
			      const struct nfsp_resolved_mutation *b)
{
	uint64_t ae = (uint64_t)a->footprint.off + a->footprint.len;
	uint64_t be = (uint64_t)b->footprint.off + b->footprint.len;

	if (a->field_index == b->field_index && a->part == b->part)
		return 1;
	return a->footprint.off < be && b->footprint.off < ae;
}

static int path_matches(const struct nfsp_decoded_msg *message, uint32_t field,
			const char *path)
{
	char actual[NFSP_RULE_PATH_MAX + 1u];
	size_t n;

	if (path == NULL || field >= message->nfields)
		return 0;
	n = nfsp_field_path(message, field, actual, sizeof(actual));
	return n == strlen(path) && n < sizeof(actual) && !strcmp(actual, path);
}

static int is_variable(uint8_t kind)
{
	return kind == NFSP_XK_OPAQUE_VAR || kind == NFSP_XK_STRING;
}

static int mutation_shape(const struct nfsp_resolver_record *record,
			  const struct nfsp_resolved_mutation *mutation,
			  uint32_t *old_padding, uint32_t *new_padding)
{
	const struct nfsp_semantic_field *field;
	const struct nfsp_schema_type *type;
	struct nfsp_span selected, footprint;
	enum nfsp_rule_literal_kind kind;
	uint64_t end;

	if (mutation->rule_id == NULL || mutation->semantic_path == NULL ||
	    mutation->field_index >= record->message->nfields ||
	    mutation->policy > NFSP_POLICY_RAW ||
	    mutation->part > NFSP_PART_PADDING ||
	    !span_valid(mutation->selected, record->payload_len) ||
	    !span_valid(mutation->footprint, record->payload_len))
		return 0;
	field = &record->message->fields[mutation->field_index];
	if (field->type >= record->message->schema->ntypes ||
	    !wire_equal(&field->wire, &mutation->wire) ||
	    !wire_valid(&mutation->wire, record->payload_len) ||
	    field->op != mutation->operation_index ||
	    !path_matches(record->message, mutation->field_index,
			  mutation->semantic_path) ||
	    part_span(&mutation->wire, mutation->part, &selected) != 0 ||
	    !span_equal(selected, mutation->selected))
		return 0;
	type = &record->message->schema->types[field->type];
	if (mutation->part == NFSP_PART_VALUE) {
		kind = value_kind(type->kind);
		if ((int)kind < 0 || mutation->current.kind != kind ||
		    mutation->output.kind != kind ||
		    mutation->current.len != selected.len ||
		    !value_encoding_valid(&mutation->current) ||
		    !value_encoding_valid(&mutation->output))
			return 0;
		if (type->kind == NFSP_XK_OPAQUE_FIXED &&
		    (mutation->current.len != type->bound ||
		     mutation->output.len != type->bound))
			return 0;
		if (is_variable(type->kind) && mutation->output.len > type->bound)
			return 0;
	} else {
		if (mutation->part == NFSP_PART_ENCODED ||
		    mutation->policy != NFSP_POLICY_RAW ||
		    mutation->current.len != selected.len ||
		    !value_encoding_valid(&mutation->current) ||
		    !value_encoding_valid(&mutation->output))
			return 0;
		if (mutation->part == NFSP_PART_PADDING) {
			if (mutation->current.kind != NFSP_LIT_OPAQUE ||
			    mutation->output.kind != NFSP_LIT_OPAQUE ||
			    mutation->output.len == 0u ||
			    mutation->output.len > 3u)
				return 0;
		} else if (mutation->current.kind != NFSP_LIT_UINT ||
			   mutation->output.kind != NFSP_LIT_UINT ||
			   mutation->output.len != 4u) {
			return 0;
		}
	}

	footprint = selected;
	*old_padding = 0;
	*new_padding = 0;
	if (mutation->policy == NFSP_POLICY_PRESERVE &&
	    mutation->part == NFSP_PART_VALUE && is_variable(type->kind)) {
		*old_padding = (4u - (mutation->current.len & 3u)) & 3u;
		*new_padding = (4u - (mutation->output.len & 3u)) & 3u;
		if (mutation->current.len > UINT32_MAX - *old_padding ||
		    mutation->output.len > UINT32_MAX - *new_padding)
			return 0;
		end = (uint64_t)mutation->wire.value.off +
		      mutation->wire.value.len + *old_padding;
		if (!(mutation->wire.meta & NFSP_META_LENGTH) ||
		    mutation->wire.length.len != 4u ||
		    (uint64_t)mutation->wire.length.off + 4u !=
			mutation->wire.value.off ||
		    (*old_padding != 0u &&
		     (!(mutation->wire.meta & NFSP_META_PADDING) ||
		      mutation->wire.padding.off !=
			mutation->wire.value.off + mutation->wire.value.len ||
		      mutation->wire.padding.len != *old_padding)) ||
		    (*old_padding == 0u &&
		     (mutation->wire.meta & NFSP_META_PADDING)) ||
		    mutation->wire.encoded.off != mutation->wire.length.off ||
		    end != (uint64_t)mutation->wire.encoded.off +
			   mutation->wire.encoded.len)
			return 0;
		footprint = mutation->wire.encoded;
	} else if (mutation->policy == NFSP_POLICY_PRESERVE &&
		   mutation->output.len != selected.len) {
		return 0;
	}
	if (mutation->policy == NFSP_POLICY_RAW)
		footprint = selected;
	return span_equal(footprint, mutation->footprint);
}

static enum nfsp_mutation_status
map_concrete(enum nfsp_concrete_status status)
{
	switch (status) {
	case NFSP_CONCRETE_OK:
		return NFSP_MUTATION_OK;
	case NFSP_CONCRETE_CONFLICT:
		return NFSP_MUTATION_CONFLICT;
	case NFSP_CONCRETE_ORIGINAL_MISMATCH:
		return NFSP_MUTATION_ORIGINAL_MISMATCH;
	case NFSP_CONCRETE_TOO_LARGE:
		return NFSP_MUTATION_OUTPUT_TOO_LARGE;
	case NFSP_CONCRETE_INVALID:
	case NFSP_CONCRETE_BOUNDS:
		return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;
	}
	return NFSP_MUTATION_INVALID;
}

void nfsp_mutation_batch_free(struct nfsp_mutation_batch *batch)
{
	if (batch == NULL)
		return;
	free(batch->storage);
	memset(batch, 0, sizeof(*batch));
}

static void sort_batch(struct nfsp_mutation_batch *batch)
{
	for (size_t i = 1; i < batch->concrete.nedits; i++) {
		struct nfsp_concrete_edit edit = batch->edits[i];
		uint32_t mutation = batch->mutation_index[i];
		uint32_t flags = batch->edit_flags[i];
		size_t j = i;

		while (j > 0u && batch->edits[j - 1u].offset > edit.offset) {
			batch->edits[j] = batch->edits[j - 1u];
			batch->mutation_index[j] = batch->mutation_index[j - 1u];
			batch->edit_flags[j] = batch->edit_flags[j - 1u];
			j--;
		}
		batch->edits[j] = edit;
		batch->mutation_index[j] = mutation;
		batch->edit_flags[j] = flags;
	}
}

enum nfsp_mutation_status
nfsp_mutation_lower(const struct nfsp_resolver_record *record,
		    const struct nfsp_resolution *resolution,
		    struct nfsp_mutation_batch *out)
{
	struct edit_plan plans[NFSP_CONCRETE_EDIT_MAX];
	uint32_t old_padding[NFSP_RESOLVED_MAX];
	uint32_t new_padding[NFSP_RESOLVED_MAX];
	size_t nplans = 0, storage_len = 0, used = 0;
	enum nfsp_concrete_status concrete_status;

	if (out == NULL)
		return NFSP_MUTATION_INVALID;
	memset(out, 0, sizeof(*out));
	if (record == NULL || resolution == NULL || record->payload == NULL ||
	    record->message == NULL || record->message->schema == NULL ||
	    (record->message->status != NFSP_DECODE_DECODED &&
	     record->message->status != NFSP_DECODE_PARTIAL) ||
	    record->activation_generation == 0u ||
	    resolution->activation_generation != record->activation_generation)
		return NFSP_MUTATION_INVALID;
	switch (resolution->preflight) {
	case NFSP_PREFLIGHT_EMPTY:
		return NFSP_MUTATION_EMPTY;
	case NFSP_PREFLIGHT_CONFLICT:
		return NFSP_MUTATION_CONFLICT;
	case NFSP_PREFLIGHT_STRUCTURE_CONSTRAINT_FAILED:
		return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;
	case NFSP_PREFLIGHT_READY:
		break;
	default:
		return NFSP_MUTATION_INVALID;
	}
	if (resolution->mutations == NULL || resolution->nmutations == 0u ||
	    resolution->nmutations > NFSP_RESOLVED_MAX)
		return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;

	/* Validate every semantic mutation before allocating or materialising a
	 * partial concrete batch. */
	for (uint32_t i = 0; i < resolution->nmutations; i++)
		if (!mutation_shape(record, &resolution->mutations[i],
				    &old_padding[i], &new_padding[i]))
			return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;
	for (uint32_t i = 0; i < resolution->nmutations; i++)
		for (uint32_t j = i + 1u; j < resolution->nmutations; j++)
			if (footprint_conflict(&resolution->mutations[i],
					       &resolution->mutations[j]))
				return NFSP_MUTATION_CONFLICT;

	memset(plans, 0, sizeof(plans));
	for (uint32_t i = 0; i < resolution->nmutations; i++) {
		const struct nfsp_resolved_mutation *mutation =
			&resolution->mutations[i];
		const struct nfsp_schema_type *type =
			&record->message->schema->types[
				record->message->fields[mutation->field_index].type];

		if (mutation->policy == NFSP_POLICY_PRESERVE &&
		    mutation->part == NFSP_PART_VALUE && is_variable(type->kind)) {
			struct edit_plan *length, *tail;

			if (nplans + 2u > NFSP_CONCRETE_EDIT_MAX)
				return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;
			length = &plans[nplans++];
			length->offset = mutation->wire.length.off;
			length->remove_len = 4u;
			length->data_len = 4u;
			length->mutation = i;
			length->flags = NFSP_MUTATION_EDIT_DERIVED_LENGTH;
			length->form = PLAN_LENGTH;
			put32(length->original_word, mutation->current.len);
			put32(length->data_word, mutation->output.len);

			if (mutation->current.len + old_padding[i] != 0u ||
			    mutation->output.len + new_padding[i] != 0u) {
				tail = &plans[nplans++];
				tail->offset = mutation->wire.value.off;
				tail->remove_len =
					mutation->current.len + old_padding[i];
				tail->data_len =
					mutation->output.len + new_padding[i];
				tail->mutation = i;
				tail->flags = NFSP_MUTATION_EDIT_TARGET;
				if (old_padding[i] != 0u || new_padding[i] != 0u)
					tail->flags |=
						NFSP_MUTATION_EDIT_DERIVED_PADDING;
				tail->form = PLAN_VALUE_PADDING;
				tail->original = mutation->current.bytes;
				tail->data = mutation->output.bytes;
				tail->old_value_len = mutation->current.len;
				tail->new_value_len = mutation->output.len;
				tail->old_padding = old_padding[i];
				tail->new_padding = new_padding[i];
			}
		} else {
			struct edit_plan *plan;

			if (nplans == NFSP_CONCRETE_EDIT_MAX ||
			    (mutation->selected.len == 0u &&
			     mutation->output.len == 0u))
				return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;
			plan = &plans[nplans++];
			plan->offset = mutation->selected.off;
			plan->remove_len = mutation->selected.len;
			plan->data_len = mutation->output.len;
			plan->mutation = i;
			plan->flags = NFSP_MUTATION_EDIT_TARGET;
			plan->form = PLAN_SIMPLE;
			plan->original = mutation->current.bytes;
			plan->data = mutation->output.bytes;
		}
	}
	for (size_t i = 0; i < nplans; i++) {
		size_t bytes = (size_t)plans[i].remove_len + plans[i].data_len;

		if (bytes > MUTATION_STORAGE_MAX ||
		    storage_len > MUTATION_STORAGE_MAX - bytes)
			return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;
		storage_len += bytes;
	}
	out->storage = malloc(storage_len ? storage_len : 1u);
	if (out->storage == NULL)
		return NFSP_MUTATION_NO_MEMORY;
	out->storage_len = storage_len;
	out->activation_generation = resolution->activation_generation;
	out->concrete.edits = out->edits;
	out->concrete.nedits = nplans;

	for (size_t i = 0; i < nplans; i++) {
		const struct edit_plan *plan = &plans[i];
		struct nfsp_concrete_edit *edit = &out->edits[i];

		edit->offset = plan->offset;
		edit->remove_len = plan->remove_len;
		if (plan->remove_len != 0u) {
			edit->original = out->storage + used;
			if (plan->form == PLAN_VALUE_PADDING) {
				memcpy(out->storage + used, plan->original,
				       plan->old_value_len);
				memcpy(out->storage + used + plan->old_value_len,
				       record->payload + plan->offset +
					plan->old_value_len,
				       plan->old_padding);
			} else {
				const uint8_t *source = plan->form == PLAN_LENGTH ?
					plan->original_word : plan->original;

				memcpy(out->storage + used, source,
				       plan->remove_len);
			}
			used += plan->remove_len;
		}
		edit->data_len = plan->data_len;
		if (plan->data_len != 0u) {
			edit->data = out->storage + used;
			if (plan->form == PLAN_VALUE_PADDING) {
				memcpy(out->storage + used, plan->data,
				       plan->new_value_len);
				memset(out->storage + used + plan->new_value_len, 0,
				       plan->new_padding);
			} else {
				const uint8_t *source = plan->form == PLAN_LENGTH ?
					plan->data_word : plan->data;

				memcpy(out->storage + used, source,
				       plan->data_len);
			}
			used += plan->data_len;
		}
		out->mutation_index[i] = plan->mutation;
		out->edit_flags[i] = plan->flags;
	}
	if (used != storage_len) {
		nfsp_mutation_batch_free(out);
		return NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED;
	}
	sort_batch(out);
	concrete_status = nfsp_concrete_preflight(&out->concrete,
						 record->payload,
						 record->payload_len,
						 NFSP_FRAG_LEN_MASK,
						 &out->output_len);
	if (concrete_status != NFSP_CONCRETE_OK) {
		enum nfsp_mutation_status status = map_concrete(concrete_status);

		nfsp_mutation_batch_free(out);
		return status;
	}
	return NFSP_MUTATION_OK;
}

static int concrete_output_matches(const struct nfsp_mutation_batch *batch,
				   const uint8_t *original,
				   size_t original_len,
				   const uint8_t *payload, size_t len)
{
	size_t cursor = 0, output = 0;

	for (size_t i = 0; i < batch->concrete.nedits; i++) {
		const struct nfsp_concrete_edit *edit = &batch->edits[i];
		size_t unchanged = (size_t)edit->offset - cursor;

		if (unchanged > len - output || unchanged > original_len - cursor ||
		    (unchanged != 0u &&
		     memcmp(payload + output, original + cursor, unchanged)))
			return 0;
		output += unchanged;
		if ((size_t)edit->data_len > len - output ||
		    (edit->data_len != 0u &&
		     memcmp(payload + output, edit->data, edit->data_len)))
			return 0;
		output += edit->data_len;
		cursor = (size_t)edit->offset + edit->remove_len;
	}
	if (cursor > original_len || original_len - cursor > len - output)
		return 0;
	return output + original_len - cursor == len &&
	       (original_len == cursor ||
		!memcmp(payload + output, original + cursor,
			original_len - cursor));
}

static int layout_discriminant(const struct nfsp_decoded_msg *message,
			       const struct nfsp_resolved_mutation *mutation)
{
	const struct nfsp_semantic_field *field =
		&message->fields[mutation->field_index];

	if (field->parent == NFSP_FIELD_NONE || field->parent >= message->nfields)
		return 0;
	field = &message->fields[field->parent];
	return (field->wire.meta & NFSP_META_DISCRIMINANT) &&
	       span_equal(field->wire.discriminant, mutation->selected);
}

static int batch_is_semantically_decodable(
		const struct nfsp_resolver_record *record,
		const struct nfsp_resolution *resolution)
{
	for (uint32_t i = 0; i < resolution->nmutations; i++) {
		const struct nfsp_resolved_mutation *mutation =
			&resolution->mutations[i];

		if (mutation->policy == NFSP_POLICY_PRESERVE)
			continue;
		if (mutation->part != NFSP_PART_VALUE ||
		    mutation->selected.len != mutation->output.len ||
		    layout_discriminant(record->message, mutation))
			return 0;
	}
	return 1;
}

static int semantic_output_matches(
		const struct nfsp_resolver_record *record,
		const struct nfsp_resolution *resolution,
		const struct nfsp_mutation_verify *verify,
		const uint8_t *payload, size_t payload_len)
{
	struct nfsp_rpc_envelope rpc;
	struct nfsp_decode_input input;
	struct nfsp_decoded_msg decoded = {0};
	enum nfsp_decode_status status;
	int ok = 0;

	if (verify == NULL || verify->families == NULL ||
	    verify->nfamilies == 0u ||
	    nfsp_rpc_decode(payload, payload_len, &rpc) != NFSP_RPC_OK)
		return 0;
	memset(&input, 0, sizeof(input));
	input.payload = payload;
	input.len = payload_len;
	input.rpc = &rpc;
	input.reply_dispatch = verify->reply_dispatch;
	input.allow_test_fixture = verify->allow_test_fixture;
	status = nfsp_nfs_decode(verify->families, verify->nfamilies, &input,
				 &decoded);
	if (status != record->message->status ||
	    (status != NFSP_DECODE_DECODED && status != NFSP_DECODE_PARTIAL) ||
	    decoded.schema == NULL ||
	    strcmp(decoded.schema->schema_id,
		   record->message->schema->schema_id) ||
	    decoded.nfields != record->message->nfields ||
	    decoded.nops != record->message->nops)
		goto out;
	for (uint32_t i = 0; i < decoded.nops; i++)
		if (decoded.ops[i].opcode != record->message->ops[i].opcode ||
		    decoded.ops[i].sequence_index !=
			record->message->ops[i].sequence_index)
			goto out;
	for (uint32_t i = 0; i < resolution->nmutations; i++) {
		const struct nfsp_resolved_mutation *mutation =
			&resolution->mutations[i];
		const struct nfsp_semantic_field *field;

		if (mutation->part != NFSP_PART_VALUE ||
		    mutation->field_index >= decoded.nfields)
			goto out;
		field = &decoded.fields[mutation->field_index];
		if (field->type !=
		    record->message->fields[mutation->field_index].type ||
		    field->op != mutation->operation_index ||
		    !path_matches(&decoded, mutation->field_index,
			  mutation->semantic_path) ||
		    !span_valid(field->wire.value, payload_len) ||
		    field->wire.value.len != mutation->output.len ||
		    (mutation->output.len != 0u &&
		     memcmp(payload + field->wire.value.off,
			    mutation->output.bytes, mutation->output.len)))
			goto out;
	}
	ok = 1;
out:
	nfsp_decoded_msg_free(&decoded);
	return ok;
}

static int framed_output_matches(struct nfsp_mutation_output *out,
				 const uint8_t *payload, size_t payload_len)
{
	struct nfsp_record_buf scratch = {0};
	const uint8_t *canonical = NULL;
	size_t canonical_len = 0;
	uint32_t nfrags = 0, marker;
	int ok;

	if (out->framed_bytes == NULL || out->framed_len < 4u) {
		nfsp_record_buf_free(&scratch);
		return 0;
	}
	marker = get32(out->framed_bytes);
	ok = (marker & NFSP_LAST_FRAGMENT) != 0u &&
	     (marker & NFSP_FRAG_LEN_MASK) == payload_len &&
	     out->framed_len == payload_len + NFSP_FRAG_HEADER_LEN &&
	     nfsp_rpc_payload(out->framed_bytes, out->framed_len, &scratch,
			      &canonical, &canonical_len, &nfrags) ==
		NFSP_RECORD_OK &&
	     nfrags == 1u && canonical_len == payload_len &&
	     (payload_len == 0u || !memcmp(canonical, payload, payload_len));
	nfsp_record_buf_free(&scratch);
	return ok;
}

void nfsp_mutation_output_free(struct nfsp_mutation_output *out)
{
	if (out == NULL)
		return;
	nfsp_record_buf_free(&out->framed);
	memset(out, 0, sizeof(*out));
}

enum nfsp_mutation_status
nfsp_mutation_apply(const struct nfsp_resolver_record *record,
		    const struct nfsp_resolution *resolution,
		    const struct nfsp_mutation_verify *verify,
		    struct nfsp_mutation_output *out)
{
	struct nfsp_mutation_batch batch;
	uint8_t *payload = NULL;
	const uint8_t *framed = NULL;
	size_t payload_len = 0, framed_len = 0;
	enum nfsp_mutation_status status;
	enum nfsp_concrete_status concrete_status;
	enum nfsp_record_err frame_status;

	if (out == NULL)
		return NFSP_MUTATION_INVALID;
	memset(out, 0, sizeof(*out));
	memset(&batch, 0, sizeof(batch));
	status = nfsp_mutation_lower(record, resolution, &batch);
	if (status != NFSP_MUTATION_OK)
		return status;
	payload = malloc(batch.output_len ? batch.output_len : 1u);
	if (payload == NULL) {
		status = NFSP_MUTATION_NO_MEMORY;
		goto out;
	}
	concrete_status = nfsp_apply_concrete_batch(&batch.concrete,
						    record->payload,
						    record->payload_len,
						    payload,
						    batch.output_len,
						    &payload_len);
	if (concrete_status != NFSP_CONCRETE_OK) {
		status = map_concrete(concrete_status);
		goto out;
	}
	if (payload_len != batch.output_len ||
	    !concrete_output_matches(&batch, record->payload,
				     record->payload_len, payload, payload_len)) {
		status = NFSP_MUTATION_VERIFY_FAILED;
		goto out;
	}
	if (batch_is_semantically_decodable(record, resolution) &&
	    !semantic_output_matches(record, resolution, verify, payload,
				     payload_len)) {
		status = NFSP_MUTATION_VERIFY_FAILED;
		goto out;
	}
	frame_status = nfsp_rpc_frame(payload, payload_len, &out->framed,
				      &framed, &framed_len);
	if (frame_status == NFSP_RECORD_ERR_NOMEM) {
		status = NFSP_MUTATION_NO_MEMORY;
		goto out;
	}
	if (frame_status != NFSP_RECORD_OK) {
		status = NFSP_MUTATION_FRAMING_FAILED;
		goto out;
	}
	out->framed_bytes = framed;
	out->framed_len = framed_len;
	if (!framed_output_matches(out, payload, payload_len)) {
		status = NFSP_MUTATION_FRAMING_FAILED;
		goto out;
	}
	out->rpc_payload = out->framed_bytes + NFSP_FRAG_HEADER_LEN;
	out->rpc_payload_len = payload_len;
	status = NFSP_MUTATION_OK;
out:
	free(payload);
	nfsp_mutation_batch_free(&batch);
	if (status != NFSP_MUTATION_OK)
		nfsp_mutation_output_free(out);
	return status;
}

const char *nfsp_mutation_strstatus(enum nfsp_mutation_status status)
{
	switch (status) {
	case NFSP_MUTATION_OK: return "ok";
	case NFSP_MUTATION_INVALID: return "invalid";
	case NFSP_MUTATION_EMPTY: return "empty";
	case NFSP_MUTATION_CONFLICT: return "conflict";
	case NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED:
		return "structure_constraint_failed";
	case NFSP_MUTATION_ORIGINAL_MISMATCH: return "original_mismatch";
	case NFSP_MUTATION_OUTPUT_TOO_LARGE: return "output_too_large";
	case NFSP_MUTATION_VERIFY_FAILED: return "verify_failed";
	case NFSP_MUTATION_FRAMING_FAILED: return "framing_failed";
	case NFSP_MUTATION_NO_MEMORY: return "no_memory";
	}
	return "unknown";
}
