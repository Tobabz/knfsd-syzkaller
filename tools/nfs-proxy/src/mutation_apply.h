/* M4c semantic mutation lowering and one-pass application.
 *
 * A READY nfsp_resolution describes typed values and live WireRefs but owns no
 * output bytes.  This component lowers that immutable result to one bounded,
 * selector-free ConcreteEditBatch over the original canonical RPC payload,
 * derives the XDR length and padding required by preserve-policy variable
 * opaque/string replacements, and invokes edit.c's shared rebuild core once.
 *
 * It is intentionally a component boundary.  It installs no rule set, opens
 * no activation window, writes no journal event and exposes no bytes through
 * proxy/main.  S1a must wire the M4d component and M5 durable gates before
 * live use.
 */
#ifndef NFSP_MUTATION_APPLY_H
#define NFSP_MUTATION_APPLY_H

#include <stddef.h>
#include <stdint.h>

#include "concrete_edit.h"
#include "resolver.h"
#include "rpc_record.h"

enum nfsp_mutation_status {
	NFSP_MUTATION_OK = 0,
	NFSP_MUTATION_INVALID,
	NFSP_MUTATION_EMPTY,
	NFSP_MUTATION_CONFLICT,
	NFSP_MUTATION_STRUCTURE_CONSTRAINT_FAILED,
	NFSP_MUTATION_ORIGINAL_MISMATCH,
	NFSP_MUTATION_OUTPUT_TOO_LARGE,
	NFSP_MUTATION_VERIFY_FAILED,
	NFSP_MUTATION_FRAMING_FAILED,
	NFSP_MUTATION_NO_MEMORY
};

/* Why a concrete edit exists.  VALUE_AND_PADDING is one contiguous edit so
 * a value and its padding never become ambiguous same-boundary inserts.
 * Growing an empty preserve value includes its length word in the same edit
 * to avoid colliding with the next field; its flags combine applicable roles. */
#define NFSP_MUTATION_EDIT_TARGET		0x1u
#define NFSP_MUTATION_EDIT_DERIVED_LENGTH	0x2u
#define NFSP_MUTATION_EDIT_DERIVED_PADDING	0x4u

/* Owned lowered batch.  concrete.edits points at edits and is reset by free;
 * do not copy this structure by value after a successful lowering. */
struct nfsp_mutation_batch {
	uint64_t activation_generation;
	struct nfsp_concrete_edit edits[NFSP_CONCRETE_EDIT_MAX];
	uint32_t mutation_index[NFSP_CONCRETE_EDIT_MAX];
	uint32_t edit_flags[NFSP_CONCRETE_EDIT_MAX];
	struct nfsp_concrete_edit_batch concrete;
	size_t output_len;
	uint8_t *storage;
	size_t storage_len;
};

/* Context needed to independently decode a structure-preserving result.  A
 * REPLY uses the same transaction-derived dispatch as its original decode.
 * allow_test_fixture exists only for the decoder's host-test fixture source. */
struct nfsp_mutation_verify {
	const struct nfsp_schema_family *const *families;
	size_t nfamilies;
	const struct nfsp_reply_dispatch *reply_dispatch;
	int allow_test_fixture;
};

/* Successful output is one canonical last fragment.  rpc_payload points four
 * bytes into framed.p and remains valid until nfsp_mutation_output_free(). */
struct nfsp_mutation_output {
	struct nfsp_record_buf framed;
	const uint8_t *framed_bytes;
	size_t framed_len;
	const uint8_t *rpc_payload;
	size_t rpc_payload_len;
};

/* Lower only a READY resolution.  All semantic spans, footprints, XDR layout,
 * concrete conflicts, originals and final framing bounds are preflighted.
 * `out` must be zero-initialised or previously freed. */
enum nfsp_mutation_status
nfsp_mutation_lower(const struct nfsp_resolver_record *record,
		    const struct nfsp_resolution *resolution,
		    struct nfsp_mutation_batch *out);

void nfsp_mutation_batch_free(struct nfsp_mutation_batch *batch);

/* Lower, rebuild once, verify target bytes and every structure-safe semantic
 * value, then frame and re-parse the record marker before returning output.
 * No output is returned on any refusal. */
enum nfsp_mutation_status
nfsp_mutation_apply(const struct nfsp_resolver_record *record,
		    const struct nfsp_resolution *resolution,
		    const struct nfsp_mutation_verify *verify,
		    struct nfsp_mutation_output *out);

void nfsp_mutation_output_free(struct nfsp_mutation_output *out);

const char *nfsp_mutation_strstatus(enum nfsp_mutation_status status);

#endif /* NFSP_MUTATION_APPLY_H */
