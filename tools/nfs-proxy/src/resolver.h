/* Semantic rule resolution over one immutable decoded RPC payload (M4b).
 *
 * This component consumes only a rule set which rule.c has already validated.
 * It does not install or activate that set, write a journal event, rebuild a
 * payload, or expose mutated bytes.  The caller supplies a non-zero generation
 * which the M4d activation component has already admitted.  M4c lowers the
 * resolved values here to a ConcreteEditBatch and M5 will gate exposure on a
 * durable host-sink ACK.
 *
 * Every rule and every ValueRef observes the same `record.payload` and decoded
 * message.  Results are sorted by rule_id, independently of the order of the
 * rules array.  That canonical order is also used for all resource bounds, so
 * permuting registration cannot change eligibility or refusal results.
 */
#ifndef NFSP_RESOLVER_H
#define NFSP_RESOLVER_H

#include <stddef.h>
#include <stdint.h>

#include "nfs_decode.h"
#include "rule.h"

#define NFSP_RESOLVED_MAX		64u
#define NFSP_RESOLVED_SNAPSHOT_MAX	(1u << 20)

/* The runtime taxonomy from design 04 section 31.  TARGET_AMBIGUOUS is
 * reserved for target forms added after runtime version 1: all current field
 * occurrences use all_matches and are therefore not ambiguous merely because
 * there is more than one. */
enum nfsp_resolve_status {
	NFSP_RESOLVE_SCOPE_MISS = 0,
	NFSP_RESOLVE_RPC_SELECTOR_MISS,
	NFSP_RESOLVE_SCHEMA_MISMATCH,
	NFSP_RESOLVE_DECODE_UNAVAILABLE,
	NFSP_RESOLVE_TRANSACTION_CONTEXT_MISSING,
	NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE,
	NFSP_RESOLVE_TARGET_NOT_FOUND,
	NFSP_RESOLVE_TARGET_AMBIGUOUS,
	NFSP_RESOLVE_PREDICATE_FALSE,
	NFSP_RESOLVE_PREDICATE_REFERENCE_AMBIGUOUS,
	NFSP_RESOLVE_TRANSFORM_UNSUPPORTED,
	NFSP_RESOLVE_TRANSFORM_FAILED,
	NFSP_RESOLVE_RESOLVED,
	NFSP_RESOLVE_CONFLICT,
	NFSP_RESOLVE_STRUCTURE_CONSTRAINT_FAILED,
	NFSP_RESOLVE_STATUS_COUNT
};

/* Only FOUND may supply request views.  MISSING means there was no matching
 * transaction; UNUSABLE covers ambiguous/expired context. */
enum nfsp_resolver_txn_state {
	NFSP_RESOLVER_TXN_MISSING = 0,
	NFSP_RESOLVER_TXN_FOUND,
	NFSP_RESOLVER_TXN_UNUSABLE
};

/* A decoded CALL snapshot retained for a REPLY rule.  The payload and message
 * must describe the same immutable bytes.  The current M3 table does not yet
 * retain these arbitrary fields; an absent required view is therefore a typed
 * transaction_context_unusable result, never a fallback to the other view. */
struct nfsp_resolver_view {
	const uint8_t *payload;
	size_t payload_len;
	const struct nfsp_decoded_msg *message;
};

struct nfsp_resolver_transaction {
	enum nfsp_resolver_txn_state state;
	uint32_t program, version, procedure;
	struct nfsp_resolver_view forwarded;
	struct nfsp_resolver_view original;
};

struct nfsp_resolver_record {
	/* Non-zero generation already admitted by the activation layer.  This
	 * module intentionally has no operation that opens or closes a window. */
	uint64_t activation_generation;
	enum nfsp_rule_direction direction;
	uint32_t backend, client;
	const uint8_t *payload;
	size_t payload_len;
	const struct nfsp_decoded_msg *message;
	const struct nfsp_resolver_transaction *transaction;
};

/* A typed value and its canonical XDR value bytes (metadata excluded).  bytes
 * is owned by nfsp_resolution and remains valid until nfsp_resolution_free(). */
struct nfsp_resolved_value {
	enum nfsp_rule_literal_kind kind;
	uint64_t number;
	const uint8_t *bytes;
	uint32_t len;
};

struct nfsp_resolved_mutation {
	const char *rule_id;
	const char *semantic_path;
	uint32_t field_index;
	uint32_t operation_index;	/* NFSP_FIELD_NONE outside an operation */
	enum nfsp_rule_part part;
	enum nfsp_rule_policy policy;
	struct nfsp_wire_ref wire;
	/* The selected live part.  footprint is the original-coordinate region
	 * M4c must treat as structurally owned.  For preserve on a variable
	 * opaque/string value it is the whole encoding (length/value/padding);
	 * for raw it is exactly selected. */
	struct nfsp_span selected;
	struct nfsp_span footprint;
	struct nfsp_resolved_value current;
	struct nfsp_resolved_value output;
	/* Private owned snapshots. */
	uint8_t *current_storage;
	uint8_t *output_storage;
};

/* Counts are per semantic occurrence except stage misses, which count once
 * for the rule on this record.  eligible is the number which passed selector,
 * predicates and transform before global conflict preflight. */
struct nfsp_rule_resolution {
	const char *rule_id;
	uint32_t eligible;
	uint32_t count[NFSP_RESOLVE_STATUS_COUNT];
};

enum nfsp_resolution_preflight {
	NFSP_PREFLIGHT_EMPTY = 0,
	NFSP_PREFLIGHT_READY,
	NFSP_PREFLIGHT_CONFLICT,
	NFSP_PREFLIGHT_STRUCTURE_CONSTRAINT_FAILED
};

struct nfsp_resolution {
	uint64_t activation_generation;
	struct nfsp_rule_resolution *rules;
	uint32_t nrules;
	struct nfsp_resolved_mutation *mutations;
	uint32_t nmutations;
	enum nfsp_resolution_preflight preflight;
	size_t snapshot_bytes;
};

/* Resolve all rules against record's one pre-mutation snapshot.
 *
 * Returns 0 for every semantic result, including misses and conflicts.  -1 is
 * only a programming/resource failure (bad arguments, duplicate rule ids in
 * an allegedly validated set, or allocation failure).  `out` is reset first
 * and owns its arrays and value snapshots on success. */
int nfsp_resolve_rules(const struct nfsp_ruleset *ruleset,
		       const struct nfsp_resolver_record *record,
		       struct nfsp_resolution *out);

void nfsp_resolution_free(struct nfsp_resolution *out);

const char *nfsp_resolve_strstatus(enum nfsp_resolve_status status);

#endif /* NFSP_RESOLVER_H */
