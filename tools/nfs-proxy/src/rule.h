/* CompiledMutationRule set: the serialized form and its validation (M4a).
 *
 * WHAT IT IS
 *
 *   The Mutation Rule Compiler (Agent side) lowers a MutationRuleSet to
 *   CompiledMutationRule[] (design 03-nfs-proxy/04 §2-§19).  The Runner
 *   installs one such set, immutable, per proxy session, and records it as
 *   the RULESET journal event (design 05 §7).  This module reads that set
 *   from bytes and proves, before any traffic, that every rule is one this
 *   runtime can resolve against the ProtocolSchema it names.  It resolves
 *   nothing against live records: that is the Resolver (M4b).
 *
 * THE FORMAT, "NFSPRUL1"
 *
 *   XDR (RFC 4506): big-endian 4-byte units, strings and opaques padded with
 *   zero bytes to 4, `T *x` is a bool word then T when it is 1.  The full
 *   definition is design 04 §35; in short:
 *
 *     struct rule_set {
 *         opaque magic[8];                 "NFSPRUL1"
 *         unsigned semantic_runtime_version;    1
 *         string schema_id<256>;
 *         id     candidate_id;
 *         rule   rules<256>;               rule_id strictly ascending
 *     };
 *     struct rule {
 *         id rule_id; id intent_id;
 *         traffic_scope {direction, backend, client};
 *         rpc {message_type, program, version, unsigned *procedure};
 *         protocol {string family<32>, unsigned *nfs_version,
 *                   unsigned *minor_version};
 *         string *operation<64>;
 *         target {kind, path, part};
 *         predicate predicates<16>;
 *         mutation {kind, transform *transform, structure_policy};
 *         view_deps forwarded, original;   context_dependencies per view
 *         application_mode application;    all_matches
 *     };
 *
 *   Everything is canonical, so one rule set has one encoding and its
 *   digest (rule_set_id, computed by the host) names it: no trailing bytes,
 *   zero padding, every enum and bool in range, rule ids strictly ascending
 *   (so unique), request_fields strictly ascending, a target ValueRef with
 *   no path.  One schema_id and candidate_id serve every rule: RULESET
 *   carries one of each.
 *
 * VALIDATION
 *
 *   Loading is all or nothing.  The first rule that fails refuses the whole
 *   set with a typed status and the rule and predicate it is in: a session
 *   must run exactly the set its RULESET names.  Beyond the format, every
 *   rule must agree with its schema (program, version, minor version,
 *   procedure, operation), every path must resolve to exactly one schema
 *   node (schema.h), the target and every value the rule reads must be in
 *   one procedure (a message holds only its own procedure's values),
 *   predicates and transforms must be typed as design 04 §9, §13, §14 say
 *   with no implicit reinterpretation, and the declared context
 *   dependencies must be exactly those the rule's ValueRefs need (design 04
 *   §10, rules in §35).
 *
 *   What this runtime cannot yet apply is unsupported_capability, kept apart
 *   from input errors because it is a harness gap and not the Agent's to fix
 *   (design 04 §19): insert, delete, op_append, op_prepend, builtin
 *   transforms (no registry yet), the `encoded` part, replacing a value that
 *   is not a leaf, a copy into metadata, and a preserve-policy edit of a
 *   discriminant.
 */
#ifndef NFSP_RULE_H
#define NFSP_RULE_H

#include <stddef.h>
#include <stdint.h>

#include "schema.h"

#define NFSP_RULESET_MAGIC		"NFSPRUL1"
#define NFSP_SEMANTIC_RUNTIME_VERSION	1u

/* Bounds (design 04 "운영": rules, occurrences and edits stay bounded).
 * Initial values, to revisit with the Compiler's real output. */
#define NFSP_RULESET_MAX_LEN		(1u << 20)
#define NFSP_RULES_MAX			256u
#define NFSP_RULE_PREDICATES_MAX	16u
#define NFSP_RULE_REQUEST_FIELDS_MAX	16u
#define NFSP_RULE_BUILTIN_ARGS_MAX	8u
#define NFSP_RULE_ID_MAX		128u
#define NFSP_RULE_SCHEMA_ID_MAX		256u
#define NFSP_RULE_FAMILY_MAX		32u
#define NFSP_RULE_OPERATION_MAX		64u
#define NFSP_RULE_PATH_MAX		512u
#define NFSP_RULE_LITERAL_MAX		4096u

#define NFSP_RULE_NONE			0xffffffffu

/* Wire enums.  Their values are the format: never renumber. */
enum nfsp_rule_direction { NFSP_RULE_C2S = 0, NFSP_RULE_S2C = 1 };
enum nfsp_rule_msg_type { NFSP_RULE_CALL = 0, NFSP_RULE_REPLY = 1 };
enum nfsp_rule_target_kind {
	NFSP_RULE_FIELD = 0,
	NFSP_RULE_OPERATION_ARRAY = 1
};
enum nfsp_rule_part {
	NFSP_PART_VALUE = 0,
	NFSP_PART_ENCODED = 1,
	NFSP_PART_LENGTH = 2,
	NFSP_PART_COUNT = 3,
	NFSP_PART_DISCRIMINANT = 4,
	NFSP_PART_PADDING = 5
};
enum nfsp_rule_source {
	NFSP_SRC_TARGET = 0,
	NFSP_SRC_CURRENT_MESSAGE = 1,
	NFSP_SRC_REQUEST_FORWARDED = 2,
	NFSP_SRC_REQUEST_ORIGINAL = 3
};
enum nfsp_rule_literal_kind {
	NFSP_LIT_INT = 0,
	NFSP_LIT_UINT = 1,
	NFSP_LIT_HYPER = 2,
	NFSP_LIT_UHYPER = 3,
	NFSP_LIT_BOOL = 4,
	NFSP_LIT_ENUM = 5,	/* the value as the wire word */
	NFSP_LIT_OPAQUE = 6,
	NFSP_LIT_STRING = 7
};
enum nfsp_rule_operand_kind { NFSP_OPND_LITERAL = 0, NFSP_OPND_REF = 1 };
enum nfsp_rule_compare {
	NFSP_CMP_EQ = 0,
	NFSP_CMP_NE = 1,
	NFSP_CMP_LT = 2,
	NFSP_CMP_LE = 3,
	NFSP_CMP_GT = 4,
	NFSP_CMP_GE = 5
};
enum nfsp_rule_mutation_kind {
	NFSP_MUT_REPLACE = 0,
	NFSP_MUT_INSERT = 1,
	NFSP_MUT_DELETE = 2,
	NFSP_MUT_OP_APPEND = 3,
	NFSP_MUT_OP_PREPEND = 4
};
enum nfsp_rule_transform_kind {
	NFSP_XF_LITERAL = 0,
	NFSP_XF_COPY = 1,
	NFSP_XF_BUILTIN = 2
};
enum nfsp_rule_policy { NFSP_POLICY_PRESERVE = 0, NFSP_POLICY_RAW = 1 };
enum nfsp_rule_application { NFSP_APPLY_ALL_MATCHES = 0 };

/* Strings are NUL-terminated copies owned by the rule set; bytes may hold
 * NULs and have `len`. */
struct nfsp_rule_literal {
	enum nfsp_rule_literal_kind kind;
	uint64_t num;		/* INT/HYPER sign-extended; others as read */
	const uint8_t *bytes;	/* OPAQUE, STRING */
	uint32_t len;
};

struct nfsp_rule_value_ref {
	enum nfsp_rule_source source;
	const char *path;	/* "" for NFSP_SRC_TARGET */
	/* Set by validation. */
	struct nfsp_schema_node node;
};

struct nfsp_rule_predicate {
	struct nfsp_rule_value_ref lhs;
	enum nfsp_rule_compare op;
	enum nfsp_rule_operand_kind rhs_kind;
	struct nfsp_rule_literal rhs_literal;
	struct nfsp_rule_value_ref rhs_ref;
};

struct nfsp_rule_transform {
	enum nfsp_rule_transform_kind kind;
	struct nfsp_rule_literal value;		/* LITERAL */
	struct nfsp_rule_value_ref source;	/* COPY */
	const char *transform_id;		/* BUILTIN */
	struct nfsp_rule_literal *args;
	uint32_t nargs;
};

struct nfsp_rule_view_deps {
	int rpc_procedure;
	int request_operation_sequence;
	const char **request_fields;	/* strictly ascending (strcmp) */
	uint32_t nfields;
};

struct nfsp_rule {
	const char *rule_id, *intent_id;
	enum nfsp_rule_direction direction;
	uint32_t backend, client;

	enum nfsp_rule_msg_type message_type;
	uint32_t program, version;
	int has_procedure;
	uint32_t procedure;
	const char *family;
	int has_nfs_version, has_minor_version;
	uint32_t nfs_version, minor_version;
	const char *operation;		/* NULL when absent */

	enum nfsp_rule_target_kind target_kind;
	const char *target_path;
	enum nfsp_rule_part part;
	struct nfsp_schema_node target;	/* set by validation */

	struct nfsp_rule_predicate *predicates;
	uint32_t npredicates;

	enum nfsp_rule_mutation_kind kind;
	int has_transform;
	struct nfsp_rule_transform transform;
	enum nfsp_rule_policy policy;

	struct nfsp_rule_view_deps forwarded, original;
	enum nfsp_rule_application application;
};

struct nfsp_ruleset {
	uint32_t semantic_runtime_version;
	const char *schema_id;
	const char *candidate_id;
	struct nfsp_rule *rules;
	uint32_t nrules;
	/* Set by validation: the ProtocolSchema schema_id names. */
	const struct nfsp_protocol_schema *schema;

	/* Owned storage. */
	char *arena;
	size_t arena_len, arena_cap;
	struct nfsp_rule_predicate *pred_pool;
	struct nfsp_rule_literal *arg_pool;
	const char **field_pool;
};

enum nfsp_rule_status {
	NFSP_RULE_OK = 0,
	/* The bytes are not an NFSPRUL1 set. */
	NFSP_RULE_MALFORMED,
	NFSP_RULE_UNSUPPORTED_VERSION,
	NFSP_RULE_NO_MEMORY,
	/* No ProtocolSchema here has the set's schema_id. */
	NFSP_RULE_UNKNOWN_SCHEMA,
	/* Input errors: the rule does not say something this schema has. */
	NFSP_RULE_SELECTOR_MISMATCH,	/* program, version, family, minor,
					 * procedure or operation; or a value
					 * read outside the target's procedure */
	NFSP_RULE_MESSAGE_TYPE_INCONSISTENT,
	NFSP_RULE_UNKNOWN_PATH,
	NFSP_RULE_AMBIGUOUS_PATH,
	NFSP_RULE_PART_UNAVAILABLE,
	NFSP_RULE_TYPE_MISMATCH,
	NFSP_RULE_MUTATION_INVALID,	/* kind, transform and policy do not
					 * fit together or the target */
	NFSP_RULE_DEPENDENCIES_MISMATCH,
	/* Valid, but this runtime cannot apply it: a harness gap. */
	NFSP_RULE_UNSUPPORTED_CAPABILITY
};

struct nfsp_rule_error {
	enum nfsp_rule_status status;
	uint32_t rule;		/* index, or NFSP_RULE_NONE */
	uint32_t predicate;	/* index, or NFSP_RULE_NONE */
	uint32_t offset;	/* MALFORMED: the byte offset refused */
	const char *detail;	/* static text */
};

/* Parse the format only.  On failure *rs is freed and empty. */
enum nfsp_rule_status nfsp_ruleset_parse(const uint8_t *buf, size_t len,
					 struct nfsp_ruleset *rs,
					 struct nfsp_rule_error *err);

/* Validate a parsed set against the schemas this proxy has. */
enum nfsp_rule_status
nfsp_ruleset_validate(struct nfsp_ruleset *rs,
		      const struct nfsp_schema_family *const *families,
		      size_t nfamilies, struct nfsp_rule_error *err);

/* Parse, then validate.  On failure *rs is freed and empty. */
enum nfsp_rule_status
nfsp_ruleset_load(const uint8_t *buf, size_t len,
		  const struct nfsp_schema_family *const *families,
		  size_t nfamilies, struct nfsp_ruleset *rs,
		  struct nfsp_rule_error *err);

void nfsp_ruleset_free(struct nfsp_ruleset *rs);

const char *nfsp_rule_strstatus(enum nfsp_rule_status status);

#endif /* NFSP_RULE_H */
