/* NFS Semantic Decoder: rpc_payload + ProtocolSchema -> DecodedRpcMessage.
 *
 * WHERE IT SITS
 *
 *   rpc_decode.c (M1) reads the RPC envelope and stops at the procedure body.
 *   This decoder starts there and walks the body with a generated
 *   ProtocolSchema (schema.h), emitting one SemanticField per XDR node with
 *   an exact WireRef.  It owns no selector matching, no mutation and no
 *   verdict (design 03-nfs-proxy/02 §1).  It never writes the payload.
 *
 * WHAT A WIREREF CLAIMS
 *
 *   Every span is in rpc_payload coordinates (offset 0 is the XID, never a
 *   record marker) and was proven by the schema walk: it is where the XDR
 *   says the node is, given the bytes before it.  No span is ever produced by
 *   searching for a value.  Outputting a WireRef is the decoder's
 *   correctness claim (design 02 §11).
 *
 * FAIL CLOSED
 *
 *   status != NFSP_DECODE_DECODED means the message is not a mutation input
 *   (design 02 §15).  To make that impossible to get wrong, a failed decode
 *   leaves nfields == nops == 0: the proven prefix is not kept.  `failure`
 *   says where and why, for diagnosis.
 *
 *   truncated  the record ends before a fixed-size item (a word, a hyper, a
 *              fixed opaque) can be read.
 *   malformed  a value the XDR does not allow: an undeclared enum value, a
 *              bool other than 0/1, a union discriminant with no arm, a
 *              length or count above its bound or beyond the record, non-zero
 *              padding, or bytes after the procedure body.
 *
 * REPLIES (design 02 §6, §14, issue #18 F4)
 *
 *   A REPLY carries no program, version or procedure, and an NFSv4
 *   COMPOUND4res carries no minor version.  The result schema is chosen only
 *   from `reply_dispatch`.  Without it the status is
 *   transaction_context_missing; for a minor-versioned family without a
 *   minor version it is dispatch_incomplete.  A result that would parse
 *   under some schema is never taken as evidence of which schema applies.
 *
 *   Request context (the CALL's decoded operations, for request-dependent
 *   predicates and request/result consistency) comes from the Transaction
 *   Context in M3.  M2 never has it, so `request_context` is always 0.
 */
#ifndef NFSP_NFS_DECODE_H
#define NFSP_NFS_DECODE_H

#include <stddef.h>
#include <stdint.h>

#include "rpc_decode.h"
#include "schema.h"

/* Runtime nesting limit.  The normalizer refuses deeper schemas (MAX_DEPTH
 * in schema/normalize.py), so reaching it at runtime is a table bug. */
#define NFSP_DECODE_MAX_DEPTH		64u
#define NFSP_DECODE_DEFAULT_MAX_FIELDS	65536u
#define NFSP_FIELD_NONE			0xffffffffu

enum nfsp_decode_status {
	NFSP_DECODE_DECODED = 0,
	NFSP_DECODE_UNSUPPORTED_SCHEMA,
	NFSP_DECODE_MALFORMED,
	NFSP_DECODE_TRUNCATED,
	NFSP_DECODE_TRANSACTION_CONTEXT_MISSING,
	NFSP_DECODE_DISPATCH_INCOMPLETE,
	NFSP_DECODE_RESOURCE_LIMIT
};

/* Where a reply_dispatch came from.  Production code may only pass
 * TRANSACTION_ENTRY (a `found` TransactionEntry, M3).  TEST_FIXTURE is the
 * M2 host tests' fixture CALL and is refused unless allow_test_fixture. */
enum nfsp_dispatch_source {
	NFSP_DISPATCH_NONE = 0,
	NFSP_DISPATCH_TRANSACTION_ENTRY,
	NFSP_DISPATCH_TEST_FIXTURE
};

struct nfsp_reply_dispatch {
	uint32_t program, version, procedure;
	int has_minor;
	uint32_t minor_version;
	enum nfsp_dispatch_source source;
};

struct nfsp_decode_input {
	const uint8_t *payload;		/* RpcRecord.rpc_payload */
	size_t len;
	const struct nfsp_rpc_envelope *rpc;	/* NFSP_RPC_OK envelope of it */
	const struct nfsp_reply_dispatch *reply_dispatch;	/* REPLY only */
	int allow_test_fixture;		/* host tests only */
	uint32_t max_fields;		/* 0: NFSP_DECODE_DEFAULT_MAX_FIELDS */
};

/* WireRef metadata roles (design 02 §10).  A bit in `meta` says the span is
 * present. */
#define NFSP_META_LENGTH	0x1u	/* opaque/string length word */
#define NFSP_META_COUNT		0x2u	/* variable array count word */
#define NFSP_META_DISCRIMINANT	0x4u	/* union discriminant, list link */
#define NFSP_META_PADDING	0x8u	/* XDR padding after opaque bytes */

struct nfsp_wire_ref {
	struct nfsp_span encoded;	/* the node's whole XDR encoding */
	struct nfsp_span value;		/* the value without metadata */
	uint32_t meta;
	struct nfsp_span length, count, discriminant, padding;
};

/* One XDR node.  Nodes are in pre-order, so parent < index always.
 * Path: nfsp_field_path().  For a list element, `discriminant` is the link
 * word after it, and `encoded` covers the element through that word. */
struct nfsp_semantic_field {
	uint32_t parent;	/* NFSP_FIELD_NONE at the procedure root */
	uint32_t op;		/* index into ops, or NFSP_FIELD_NONE */
	uint32_t index;		/* element index under an array or list, or
				 * NFSP_FIELD_NONE.  Structural metadata, not a
				 * selector identity (design 02 §9). */
	const char *root;	/* procedure or operation name at a path root */
	const char *component;
	uint16_t type;		/* index into schema->types */
	uint8_t kind;		/* enum nfsp_xdr_kind */
	uint64_t value;		/* INT/HYPER sign-extended; UINT/UHYPER/BOOL/
				 * ENUM as read; others 0 */
	struct nfsp_wire_ref wire;
};

/* One COMPOUND operation (design 02 §7). */
struct nfsp_decoded_op {
	uint32_t opcode;
	const char *name;
	uint32_t sequence_index;	/* position in argarray/resarray */
	uint32_t field;			/* the operation's union node */
	int has_status;			/* response: first leaf is the status */
	uint32_t status;
};

struct nfsp_decode_failure {
	uint32_t offset;		/* payload offset of the refused item */
	const char *schema_node;	/* XDR type name or kind */
	const char *reason;
};

/* Zero-initialise once and reuse across messages; the arrays are kept and
 * grown.  Release with nfsp_decoded_msg_free(). */
struct nfsp_decoded_msg {
	enum nfsp_decode_status status;
	const struct nfsp_protocol_schema *schema;	/* schema_id is here */
	uint32_t msg_type, xid;
	uint32_t program, version, procedure;
	const char *procedure_name;
	int has_minor;
	uint32_t minor_version;
	enum nfsp_dispatch_source dispatch_source;	/* REPLY */
	int request_context;		/* always 0 in M2, see above */

	struct nfsp_semantic_field *fields;
	uint32_t nfields;
	struct nfsp_decoded_op *ops;
	uint32_t nops;
	struct nfsp_decode_failure failure;

	uint32_t fields_cap, ops_cap;
};

/* Decode in->payload against the first family matching the program and
 * version.  Always fills *out; returns out->status.  out must not be NULL. */
enum nfsp_decode_status
nfsp_nfs_decode(const struct nfsp_schema_family *const *families,
		size_t nfamilies, const struct nfsp_decode_input *in,
		struct nfsp_decoded_msg *out);

void nfsp_decoded_msg_free(struct nfsp_decoded_msg *m);

/* Write field idx's semantic path into buf (always NUL-terminated when
 * cap > 0).  Returns the full path length, or 0 for a bad index. */
size_t nfsp_field_path(const struct nfsp_decoded_msg *m, uint32_t idx,
		       char *buf, size_t cap);

/* The first field whose path is `path`, at or after `from`, or
 * NFSP_FIELD_NONE.  For tests and diagnostics; it is linear. */
uint32_t nfsp_field_find(const struct nfsp_decoded_msg *m, const char *path,
			 uint32_t from);

const char *nfsp_decode_strstatus(enum nfsp_decode_status status);

#endif /* NFSP_NFS_DECODE_H */
