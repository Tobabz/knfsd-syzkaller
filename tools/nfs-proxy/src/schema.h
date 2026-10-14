/* ProtocolSchema: the normalized XDR tables the NFS Semantic Decoder reads.
 *
 * WHERE THESE TABLES COME FROM
 *
 *   Never from hand edits.  tools/nfs-proxy/schema/normalize.py reads pinned
 *   XDR source and an annotation file and writes one C file of these tables
 *   per protocol family (design 03-nfs-proxy/02 §2-§4).  build.sh regenerates
 *   each committed table file and fails when it differs, so a table and its
 *   XDR cannot drift apart.
 *
 * WHAT A TABLE GUARANTEES
 *
 *   The normalizer refuses, at build time, every construct the runtime could
 *   only decode by guessing (see normalize.py).  So for any table reaching
 *   this header:
 *     - type graphs are acyclic except for the XDR linked-list idiom, which
 *       is flagged NFSP_STF_LISTED and decoded as a loop, not by recursion;
 *     - every array element has min_size > 0, so a declared count can be
 *       checked against the remaining bytes before any element is read;
 *     - every union case value is a member of the discriminant's type;
 *     - max_depth <= NFSP_DECODE_MAX_DEPTH.
 *   The runtime still checks bounds on every read: these properties bound
 *   its work, they do not replace its checks.
 *
 * SEMANTIC NAMING
 *
 *   A semantic path (design 02 §8-§9) is built from XDR identifiers plus the
 *   annotation layer's branch names:
 *     struct member        <parent>.<member>
 *     union discriminant   <union>.<discriminant name>
 *     union arm, struct    <union>.<branch>            members spliced in
 *     union arm, other     <union>.<branch>.<arm name>
 *     array/list element   <array>[]                   index is metadata
 *     procedure argument   <family>.request.<PROC>.<request_leaf>
 *     procedure result     <family>.response.<PROC>.<response_leaf>
 *     COMPOUND operation   <family>.<direction>.<OP>, its arm .<leaf>
 *   `arm.component` holds the precomputed "<branch>" or "<branch>.<arm name>".
 */
#ifndef NFSP_SCHEMA_H
#define NFSP_SCHEMA_H

#include <stdint.h>

#define NFSP_SCHEMA_NONE	0xffffu
#define NFSP_XDR_UNBOUNDED	0xffffffffu

enum nfsp_xdr_kind {
	NFSP_XK_VOID = 0,
	NFSP_XK_INT,		/* int, 4 bytes, signed */
	NFSP_XK_UINT,		/* unsigned int */
	NFSP_XK_HYPER,		/* hyper, 8 bytes, signed */
	NFSP_XK_UHYPER,		/* unsigned hyper */
	NFSP_XK_BOOL,		/* 0 or 1 only */
	NFSP_XK_ENUM,		/* declared values only */
	NFSP_XK_OPAQUE_FIXED,	/* opaque x[bound] */
	NFSP_XK_OPAQUE_VAR,	/* opaque x<bound> */
	NFSP_XK_STRING,		/* string x<bound> */
	NFSP_XK_ARRAY_FIXED,	/* T x[bound] */
	NFSP_XK_ARRAY_VAR,	/* T x<bound> */
	NFSP_XK_LIST,		/* T *x where T is NFSP_STF_LISTED */
	NFSP_XK_STRUCT,
	NFSP_XK_UNION
};

/* type flags */
#define NFSP_STF_LISTED		0x01u	/* struct whose last member is T *next;
					 * the link is not in `fields` */
#define NFSP_STF_OPS_REQUEST	0x02u	/* union is the COMPOUND request op */
#define NFSP_STF_OPS_RESPONSE	0x04u	/* union is the COMPOUND result op */
#define NFSP_STF_STATUS		0x08u	/* enum is the operation status type */

struct nfsp_schema_type {
	const char *name;	/* XDR name; NULL when anonymous */
	uint8_t kind;		/* enum nfsp_xdr_kind */
	uint8_t flags;		/* NFSP_STF_* */
	uint16_t sub;		/* element type (arrays, list); discriminant
				 * type (union) */
	uint32_t bound;		/* fixed size/count, or maximum, or
				 * NFSP_XDR_UNBOUNDED */
	uint32_t first;		/* into fields (struct), arms (union), enums */
	uint32_t count;
	uint16_t default_arm;	/* union: arm index relative to first, or
				 * NFSP_SCHEMA_NONE */
	const char *disc_name;	/* union discriminant name */
	uint32_t min_size;	/* smallest valid encoding in bytes */
};

struct nfsp_schema_field {
	const char *name;
	uint16_t type;
};

struct nfsp_schema_arm {
	uint32_t value;		/* case value as the 4 wire bytes read */
	const char *label;	/* XDR case label, for diagnosis */
	const char *branch;	/* path branch; the op name for op unions */
	const char *component;	/* path component of the arm's value; NULL
				 * when the arm is void */
	uint16_t type;		/* NFSP_SCHEMA_NONE when void */
};

struct nfsp_schema_enumval {
	uint32_t value;
	const char *name;
};

struct nfsp_schema_proc {
	uint32_t number;
	const char *name;	/* without the annotation's procedure prefix */
	uint16_t arg, res;	/* NFSP_SCHEMA_NONE when void */
};

/* One ProtocolSchema(schema_id): one program/version, and for NFSv4 one
 * minor version (design 02 §3). */
struct nfsp_protocol_schema {
	const char *schema_id;
	const char *family;
	uint32_t program, version;
	int has_minor;
	uint32_t minor;
	const char *request_leaf, *response_leaf;
	const struct nfsp_schema_type *types;
	uint32_t ntypes;
	const struct nfsp_schema_field *fields;
	const struct nfsp_schema_arm *arms;
	const struct nfsp_schema_enumval *enums;
	const struct nfsp_schema_proc *procs;
	uint32_t nprocs;
	/* has_minor only: the CALL procedure whose argument struct carries the
	 * minor version, and that member's index.  The normalizer proves the
	 * members up to it encode identically in every minor of the family. */
	uint32_t selector_proc;
	uint32_t selector_field;
	uint32_t max_depth;
};

/* Every ProtocolSchema of one program/version.  Without minor versions it
 * holds exactly one. */
struct nfsp_schema_family {
	const char *family;
	uint32_t program, version;
	int has_minor;
	const struct nfsp_protocol_schema *const *schemas;
	uint32_t nschemas;
};

const struct nfsp_schema_proc *
nfsp_schema_proc(const struct nfsp_protocol_schema *s, uint32_t number);

/* The family's schema for `minor`, or NULL. */
const struct nfsp_protocol_schema *
nfsp_schema_minor(const struct nfsp_schema_family *f, uint32_t minor);

/* Symbolic name of an enum value, or NULL when it is not declared. */
const char *nfsp_schema_enum_name(const struct nfsp_protocol_schema *s,
				  uint16_t type, uint32_t value);

#endif /* NFSP_SCHEMA_H */
