/* Variable-length wire edits: the mutations that change a record's length.
 *
 * WHY THIS IS A SEPARATE LAYER FROM delta.h
 *
 *   delta.h/`nfsp_apply_rule` patch a fixed-width field in place: the output is
 *   the same length as the input, so the proxy forwards the same number of bytes
 *   and the record marker never changes.  That is enough to flip a status, a
 *   stateid or a length word, and it is deliberately the simplest thing that can
 *   reproduce a crash.
 *
 *   A 1-day scenario can need more than a same-width flip: it can require adding
 *   an operation to a COMPOUND, or growing/shrinking a variable-length field so
 *   that a length word and the bytes that follow it disagree.  Both change the
 *   message length, which means the 4-byte record marker must be rebuilt and the
 *   op count may have to move.  That is a different contract from "patch N bytes
 *   with N bytes", so it lives in its own module rather than complicating the
 *   fixed-width path that the bulk of the tests already pin.
 *
 * WHAT THIS LAYER GUARANTEES (Phase 1, "layer 0": no per-op schema)
 *
 *   - Edits are addressed in the ORIGINAL message's coordinates.  Applying one
 *     edit never shifts the offset another edit refers to; the whole record is
 *     rebuilt once, in offset order.  Overlapping edits are refused, not merged.
 *   - REPLACE and DELETE name the bytes they expect at their offset and are
 *     VERIFIED before anything is written, exactly as `nfsp_apply_rule` is: a
 *     mismatch is a counted refusal, never a silent patch of the wrong message.
 *   - The record marker (RFC 5531 fragment header) is ALWAYS rebuilt from the
 *     final length, in both modes.  A wrong marker desynchronises the whole TCP
 *     stream, so the intentional "length field disagrees with reality" mismatch
 *     a scenario may want is made inside the RPC/XDR body, never in the marker.
 *   - Edits are confined to the op-array body (everything after the COMPOUND
 *     header).  The fixed RPC and COMPOUND header the walk understands is never
 *     grown or shifted, so every structural offset stays meaningful.  Editing
 *     inside the fixed header, and per-op XDR length fix-ups, are Phase 2.
 *
 * STRUCTURE-PRESERVING vs RAW
 *
 *   Both modes rebuild the marker.  They differ in one thing: in
 *   NFSP_EDIT_MODE_STRUCT, OP_APPEND/OP_PREPEND also bump the COMPOUND op count
 *   so the added op is actually dispatched; in NFSP_EDIT_MODE_RAW the count is
 *   left alone, which is how a scenario builds a message whose declared op count
 *   and real op bytes disagree.  INSERT/DELETE/REPLACE touch no structural field
 *   in either mode in Phase 1, so for them the two modes are identical.
 */
#ifndef NFSP_EDIT_H
#define NFSP_EDIT_H

#include <stddef.h>
#include <stdint.h>

#include "delta.h"	/* nfsp_msg_ctx, nfsp_apply_stats, enums, ANCHOR_MAX */
#include "walk.h"	/* nfsp_walk, for op-array layout */

/* Per-field byte cap.  One NFS operation (the largest thing OP_APPEND carries)
 * and the originals a REPLACE/DELETE verifies are both far smaller; the cap only
 * exists so a hostile arm cannot drive a large allocation.  A value that matters
 * to a scenario can be raised here and in the syzlang arm description together. */
#define NFSP_EDIT_BYTES_MAX	1024u
#define NFSP_EDIT_MAX		8u	/* edits per rule */
/* Sum of every edit's orig_len + data_len in one rule.  This is the cap the
 * arm packet inherits: it bounds what one syzkaller argument can carry and
 * therefore what one arm can make the proxy allocate or rebuild. */
#define NFSP_EDIT_TOTAL_MAX	4096u
/* Edits resolved across ALL rules matching one record.  Bounds the sort and
 * the worst-case growth of one rebuilt record. */
#define NFSP_EDIT_RESOLVED_MAX	64u

enum nfsp_edit_mode {
	NFSP_EDIT_MODE_STRUCT = 0,	/* bump op count for OP_APPEND/OP_PREPEND */
	NFSP_EDIT_MODE_RAW = 1		/* leave structural fields alone */
};

enum nfsp_edit_kind {
	NFSP_EDIT_REPLACE = 0,	/* verify orig[orig_len], write data[data_len] */
	NFSP_EDIT_INSERT = 1,	/* insert data[data_len] before offset */
	NFSP_EDIT_DELETE = 2,	/* verify orig[orig_len], remove it */
	NFSP_EDIT_OP_APPEND = 3,	/* insert data at end of the op array */
	NFSP_EDIT_OP_PREPEND = 4,	/* insert data at the start of the op array */
	NFSP_EDIT_KIND_COUNT
};

/* One edit.  For OP_APPEND/OP_PREPEND `offset` and `orig_len` are unused: the
 * offset is derived from the message (end / start of the op array) at apply
 * time, which is what makes an OP_* edit apply correctly to messages of
 * different lengths.  For INSERT, `orig_len` is 0.  For DELETE, `data_len` is 0. */
struct nfsp_edit {
	uint32_t	kind;		/* enum nfsp_edit_kind */
	uint32_t	offset;		/* original-message coords (REPLACE/INSERT/DELETE) */
	uint32_t	orig_len;	/* bytes verified/removed */
	uint32_t	data_len;	/* bytes written/inserted */
	uint8_t		orig[NFSP_EDIT_BYTES_MAX];
	uint8_t		data[NFSP_EDIT_BYTES_MAX];
};

/* A variable-length edit rule: the same predicate as nfsp_rule, a mode, and a
 * list of edits applied together as one rebuild of the record. */
struct nfsp_edit_rule {
	uint32_t	dir;		/* enum nfsp_delta_dir */
	uint32_t	backend;	/* enum nfsp_delta_backend */
	uint32_t	client;		/* 0 or 1 */
	uint32_t	first_opcode;	/* NFSP_DELTA_OPCODE_ANY to ignore */
	uint32_t	anchor_off;
	uint32_t	anchor_len;	/* 0 = no anchor */
	uint32_t	mode;		/* enum nfsp_edit_mode */
	uint32_t	nedits;		/* 1..NFSP_EDIT_MAX */
	uint32_t	applied_count;	/* how often it applied when produced */
	uint8_t		anchor[NFSP_DELTA_ANCHOR_MAX];
	struct nfsp_edit edits[NFSP_EDIT_MAX];
};

/* Extra refusal counters specific to variable-length edits.  Kept next to the
 * fixed-width ones in nfsp_apply_stats would mean touching the struct the v1
 * tests pin, so they are separate and the control layer aggregates both. */
struct nfsp_edit_stats {
	uint32_t	predicate_hits;
	uint32_t	applied;
	uint32_t	refused_orig_diff;	/* a verified original did not match */
	uint32_t	refused_out_of_range;	/* an edit fell outside the op body */
	uint32_t	refused_unknown_layout;	/* not a COMPOUND the walk understood */
	uint32_t	refused_overlap;	/* two edits touch the same bytes */
	uint32_t	refused_too_big;	/* output would exceed out_cap */
};

int nfsp_edit_rule_valid(const struct nfsp_edit_rule *r);

/* Apply `r` to in[0..in_len), writing the rebuilt record to out[0..*out_len).
 *
 *   1  the rule applied; out holds the new record and *out_len its length
 *   0  the rule did not apply (predicate miss, or a counted refusal); out is
 *      untouched and the caller must forward `in` unchanged
 *  -1  a programming error (NULL argument or invalid rule)
 *
 * `walk` must be the result of nfsp_walk(in, in_len, ...); it supplies the op
 * array layout.  The produce path and the replay path both call this function;
 * nothing else rebuilds a record. */
int nfsp_apply_edit_rule(const struct nfsp_edit_rule *r,
			 const struct nfsp_msg_ctx *ctx,
			 const struct nfsp_walk *walk,
			 const uint8_t *in, size_t in_len,
			 uint8_t *out, size_t out_cap, size_t *out_len,
			 struct nfsp_edit_stats *st);

/* Apply every matching rule of `rules[0..nrules)` to the same record in ONE
 * rebuild.  This is what makes "all offsets are original-record coordinates"
 * true when several arms match: no rule sees another rule's output, and edits
 * from different rules are ordered by (offset, rule order, edit order) and
 * checked for overlap together.
 *
 * Each rule is judged independently first (predicate, range, verified
 * originals); a rule that refuses is excluded and counted in its own stats
 * while the others proceed.  Overlap among the remaining edits, or an output
 * over out_cap, refuses ALL of them (counted for each) because there is no
 * principled way to keep some of a conflicting set.
 *
 * Returns the number of rules applied (0 = none; out untouched, forward `in`),
 * or -1 on a programming error.  stats[i] belongs to rules[i]. */
int nfsp_apply_edit_rules(const struct nfsp_edit_rule *const *rules,
			  struct nfsp_edit_stats *const *stats, size_t nrules,
			  const struct nfsp_msg_ctx *ctx,
			  const struct nfsp_walk *walk,
			  const uint8_t *in, size_t in_len,
			  uint8_t *out, size_t out_cap, size_t *out_len);

/* ---- delta v2 (replay) --------------------------------------------------
 *
 * The same reproduction contract as delta.h, for variable-length rules: one
 * self-contained record per arm, made durable with O_SYNC, carrying the edit
 * list and the observed apply count so a replay can re-apply it and check that
 * it applied exactly where it was recorded.  A distinct magic ("NFSPDLT2") lets
 * a reader tell a variable-length file from a fixed-width one. */
#define NFSP_EDIT_DELTA_MAGIC	"NFSPDLT2"
#define NFSP_EDIT_DELTA_VERSION	2u

struct nfsp_edit_writer;

int nfsp_edit_write_open(struct nfsp_edit_writer **out, const char *path,
			 uint64_t seed);
int nfsp_edit_write_rule(struct nfsp_edit_writer *w,
			 const struct nfsp_edit_rule *r);
int nfsp_edit_write_applied_count(struct nfsp_edit_writer *w, long index,
				  uint32_t applied_count);
long nfsp_edit_write_close(struct nfsp_edit_writer *w);

struct nfsp_edit_reader;

int nfsp_edit_read_open(struct nfsp_edit_reader **out, const char *path);
/* 1 = a rule was read, 0 = end of file, -1 = corrupt. */
int nfsp_edit_read_rule(struct nfsp_edit_reader *r, struct nfsp_edit_rule *out);
void nfsp_edit_read_close(struct nfsp_edit_reader *r);

#endif /* NFSP_EDIT_H */
