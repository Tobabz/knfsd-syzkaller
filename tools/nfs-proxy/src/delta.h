/* Self-contained mutation delta: the record that makes a crash reproducible.
 *
 * WHY THIS IS THE CONTRACT OF THE WHOLE DESIGN
 *
 *   The proxy mutates responses and requests, so a crash is caused by a specific
 *   patched message reaching the kernel.  syzkaller reproduces a crash by
 *   re-running the program, but the RPC stream a kernel client produces is NOT
 *   perfectly reproducible: caches, timeouts and prior calls shift it.  A
 *   mutation identified as "the Nth matching RPC" therefore lands somewhere else
 *   on replay, and the crash does not come back -- which reads as "that crash is
 *   not reproducible" when in fact the harness aimed wrong.
 *
 *   So the delta is the unit of reproduction, and it must carry everything
 *   needed to re-apply itself:
 *
 *     SELF-CONTAINED   values are literals.  A record never says "take the
 *                      value from the observed-identifier pool", because on
 *                      replay the pool may be empty and the mutation would
 *                      silently do nothing.  Pool-derived mutations are
 *                      resolved to bytes at RECORD time.
 *
 *     CONTENT-ADDRESSED the predicate matches on a stable subset of the
 *                      message (direction, connection, first opcode, and an
 *                      optional literal anchor), never on ordinal position.
 *
 *     APPLY-TO-ALL      a rule applies to every match rather than to the Nth,
 *                      which is what makes the result order-independent.
 *
 *     VERIFIED          before patching, the bytes at the patch offset must
 *                      equal the recorded originals.  A mismatch means this is
 *                      not the message we recorded, and the rule refuses to
 *                      apply.  That turns "silently mutated the wrong message"
 *                      into a countable, loud failure.
 *
 *   And the produce path and the replay path call the SAME apply function.  A
 *   separate replay tool would mean two implementations of "how a mutation is
 *   applied", and their drift would be a silent reproduction failure.  Here the
 *   only input to replay is the delta file.
 *
 * WHAT REPLAY CAN AND CANNOT TELL YOU
 *
 *   Replay reports three distinct outcomes, and keeping them distinct is the
 *   point:
 *
 *     applied == recorded            the mutation was re-applied
 *     predicate matched, orig differs  THE STREAM IS NOT THE ONE RECORDED
 *     predicate never matched        the RPC never arrived
 *
 *   The middle one is the one that must not be confused with "the crash did not
 *   reproduce".  It means replay itself failed, and it is a hard error.
 */
#ifndef NFSP_DELTA_H
#define NFSP_DELTA_H

#include <stddef.h>
#include <stdint.h>

#define NFSP_DELTA_MAGIC	"NFSPDLT1"
#define NFSP_DELTA_VERSION	1u

/* Caps exist so a corrupt or hostile file cannot drive an allocation.  Both are
 * far larger than any field the proxy addresses: patches are single fields, and
 * anchors are short identifying spans. */
/* Ten u32 fields: dir, backend, client, first_opcode, match_index,
 * anchor_off, anchor_len, patch_off, patch_w, applied_count. */
#define NFSP_DELTA_REC_HDR_LEN	(10u * 4u)

#define NFSP_DELTA_ANCHOR_MAX	64u
#define NFSP_DELTA_PATCH_MAX	16u

enum nfsp_delta_dir {
	NFSP_DELTA_C2S = 0,
	NFSP_DELTA_S2C = 1
};

/* Which backend.  Part of the predicate because one executor drives four
 * connections, and a rule that did not name its connection could mutate another
 * client's or another server's traffic -- breaking attribution and replay at
 * once. */
enum nfsp_delta_backend {
	NFSP_DELTA_BACKEND_KNFSD = 0,
	NFSP_DELTA_BACKEND_GANESHA = 1
};

#define NFSP_DELTA_MATCH_ANY	0xffffffffu	/* match_index: every match */
#define NFSP_DELTA_OPCODE_ANY	0xffffffffu

struct nfsp_rule {
	uint32_t	dir;		/* enum nfsp_delta_dir */
	uint32_t	backend;	/* enum nfsp_delta_backend */
	uint32_t	client;		/* 0 or 1 */
	uint32_t	first_opcode;	/* NFSP_DELTA_OPCODE_ANY to ignore */
	uint32_t	match_index;	/* index or NFSP_DELTA_MATCH_ANY */
	uint32_t	anchor_off;	/* from message start */
	uint32_t	anchor_len;	/* 0 = no anchor */
	uint32_t	patch_off;	/* from message start */
	uint32_t	patch_w;	/* 1..NFSP_DELTA_PATCH_MAX */
	uint32_t	applied_count;	/* how often it applied when produced */
	uint8_t		anchor[NFSP_DELTA_ANCHOR_MAX];
	uint8_t		orig[NFSP_DELTA_PATCH_MAX];
	uint8_t		repl[NFSP_DELTA_PATCH_MAX];
};

/* What the proxy knows about a message when deciding whether a rule applies. */
struct nfsp_msg_ctx {
	uint32_t	dir;
	uint32_t	backend;
	uint32_t	client;
	uint32_t	first_opcode;	/* NFSP_DELTA_OPCODE_ANY if unknown */
};

/* Outcome counters for one rule over one trial.  Kept separate per outcome
 * because collapsing them would hide the distinction replay exists to make. */
struct nfsp_apply_stats {
	uint32_t	predicate_hits;		/* matched the predicate */
	uint32_t	applied;		/* actually patched */
	uint32_t	refused_orig_diff;	/* right offsets, wrong bytes */
	uint32_t	refused_out_of_range;	/* patch would leave the message */
	uint32_t	skipped_match_index;	/* match_index filtered it out */
};

/* Apply `r` to buf[0..len).
 *
 * Returns 1 when the rule applied (buf was modified), 0 when it did not apply
 * (buf untouched), -1 only if `st` or `r` is NULL.
 *
 * This is the single implementation shared by the produce path and the replay
 * path.  Both call it; nothing else patches bytes.
 *
 * The verify-before-patch step is not optional and not a debug build feature:
 * patching unverified bytes is how a replay silently mutates a different
 * message and reports a reproduction failure that never happened. */
int nfsp_apply_rule(const struct nfsp_rule *r, const struct nfsp_msg_ctx *ctx,
		    uint8_t *buf, size_t len, struct nfsp_apply_stats *st);

int nfsp_rule_valid(const struct nfsp_rule *r);

/* ---- writer -------------------------------------------------------------
 *
 * Records are appended and made durable one at a time with O_SYNC.  A kernel
 * oops takes the proxy's buffered state with it, so the last mutation before a
 * crash is exactly the record that must survive.  Mutations are rare relative
 * to total RPCs, so per-record durability is cheap.
 */
struct nfsp_delta_writer;

int nfsp_delta_write_open(struct nfsp_delta_writer **out, const char *path,
			  uint64_t seed);
int nfsp_delta_write_rule(struct nfsp_delta_writer *w,
			  const struct nfsp_rule *r);
/* Persist the observed application count in an already-written record.
 * O_SYNC makes a crash between two matches leave the last completed count.
 * index is zero-based, in the same order as write_rule calls. */
int nfsp_delta_write_applied_count(struct nfsp_delta_writer *w,
				   long index, uint32_t applied_count);
/* Flush and close.  Returns the number of records written, or -1. */
long nfsp_delta_write_close(struct nfsp_delta_writer *w);
long nfsp_delta_write_count(const struct nfsp_delta_writer *w);

/* ---- reader ------------------------------------------------------------- */

struct nfsp_delta_reader;

int nfsp_delta_read_open(struct nfsp_delta_reader **out, const char *path);
uint64_t nfsp_delta_reader_seed(const struct nfsp_delta_reader *r);
/* 1 = a rule was read, 0 = end of file, -1 = corrupt. */
int nfsp_delta_read_rule(struct nfsp_delta_reader *r, struct nfsp_rule *out);
void nfsp_delta_read_close(struct nfsp_delta_reader *r);

const char *nfsp_delta_strerror(int code);

#endif /* NFSP_DELTA_H */
