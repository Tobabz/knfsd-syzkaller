/* Structural walk of an NFSv4 RPC message: where the fields are, and where we
 * are NOT entitled to claim anything.
 *
 * THE PROBLEM
 *
 *   XDR structs are not self-describing.  A COMPOUND's op array is a count
 *   followed by ops, and without a per-op schema there is no way to know where
 *   op N's arguments end and op N+1 begins.  A walker that guesses would place
 *   mutations at wrong offsets, and a wrong offset inside a stateid or a length
 *   field produces exactly the class of failure this project keeps paying for:
 *   a defect that reports itself as an NFS protocol error.
 *
 * THE ANSWER: CLAIM ONLY WHAT THE RFC DEFINES
 *
 *   Certain layer  -- the RPC message header (RFC 5531) and the COMPOUND header
 *                     (RFC 5661) are fully specified, so every field there is
 *                     emitted as a typed slot with an exact offset.
 *
 *   Raw layer      -- everything after the COMPOUND header is emitted as
 *                     REGIONS: (offset, length) spans whose internal structure
 *                     is explicitly unknown.  A caller may address any byte
 *                     inside a region by offset, which is what makes mutation
 *                     general-purpose without any NFS schema.  The walker
 *                     claims nothing about those bytes and therefore cannot
 *                     mis-locate anything.
 *
 *   Schema layer   -- NOT here.  Per-op field tables are a later addition, and
 *                     they attach to a region rather than replacing it.
 *
 * WHY REGIONS AND NOT ONE SLOT PER WORD
 *
 *   A 16 MiB message contains four million aligned words.  Materialising a slot
 *   per word would make the walk allocate in proportion to hostile input, which
 *   is how an instrument becomes the bug it was meant to observe.  Regions keep
 *   the output size proportional to the message's *structure* (a handful), and
 *   the caller addresses within them arithmetically.
 *
 * WHAT IS VERIFIED AND WHAT IS NOT
 *
 *   The offsets here are read from RFC 5531 and RFC 5661 and are asserted by
 *   tests built from the same reading.  That is a real limitation and it is
 *   stated rather than hidden: a shared misreading of the RFC would pass both
 *   the walker and its tests.  The mitigation is that this walker is also
 *   exercised against messages captured from a live lane as soon as one exists;
 *   until then the structural invariants (bounds, ordering, exact end-of-header
 *   offsets) are what the tests can honestly guarantee.
 */
#ifndef NFSP_WALK_H
#define NFSP_WALK_H

#include <stddef.h>
#include <stdint.h>

/* Program and procedure numbers that identify an NFSv4 COMPOUND. */
#define NFSP_PROG_NFS		100003u
#define NFSP_PROC4_COMPOUND	1u
#define NFSP_RPCVERS		2u
#define NFSP_NFS_V4		4u

/* RPC message types (RFC 5531). */
#define NFSP_MSGTYPE_CALL	0u
#define NFSP_MSGTYPE_REPLY	1u
/* reply_stat */
#define NFSP_MSGP_ACCEPTED	0u
/* accept_stat */
#define NFSP_MSGS_ACCEPTED	0u

enum nfsp_walk_status {
	NFSP_WALK_OK = 0,
	NFSP_WALK_TRUNCATED,	/* input ended inside a declared field */
	NFSP_WALK_BAD_MTYPE,	/* neither CALL nor REPLY */
	NFSP_WALK_BAD_RPCVERS,	/* rpcvers != 2 on a CALL */
	NFSP_WALK_BAD_REPLY_STAT,	/* reply_stat is not a value we know */
	NFSP_WALK_BAD_AUTH_LEN,	/* opaque_auth length overflows the message */
	NFSP_WALK_BAD_TAG_LEN,	/* compound tag length overflows the message */
	NFSP_WALK_BAD_OPCOUNT,	/* op count cannot fit in the remaining bytes */
	NFSP_WALK_NOMEM
};

enum nfsp_slot_role {
	NFSP_SR_NONE = 0,
	/* RPC header */
	NFSP_SR_XID,
	NFSP_SR_MTYPE,
	NFSP_SR_RPCVERS,
	NFSP_SR_PROG,
	NFSP_SR_VERS,
	NFSP_SR_PROC,
	NFSP_SR_CRED_FLAVOR,
	NFSP_SR_CRED_LEN,
	NFSP_SR_VERF_FLAVOR,
	NFSP_SR_VERF_LEN,
	NFSP_SR_REPLY_STAT,
	NFSP_SR_ACCEPT_STAT,
	/* COMPOUND header */
	NFSP_SR_TAG_LEN,
	NFSP_SR_MINORVERSION,
	NFSP_SR_OPCOUNT,	/* argarray<> or resarray<> count */
	NFSP_SR_NFS_STATUS,	/* COMPOUND4res status, replies only */
	/* The first word of the op array body.  This is the only op-array byte
	 * whose meaning is certain, because op[0] starts where the header ends. */
	NFSP_SR_FIRST_OPCODE
};

struct nfsp_slot {
	uint32_t	offset;	/* from the start of the message */
	uint32_t	role;	/* enum nfsp_slot_role */
};

enum nfsp_region_role {
	NFSP_RR_NONE = 0,
	NFSP_RR_CRED_BODY,	/* opaque_auth body, padded */
	NFSP_RR_VERF_BODY,	/* opaque_auth body, padded */
	NFSP_RR_TAG_BODY,	/* utf8str_cs body, padded */
	NFSP_RR_OP_BODY,	/* op array body; internal structure UNKNOWN */
	NFSP_RR_TRAILER		/* bytes after everything we understood */
};

struct nfsp_region {
	uint32_t	offset;
	uint32_t	len;
	uint32_t	role;	/* enum nfsp_region_role */
};

#define NFSP_WALK_MAX_SLOTS	64u
#define NFSP_WALK_MAX_REGIONS	16u

struct nfsp_walk {
	enum nfsp_walk_status	status;
	/* certain fields */
	struct nfsp_slot	slots[NFSP_WALK_MAX_SLOTS];
	size_t			nslots;
	/* spans whose structure is unknown */
	struct nfsp_region	regions[NFSP_WALK_MAX_REGIONS];
	size_t			nregions;

	/* summary, valid as far as `status` allowed */
	int			is_call;
	uint32_t		xid;
	uint32_t		prog;
	uint32_t		vers;
	uint32_t		proc;
	uint32_t		opcount;
	uint32_t		nfs_status;	/* replies only */
	uint32_t		minorversion;
	size_t			msg_len;
	size_t			header_end;	/* bytes up to the op array body */
	/* how far the walk got before it stopped, for diagnosis */
	size_t			stopped_at;
};

/* Walk `buf[0..len)` as one complete RPC message.
 *
 * `len` must be the exact message length as produced by nfsp_framing_peek's
 * *msglen, INCLUDING fragment headers: the offsets in the result are absolute
 * within the message so that a mutator can patch the buffer directly without
 * translating anything.  Note that the fragment headers are therefore inside
 * `header_end`'s coordinate space but before all slots; the RPC body begins
 * after them.
 *
 * Always returns 0.  A message the walker cannot fully understand yields
 * status != NFSP_WALK_OK plus whatever prefix was certain, and the caller is
 * expected to pass the bytes through untouched rather than guess. */
int nfsp_walk(const uint8_t *buf, size_t len, struct nfsp_walk *out);

const char *nfsp_walk_strerror(enum nfsp_walk_status status);
const char *nfsp_walk_role_name(uint32_t role);
const char *nfsp_walk_region_name(uint32_t role);

/* Look up a certain slot by role.  Returns NULL when the message did not have
 * that field (an early stop), which callers must treat as "not available"
 * rather than as an error. */
const struct nfsp_slot *nfsp_walk_find(const struct nfsp_walk *w, uint32_t role);

#endif /* NFSP_WALK_H */
