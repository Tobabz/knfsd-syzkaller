/* Target RPC Decoder: the RPC envelope of one canonical rpc_payload.
 *
 * WHY THIS IS NOT walk.c
 *
 *   walk.c is the legacy Layer 0 walk.  It reads framed records (offset 0 is a
 *   fragment header), refuses fragmented ones, and folds the NFSv4 COMPOUND
 *   header into the same pass.  The target architecture (design 03-nfs-proxy/01
 *   §3, 06 §4) splits that responsibility: this decoder reads the RPC envelope
 *   only, from a marker-free rpc_payload, and stops at the procedure body.  The
 *   NFS Semantic Decoder (M2) starts where this one stops.  walk.c stays as is
 *   for NFSPARM1/2.
 *
 * WHAT IS DECODED (RFC 5531 §9)
 *
 *   CALL   xid, mtype, rpcvers(=2), prog, vers, proc, cred, verf, body
 *   REPLY  xid, mtype, reply_stat, then
 *            MSG_ACCEPTED  verf, accept_stat, [mismatch_info], body
 *            MSG_DENIED    reject_stat, mismatch_info | auth_stat, body
 *
 *   `body` is every byte after the envelope.  For a CALL and for an accepted
 *   SUCCESS reply that is the procedure's arguments or results.  For the other
 *   reply arms the RFC defines no body, and a non-empty `body` there is a fact
 *   the decoder reports rather than a judgement it makes.
 *
 *   A REPLY carries no procedure.  The decoder does not guess one; the
 *   Transaction Context (M3) supplies it from the matching CALL.
 *
 * FAIL CLOSED
 *
 *   status != NFSP_RPC_OK means nothing in the result may be used to decide
 *   meaning.  Values are filled as far as `stopped_at` for diagnosis only.
 *   Every span in an OK result lies inside the payload; that invariant is set
 *   where spans are created, not trusted from call sites.
 */
#ifndef NFSP_RPC_DECODE_H
#define NFSP_RPC_DECODE_H

#include <stddef.h>
#include <stdint.h>

/* RFC 5531 constants not already named in walk.h.  Values are the RFC's. */
#define NFSP_RPC_CALL		0u
#define NFSP_RPC_REPLY		1u
#define NFSP_RPC_VERSION	2u
#define NFSP_RPC_MAX_AUTH_BYTES	400u

enum nfsp_rpc_reply_stat {
	NFSP_RPC_MSG_ACCEPTED = 0,
	NFSP_RPC_MSG_DENIED = 1
};

enum nfsp_rpc_accept_stat {
	NFSP_RPC_SUCCESS = 0,
	NFSP_RPC_PROG_UNAVAIL = 1,
	NFSP_RPC_PROG_MISMATCH = 2,
	NFSP_RPC_PROC_UNAVAIL = 3,
	NFSP_RPC_GARBAGE_ARGS = 4,
	NFSP_RPC_SYSTEM_ERR = 5
};

enum nfsp_rpc_reject_stat {
	NFSP_RPC_RPC_MISMATCH = 0,
	NFSP_RPC_AUTH_ERROR = 1
};

/* auth_stat: AUTH_OK (0) through RPCSEC_GSS_CTXPROBLEM (14), RFC 5531 §9. */
#define NFSP_RPC_AUTH_STAT_MAX	14u

enum nfsp_rpc_status {
	NFSP_RPC_OK = 0,
	NFSP_RPC_TRUNCATED,		/* payload ends inside the envelope */
	NFSP_RPC_BAD_MTYPE,		/* neither CALL nor REPLY */
	NFSP_RPC_BAD_RPCVERS,		/* CALL rpcvers != 2 */
	NFSP_RPC_BAD_AUTH_LEN,		/* opaque_auth longer than 400 bytes */
	NFSP_RPC_BAD_REPLY_STAT,	/* reply_stat not ACCEPTED/DENIED */
	NFSP_RPC_BAD_ACCEPT_STAT,	/* accept_stat outside RFC 5531 */
	NFSP_RPC_BAD_REJECT_STAT,	/* reject_stat outside RFC 5531 */
	NFSP_RPC_BAD_AUTH_STAT,		/* auth_stat outside RFC 5531 */
	NFSP_RPC_TOO_LONG		/* payload offsets would not fit u32 */
};

/* [off, off + len) inside rpc_payload. */
struct nfsp_span {
	uint32_t off;
	uint32_t len;
};

/* opaque_auth: u32 flavor, u32 length, body padded to four bytes.
 * `encoded` is the whole encoding including padding; `body` is the opaque
 * bytes without padding. */
struct nfsp_rpc_auth {
	uint32_t flavor;
	struct nfsp_span encoded;
	struct nfsp_span body;
};

struct nfsp_rpc_envelope {
	enum nfsp_rpc_status status;
	uint32_t stopped_at;		/* payload offset where decoding stopped */

	uint32_t msg_type;		/* NFSP_RPC_CALL / NFSP_RPC_REPLY */
	uint32_t xid;

	/* CALL */
	uint32_t rpcvers, prog, vers, proc;
	struct nfsp_rpc_auth cred;

	/* CALL verifier, or the server verifier of an accepted REPLY */
	struct nfsp_rpc_auth verf;

	/* REPLY */
	uint32_t reply_stat;
	uint32_t accept_stat;		/* MSG_ACCEPTED only */
	uint32_t reject_stat;		/* MSG_DENIED only */
	uint32_t auth_stat;		/* MSG_DENIED / AUTH_ERROR only */
	uint32_t mismatch_low, mismatch_high;	/* PROG_ / RPC_MISMATCH only */

	struct nfsp_span body;
};

/* Decode the envelope of payload[0..len).  Offsets are rpc_payload
 * coordinates: 0 is the first byte of the XID, never a record marker.
 * Always fills *out; returns out->status, or NFSP_RPC_TRUNCATED for a NULL
 * payload with len != 0.  out must not be NULL. */
enum nfsp_rpc_status nfsp_rpc_decode(const uint8_t *payload, size_t len,
				     struct nfsp_rpc_envelope *out);

const char *nfsp_rpc_strerror(enum nfsp_rpc_status status);

#endif /* NFSP_RPC_DECODE_H */
