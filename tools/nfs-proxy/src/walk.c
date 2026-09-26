#include "walk.h"

#include <string.h>

#define U32_AT(p) (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) |           \
		   ((uint32_t)(p)[2] << 8) | (uint32_t)(p)[3])

/* A bounds-checked cursor over the message.  Every read either advances past a
 * fully present field or marks the cursor failed; there is no path that reads
 * partially or past the end. */
struct cur {
	const uint8_t	*buf;
	size_t		 len;
	size_t		 off;
	int		 ok;
};

static void cur_init(struct cur *c, const uint8_t *buf, size_t len)
{
	c->buf = buf;
	c->len = len;
	c->off = 0;
	c->ok = 1;
}

static uint32_t cur_u32(struct cur *c)
{
	if (!c->ok || c->len - c->off < 4) {
		c->ok = 0;
		return 0;
	}
	{
		uint32_t v = U32_AT(c->buf + c->off);
		c->off += 4;
		return v;
	}
}

/* XDR pads variable-length data to a 4-byte boundary.  A declared length that
 * cannot be rounded up without overflowing is a hostile input, not a wrap. */
static int cur_skip_padded(struct cur *c, uint32_t n, size_t *body_off,
			   size_t *body_len)
{
	size_t padded;

	if (!c->ok)
		return -1;
	if (n > (uint32_t)-1 - 3u) {
		c->ok = 0;
		return -1;
	}
	padded = ((size_t)n + 3u) & ~(size_t)3u;
	if (padded > c->len - c->off) {
		c->ok = 0;
		return -1;
	}
	if (body_off != NULL)
		*body_off = c->off;
	if (body_len != NULL)
		*body_len = n;
	c->off += padded;
	return 0;
}

/* A slot must address four bytes that are actually present, and a region must
 * lie inside the message.
 *
 * WHY THE GUARD IS HERE AND NOT AT EVERY CALL SITE
 *
 *   The first version read a field, recorded the slot, and only then checked
 *   whether the read had succeeded.  A failed read does not advance the cursor,
 *   so a truncated message produced slots whose offsets sat at or past its end
 *   -- and a mutation applied at such an offset writes outside the buffer.  The
 *   truncation sweep in the tests caught it: 26 failures such as
 *   "slot 5 (proc) at 24+4 exceeds msg len 24".
 *
 *   Fixing the eight call sites would have worked and would have left the next
 *   call site free to reintroduce it.  Enforcing the invariant where the slot is
 *   created makes the invalid state unrepresentable instead: no matter what
 *   order a caller does things in, a slot outside the message cannot be
 *   recorded.  msg_len is set before any slot is emitted, so it is always valid
 *   here.
 *
 *   This is a silent drop rather than an error on purpose.  The caller learns
 *   the message was not fully understood from `status`, and a walk never claims
 *   a field it did not see. */
static void add_slot(struct nfsp_walk *w, size_t off, uint32_t role)
{
	if (off + 4u > w->msg_len)
		return;
	if (w->nslots >= NFSP_WALK_MAX_SLOTS)
		return;		/* overflow is not silently wrong: see header_end */
	w->slots[w->nslots].offset = (uint32_t)off;
	w->slots[w->nslots].role = role;
	w->nslots++;
}

static void add_region(struct nfsp_walk *w, size_t off, size_t len, uint32_t role)
{
	if (len == 0)
		return;
	if (off > w->msg_len || len > w->msg_len - off)
		return;
	if (w->nregions >= NFSP_WALK_MAX_REGIONS)
		return;
	w->regions[w->nregions].offset = (uint32_t)off;
	w->regions[w->nregions].len = (uint32_t)len;
	w->regions[w->nregions].role = role;
	w->nregions++;
}

/* Consume an opaque_auth: u32 flavour, u32 length, padded body.  Emits the two
 * certain words; the body becomes a region. */
static int walk_auth(struct cur *c, struct nfsp_walk *w, uint32_t flavor_role,
		     uint32_t len_role, uint32_t region_role)
{
	size_t flav_off = c->off;
	size_t len_off, body_off, body_len;
	uint32_t len;

	(void)cur_u32(c);			/* flavour */
	if (!c->ok)
		return -1;
	add_slot(w, flav_off, flavor_role);

	len_off = c->off;
	len = cur_u32(c);
	if (!c->ok)
		return -1;
	add_slot(w, len_off, len_role);

	if (cur_skip_padded(c, len, &body_off, &body_len) != 0)
		return -1;
	add_region(w, body_off, body_len, region_role);
	return 0;
}

/* The COMPOUND header, shared by args and results except for the leading
 * nfsstat4 on the reply side. */
static int walk_compound(struct cur *c, int reply, struct nfsp_walk *out)
{
	size_t tag_len_off, body_off, body_len, minor_off, count_off;
	uint32_t tag_len, opcount;

	if (reply) {
		size_t st_off = c->off;
		uint32_t st = cur_u32(c);

		if (!c->ok)
			return -1;
		add_slot(out, st_off, NFSP_SR_NFS_STATUS);
		out->nfs_status = st;
	}

	tag_len_off = c->off;
	tag_len = cur_u32(c);
	if (!c->ok)
		return -1;
	add_slot(out, tag_len_off, NFSP_SR_TAG_LEN);
	if (cur_skip_padded(c, tag_len, &body_off, &body_len) != 0)
		return -1;
	add_region(out, body_off, body_len, NFSP_RR_TAG_BODY);

	if (!reply) {
		minor_off = c->off;
		out->minorversion = cur_u32(c);
		if (!c->ok)
			return -1;
		add_slot(out, minor_off, NFSP_SR_MINORVERSION);
	}

	count_off = c->off;
	opcount = cur_u32(c);
	if (!c->ok)
		return -1;
	add_slot(out, count_off, NFSP_SR_OPCOUNT);
	out->opcount = opcount;

	/* An op is at minimum one u32 (the opcode), so a count larger than the
	 * remaining words cannot be honest.  Rejecting it here keeps a hostile
	 * count from driving any later per-op work. */
	if ((size_t)opcount > (c->len - c->off) / 4u)
		return -2;

	out->header_end = c->off;

	/* The only op-array byte with a certain meaning: op[0] begins here. */
	if ((size_t)opcount > 0 && c->len - c->off >= 4u)
		add_slot(out, c->off, NFSP_SR_FIRST_OPCODE);

	add_region(out, c->off, c->len - c->off, NFSP_RR_OP_BODY);
	return 0;
}

int nfsp_walk(const uint8_t *buf, size_t len, struct nfsp_walk *out)
{
	struct cur c;
	size_t body_begin;
	int rc;

	if (out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));
	out->status = NFSP_WALK_OK;
	out->is_call = -1;
	if (buf == NULL) {
		out->status = NFSP_WALK_TRUNCATED;
		return 0;
	}
	out->msg_len = len;

	cur_init(&c, buf, len);

	/* Skip the fragment header: it is transport framing, not RPC.  A caller
	 * hands us the whole message including it so that offsets in the result
	 * can be used to patch the buffer directly.
	 *
	 * A fragmented RPC (more than one fragment in the record) is refused
	 * outright rather than handled.  Handling it would mean a mutation could
	 * land on a fragment header instead of on RPC bytes, and the offsets in
	 * the result would no longer mean what they say.  Refusing is the honest
	 * answer: the caller passes the message through untouched. */
	if (len < 4) {
		out->status = NFSP_WALK_TRUNCATED;
		out->stopped_at = 0;
		return 0;
	}
	if ((U32_AT(buf) & 0x80000000u) == 0) {
		out->status = NFSP_WALK_TRUNCATED;
		out->stopped_at = 0;
		return 0;
	}
	c.off = 4;

	/* --- RPC header (RFC 5531) --- */
	{
		size_t xid_off = c.off;
		out->xid = cur_u32(&c);
		if (!c.ok) {
			out->status = NFSP_WALK_TRUNCATED;
			out->stopped_at = c.off;
			return 0;
		}
		add_slot(out, xid_off, NFSP_SR_XID);
	}
	{
		size_t mt_off = c.off;
		uint32_t mtype = cur_u32(&c);

		if (!c.ok) {
			out->status = NFSP_WALK_TRUNCATED;
			out->stopped_at = c.off;
			return 0;
		}
		add_slot(out, mt_off, NFSP_SR_MTYPE);
		if (mtype != NFSP_MSGTYPE_CALL && mtype != NFSP_MSGTYPE_REPLY) {
			out->status = NFSP_WALK_BAD_MTYPE;
			out->stopped_at = c.off;
			return 0;
		}
		out->is_call = (mtype == NFSP_MSGTYPE_CALL);
	}

	if (out->is_call) {
		size_t off;

		off = c.off;
		if (cur_u32(&c) != NFSP_RPCVERS) {
			out->status = c.ok ? NFSP_WALK_BAD_RPCVERS
					   : NFSP_WALK_TRUNCATED;
			out->stopped_at = c.off;
			return 0;
		}
		add_slot(out, off, NFSP_SR_RPCVERS);

		off = c.off;
		out->prog = cur_u32(&c);
		add_slot(out, off, NFSP_SR_PROG);
		off = c.off;
		out->vers = cur_u32(&c);
		add_slot(out, off, NFSP_SR_VERS);
		off = c.off;
		out->proc = cur_u32(&c);
		add_slot(out, off, NFSP_SR_PROC);
		if (!c.ok) {
			out->status = NFSP_WALK_TRUNCATED;
			out->stopped_at = c.off;
			return 0;
		}

		if (walk_auth(&c, out, NFSP_SR_CRED_FLAVOR, NFSP_SR_CRED_LEN,
			      NFSP_RR_CRED_BODY) != 0) {
			out->status = NFSP_WALK_BAD_AUTH_LEN;
			out->stopped_at = c.off;
			return 0;
		}
		if (walk_auth(&c, out, NFSP_SR_VERF_FLAVOR, NFSP_SR_VERF_LEN,
			      NFSP_RR_VERF_BODY) != 0) {
			out->status = NFSP_WALK_BAD_AUTH_LEN;
			out->stopped_at = c.off;
			return 0;
		}

		body_begin = c.off;
		if (out->vers == NFSP_NFS_V4 && out->proc == NFSP_PROC4_COMPOUND) {
			rc = walk_compound(&c, 0, out);
			if (rc == -2) {
				out->status = NFSP_WALK_BAD_OPCOUNT;
				out->stopped_at = c.off;
				return 0;
			}
			if (rc != 0) {
				out->status = (c.ok ? NFSP_WALK_BAD_TAG_LEN
						    : NFSP_WALK_TRUNCATED);
				out->stopped_at = c.off;
				return 0;
			}
		} else {
			/* Not a v4 COMPOUND: the header is certain, the rest
			 * is not, and saying so is the whole point. */
			add_region(out, body_begin, c.len - body_begin,
				   NFSP_RR_TRAILER);
			out->header_end = body_begin;
		}
	} else {
		size_t off = c.off;
		uint32_t reply_stat = cur_u32(&c);

		if (!c.ok) {
			out->status = NFSP_WALK_TRUNCATED;
			out->stopped_at = c.off;
			return 0;
		}
		add_slot(out, off, NFSP_SR_REPLY_STAT);
		if (reply_stat != NFSP_MSGP_ACCEPTED) {
			/* DENIED / RPC_MISMATCH / AUTH_ERROR: no COMPOUND inside,
			 * and the layout after this word depends on which.  Stop
			 * at what is certain. */
			add_region(out, c.off, c.len - c.off, NFSP_RR_TRAILER);
			out->header_end = c.off;
			return 0;
		}
		if (walk_auth(&c, out, NFSP_SR_VERF_FLAVOR, NFSP_SR_VERF_LEN,
			      NFSP_RR_VERF_BODY) != 0) {
			out->status = NFSP_WALK_BAD_AUTH_LEN;
			out->stopped_at = c.off;
			return 0;
		}
		off = c.off;
		{
			uint32_t accept_stat = cur_u32(&c);

			if (!c.ok) {
				out->status = NFSP_WALK_TRUNCATED;
				out->stopped_at = c.off;
				return 0;
			}
			add_slot(out, off, NFSP_SR_ACCEPT_STAT);
			if (accept_stat != NFSP_MSGS_ACCEPTED) {
				add_region(out, c.off, c.len - c.off,
					   NFSP_RR_TRAILER);
				out->header_end = c.off;
				return 0;
			}
		}
		body_begin = c.off;
		rc = walk_compound(&c, 1, out);
		if (rc == -2) {
			out->status = NFSP_WALK_BAD_OPCOUNT;
			out->stopped_at = c.off;
			return 0;
		}
		if (rc != 0) {
			out->status = (c.ok ? NFSP_WALK_BAD_TAG_LEN
					    : NFSP_WALK_TRUNCATED);
			out->stopped_at = c.off;
			return 0;
		}
	}

	return 0;
}

const struct nfsp_slot *nfsp_walk_find(const struct nfsp_walk *w, uint32_t role)
{
	size_t i;

	if (w == NULL)
		return NULL;
	for (i = 0; i < w->nslots; i++)
		if (w->slots[i].role == role)
			return &w->slots[i];
	return NULL;
}

const char *nfsp_walk_strerror(enum nfsp_walk_status status)
{
	switch (status) {
	case NFSP_WALK_OK:
		return "ok";
	case NFSP_WALK_TRUNCATED:
		return "input ended inside a declared field";
	case NFSP_WALK_BAD_MTYPE:
		return "rpc message type is neither CALL nor REPLY";
	case NFSP_WALK_BAD_RPCVERS:
		return "CALL with rpcvers != 2";
	case NFSP_WALK_BAD_REPLY_STAT:
		return "unrecognised reply_stat";
	case NFSP_WALK_BAD_AUTH_LEN:
		return "opaque_auth length overflows the message";
	case NFSP_WALK_BAD_TAG_LEN:
		return "compound tag length overflows the message";
	case NFSP_WALK_BAD_OPCOUNT:
		return "op count cannot fit in the remaining bytes";
	case NFSP_WALK_NOMEM:
		return "out of memory";
	}
	return "unknown walk status";
}

const char *nfsp_walk_role_name(uint32_t role)
{
	switch (role) {
	case NFSP_SR_NONE:		return "none";
	case NFSP_SR_XID:		return "xid";
	case NFSP_SR_MTYPE:		return "mtype";
	case NFSP_SR_RPCVERS:		return "rpcvers";
	case NFSP_SR_PROG:		return "prog";
	case NFSP_SR_VERS:		return "vers";
	case NFSP_SR_PROC:		return "proc";
	case NFSP_SR_CRED_FLAVOR:	return "cred_flavor";
	case NFSP_SR_CRED_LEN:		return "cred_len";
	case NFSP_SR_VERF_FLAVOR:	return "verf_flavor";
	case NFSP_SR_VERF_LEN:		return "verf_len";
	case NFSP_SR_REPLY_STAT:	return "reply_stat";
	case NFSP_SR_ACCEPT_STAT:	return "accept_stat";
	case NFSP_SR_TAG_LEN:		return "tag_len";
	case NFSP_SR_MINORVERSION:	return "minorversion";
	case NFSP_SR_OPCOUNT:		return "opcount";
	case NFSP_SR_NFS_STATUS:	return "nfs_status";
	case NFSP_SR_FIRST_OPCODE:	return "first_opcode";
	}
	return "?";
}

const char *nfsp_walk_region_name(uint32_t role)
{
	switch (role) {
	case NFSP_RR_NONE:		return "none";
	case NFSP_RR_CRED_BODY:		return "cred_body";
	case NFSP_RR_VERF_BODY:		return "verf_body";
	case NFSP_RR_TAG_BODY:		return "tag_body";
	case NFSP_RR_OP_BODY:		return "op_body";
	case NFSP_RR_TRAILER:		return "trailer";
	}
	return "?";
}
