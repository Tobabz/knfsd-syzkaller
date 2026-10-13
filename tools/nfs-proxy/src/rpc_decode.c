#include "rpc_decode.h"

#include <string.h>

/* A bounds-checked cursor, the same discipline as walk.c's: every read either
 * consumes a fully present field or fails the cursor, and a failed cursor
 * never advances.  It is duplicated rather than shared so that the legacy
 * walk, which is a regression baseline, does not change under M1. */
struct cur {
	const uint8_t *buf;
	size_t len;
	size_t off;
	int ok;
};

static uint32_t cur_u32(struct cur *c)
{
	const uint8_t *p;

	if (!c->ok || c->len - c->off < 4u) {
		c->ok = 0;
		return 0;
	}
	p = c->buf + c->off;
	c->off += 4u;
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static struct nfsp_span span(size_t off, size_t len)
{
	struct nfsp_span s;

	s.off = (uint32_t)off;
	s.len = (uint32_t)len;
	return s;
}

/* opaque_auth.  The length is checked against the RFC maximum before it is
 * used for anything, so a hostile length never reaches the padding
 * arithmetic.  Returns the failure status, or NFSP_RPC_OK. */
static enum nfsp_rpc_status read_auth(struct cur *c, struct nfsp_rpc_auth *a)
{
	size_t start = c->off, padded;
	uint32_t n;

	a->flavor = cur_u32(c);
	n = cur_u32(c);
	if (!c->ok)
		return NFSP_RPC_TRUNCATED;
	if (n > NFSP_RPC_MAX_AUTH_BYTES)
		return NFSP_RPC_BAD_AUTH_LEN;
	padded = ((size_t)n + 3u) & ~(size_t)3u;
	if (padded > c->len - c->off)
		return NFSP_RPC_TRUNCATED;
	a->body = span(c->off, n);
	c->off += padded;
	a->encoded = span(start, c->off - start);
	return NFSP_RPC_OK;
}

static enum nfsp_rpc_status stop(struct nfsp_rpc_envelope *out,
				 const struct cur *c, enum nfsp_rpc_status st)
{
	out->status = st;
	out->stopped_at = (uint32_t)c->off;
	return st;
}

static enum nfsp_rpc_status decode_call(struct cur *c,
					struct nfsp_rpc_envelope *out)
{
	enum nfsp_rpc_status st;

	out->rpcvers = cur_u32(c);
	if (!c->ok)
		return stop(out, c, NFSP_RPC_TRUNCATED);
	if (out->rpcvers != NFSP_RPC_VERSION)
		return stop(out, c, NFSP_RPC_BAD_RPCVERS);
	out->prog = cur_u32(c);
	out->vers = cur_u32(c);
	out->proc = cur_u32(c);
	if (!c->ok)
		return stop(out, c, NFSP_RPC_TRUNCATED);
	st = read_auth(c, &out->cred);
	if (st != NFSP_RPC_OK)
		return stop(out, c, st);
	st = read_auth(c, &out->verf);
	if (st != NFSP_RPC_OK)
		return stop(out, c, st);
	return NFSP_RPC_OK;
}

static enum nfsp_rpc_status read_mismatch(struct cur *c,
					  struct nfsp_rpc_envelope *out)
{
	out->mismatch_low = cur_u32(c);
	out->mismatch_high = cur_u32(c);
	if (!c->ok)
		return stop(out, c, NFSP_RPC_TRUNCATED);
	return NFSP_RPC_OK;
}

static enum nfsp_rpc_status decode_reply(struct cur *c,
					 struct nfsp_rpc_envelope *out)
{
	enum nfsp_rpc_status st;

	out->reply_stat = cur_u32(c);
	if (!c->ok)
		return stop(out, c, NFSP_RPC_TRUNCATED);

	if (out->reply_stat == NFSP_RPC_MSG_ACCEPTED) {
		st = read_auth(c, &out->verf);
		if (st != NFSP_RPC_OK)
			return stop(out, c, st);
		out->accept_stat = cur_u32(c);
		if (!c->ok)
			return stop(out, c, NFSP_RPC_TRUNCATED);
		switch (out->accept_stat) {
		case NFSP_RPC_PROG_MISMATCH:
			return read_mismatch(c, out);
		case NFSP_RPC_SUCCESS:
		case NFSP_RPC_PROG_UNAVAIL:
		case NFSP_RPC_PROC_UNAVAIL:
		case NFSP_RPC_GARBAGE_ARGS:
		case NFSP_RPC_SYSTEM_ERR:
			return NFSP_RPC_OK;
		default:
			return stop(out, c, NFSP_RPC_BAD_ACCEPT_STAT);
		}
	}

	if (out->reply_stat == NFSP_RPC_MSG_DENIED) {
		out->reject_stat = cur_u32(c);
		if (!c->ok)
			return stop(out, c, NFSP_RPC_TRUNCATED);
		switch (out->reject_stat) {
		case NFSP_RPC_RPC_MISMATCH:
			return read_mismatch(c, out);
		case NFSP_RPC_AUTH_ERROR:
			out->auth_stat = cur_u32(c);
			if (!c->ok)
				return stop(out, c, NFSP_RPC_TRUNCATED);
			return NFSP_RPC_OK;
		default:
			return stop(out, c, NFSP_RPC_BAD_REJECT_STAT);
		}
	}

	return stop(out, c, NFSP_RPC_BAD_REPLY_STAT);
}

enum nfsp_rpc_status nfsp_rpc_decode(const uint8_t *payload, size_t len,
				     struct nfsp_rpc_envelope *out)
{
	struct cur c;
	enum nfsp_rpc_status st;

	memset(out, 0, sizeof(*out));
	c.buf = payload;
	c.len = len;
	c.off = 0;
	c.ok = 1;
	if (payload == NULL && len != 0)
		return stop(out, &c, NFSP_RPC_TRUNCATED);
	/* Spans are u32.  The relay's 16 MiB record limit keeps real input far
	 * below this; the check makes the narrowing in span() provably exact. */
	if (len > UINT32_MAX)
		return stop(out, &c, NFSP_RPC_TOO_LONG);

	out->xid = cur_u32(&c);
	out->msg_type = cur_u32(&c);
	if (!c.ok)
		return stop(out, &c, NFSP_RPC_TRUNCATED);

	if (out->msg_type == NFSP_RPC_CALL)
		st = decode_call(&c, out);
	else if (out->msg_type == NFSP_RPC_REPLY)
		st = decode_reply(&c, out);
	else
		st = stop(out, &c, NFSP_RPC_BAD_MTYPE);
	if (st != NFSP_RPC_OK)
		return st;

	out->body = span(c.off, c.len - c.off);
	out->stopped_at = (uint32_t)c.off;
	out->status = NFSP_RPC_OK;
	return NFSP_RPC_OK;
}

const char *nfsp_rpc_strerror(enum nfsp_rpc_status status)
{
	switch (status) {
	case NFSP_RPC_OK:
		return "ok";
	case NFSP_RPC_TRUNCATED:
		return "payload ends inside the RPC envelope";
	case NFSP_RPC_BAD_MTYPE:
		return "message type is neither CALL nor REPLY";
	case NFSP_RPC_BAD_RPCVERS:
		return "CALL with rpcvers != 2";
	case NFSP_RPC_BAD_AUTH_LEN:
		return "opaque_auth longer than 400 bytes";
	case NFSP_RPC_BAD_REPLY_STAT:
		return "unrecognised reply_stat";
	case NFSP_RPC_BAD_ACCEPT_STAT:
		return "unrecognised accept_stat";
	case NFSP_RPC_BAD_REJECT_STAT:
		return "unrecognised reject_stat";
	case NFSP_RPC_TOO_LONG:
		return "payload too long for u32 offsets";
	}
	return "unknown rpc decode status";
}
