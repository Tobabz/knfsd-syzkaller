/* NFS/RPC over TCP record-marking reassembly (RFC 5531 section 11).
 *
 * WHY THIS EXISTS
 *
 *   Every byte the proxy handles arrives as a TCP stream, but the unit it must
 *   reason about is the RPC message.  One message is one "record", and a record
 *   is one or more fragments:
 *
 *     +-------------------------------+-------------------------------+
 *     |  4-byte fragment header       |  fragment body                |
 *     |  bit31 = last fragment        |  (length bytes)               |
 *     |  bits30..0 = body length      |                               |
 *     +-------------------------------+-------------------------------+
 *
 *   A message may be split across several fragments, and those fragments may
 *   arrive split across any number of read() calls.  Getting this wrong is not
 *   a cosmetic bug: mis-framing means the proxy hands the kernel or the server a
 *   byte stream that is shifted by some amount, which produces errors that look
 *   like NFS protocol errors rather than like a proxy bug.  That is exactly the
 *   failure mode this project keeps paying for -- a defect that reports itself
 *   as something else.  So it is a separate, pure, heavily tested unit.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 *   No NFS semantics.  No XDR.  No knowledge of what any byte means beyond the
 *   four-byte record header.  Those layers sit above this one and are allowed to
 *   give up and pass bytes through; this layer may not, because without correct
 *   framing there is no message to pass through.
 *
 * HARDENING
 *
 *   A proxy is fed by a fuzzer, so this code is on the receiving end of
 *   deliberately hostile input.  The three hazards are unbounded allocation, an
 *   infinite loop, and a silent truncation, so:
 *     - a fragment longer than the configured limit is an error, not a malloc
 *     - a zero-length fragment that is not the last is an error, not a no-op
 *       (zero-length non-final fragments would let a peer spin this forever)
 *     - running out of bytes is "need more", never a partial message
 *   Errors are reported, never absorbed.  A message that cannot be framed is a
 *   hard failure of the connection, because continuing would mean guessing at
 *   message boundaries.
 */
#ifndef NFSP_FRAMING_H
#define NFSP_FRAMING_H

#include <stddef.h>
#include <stdint.h>

/* Errors are enumerated so tests can assert on the specific reason rather than
 * on "it failed", which is the difference between a useful test and a smoke
 * test. */
enum nfsp_framing_err {
	NFSP_FRAMING_OK = 0,
	NFSP_FRAMING_NEED_MORE,		/* not an error: incomplete input */
	NFSP_FRAMING_ERR_FRAG_LEN,	/* fragment longer than the limit */
	NFSP_FRAMING_ERR_ZERO_FRAG,	/* zero-length fragment, not last */
	NFSP_FRAMING_ERR_MSG_LEN,	/* accumulated message over the limit */
	NFSP_FRAMING_ERR_FRAG_COUNT,	/* too many fragments in one message */
	NFSP_FRAMING_ERR_NOMEM
};

#define NFSP_FRAG_HEADER_LEN	4
#define NFSP_LAST_FRAGMENT	0x80000000u
#define NFSP_FRAG_LEN_MASK	0x7fffffffu

/* 16 MiB per message.  NFS RPCs are far smaller; the cap exists so a hostile
 * stream cannot make the proxy allocate without bound. */
#define NFSP_MSG_LIMIT_DEFAULT	(16u * 1024u * 1024u)
/* A pathological peer could otherwise send an endless run of tiny fragments. */
#define NFSP_FRAG_COUNT_LIMIT	4096u

struct nfsp_framing {
	uint8_t *buf;
	size_t cap;		/* allocated bytes */
	size_t len;		/* bytes currently buffered */
	size_t limit;		/* max accepted message size */
	enum nfsp_framing_err err;	/* sticky reason for the last failure */
};

int nfsp_framing_init(struct nfsp_framing *f, size_t limit);
void nfsp_framing_free(struct nfsp_framing *f);
void nfsp_framing_reset(struct nfsp_framing *f);

/* Append received bytes.  Returns 0, or -1 with f->err set. */
int nfsp_framing_append(struct nfsp_framing *f, const uint8_t *p, size_t n);

/* Inspect the front of the buffer.
 *
 *   1 -> a complete message occupies [0, *msglen); *nfrags is its fragment
 *        count and *msg_frags_len is the bytes consumed by fragment headers
 *        (so callers can compute the payload size without re-walking).
 *   0 -> incomplete; the three out-parameters are set to 0.
 *  -1 -> protocol error; f->err names it.  The connection must be dropped.
 *
 * The returned length includes the fragment headers, because the proxy must be
 * able to re-emit the message byte-for-byte.  Recording or forwarding a
 * re-serialised message would mean the proxy had rewritten the wire, and this
 * proxy is required never to do that.
 *
 * Takes a non-const pointer because an error is recorded in f->err: tests
 * assert on the specific reason, and the caller must be able to log it. */
int nfsp_framing_peek(struct nfsp_framing *f, size_t *msglen, size_t *nfrags,
		      size_t *msg_frags_len);

/* Drop the first n bytes, which must not exceed f->len. */
void nfsp_framing_consume(struct nfsp_framing *f, size_t n);

const char *nfsp_framing_strerror(enum nfsp_framing_err err);

#endif /* NFSP_FRAMING_H */
