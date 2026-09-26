#include "framing.h"

#include <stdlib.h>
#include <string.h>

static uint32_t rd_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int nfsp_framing_init(struct nfsp_framing *f, size_t limit)
{
	if (f == NULL)
		return -1;
	memset(f, 0, sizeof(*f));
	f->limit = limit ? limit : NFSP_MSG_LIMIT_DEFAULT;
	return 0;
}

void nfsp_framing_free(struct nfsp_framing *f)
{
	if (f == NULL)
		return;
	free(f->buf);
	f->buf = NULL;
	f->cap = 0;
	f->len = 0;
}

void nfsp_framing_reset(struct nfsp_framing *f)
{
	if (f == NULL)
		return;
	f->len = 0;
	f->err = NFSP_FRAMING_OK;
}

/* Grow to hold at least `need` bytes.  Geometric so a stream of small reads
 * does not become quadratic copying. */
static int ensure_cap(struct nfsp_framing *f, size_t need)
{
	size_t cap;
	uint8_t *nb;

	if (need <= f->cap)
		return 0;
	cap = f->cap ? f->cap : 4096;
	while (cap < need) {
		if (cap > (size_t)-1 / 2) {
			f->err = NFSP_FRAMING_ERR_NOMEM;
			return -1;
		}
		cap *= 2;
	}
	nb = realloc(f->buf, cap);
	if (nb == NULL) {
		f->err = NFSP_FRAMING_ERR_NOMEM;
		return -1;
	}
	f->buf = nb;
	f->cap = cap;
	return 0;
}

int nfsp_framing_append(struct nfsp_framing *f, const uint8_t *p, size_t n)
{
	size_t ceiling;

	if (f == NULL || (p == NULL && n != 0))
		return -1;
	if (n == 0)
		return 0;

	/* One message is at most `limit` bytes; a stream may in principle hold a
	 * complete message plus the start of the next one.  Refuse anything
	 * beyond that, because growing without bound is how a proxy becomes the
	 * bug it was meant to observe. */
	ceiling = f->limit + NFSP_FRAG_HEADER_LEN;
	if (f->len >= ceiling) {
		f->err = NFSP_FRAMING_ERR_MSG_LEN;
		return -1;
	}
	if (n > ceiling - f->len) {
		f->err = NFSP_FRAMING_ERR_MSG_LEN;
		return -1;
	}
	if (ensure_cap(f, f->len + n) != 0)
		return -1;
	memcpy(f->buf + f->len, p, n);
	f->len += n;
	return 0;
}

int nfsp_framing_peek(struct nfsp_framing *f, size_t *msglen, size_t *nfrags,
		      size_t *msg_frags_len)
{
	size_t off = 0;
	size_t frags = 0;
	size_t hdr_bytes = 0;

	if (msglen != NULL)
		*msglen = 0;
	if (nfrags != NULL)
		*nfrags = 0;
	if (msg_frags_len != NULL)
		*msg_frags_len = 0;
	if (f == NULL)
		return -1;

	for (;;) {
		uint32_t word, body_len;

		if (f->len - off < NFSP_FRAG_HEADER_LEN)
			return 0;	/* header not fully arrived */
		word = rd_be32(f->buf + off);
		body_len = word & NFSP_FRAG_LEN_MASK;

		frags++;
		if (frags > NFSP_FRAG_COUNT_LIMIT) {
			f->err = NFSP_FRAMING_ERR_FRAG_COUNT;
			return -1;
		}
		/* A zero-length fragment carries no data and no progress, so a
		 * non-final one lets a peer spin this loop forever.  Reject it
		 * rather than loop. */
		if (body_len == 0 && (word & NFSP_LAST_FRAGMENT) == 0) {
			f->err = NFSP_FRAMING_ERR_ZERO_FRAG;
			return -1;
		}
		/* Check the header itself before subtracting.  After a non-final
		 * fragment, off may already be too close to limit; subtraction
		 * would underflow and incorrectly admit an oversized record. */
		if (off > f->limit ||
		    f->limit - off < NFSP_FRAG_HEADER_LEN ||
		    (size_t)body_len > f->limit - off - NFSP_FRAG_HEADER_LEN) {
			f->err = NFSP_FRAMING_ERR_FRAG_LEN;
			return -1;
		}

		hdr_bytes += NFSP_FRAG_HEADER_LEN;
		off += NFSP_FRAG_HEADER_LEN;

		if ((size_t)body_len > f->len - off)
			return 0;	/* body not fully arrived */

		off += body_len;
		if (word & NFSP_LAST_FRAGMENT) {
			if (msglen != NULL)
				*msglen = off;
			if (nfrags != NULL)
				*nfrags = frags;
			if (msg_frags_len != NULL)
				*msg_frags_len = hdr_bytes;
			return 1;
		}
	}
}

void nfsp_framing_consume(struct nfsp_framing *f, size_t n)
{
	if (f == NULL || n == 0)
		return;
	if (n > f->len)
		n = f->len;
	memmove(f->buf, f->buf + n, f->len - n);
	f->len -= n;
}

const char *nfsp_framing_strerror(enum nfsp_framing_err err)
{
	switch (err) {
	case NFSP_FRAMING_OK:
		return "ok";
	case NFSP_FRAMING_NEED_MORE:
		return "need more data";
	case NFSP_FRAMING_ERR_FRAG_LEN:
		return "fragment length exceeds the message limit";
	case NFSP_FRAMING_ERR_ZERO_FRAG:
		return "zero-length fragment that is not the last";
	case NFSP_FRAMING_ERR_MSG_LEN:
		return "message exceeds the configured limit";
	case NFSP_FRAMING_ERR_FRAG_COUNT:
		return "too many fragments in one message";
	case NFSP_FRAMING_ERR_NOMEM:
		return "out of memory";
	}
	return "unknown framing error";
}
