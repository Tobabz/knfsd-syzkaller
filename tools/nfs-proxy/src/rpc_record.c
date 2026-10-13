#include "rpc_record.h"
#include "framing.h"

#include <stdlib.h>
#include <string.h>

static uint32_t rd_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

void nfsp_record_buf_free(struct nfsp_record_buf *b)
{
	if (b == NULL)
		return;
	free(b->p);
	b->p = NULL;
	b->cap = 0;
}

static int reserve(struct nfsp_record_buf *b, size_t need)
{
	uint8_t *grown;
	size_t cap;

	if (need <= b->cap)
		return 0;
	cap = b->cap ? b->cap : 4096u;
	while (cap < need) {
		if (cap > (size_t)-1 / 2u)
			return -1;
		cap *= 2u;
	}
	grown = realloc(b->p, cap);
	if (grown == NULL)
		return -1;
	b->p = grown;
	b->cap = cap;
	return 0;
}

/* One pass over the fragment headers: prove the input is exactly one record
 * and count what it holds.  Copying happens only after this succeeds, so a
 * malformed record never leaves half a payload in the scratch buffer. */
static enum nfsp_record_err scan(const uint8_t *framed, size_t framed_len,
				 size_t *body_total, uint32_t *nfrags)
{
	size_t off = 0, total = 0;
	uint32_t frags = 0;

	for (;;) {
		uint32_t word, body_len;

		if (framed_len - off < NFSP_FRAG_HEADER_LEN)
			return NFSP_RECORD_ERR_SHORT;
		word = rd_be32(framed + off);
		body_len = word & NFSP_FRAG_LEN_MASK;
		if (++frags > NFSP_FRAG_COUNT_LIMIT)
			return NFSP_RECORD_ERR_FRAG_COUNT;
		if (body_len == 0 && (word & NFSP_LAST_FRAGMENT) == 0)
			return NFSP_RECORD_ERR_ZERO_FRAG;
		off += NFSP_FRAG_HEADER_LEN;
		if ((size_t)body_len > framed_len - off)
			return NFSP_RECORD_ERR_SHORT;
		off += body_len;
		total += body_len;
		if (word & NFSP_LAST_FRAGMENT)
			break;
	}
	if (off != framed_len)
		return NFSP_RECORD_ERR_TRAILING;
	*body_total = total;
	*nfrags = frags;
	return NFSP_RECORD_OK;
}

enum nfsp_record_err nfsp_rpc_payload(const uint8_t *framed, size_t framed_len,
				      struct nfsp_record_buf *scratch,
				      const uint8_t **payload,
				      size_t *payload_len, uint32_t *nfrags)
{
	enum nfsp_record_err err;
	size_t total = 0, off = 0, w = 0;
	uint32_t frags = 0, i;

	if (payload != NULL)
		*payload = NULL;
	if (payload_len != NULL)
		*payload_len = 0;
	if (nfrags != NULL)
		*nfrags = 0;
	if (framed == NULL || scratch == NULL || payload == NULL ||
	    payload_len == NULL || nfrags == NULL)
		return NFSP_RECORD_ERR_INVAL;

	err = scan(framed, framed_len, &total, &frags);
	if (err != NFSP_RECORD_OK)
		return err;

	if (frags == 1u) {
		*payload = framed + NFSP_FRAG_HEADER_LEN;
		*payload_len = total;
		*nfrags = 1u;
		return NFSP_RECORD_OK;
	}

	/* reserve(…, 0) would leave p NULL; an all-empty multi-fragment record
	 * is impossible (only the last fragment may be empty) but stay safe. */
	if (reserve(scratch, total ? total : 1u) != 0)
		return NFSP_RECORD_ERR_NOMEM;
	for (i = 0; i < frags; i++) {
		uint32_t body_len = rd_be32(framed + off) & NFSP_FRAG_LEN_MASK;

		off += NFSP_FRAG_HEADER_LEN;
		memcpy(scratch->p + w, framed + off, body_len);
		off += body_len;
		w += body_len;
	}
	*payload = scratch->p;
	*payload_len = total;
	*nfrags = frags;
	return NFSP_RECORD_OK;
}

enum nfsp_record_err nfsp_rpc_frame(const uint8_t *payload, size_t len,
				    struct nfsp_record_buf *out,
				    const uint8_t **framed, size_t *framed_len)
{
	if (framed != NULL)
		*framed = NULL;
	if (framed_len != NULL)
		*framed_len = 0;
	if ((payload == NULL && len != 0) || out == NULL || framed == NULL ||
	    framed_len == NULL)
		return NFSP_RECORD_ERR_INVAL;
	if (len > NFSP_FRAG_LEN_MASK)
		return NFSP_RECORD_ERR_TOO_LONG;
	if (reserve(out, len + NFSP_FRAG_HEADER_LEN) != 0)
		return NFSP_RECORD_ERR_NOMEM;
	wr_be32(out->p, NFSP_LAST_FRAGMENT | (uint32_t)len);
	if (len != 0)
		memcpy(out->p + NFSP_FRAG_HEADER_LEN, payload, len);
	*framed = out->p;
	*framed_len = len + NFSP_FRAG_HEADER_LEN;
	return NFSP_RECORD_OK;
}

const char *nfsp_record_strerror(enum nfsp_record_err err)
{
	switch (err) {
	case NFSP_RECORD_OK:
		return "ok";
	case NFSP_RECORD_ERR_INVAL:
		return "invalid argument";
	case NFSP_RECORD_ERR_SHORT:
		return "input ends inside a fragment";
	case NFSP_RECORD_ERR_TRAILING:
		return "bytes after the last fragment";
	case NFSP_RECORD_ERR_ZERO_FRAG:
		return "zero-length fragment that is not the last";
	case NFSP_RECORD_ERR_FRAG_COUNT:
		return "too many fragments in one record";
	case NFSP_RECORD_ERR_TOO_LONG:
		return "payload does not fit one fragment";
	case NFSP_RECORD_ERR_NOMEM:
		return "out of memory";
	}
	return "unknown record error";
}
