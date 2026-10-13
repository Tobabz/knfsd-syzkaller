/* Tests for the canonical RpcRecord adapter.
 *
 * The property everything above M1 depends on: the same RPC message yields the
 * same rpc_payload bytes however the sender fragmented it.  If that fails, a
 * WireRef computed on one transmission points at different bytes on the next,
 * and a semantic edit lands on a fragment header -- which the peer reports as
 * a protocol error, not as a proxy bug.
 */
#include "rpc_record.h"
#include "framing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: ", __FILE__, __LINE__);          \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
		}                                                              \
	} while (0)

static void put_hdr(uint8_t *out, size_t body_len, int last)
{
	uint32_t w = (uint32_t)body_len;

	if (last)
		w |= NFSP_LAST_FRAGMENT;
	out[0] = (uint8_t)(w >> 24);
	out[1] = (uint8_t)(w >> 16);
	out[2] = (uint8_t)(w >> 8);
	out[3] = (uint8_t)w;
}

/* Frame body[0..n) into fragments of at most `frag` bytes. */
static size_t frame_as(uint8_t *out, const uint8_t *body, size_t n, size_t frag)
{
	size_t off = 0, sent = 0;

	do {
		size_t chunk = n - sent;

		if (chunk > frag)
			chunk = frag;
		put_hdr(out + off, chunk, sent + chunk == n);
		off += NFSP_FRAG_HEADER_LEN;
		memcpy(out + off, body + sent, chunk);
		off += chunk;
		sent += chunk;
	} while (sent < n);
	return off;
}

static void test_single_fragment_is_a_view(void)
{
	uint8_t framed[4 + 12];
	uint8_t body[12];
	struct nfsp_record_buf scratch = {0};
	const uint8_t *p;
	size_t plen;
	uint32_t nfrags;

	printf("single fragment: payload is the bytes after the marker, no copy\n");
	for (size_t i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)(0x40 + i);
	frame_as(framed, body, sizeof(body), 64);
	CHECK(nfsp_rpc_payload(framed, sizeof(framed), &scratch, &p, &plen,
			       &nfrags) == NFSP_RECORD_OK, "canonicalise");
	CHECK(p == framed + 4, "a single fragment must be a zero-copy view");
	CHECK(plen == sizeof(body) && memcmp(p, body, plen) == 0,
	      "payload must be the body without its marker");
	CHECK(nfrags == 1, "nfrags=%u", nfrags);
	CHECK(scratch.p == NULL, "a single fragment must not touch scratch");
	nfsp_record_buf_free(&scratch);
}

/* Every fragmentation of the same body must canonicalise to the same bytes. */
static void test_fragmentation_invariance(void)
{
	uint8_t body[257];
	uint8_t framed[257 + 4 * 257];
	struct nfsp_record_buf scratch = {0};

	printf("every fragment size gives the same marker-free payload\n");
	for (size_t i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)(i * 7u + 3u);
	for (size_t frag = 1; frag <= sizeof(body) + 1; frag++) {
		const uint8_t *p;
		size_t plen;
		uint32_t nfrags;
		size_t flen = frame_as(framed, body, sizeof(body), frag);
		size_t want = (sizeof(body) + frag - 1) / frag;

		CHECK(nfsp_rpc_payload(framed, flen, &scratch, &p, &plen,
				       &nfrags) == NFSP_RECORD_OK,
		      "frag=%zu canonicalise", frag);
		CHECK(plen == sizeof(body) && p != NULL &&
		      memcmp(p, body, sizeof(body)) == 0,
		      "frag=%zu payload differs from the original body", frag);
		CHECK(nfrags == want, "frag=%zu nfrags=%u want %zu", frag,
		      nfrags, want);
	}
	nfsp_record_buf_free(&scratch);
}

/* The payload must agree with what framing.c accepted on the same bytes:
 * the two units are the relay's two readings of one record. */
static void test_agrees_with_framing(void)
{
	uint8_t body[40], framed[40 + 4 * 40];
	struct nfsp_record_buf scratch = {0};
	struct nfsp_framing f;

	printf("payload length = framing length minus fragment headers\n");
	for (size_t i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)i;
	for (size_t frag = 1; frag <= sizeof(body); frag += 3) {
		size_t flen = frame_as(framed, body, sizeof(body), frag);
		size_t msglen, nfr, hdrs, plen;
		const uint8_t *p;
		uint32_t nfrags;

		nfsp_framing_init(&f, 0);
		CHECK(nfsp_framing_append(&f, framed, flen) == 0, "append");
		CHECK(nfsp_framing_peek(&f, &msglen, &nfr, &hdrs) == 1, "peek");
		CHECK(nfsp_rpc_payload(f.buf, msglen, &scratch, &p, &plen,
				       &nfrags) == NFSP_RECORD_OK, "payload");
		CHECK(plen == msglen - hdrs && nfrags == nfr,
		      "frag=%zu framing says %zu-%zu/%zu, record says %zu/%u",
		      frag, msglen, hdrs, nfr, plen, nfrags);
		nfsp_framing_free(&f);
	}
	nfsp_record_buf_free(&scratch);
}

static void test_empty_last_fragment(void)
{
	uint8_t framed[4 + 3 + 4];
	struct nfsp_record_buf scratch = {0};
	const uint8_t *p;
	size_t plen;
	uint32_t nfrags;

	printf("an empty final fragment ends the record without adding bytes\n");
	put_hdr(framed, 3, 0);
	memcpy(framed + 4, "abc", 3);
	put_hdr(framed + 7, 0, 1);
	CHECK(nfsp_rpc_payload(framed, sizeof(framed), &scratch, &p, &plen,
			       &nfrags) == NFSP_RECORD_OK, "canonicalise");
	CHECK(plen == 3 && memcmp(p, "abc", 3) == 0 && nfrags == 2,
	      "payload %zu/%u", plen, nfrags);

	put_hdr(framed, 0, 1);
	CHECK(nfsp_rpc_payload(framed, 4, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_OK && plen == 0 && nfrags == 1,
	      "an empty record is an empty payload, not an error");
	nfsp_record_buf_free(&scratch);
}

/* A wrong length from the caller must be an error, never a payload that
 * silently includes or omits a header. */
static void test_not_exactly_one_record(void)
{
	uint8_t framed[64];
	uint8_t body[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	struct nfsp_record_buf scratch = {0};
	const uint8_t *p = body;
	size_t plen = 99, flen;
	uint32_t nfrags = 99;

	printf("anything other than exactly one complete record is refused\n");
	flen = frame_as(framed, body, sizeof(body), 3);	/* 3 fragments */

	for (size_t cut = 0; cut < flen; cut++) {
		enum nfsp_record_err e = nfsp_rpc_payload(framed, cut, &scratch,
							  &p, &plen, &nfrags);
		CHECK(e == NFSP_RECORD_ERR_SHORT, "prefix %zu/%zu: %s", cut,
		      flen, nfsp_record_strerror(e));
		CHECK(p == NULL && plen == 0 && nfrags == 0,
		      "prefix %zu left out-parameters set", cut);
	}

	framed[flen] = 0xff;
	CHECK(nfsp_rpc_payload(framed, flen + 1, &scratch, &p, &plen,
			       &nfrags) == NFSP_RECORD_ERR_TRAILING,
	      "a byte after the last fragment must be refused");

	put_hdr(framed, 0, 0);
	put_hdr(framed + 4, 0, 1);
	CHECK(nfsp_rpc_payload(framed, 8, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_ERR_ZERO_FRAG, "zero-length non-final fragment");

	CHECK(nfsp_rpc_payload(NULL, 0, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_ERR_INVAL, "NULL input");
	nfsp_record_buf_free(&scratch);
}

static void test_fragment_count_limit(void)
{
	size_t n = NFSP_FRAG_COUNT_LIMIT + 1u;
	uint8_t *framed = malloc(n * 5u);
	uint8_t *body = malloc(n);
	struct nfsp_record_buf scratch = {0};
	const uint8_t *p;
	size_t plen, flen;
	uint32_t nfrags;

	printf("the fragment count limit matches framing.c\n");
	if (framed == NULL || body == NULL) {
		CHECK(0, "allocation");
		free(framed);
		free(body);
		return;
	}
	memset(body, 0x5a, n);
	flen = frame_as(framed, body, n - 1u, 1);
	CHECK(nfsp_rpc_payload(framed, flen, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_OK && nfrags == NFSP_FRAG_COUNT_LIMIT,
	      "exactly the limit is accepted");
	flen = frame_as(framed, body, n, 1);
	CHECK(nfsp_rpc_payload(framed, flen, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_ERR_FRAG_COUNT, "one over the limit is refused");
	nfsp_record_buf_free(&scratch);
	free(framed);
	free(body);
}

static void test_frame_round_trip(void)
{
	uint8_t body[300], framed[300 + 4 * 300];
	struct nfsp_record_buf scratch = {0}, out = {0};
	const uint8_t *p, *fr;
	size_t plen, frlen, flen;
	uint32_t nfrags;

	printf("frame(payload) is one last fragment and canonicalises back\n");
	for (size_t i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)(255u - i);
	flen = frame_as(framed, body, sizeof(body), 7);
	CHECK(nfsp_rpc_payload(framed, flen, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_OK, "canonicalise");
	CHECK(nfsp_rpc_frame(p, plen, &out, &fr, &frlen) == NFSP_RECORD_OK,
	      "frame");
	CHECK(frlen == plen + 4 && fr[0] == 0x80 && fr[1] == 0 &&
	      fr[2] == 0x01 && fr[3] == 0x2c, "marker must be last|300");
	CHECK(memcmp(fr + 4, body, sizeof(body)) == 0, "framed body differs");
	CHECK(nfsp_rpc_payload(fr, frlen, &scratch, &p, &plen, &nfrags) ==
	      NFSP_RECORD_OK && nfrags == 1 && plen == sizeof(body) &&
	      memcmp(p, body, plen) == 0, "round trip");

	CHECK(nfsp_rpc_frame(NULL, 0, &out, &fr, &frlen) == NFSP_RECORD_OK &&
	      frlen == 4 && fr[0] == 0x80 && fr[3] == 0,
	      "an empty payload frames as an empty last fragment");
	CHECK(nfsp_rpc_frame(body, (size_t)NFSP_FRAG_LEN_MASK + 1u, &out, &fr,
			     &frlen) == NFSP_RECORD_ERR_TOO_LONG && fr == NULL,
	      "a payload one fragment cannot carry must be refused");
	nfsp_record_buf_free(&scratch);
	nfsp_record_buf_free(&out);
}

int main(void)
{
	test_single_fragment_is_a_view();
	test_fragmentation_invariance();
	test_agrees_with_framing();
	test_empty_last_fragment();
	test_not_exactly_one_record();
	test_fragment_count_limit();
	test_frame_round_trip();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
