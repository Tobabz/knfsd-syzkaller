/* Tests for record-marking reassembly.
 *
 * Style: every case states what breaks in the field if it regresses.  A test
 * whose failure message is "expected 1 got 0" tells the next person nothing;
 * these say what the wrong answer would have looked like to a kernel client.
 *
 * The split-point cases matter more than the whole-message cases.  A TCP stream
 * delivers fragments and even single headers in pieces, and a reassembler that
 * only works on whole messages passes every naive test and fails in the guest.
 */
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

/* Build a fragment header into out[0..3]. */
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

/* A message of `nbody` payload bytes split into fragments of at most `frag`
 * bytes, the last one flagged.  Returns the total encoded length. */
static size_t build_msg(uint8_t *out, size_t nbody, size_t frag, uint8_t fill)
{
	size_t off = 0, sent = 0;

	if (frag == 0)
		frag = nbody ? nbody : 1;
	do {
		size_t chunk = nbody - sent;
		int last;

		if (chunk > frag)
			chunk = frag;
		last = (sent + chunk == nbody);
		put_hdr(out + off, chunk, last);
		off += NFSP_FRAG_HEADER_LEN;
		memset(out + off, fill, chunk);
		off += chunk;
		sent += chunk;
	} while (sent < nbody);
	return off;
}

static void test_single_fragment(void)
{
	struct nfsp_framing f;
	uint8_t msg[64];
	size_t len, msglen = 0, nfrags = 0, hdrs = 0;
	int rc;

	printf("single-fragment message\n");
	len = build_msg(msg, 32, 32, 0xa5);
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	CHECK(nfsp_framing_append(&f, msg, len) == 0, "append");
	rc = nfsp_framing_peek(&f, &msglen, &nfrags, &hdrs);
	CHECK(rc == 1, "expected a complete message, got %d", rc);
	CHECK(msglen == len, "msglen %zu != %zu", msglen, len);
	CHECK(nfrags == 1, "expected 1 fragment, got %zu", nfrags);
	CHECK(hdrs == 4, "expected 4 header bytes, got %zu", hdrs);
	/* The bytes must survive verbatim: the proxy re-emits, never rewrites. */
	CHECK(memcmp(f.buf, msg, len) == 0, "buffered bytes differ from input");
	nfsp_framing_free(&f);
}

static void test_multi_fragment(void)
{
	struct nfsp_framing f;
	uint8_t msg[256];
	size_t len, msglen = 0, nfrags = 0, hdrs = 0;
	int rc;

	printf("multi-fragment message\n");
	len = build_msg(msg, 100, 30, 0x5a);	/* 30+30+30+10 */
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	CHECK(nfsp_framing_append(&f, msg, len) == 0, "append");
	rc = nfsp_framing_peek(&f, &msglen, &nfrags, &hdrs);
	CHECK(rc == 1, "expected a complete message, got %d", rc);
	CHECK(msglen == len, "msglen %zu != %zu", msglen, len);
	CHECK(nfrags == 4, "expected 4 fragments, got %zu", nfrags);
	CHECK(hdrs == 16, "expected 16 header bytes, got %zu", hdrs);
	CHECK(memcmp(f.buf, msg, len) == 0, "buffered bytes differ from input");
	nfsp_framing_free(&f);
}

/* THE case that matters: a message delivered one byte at a time.  A reassembler
 * that assumes it will see at least a whole fragment header, or a whole
 * fragment body, passes every other test here and fails in the guest with what
 * looks like a protocol error. */
static void test_byte_at_a_time(void)
{
	struct nfsp_framing f;
	uint8_t msg[256];
	size_t len, i;
	int rc;
	int saw_complete_at = -1;

	printf("byte-at-a-time delivery\n");
	len = build_msg(msg, 60, 17, 0x3c);	/* several fragments */
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	for (i = 0; i < len; i++) {
		size_t msglen = 0;
		int complete;

		CHECK(nfsp_framing_append(&f, msg + i, 1) == 0,
		      "append byte %zu", i);
		complete = nfsp_framing_peek(&f, &msglen, NULL, NULL);
		CHECK(complete >= 0, "peek error at byte %zu: %s", i,
		      nfsp_framing_strerror(f.err));
		if (complete == 1) {
			saw_complete_at = (int)i;
			CHECK(msglen == len, "msglen %zu != %zu", msglen, len);
			CHECK(memcmp(f.buf, msg, len) == 0, "bytes differ");
			break;
		}
	}
	CHECK(saw_complete_at == (int)len - 1,
	      "completion was seen at byte %d, expected %zu",
	      saw_complete_at, len - 1);
	rc = saw_complete_at >= 0;
	CHECK(rc, "never completed");
	nfsp_framing_free(&f);
}

/* Two messages in one read, which is the normal case on a busy connection. */
static void test_two_messages_one_read(void)
{
	struct nfsp_framing f;
	uint8_t buf[256];
	size_t l1, l2, msglen = 0;
	int rc;

	printf("two messages in one read\n");
	l1 = build_msg(buf, 20, 20, 0x11);
	l2 = build_msg(buf + l1, 40, 12, 0x22);
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	CHECK(nfsp_framing_append(&f, buf, l1 + l2) == 0, "append");

	rc = nfsp_framing_peek(&f, &msglen, NULL, NULL);
	CHECK(rc == 1 && msglen == l1,
	      "first message: rc=%d msglen=%zu expected %zu", rc, msglen, l1);
	nfsp_framing_consume(&f, msglen);

	rc = nfsp_framing_peek(&f, &msglen, NULL, NULL);
	CHECK(rc == 1 && msglen == l2,
	      "second message: rc=%d msglen=%zu expected %zu", rc, msglen, l2);
	nfsp_framing_consume(&f, msglen);

	rc = nfsp_framing_peek(&f, &msglen, NULL, NULL);
	CHECK(rc == 0, "expected drained, got rc=%d", rc);
	CHECK(f.len == 0, "expected empty buffer, len=%zu", f.len);
	nfsp_framing_free(&f);
}

/* A header split across two reads.  Rare, and exactly the kind of case that
 * produces a shifted byte stream when missed. */
static void test_split_header(void)
{
	struct nfsp_framing f;
	uint8_t msg[64];
	size_t len, msglen = 0;
	int rc;

	printf("fragment header split across reads\n");
	len = build_msg(msg, 16, 16, 0x77);
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	CHECK(nfsp_framing_append(&f, msg, 2) == 0, "append first half");
	rc = nfsp_framing_peek(&f, &msglen, NULL, NULL);
	CHECK(rc == 0, "half a header must not complete a message, rc=%d", rc);
	CHECK(nfsp_framing_append(&f, msg + 2, len - 2) == 0, "append rest");
	rc = nfsp_framing_peek(&f, &msglen, NULL, NULL);
	CHECK(rc == 1 && msglen == len, "rc=%d msglen=%zu expected %zu", rc,
	      msglen, len);
	nfsp_framing_free(&f);
}

/* A zero-length non-final fragment carries no data and no progress.  Accepting
 * it would let a peer spin the reassembler forever; this must be an error, not
 * a no-op. */
static void test_zero_length_non_final_is_rejected(void)
{
	struct nfsp_framing f;
	uint8_t msg[8];
	int rc;

	printf("zero-length non-final fragment\n");
	put_hdr(msg, 0, 0);
	put_hdr(msg + 4, 4, 1);
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	CHECK(nfsp_framing_append(&f, msg, sizeof(msg)) == 0, "append");
	rc = nfsp_framing_peek(&f, NULL, NULL, NULL);
	CHECK(rc == -1, "must be rejected, got rc=%d", rc);
	CHECK(f.err == NFSP_FRAMING_ERR_ZERO_FRAG,
	      "expected ZERO_FRAG, got %s", nfsp_framing_strerror(f.err));
	nfsp_framing_free(&f);
}

/* A zero-length FINAL fragment is legal: it is how a zero-length record is
 * expressed.  Rejecting it would break a conformant peer. */
static void test_zero_length_final_is_accepted(void)
{
	struct nfsp_framing f;
	uint8_t msg[4];
	size_t msglen = 0, nfrags = 0;
	int rc;

	printf("zero-length final fragment\n");
	put_hdr(msg, 0, 1);
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	CHECK(nfsp_framing_append(&f, msg, sizeof(msg)) == 0, "append");
	rc = nfsp_framing_peek(&f, &msglen, &nfrags, NULL);
	CHECK(rc == 1, "must be accepted, got rc=%d", rc);
	CHECK(msglen == 4, "msglen %zu != 4", msglen);
	CHECK(nfrags == 1, "nfrags %zu != 1", nfrags);
	nfsp_framing_free(&f);
}

/* A fragment claiming a huge body must be refused, not allocated.  This is the
 * difference between a proxy that survives a hostile peer and one that does
 * not. */
static void test_oversized_fragment_rejected(void)
{
	struct nfsp_framing f;
	uint8_t msg[64];
	int rc;

	printf("oversized fragment\n");
	put_hdr(msg, 4096, 1);
	memset(msg + 4, 0, sizeof(msg) - 4);
	CHECK(nfsp_framing_init(&f, 1024) == 0, "init with limit 1024");
	CHECK(nfsp_framing_append(&f, msg, sizeof(msg)) == 0, "append");
	rc = nfsp_framing_peek(&f, NULL, NULL, NULL);
	CHECK(rc == -1, "4096-byte body over a 1024 limit must be rejected, rc=%d",
	      rc);
	CHECK(f.err == NFSP_FRAMING_ERR_FRAG_LEN,
	      "expected FRAG_LEN, got %s", nfsp_framing_strerror(f.err));
	nfsp_framing_free(&f);
}

/* Append must refuse to grow without bound. */
static void test_append_bounded(void)
{
	struct nfsp_framing f;
	uint8_t chunk[2048];

	printf("append is bounded\n");
	memset(chunk, 0x41, sizeof(chunk));
	CHECK(nfsp_framing_init(&f, 1024) == 0, "init with limit 1024");

	/* A header promising 1000 more bytes, which is inside the 1024 limit
	 * and has not arrived yet.  This is the honest "incomplete" case: the
	 * reassembler must report NEED MORE, not an error, because the rest is
	 * simply still in flight. */
	put_hdr(chunk, 1000, 1);
	CHECK(nfsp_framing_append(&f, chunk, NFSP_FRAG_HEADER_LEN) == 0,
	      "append a header that promises 1000 more");
	CHECK(nfsp_framing_peek(&f, NULL, NULL, NULL) == 0,
	      "must report incomplete, not an error (%s)",
	      nfsp_framing_strerror(f.err));
	CHECK(f.err == NFSP_FRAMING_OK, "incomplete is not an error state");

	/* The ceiling is limit + one fragment header = 1028.  The buffer holds
	 * 4 bytes, so appending 2048 must be refused rather than allocated. */
	CHECK(nfsp_framing_append(&f, chunk, sizeof(chunk)) == -1,
	      "appending past the ceiling must fail");
	CHECK(f.err == NFSP_FRAMING_ERR_MSG_LEN,
	      "expected MSG_LEN, got %s", nfsp_framing_strerror(f.err));
	CHECK(f.len == NFSP_FRAG_HEADER_LEN,
	      "buffer grew to %zu despite the refusal", f.len);
	CHECK(f.cap <= 4096, "allocation grew to %zu despite the limit", f.cap);
	nfsp_framing_free(&f);
}

/* Many tiny fragments in one message: legal, and must not trip the count cap. */
static void test_many_fragments(void)
{
	struct nfsp_framing f;
	uint8_t msg[512];
	size_t len, msglen = 0, nfrags = 0;
	int rc;

	printf("many small fragments\n");
	len = build_msg(msg, 100, 1, 0x99);	/* 100 fragments + 100 headers */
	CHECK(nfsp_framing_init(&f, 0) == 0, "init");
	CHECK(nfsp_framing_append(&f, msg, len) == 0, "append");
	rc = nfsp_framing_peek(&f, &msglen, &nfrags, NULL);
	CHECK(rc == 1, "expected complete, got rc=%d (%s)", rc,
	      nfsp_framing_strerror(f.err));
	CHECK(nfrags == 100, "nfrags %zu != 100", nfrags);
	CHECK(msglen == len, "msglen %zu != %zu", msglen, len);
	nfsp_framing_free(&f);
}

int main(void)
{
	printf("framing tests\n");
	test_single_fragment();
	test_multi_fragment();
	test_byte_at_a_time();
	test_two_messages_one_read();
	test_split_header();
	test_zero_length_non_final_is_rejected();
	test_zero_length_final_is_accepted();
	test_oversized_fragment_rejected();
	test_append_bounded();
	test_many_fragments();

	printf("\n%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
