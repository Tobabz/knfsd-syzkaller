/* -std=c11 is strict ISO C, which hides the POSIX declarations this
 * module needs (open, write, fsync, read, unlink).  Asking for them
 * explicitly is correct rather than relying on a header happening to
 * expose them: an accidental dependency breaks on the next libc. */
#define _POSIX_C_SOURCE 200809L

#include "delta.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- big-endian helpers --------------------------------------------------
 *
 * The file is written big-endian so the format is explicit rather than whatever
 * the host happens to be.  Produce and replay currently run on the same host,
 * but a format that depends on that is a trap for the next person. */
static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)(v >> 32));
	put32(p + 4, (uint32_t)v);
}

static uint64_t get64(const uint8_t *p)
{
	return ((uint64_t)get32(p) << 32) | (uint64_t)get32(p + 4);
}

int nfsp_rule_valid(const struct nfsp_rule *r)
{
	if (r == NULL)
		return 0;
	if (r->dir > NFSP_DELTA_S2C)
		return 0;
	if (r->backend > NFSP_DELTA_BACKEND_GANESHA)
		return 0;
	if (r->client > 1)
		return 0;
	if (r->anchor_len > NFSP_DELTA_ANCHOR_MAX)
		return 0;
	if (r->patch_w == 0 || r->patch_w > NFSP_DELTA_PATCH_MAX)
		return 0;
	if (r->patch_off > (uint32_t)-1 - r->patch_w)
		return 0;
	if (r->anchor_len > 0 &&
	    r->anchor_off > (uint32_t)-1 - r->anchor_len)
		return 0;
	return 1;
}

int nfsp_apply_rule(const struct nfsp_rule *r, const struct nfsp_msg_ctx *ctx,
		    uint8_t *buf, size_t len, struct nfsp_apply_stats *st)
{
	if (r == NULL || ctx == NULL || st == NULL)
		return -1;
	if (!nfsp_rule_valid(r))
		return -1;

	/* --- predicate: direction, backend, client --- */
	if (r->dir != ctx->dir || r->backend != ctx->backend ||
	    r->client != ctx->client)
		return 0;

	if (r->first_opcode != NFSP_DELTA_OPCODE_ANY &&
	    r->first_opcode != ctx->first_opcode)
		return 0;

	/* --- predicate: optional literal anchor ---
	 *
	 * The anchor is what makes the predicate content-addressed rather than
	 * positional.  A caller that needs to target one request among many
	 * records a short identifying span (a file handle, a path fragment) and
	 * the rule then matches that content wherever it appears. */
	if (r->anchor_len > 0) {
		if ((size_t)r->anchor_off + r->anchor_len > len)
			return 0;
		if (memcmp(buf + r->anchor_off, r->anchor, r->anchor_len) != 0)
			return 0;
	}

	st->predicate_hits++;

	/* --- match_index filtering (the support case; MATCH_ANY is the norm) --- */
	if (r->match_index != NFSP_DELTA_MATCH_ANY) {
		if ((uint32_t)st->predicate_hits - 1u != r->match_index) {
			st->skipped_match_index++;
			return 0;
		}
	}

	/* --- the patch must lie inside the message ---
	 *
	 * Checked before the verify so an out-of-range rule is reported as
	 * out-of-range rather than as a byte mismatch, which would be a
	 * misleading diagnosis. */
	if ((size_t)r->patch_off + r->patch_w > len) {
		st->refused_out_of_range++;
		return 0;
	}

	/* --- VERIFY BEFORE PATCH ---
	 *
	 * If the bytes are not what was recorded, this is not the message the
	 * mutation was recorded against.  Refusing is what keeps "replay
	 * failed" distinguishable from "the crash did not reproduce". */
	if (memcmp(buf + r->patch_off, r->orig, r->patch_w) != 0) {
		st->refused_orig_diff++;
		return 0;
	}

	memcpy(buf + r->patch_off, r->repl, r->patch_w);
	st->applied++;
	return 1;
}

/* ---- writer -------------------------------------------------------------- */

struct nfsp_delta_writer {
	int	fd;
	uint64_t	seed;
	long	count;
	int	saved_errno;
};

#define NFSP_DELTA_HEADER_LEN	(8u + 4u + 8u)	/* magic, version, seed */

int nfsp_delta_write_open(struct nfsp_delta_writer **out, const char *path,
			  uint64_t seed)
{
	uint8_t hdr[NFSP_DELTA_HEADER_LEN];
	struct nfsp_delta_writer *w;

	if (out == NULL || path == NULL)
		return -1;
	w = calloc(1, sizeof(*w));
	if (w == NULL)
		return -1;

	/* O_SYNC: every write below is durable when it returns.  See the header
	 * for why the last mutation before a crash must survive. */
	w->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
	if (w->fd < 0) {
		w->saved_errno = errno;
		free(w);
		return -1;
	}
	w->seed = seed;

	memcpy(hdr, NFSP_DELTA_MAGIC, 8);
	put32(hdr + 8, NFSP_DELTA_VERSION);
	put64(hdr + 12, seed);
	if (write(w->fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
		w->saved_errno = errno;
		close(w->fd);
		free(w);
		return -1;
	}
	*out = w;
	return 0;
}

int nfsp_delta_write_rule(struct nfsp_delta_writer *w,
			  const struct nfsp_rule *r)
{
	uint8_t rec[NFSP_DELTA_REC_HDR_LEN + NFSP_DELTA_ANCHOR_MAX +
		    2u * NFSP_DELTA_PATCH_MAX];
	size_t n = 0;

	if (w == NULL || r == NULL)
		return -1;
	if (!nfsp_rule_valid(r))
		return -1;

	put32(rec + n, r->dir);			n += 4;
	put32(rec + n, r->backend);		n += 4;
	put32(rec + n, r->client);		n += 4;
	put32(rec + n, r->first_opcode);	n += 4;
	put32(rec + n, r->match_index);		n += 4;
	put32(rec + n, r->anchor_off);		n += 4;
	put32(rec + n, r->anchor_len);		n += 4;
	put32(rec + n, r->patch_off);		n += 4;
	put32(rec + n, r->patch_w);		n += 4;
	/* applied_count is stored because the replay gate compares against it.
	 * Without it, "the mutation was re-applied everywhere it was recorded"
	 * cannot be checked, and a partial replay would look like a
	 * non-reproducing crash. */
	put32(rec + n, r->applied_count);	n += 4;
	memcpy(rec + n, r->anchor, r->anchor_len);	n += r->anchor_len;
	memcpy(rec + n, r->orig, r->patch_w);		n += r->patch_w;
	memcpy(rec + n, r->repl, r->patch_w);		n += r->patch_w;

	/* One write call per record, and O_SYNC makes it durable: a torn record
	 * cannot be left behind by a crash between two writes. */
	if (write(w->fd, rec, n) != (ssize_t)n) {
		w->saved_errno = errno;
		return -1;
	}
	w->count++;
	return 0;
}

long nfsp_delta_write_count(const struct nfsp_delta_writer *w)
{
	return w == NULL ? -1 : w->count;
}

long nfsp_delta_write_close(struct nfsp_delta_writer *w)
{
	long n;

	if (w == NULL)
		return -1;
	n = w->count;
	if (fsync(w->fd) != 0 && w->saved_errno == 0)
		w->saved_errno = errno;
	close(w->fd);
	free(w);
	return n;
}

/* ---- reader -------------------------------------------------------------- */

struct nfsp_delta_reader {
	int	fd;
	uint64_t	seed;
	int	eof;
	int	corrupt;
	int	saved_errno;
};

static int read_full(int fd, uint8_t *p, size_t n)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);

		if (r == 0)
			return got == 0 ? 0 : -1;	/* short record != clean EOF */
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		got += (size_t)r;
	}
	return 1;
}

int nfsp_delta_read_open(struct nfsp_delta_reader **out, const char *path)
{
	uint8_t hdr[NFSP_DELTA_HEADER_LEN];
	struct nfsp_delta_reader *r;
	int rc;

	if (out == NULL || path == NULL)
		return -1;
	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return -1;

	r->fd = open(path, O_RDONLY);
	if (r->fd < 0) {
		r->saved_errno = errno;
		free(r);
		return -1;
	}
	rc = read_full(r->fd, hdr, sizeof(hdr));
	if (rc != 1) {
		r->saved_errno = rc == 0 ? 0 : errno;
		close(r->fd);
		free(r);
		return -1;
	}
	if (memcmp(hdr, NFSP_DELTA_MAGIC, 8) != 0 ||
	    get32(hdr + 8) != NFSP_DELTA_VERSION) {
		close(r->fd);
		free(r);
		errno = EINVAL;
		return -1;
	}
	r->seed = get64(hdr + 12);
	*out = r;
	return 0;
}

uint64_t nfsp_delta_reader_seed(const struct nfsp_delta_reader *r)
{
	return r == NULL ? 0 : r->seed;
}

int nfsp_delta_read_rule(struct nfsp_delta_reader *r, struct nfsp_rule *out)
{
	uint8_t hdr[NFSP_DELTA_REC_HDR_LEN];
	uint32_t anchor_len, patch_w;
	int rc;

	if (r == NULL || out == NULL)
		return -1;
	if (r->eof || r->corrupt)
		return r->corrupt ? -1 : 0;

	rc = read_full(r->fd, hdr, sizeof(hdr));
	if (rc == 0) {
		r->eof = 1;
		return 0;
	}
	if (rc < 0) {
		r->corrupt = 1;
		r->saved_errno = errno;
		return -1;
	}

	memset(out, 0, sizeof(*out));
	out->dir		= get32(hdr + 0);
	out->backend		= get32(hdr + 4);
	out->client		= get32(hdr + 8);
	out->first_opcode	= get32(hdr + 12);
	out->match_index	= get32(hdr + 16);
	out->anchor_off		= get32(hdr + 20);
	anchor_len		= get32(hdr + 24);
	out->patch_off		= get32(hdr + 28);
	patch_w			= get32(hdr + 32);
	out->applied_count	= get32(hdr + 36);
	out->anchor_len		= anchor_len;
	out->patch_w		= patch_w;

	/* Validate the declared sizes BEFORE reading the variable parts, so a
	 * corrupt length can never drive a large read or an overflow. */
	if (anchor_len > NFSP_DELTA_ANCHOR_MAX ||
	    patch_w == 0 || patch_w > NFSP_DELTA_PATCH_MAX) {
		r->corrupt = 1;
		errno = EINVAL;
		return -1;
	}
	if (anchor_len > 0 && read_full(r->fd, out->anchor, anchor_len) != 1) {
		r->corrupt = 1;
		errno = EINVAL;
		return -1;
	}
	if (read_full(r->fd, out->orig, patch_w) != 1 ||
	    read_full(r->fd, out->repl, patch_w) != 1) {
		r->corrupt = 1;
		errno = EINVAL;
		return -1;
	}
	if (!nfsp_rule_valid(out)) {
		r->corrupt = 1;
		errno = EINVAL;
		return -1;
	}
	return 1;
}

void nfsp_delta_read_close(struct nfsp_delta_reader *r)
{
	if (r == NULL)
		return;
	close(r->fd);
	free(r);
}

const char *nfsp_delta_strerror(int code)
{
	(void)code;
	return "delta error";
}
