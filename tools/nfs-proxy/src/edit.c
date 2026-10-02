/* File IO below (the delta v2 reader/writer) needs the POSIX declarations that
 * -std=c11 hides, exactly as delta.c does; the apply logic above is pure. */
#define _POSIX_C_SOURCE 200809L

#include "edit.h"
#include "framing.h"	/* NFSP_FRAG_HEADER_LEN, NFSP_LAST_FRAGMENT, mask */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static int edit_valid(const struct nfsp_edit *e)
{
	if (e->kind >= NFSP_EDIT_KIND_COUNT)
		return 0;
	if (e->orig_len > NFSP_EDIT_BYTES_MAX || e->data_len > NFSP_EDIT_BYTES_MAX)
		return 0;
	if (e->offset > (uint32_t)-1 - e->orig_len)
		return 0;
	switch (e->kind) {
	case NFSP_EDIT_REPLACE:
		return e->orig_len >= 1u;
	case NFSP_EDIT_INSERT:
		return e->orig_len == 0u && e->data_len >= 1u;
	case NFSP_EDIT_DELETE:
		return e->orig_len >= 1u && e->data_len == 0u;
	case NFSP_EDIT_OP_APPEND:
	case NFSP_EDIT_OP_PREPEND:
		/* An op is at least one XDR word and is always word-aligned. */
		return e->orig_len == 0u && e->data_len >= 4u &&
		       (e->data_len % 4u) == 0u;
	default:
		return 0;
	}
}

int nfsp_edit_rule_valid(const struct nfsp_edit_rule *r)
{
	uint32_t i, total = 0;

	if (r == NULL)
		return 0;
	if (r->dir > NFSP_DELTA_S2C || r->backend > NFSP_DELTA_BACKEND_GANESHA ||
	    r->client > 1u)
		return 0;
	if (r->mode > NFSP_EDIT_MODE_RAW)
		return 0;
	if (r->anchor_len > NFSP_DELTA_ANCHOR_MAX)
		return 0;
	if (r->anchor_len > 0u && r->anchor_off > (uint32_t)-1 - r->anchor_len)
		return 0;
	if (r->nedits == 0u || r->nedits > NFSP_EDIT_MAX)
		return 0;
	for (i = 0; i < r->nedits; i++) {
		if (!edit_valid(&r->edits[i]))
			return 0;
		total += r->edits[i].orig_len + r->edits[i].data_len;
	}
	return total <= NFSP_EDIT_TOTAL_MAX;
}

/* A resolved edit in original-message coordinates: a span [offset,offset+remove)
 * to drop and `ins_len` bytes to put in its place.  OP_* and the structural op
 * count fix-up are reduced to this same shape so the rebuild below is uniform. */
struct resolved {
	uint32_t	offset;
	uint32_t	remove;
	const uint8_t	*ins;
	uint32_t	ins_len;
	int		order;		/* tie-break at equal offsets */
};

static void sort_resolved(struct resolved *res, size_t n)
{
	size_t i, j;

	for (i = 1; i < n; i++) {
		struct resolved key = res[i];

		j = i;
		while (j > 0 && (res[j - 1].offset > key.offset ||
				 (res[j - 1].offset == key.offset &&
				  res[j - 1].order > key.order))) {
			res[j] = res[j - 1];
			j--;
		}
		res[j] = key;
	}
}

int nfsp_apply_edit_rules(const struct nfsp_edit_rule *const *rules,
			  struct nfsp_edit_stats *const *stats, size_t nrules,
			  const struct nfsp_msg_ctx *ctx,
			  const struct nfsp_walk *walk,
			  const uint8_t *in, size_t in_len,
			  uint8_t *out, size_t out_cap, size_t *out_len)
{
	/* +1 for the op-count fix-up */
	struct resolved res[NFSP_EDIT_RESOLVED_MAX + 1u];
	uint8_t participating[64];
	uint8_t opcount_buf[4];
	size_t nres = 0, body_off = 0, body_end = 0, grown, cursor, o;
	size_t i, j, ntaking = 0;
	const struct nfsp_slot *opcount_slot = NULL;
	uint32_t op_bump = 0;
	int order = 0;
	int have_body = 0;

	if (rules == NULL || stats == NULL || ctx == NULL || walk == NULL ||
	    in == NULL || out == NULL || out_len == NULL ||
	    nrules == 0 || nrules > sizeof(participating))
		return -1;
	for (i = 0; i < nrules; i++)
		if (rules[i] == NULL || stats[i] == NULL ||
		    !nfsp_edit_rule_valid(rules[i]))
			return -1;
	memset(participating, 0, sizeof(participating));

	/* Op-array layout, once.  Every edit is confined to the op array body, so
	 * a message the walk could not resolve to a COMPOUND has no place to put
	 * one; each matching rule then refuses and the caller forwards untouched. */
	if (walk->status == NFSP_WALK_OK) {
		for (i = 0; i < walk->nregions; i++)
			if (walk->regions[i].role == NFSP_RR_OP_BODY) {
				body_off = walk->regions[i].offset;
				body_end = (size_t)walk->regions[i].offset +
					   walk->regions[i].len;
				have_body = body_end <= in_len;
				break;
			}
		opcount_slot = nfsp_walk_find(walk, NFSP_SR_OPCOUNT);
	}

	for (i = 0; i < nrules; i++) {
		const struct nfsp_edit_rule *r = rules[i];
		struct nfsp_edit_stats *st = stats[i];
		size_t first = nres;
		uint32_t rule_bump = 0;
		int refused = 0;

		/* --- predicate: direction, backend, client, first opcode --- */
		if (r->dir != ctx->dir || r->backend != ctx->backend ||
		    r->client != ctx->client)
			continue;
		if (r->first_opcode != NFSP_DELTA_OPCODE_ANY &&
		    r->first_opcode != ctx->first_opcode)
			continue;
		/* --- predicate: optional literal anchor (original bytes) --- */
		if (r->anchor_len > 0u) {
			if ((size_t)r->anchor_off + r->anchor_len > in_len)
				continue;
			if (memcmp(in + r->anchor_off, r->anchor, r->anchor_len) != 0)
				continue;
		}
		st->predicate_hits++;

		if (!have_body) {
			st->refused_unknown_layout++;
			continue;
		}
		if (nres + r->nedits > NFSP_EDIT_RESOLVED_MAX) {
			st->refused_too_big++;
			continue;
		}

		/* --- resolve each edit into a (offset, remove, insert) triple --- */
		for (j = 0; j < r->nedits && !refused; j++) {
			const struct nfsp_edit *e = &r->edits[j];
			struct resolved *rr = &res[nres];

			rr->order = order++;
			switch (e->kind) {
			case NFSP_EDIT_REPLACE:
			case NFSP_EDIT_DELETE:
				rr->offset = e->offset;
				rr->remove = e->orig_len;
				rr->ins = e->kind == NFSP_EDIT_REPLACE ? e->data : NULL;
				rr->ins_len = e->kind == NFSP_EDIT_REPLACE ? e->data_len : 0u;
				break;
			case NFSP_EDIT_INSERT:
				rr->offset = e->offset;
				rr->remove = 0u;
				rr->ins = e->data;
				rr->ins_len = e->data_len;
				break;
			case NFSP_EDIT_OP_APPEND:
				rr->offset = (uint32_t)body_end;
				rr->remove = 0u;
				rr->ins = e->data;
				rr->ins_len = e->data_len;
				rule_bump++;
				break;
			case NFSP_EDIT_OP_PREPEND:
				rr->offset = (uint32_t)body_off;
				rr->remove = 0u;
				rr->ins = e->data;
				rr->ins_len = e->data_len;
				rule_bump++;
				break;
			default:
				return -1;	/* edit_valid already rejected this */
			}

			/* Confine to the op-array body.  INSERT may sit at the very
			 * end (an append), so the upper bound is inclusive. */
			if ((size_t)rr->offset < body_off ||
			    (size_t)rr->offset + rr->remove > body_end) {
				st->refused_out_of_range++;
				refused = 1;
				break;
			}
			/* Verify the bytes a REPLACE/DELETE claims BEFORE anything is
			 * written, exactly as the fixed-width path does. */
			if (rr->remove > 0u &&
			    memcmp(in + rr->offset, e->orig, rr->remove) != 0) {
				st->refused_orig_diff++;
				refused = 1;
				break;
			}
			nres++;
		}
		if (refused) {
			nres = first;	/* drop this rule's partial edits */
			continue;
		}
		participating[i] = 1;
		ntaking++;
		/* The op count moves only for structure-preserving rules: a raw
		 * rule's OP_* edit deliberately leaves the declared count alone. */
		if (r->mode == NFSP_EDIT_MODE_STRUCT)
			op_bump += rule_bump;
	}

	if (ntaking == 0)
		return 0;

	/* --- structure-preserving op-count fix-up ---
	 *
	 * Recomputed from the live message, never stored: on replay the same
	 * bump is derived from the replayed stream.  It is a structural field,
	 * like the record marker, so it is not verified against a recorded
	 * original. */
	if (op_bump > 0u) {
		uint32_t cur;

		if (opcount_slot == NULL || nres >= sizeof(res) / sizeof(res[0])) {
			for (i = 0; i < nrules; i++)
				if (participating[i])
					stats[i]->refused_unknown_layout++;
			return 0;
		}
		cur = get32(in + opcount_slot->offset);
		if (cur > (uint32_t)-1 - op_bump) {
			for (i = 0; i < nrules; i++)
				if (participating[i])
					stats[i]->refused_out_of_range++;
			return 0;
		}
		put32(opcount_buf, cur + op_bump);
		res[nres].offset = opcount_slot->offset;
		res[nres].remove = 4u;
		res[nres].ins = opcount_buf;
		res[nres].ins_len = 4u;
		res[nres].order = -1;	/* sorts first among equal offsets */
		nres++;
	}

	sort_resolved(res, nres);
	for (i = 1; i < nres; i++)
		if ((size_t)res[i - 1].offset + res[i - 1].remove > res[i].offset) {
			for (j = 0; j < nrules; j++)
				if (participating[j])
					stats[j]->refused_overlap++;
			return 0;
		}

	/* --- final length, bounded by the caller's buffer ---
	 *
	 * Accumulate against in_len + inserted first so the subtraction cannot
	 * wrap: every removed span lies inside the message (range-checked). */
	grown = in_len;
	for (i = 0; i < nres; i++) {
		grown += res[i].ins_len;
		grown -= res[i].remove;
	}
	if (grown < NFSP_FRAG_HEADER_LEN || grown > out_cap ||
	    grown - NFSP_FRAG_HEADER_LEN > NFSP_FRAG_LEN_MASK) {
		for (j = 0; j < nrules; j++)
			if (participating[j])
				stats[j]->refused_too_big++;
		return 0;
	}

	/* --- rebuild the record once, in offset order --- */
	cursor = 0;
	o = 0;
	for (i = 0; i < nres; i++) {
		size_t span = (size_t)res[i].offset - cursor;

		memcpy(out + o, in + cursor, span);
		o += span;
		if (res[i].ins_len > 0u) {
			memcpy(out + o, res[i].ins, res[i].ins_len);
			o += res[i].ins_len;
		}
		cursor = (size_t)res[i].offset + res[i].remove;
	}
	memcpy(out + o, in + cursor, in_len - cursor);
	o += in_len - cursor;

	/* Rebuild the record marker from the final length: one last fragment. */
	put32(out, (uint32_t)(o - NFSP_FRAG_HEADER_LEN) | NFSP_LAST_FRAGMENT);

	*out_len = o;
	for (i = 0; i < nrules; i++)
		if (participating[i])
			stats[i]->applied++;
	return (int)ntaking;
}

int nfsp_apply_edit_rule(const struct nfsp_edit_rule *r,
			 const struct nfsp_msg_ctx *ctx,
			 const struct nfsp_walk *walk,
			 const uint8_t *in, size_t in_len,
			 uint8_t *out, size_t out_cap, size_t *out_len,
			 struct nfsp_edit_stats *st)
{
	struct nfsp_edit_stats *stats[1] = { st };
	const struct nfsp_edit_rule *rules[1] = { r };

	return nfsp_apply_edit_rules(rules, stats, 1, ctx, walk, in, in_len,
				     out, out_cap, out_len);
}

/* ---- delta v2 IO --------------------------------------------------------- */

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)(v >> 32));
	put32(p + 4, (uint32_t)v);
}

static uint64_t get64(const uint8_t *p)
{
	return ((uint64_t)get32(p) << 32) | (uint64_t)get32(p + 4);
}

#define EDIT_DELTA_HEADER_LEN	(8u + 4u + 8u)	/* magic, version, seed */
#define EDIT_REC_HDR_LEN	(10u * 4u)	/* ten u32 header words */
#define EDIT_FIELD_HDR_LEN	(4u * 4u)	/* kind, offset, orig_len, data_len */
/* applied_count is the ninth header word, updated in place like the v1 path. */
#define EDIT_APPLIED_OFF	(8u * 4u)

struct nfsp_edit_writer {
	int		fd;
	uint64_t	seed;
	long		count;
	off_t		*offsets;
	size_t		capacity;
	int		saved_errno;
};

/* Serialised size of one record: header, anchor, then each edit's header and
 * its orig/data bytes.  Bounded by the rule validity caps. */
static size_t rec_size(const struct nfsp_edit_rule *r)
{
	size_t n = EDIT_REC_HDR_LEN + r->anchor_len;
	uint32_t i;

	for (i = 0; i < r->nedits; i++)
		n += EDIT_FIELD_HDR_LEN + r->edits[i].orig_len +
		     r->edits[i].data_len;
	return n;
}

int nfsp_edit_write_open(struct nfsp_edit_writer **out, const char *path,
			 uint64_t seed)
{
	uint8_t hdr[EDIT_DELTA_HEADER_LEN];
	struct nfsp_edit_writer *w;

	if (out == NULL || path == NULL)
		return -1;
	w = calloc(1, sizeof(*w));
	if (w == NULL)
		return -1;
	w->fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_SYNC, 0644);
	if (w->fd < 0) {
		w->saved_errno = errno;
		free(w);
		return -1;
	}
	w->seed = seed;
	memcpy(hdr, NFSP_EDIT_DELTA_MAGIC, 8);
	put32(hdr + 8, NFSP_EDIT_DELTA_VERSION);
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

int nfsp_edit_write_rule(struct nfsp_edit_writer *w,
			 const struct nfsp_edit_rule *r)
{
	uint8_t *rec;
	size_t n = 0, total;
	off_t pos;
	uint32_t i;

	if (w == NULL || r == NULL || !nfsp_edit_rule_valid(r))
		return -1;
	if ((size_t)w->count == w->capacity) {
		size_t capacity = w->capacity ? w->capacity * 2u : 16u;
		off_t *offsets;
		if (capacity < w->capacity || capacity > SIZE_MAX / sizeof(*offsets))
			return -1;
		offsets = realloc(w->offsets, capacity * sizeof(*offsets));
		if (offsets == NULL)
			return -1;
		w->offsets = offsets;
		w->capacity = capacity;
	}
	total = rec_size(r);
	rec = malloc(total);
	if (rec == NULL)
		return -1;
	pos = lseek(w->fd, 0, SEEK_END);
	if (pos < 0) {
		free(rec);
		return -1;
	}

	put32(rec + n, r->dir);			n += 4;
	put32(rec + n, r->backend);		n += 4;
	put32(rec + n, r->client);		n += 4;
	put32(rec + n, r->first_opcode);	n += 4;
	put32(rec + n, r->anchor_off);		n += 4;
	put32(rec + n, r->anchor_len);		n += 4;
	put32(rec + n, r->mode);		n += 4;
	put32(rec + n, r->nedits);		n += 4;
	put32(rec + n, r->applied_count);	n += 4;	/* EDIT_APPLIED_OFF */
	put32(rec + n, 0u);			n += 4;	/* reserved */
	memcpy(rec + n, r->anchor, r->anchor_len);	n += r->anchor_len;
	for (i = 0; i < r->nedits; i++) {
		const struct nfsp_edit *e = &r->edits[i];

		put32(rec + n, e->kind);	n += 4;
		put32(rec + n, e->offset);	n += 4;
		put32(rec + n, e->orig_len);	n += 4;
		put32(rec + n, e->data_len);	n += 4;
		memcpy(rec + n, e->orig, e->orig_len);	n += e->orig_len;
		memcpy(rec + n, e->data, e->data_len);	n += e->data_len;
	}

	if (write(w->fd, rec, n) != (ssize_t)n) {
		w->saved_errno = errno;
		free(rec);
		return -1;
	}
	free(rec);
	w->offsets[w->count] = pos;
	w->count++;
	return 0;
}

int nfsp_edit_write_applied_count(struct nfsp_edit_writer *w, long index,
				  uint32_t applied_count)
{
	uint8_t count[4];
	off_t pos;

	if (w == NULL || index < 0 || index >= w->count)
		return -1;
	pos = w->offsets[index] + EDIT_APPLIED_OFF;
	put32(count, applied_count);
	if (pwrite(w->fd, count, sizeof(count), pos) != (ssize_t)sizeof(count)) {
		w->saved_errno = errno;
		return -1;
	}
	return 0;
}

long nfsp_edit_write_close(struct nfsp_edit_writer *w)
{
	long n;

	if (w == NULL)
		return -1;
	n = w->count;
	if (fsync(w->fd) != 0 && w->saved_errno == 0)
		w->saved_errno = errno;
	close(w->fd);
	free(w->offsets);
	free(w);
	return n;
}

struct nfsp_edit_reader {
	int		fd;
	uint64_t	seed;
	int		eof;
	int		corrupt;
};

static int read_full(int fd, uint8_t *p, size_t n)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);

		if (r == 0)
			return got == 0 ? 0 : -1;	/* short record != EOF */
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		got += (size_t)r;
	}
	return 1;
}

int nfsp_edit_read_open(struct nfsp_edit_reader **out, const char *path)
{
	uint8_t hdr[EDIT_DELTA_HEADER_LEN];
	struct nfsp_edit_reader *r;
	int rc;

	if (out == NULL || path == NULL)
		return -1;
	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return -1;
	r->fd = open(path, O_RDONLY);
	if (r->fd < 0) {
		free(r);
		return -1;
	}
	rc = read_full(r->fd, hdr, sizeof(hdr));
	if (rc != 1 || memcmp(hdr, NFSP_EDIT_DELTA_MAGIC, 8) != 0 ||
	    get32(hdr + 8) != NFSP_EDIT_DELTA_VERSION) {
		close(r->fd);
		free(r);
		errno = EINVAL;
		return -1;
	}
	r->seed = get64(hdr + 12);
	*out = r;
	return 0;
}

int nfsp_edit_read_rule(struct nfsp_edit_reader *r, struct nfsp_edit_rule *out)
{
	uint8_t hdr[EDIT_REC_HDR_LEN];
	uint8_t fh[EDIT_FIELD_HDR_LEN];
	uint32_t anchor_len, i;
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
		return -1;
	}
	memset(out, 0, sizeof(*out));
	out->dir		= get32(hdr + 0);
	out->backend		= get32(hdr + 4);
	out->client		= get32(hdr + 8);
	out->first_opcode	= get32(hdr + 12);
	out->anchor_off		= get32(hdr + 16);
	anchor_len		= get32(hdr + 20);
	out->mode		= get32(hdr + 24);
	out->nedits		= get32(hdr + 28);
	out->applied_count	= get32(hdr + 32);
	out->anchor_len		= anchor_len;

	/* Validate declared sizes BEFORE reading the variable parts. */
	if (anchor_len > NFSP_DELTA_ANCHOR_MAX ||
	    out->nedits == 0u || out->nedits > NFSP_EDIT_MAX) {
		r->corrupt = 1;
		errno = EINVAL;
		return -1;
	}
	if (anchor_len > 0u && read_full(r->fd, out->anchor, anchor_len) != 1) {
		r->corrupt = 1;
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < out->nedits; i++) {
		struct nfsp_edit *e = &out->edits[i];

		if (read_full(r->fd, fh, sizeof(fh)) != 1) {
			r->corrupt = 1;
			errno = EINVAL;
			return -1;
		}
		e->kind = get32(fh + 0);
		e->offset = get32(fh + 4);
		e->orig_len = get32(fh + 8);
		e->data_len = get32(fh + 12);
		if (e->orig_len > NFSP_EDIT_BYTES_MAX ||
		    e->data_len > NFSP_EDIT_BYTES_MAX) {
			r->corrupt = 1;
			errno = EINVAL;
			return -1;
		}
		if ((e->orig_len > 0u &&
		     read_full(r->fd, e->orig, e->orig_len) != 1) ||
		    (e->data_len > 0u &&
		     read_full(r->fd, e->data, e->data_len) != 1)) {
			r->corrupt = 1;
			errno = EINVAL;
			return -1;
		}
	}
	if (!nfsp_edit_rule_valid(out)) {
		r->corrupt = 1;
		errno = EINVAL;
		return -1;
	}
	return 1;
}

void nfsp_edit_read_close(struct nfsp_edit_reader *r)
{
	if (r == NULL)
		return;
	close(r->fd);
	free(r);
}
