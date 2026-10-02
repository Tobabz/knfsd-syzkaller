#define _POSIX_C_SOURCE 200809L
#include "control.h"
#include "walk.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define NFSP_ARM_SLOTS 64u

/* One armed rule, either v1 (fixed-width overwrite) or v2 (variable-length
 * edit list).  `is_edit` selects which of the two payloads/stats/writer
 * fields is live; the other is zeroed and unused.  A tagged pair of fields
 * rather than a true union, so each format keeps its own type without a cast. */
struct arm {
	int fd;
	int armed;
	int is_edit;
	struct nfsp_rule rule;
	struct nfsp_apply_stats stats;
	struct nfsp_delta_writer *writer;
	struct nfsp_edit_rule edit;
	struct nfsp_edit_stats edit_stats;
	struct nfsp_edit_writer *edit_writer;
};

struct nfsp_control {
	int listener;
	char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	const char *delta_dir;
	int replay;
	struct arm arms[NFSP_ARM_SLOTS];
	uint64_t next_id;
	uint32_t registrations, expirations, applied, refused_orig;
	uint32_t refused_bounds, unknown_layout, invalid_arms;
	/* v2 counterparts of applied/refused_orig/refused_bounds/unknown_layout,
	 * plus the two refusal reasons that have no v1 equivalent (overlap
	 * between two rules' edits, and an output too large for this record's
	 * scratch buffer).  Kept separate from the v1 fields rather than shared,
	 * because collapsing "a same-width patch was refused" and "a
	 * length-changing edit was refused" into one counter would hide which
	 * engine actually produced a given trial's refusals. */
	uint32_t edit_applied, edit_refused_orig, edit_refused_bounds;
	uint32_t edit_refused_unknown, edit_refused_overlap, edit_refused_toobig;
	/* Scratch buffers reused across calls (single-threaded event loop, so one
	 * buffer per kind is enough).  v1_buf holds a working copy of the record
	 * so v1's same-width patches never touch the caller's read-only buffer;
	 * edit_buf holds the possibly longer-or-shorter rebuild the edit pass
	 * produces.  Both grow on demand and are freed once, in
	 * nfsp_control_close. */
	uint8_t *v1_buf;
	size_t v1_cap;
	uint8_t *edit_buf;
	size_t edit_cap;
};

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int ensure_cap(uint8_t **buf, size_t *cap, size_t need)
{
	uint8_t *grown;
	if (need <= *cap)
		return 0;
	grown = realloc(*buf, need);
	if (grown == NULL)
		return -1;
	*buf = grown;
	*cap = need;
	return 0;
}

static void release_arm(struct nfsp_control *s, struct arm *a)
{
	if (a->fd >= 0)
		close(a->fd);
	if (a->armed) {
		if (a->is_edit) {
			if (a->edit_writer != NULL)
				(void)nfsp_edit_write_close(a->edit_writer);
		} else {
			if (a->writer != NULL)
				(void)nfsp_delta_write_close(a->writer);
		}
		s->expirations++;
	}
	memset(a, 0, sizeof(*a));
	a->fd = -1;
}

static int decode_v1(const uint8_t *buf, size_t len, struct nfsp_rule *r)
{
	uint32_t words[NFSP_ARM_WORDS];
	if (len != NFSP_ARM_WIRE_LEN || memcmp(buf, NFSP_ARM_MAGIC, 8) != 0)
		return -1;
	for (unsigned i = 0; i < NFSP_ARM_WORDS; i++)
		words[i] = get32(buf + 8u + 4u * i);
	memset(r, 0, sizeof(*r));
	r->dir = words[0];
	r->backend = words[1];
	r->client = words[2];
	r->first_opcode = words[3];
	r->match_index = NFSP_DELTA_MATCH_ANY;
	r->anchor_off = words[4];
	r->anchor_len = words[5];
	r->patch_off = words[6];
	r->patch_w = words[7];
	if (words[8] != 0 || r->patch_off < 4 || !nfsp_rule_valid(r))
		return -1;
	memcpy(r->anchor, buf + 8u + 4u * NFSP_ARM_WORDS, NFSP_DELTA_ANCHOR_MAX);
	memcpy(r->orig, buf + 8u + 4u * NFSP_ARM_WORDS + NFSP_DELTA_ANCHOR_MAX,
	       NFSP_DELTA_PATCH_MAX);
	memcpy(r->repl, buf + 8u + 4u * NFSP_ARM_WORDS + NFSP_DELTA_ANCHOR_MAX +
	       NFSP_DELTA_PATCH_MAX, NFSP_DELTA_PATCH_MAX);
	if (memcmp(r->orig, r->repl, r->patch_w) == 0)
		return -1;
	return 0;
}

/* Self-describing, unlike v1: the header says how many edits follow and each
 * edit says its own byte counts, so the only external input to parsing is
 * `len` itself.  Every declared size is checked against the bytes actually
 * present BEFORE it is used to advance the cursor or sized a memcpy, and the
 * cursor must land exactly on `len` at the end -- a packet that understates
 * its own length is rejected rather than silently read with trailing bytes
 * ignored, which would let a future field be added without ever being seen
 * by an older proxy build. */
static int decode_v2(const uint8_t *buf, size_t len, struct nfsp_edit_rule *r)
{
	uint32_t words[NFSP_EDIT_ARM_HDR_WORDS];
	size_t off = 8u;
	uint32_t i;

	if (len < NFSP_EDIT_ARM_HDR_LEN || memcmp(buf, NFSP_EDIT_ARM_MAGIC, 8) != 0)
		return -1;
	for (i = 0; i < NFSP_EDIT_ARM_HDR_WORDS; i++) {
		words[i] = get32(buf + off);
		off += 4u;
	}
	memset(r, 0, sizeof(*r));
	r->dir = words[0];
	r->backend = words[1];
	r->client = words[2];
	r->first_opcode = words[3];
	r->anchor_off = words[4];
	r->anchor_len = words[5];
	r->mode = words[6];
	r->nedits = words[7];
	if (words[8] != 0)		/* reserved */
		return -1;
	if (r->anchor_len > NFSP_DELTA_ANCHOR_MAX || off + r->anchor_len > len)
		return -1;
	memcpy(r->anchor, buf + off, r->anchor_len);
	off += r->anchor_len;
	if (r->nedits == 0u || r->nedits > NFSP_EDIT_MAX)
		return -1;
	for (i = 0; i < r->nedits; i++) {
		struct nfsp_edit *e = &r->edits[i];
		if (off + NFSP_EDIT_ARM_FIELD_HDR_LEN > len)
			return -1;
		e->kind = get32(buf + off);
		e->offset = get32(buf + off + 4u);
		e->orig_len = get32(buf + off + 8u);
		e->data_len = get32(buf + off + 12u);
		off += NFSP_EDIT_ARM_FIELD_HDR_LEN;
		if (e->orig_len > NFSP_EDIT_BYTES_MAX || off + e->orig_len > len)
			return -1;
		memcpy(e->orig, buf + off, e->orig_len);
		off += e->orig_len;
		if (e->data_len > NFSP_EDIT_BYTES_MAX || off + e->data_len > len)
			return -1;
		memcpy(e->data, buf + off, e->data_len);
		off += e->data_len;
	}
	if (off != len)
		return -1;
	if (!nfsp_edit_rule_valid(r))
		return -1;
	return 0;
}

int nfsp_control_open(struct nfsp_control **out, const char *socket_path,
		      const char *delta_dir, const char *replay_path)
{
	struct nfsp_control *s;
	struct sockaddr_un sa = {0};
	int fd = -1;
	int bound = 0;
	if (out == NULL || ((socket_path == NULL || delta_dir == NULL) &&
			(socket_path != NULL || delta_dir != NULL)) ||
	    (replay_path != NULL && (socket_path != NULL || delta_dir != NULL)) ||
	    (socket_path == NULL && replay_path == NULL))
		return -1;
	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return -1;
	s->listener = -1;
	for (unsigned i = 0; i < NFSP_ARM_SLOTS; i++) s->arms[i].fd = -1;
	if (replay_path != NULL) {
		struct nfsp_delta_reader *rd = NULL;
		struct nfsp_edit_reader *erd = NULL;
		int rc;
		/* A delta file is homogeneous: its magic is checked once, at the
		 * top, so the file is either all v1 records or all v2 records.
		 * Try v1 first (matches the format every existing delta file on
		 * disk uses); a bad magic there means try v2 before giving up. */
		if (nfsp_delta_read_open(&rd, replay_path) == 0) {
			while ((rc = nfsp_delta_read_rule(rd,
				&s->arms[s->registrations < NFSP_ARM_SLOTS ? s->registrations : 0].rule)) == 1) {
				if (s->registrations >= NFSP_ARM_SLOTS ||
				    !nfsp_rule_valid(&s->arms[s->registrations].rule) ||
				    s->arms[s->registrations].rule.match_index != NFSP_DELTA_MATCH_ANY) {
					nfsp_delta_read_close(rd);
					goto fail;
				}
				s->arms[s->registrations++].armed = 1;
			}
			nfsp_delta_read_close(rd);
			if (rc < 0 || s->registrations == 0) goto fail;
		} else if (nfsp_edit_read_open(&erd, replay_path) == 0) {
			while ((rc = nfsp_edit_read_rule(erd,
				&s->arms[s->registrations < NFSP_ARM_SLOTS ? s->registrations : 0].edit)) == 1) {
				if (s->registrations >= NFSP_ARM_SLOTS ||
				    !nfsp_edit_rule_valid(&s->arms[s->registrations].edit)) {
					nfsp_edit_read_close(erd);
					goto fail;
				}
				s->arms[s->registrations].is_edit = 1;
				s->arms[s->registrations++].armed = 1;
			}
			nfsp_edit_read_close(erd);
			if (rc < 0 || s->registrations == 0) goto fail;
		} else {
			goto fail;
		}
		s->replay = 1;
		*out = s;
		return 0;
	}
	if (strlen(socket_path) >= sizeof(sa.sun_path)) goto fail;
	if (access(socket_path, F_OK) == 0 || errno != ENOENT) goto fail;
	if (access(delta_dir, W_OK | X_OK) != 0) goto fail;
	s->delta_dir = delta_dir;
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, socket_path, strlen(socket_path) + 1u);
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0 || nonblock(fd) != 0 ||
	    bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) goto fail;
	bound = 1;
	if (chmod(socket_path, 0600) != 0 || listen(fd, 32) != 0) goto fail;
	s->listener = fd;
	memcpy(s->socket_path, socket_path, strlen(socket_path) + 1u);
	*out = s;
	return 0;
fail:
	if (fd >= 0) close(fd);
	if (bound) unlink(socket_path);
	free(s);
	return -1;
}

static int arm_from_packet(struct nfsp_control *s, struct arm *a,
			   const uint8_t *buf, size_t len)
{
	struct nfsp_rule rule;
	struct nfsp_edit_rule edit;
	char path[PATH_MAX];
	uint8_t ack = 0;
	int is_edit;

	/* Dispatch purely on magic: the two formats' first 8 bytes can never
	 * collide, so there is no length-based ambiguity to resolve. */
	if (len >= 8u && memcmp(buf, NFSP_ARM_MAGIC, 8) == 0) {
		if (decode_v1(buf, len, &rule) != 0) return -1;
		is_edit = 0;
	} else if (len >= 8u && memcmp(buf, NFSP_EDIT_ARM_MAGIC, 8) == 0) {
		if (decode_v2(buf, len, &edit) != 0) return -1;
		is_edit = 1;
	} else {
		return -1;
	}
	if (snprintf(path, sizeof(path), "%s/arm-%llu.delta", s->delta_dir,
		     (unsigned long long)s->next_id) >= (int)sizeof(path)) return -1;
	/* A fresh fixture directory and monotonically numbered filename keep
	 * separate arms separate; never overwrite an existing delta. */
	if (access(path, F_OK) == 0 || errno != ENOENT) return -1;
	if (is_edit) {
		struct nfsp_edit_writer *writer = NULL;
		if (nfsp_edit_write_open(&writer, path, 0) != 0) return -1;
		if (nfsp_edit_write_rule(writer, &edit) != 0 ||
		    send(a->fd, &ack, 1, MSG_NOSIGNAL | MSG_DONTWAIT) != 1) {
			(void)nfsp_edit_write_close(writer);
			unlink(path);
			return -1;
		}
		a->is_edit = 1;
		a->edit = edit;
		a->edit_writer = writer;
	} else {
		struct nfsp_delta_writer *writer = NULL;
		if (nfsp_delta_write_open(&writer, path, 0) != 0) return -1;
		if (nfsp_delta_write_rule(writer, &rule) != 0 ||
		    send(a->fd, &ack, 1, MSG_NOSIGNAL | MSG_DONTWAIT) != 1) {
			(void)nfsp_delta_write_close(writer);
			unlink(path);
			return -1;
		}
		a->is_edit = 0;
		a->rule = rule;
		a->writer = writer;
	}
	a->armed = 1;
	s->next_id++;
	s->registrations++;
	return 0;
}

void nfsp_control_tick(void *state)
{
	struct nfsp_control *s = state;
	if (s == NULL || s->replay) return;
	for (unsigned n = 0; n < NFSP_ARM_SLOTS; n++) {
		int fd = accept(s->listener, NULL, NULL);
		struct arm *free_slot = NULL;
		if (fd < 0) break;
		for (unsigned j = 0; j < NFSP_ARM_SLOTS; j++)
			if (s->arms[j].fd < 0) { free_slot = &s->arms[j]; break; }
		if (free_slot == NULL || nonblock(fd) != 0) {
			close(fd);
			s->invalid_arms++;
		} else {
			free_slot->fd = fd;
		}
	}
	for (unsigned i = 0; i < NFSP_ARM_SLOTS; i++) {
		struct arm *a = &s->arms[i];
		/* Sized for the larger of the two formats (v2, which is
		 * variable-length up to this bound); a v1 packet is simply a
		 * shorter datagram on the same buffer. */
		uint8_t buf[NFSP_EDIT_ARM_MAX_LEN];
		ssize_t n;
		if (a->fd < 0) continue;
		n = recv(a->fd, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
		/* MSG_TRUNC reports the true datagram size even when it exceeds
		 * the buffer; only bytes up to sizeof(buf) were actually copied,
		 * so n > sizeof(buf) must be rejected before it is ever used as a
		 * length into buf. */
		if (n > 0 && (size_t)n <= sizeof(buf) && !a->armed &&
		    arm_from_packet(s, a, buf, (size_t)n) == 0) continue;
		if (n != 0 || !a->armed) s->invalid_arms++;
		release_arm(s, a);
	}
}

static int patch_allowed(const struct nfsp_walk *walk,
			 const struct nfsp_rule *rule)
{
	size_t begin = rule->patch_off, end = begin + rule->patch_w;
	if (walk->status != NFSP_WALK_OK) return 0;
	for (size_t i = 0; i < walk->nslots; i++)
		if (begin == walk->slots[i].offset && rule->patch_w == 4u) return 1;
	for (size_t i = 0; i < walk->nregions; i++)
		if (walk->regions[i].role != NFSP_RR_TRAILER &&
		    begin >= walk->regions[i].offset &&
		    end <= (size_t)walk->regions[i].offset + walk->regions[i].len)
			return 1;
	return 0;
}

int nfsp_control_record(unsigned client, unsigned backend, int dir,
			const uint8_t *record, size_t len,
			const uint8_t **out, size_t *out_len, void *state)
{
	struct nfsp_control *s = state;
	struct nfsp_walk walk;
	struct nfsp_msg_ctx ctx;
	const struct nfsp_slot *first;
	const struct nfsp_edit_rule *edit_rules[NFSP_ARM_SLOTS];
	struct nfsp_edit_stats *edit_stats_ptrs[NFSP_ARM_SLOTS];
	struct nfsp_edit_stats edit_before[NFSP_ARM_SLOTS];
	unsigned edit_arm_index[NFSP_ARM_SLOTS];
	size_t nedit = 0;
	int needs_walk = 0, has_v1 = 0, has_edit = 0;
	unsigned i;

	if (s == NULL) return 0;
	nfsp_control_tick(s);
	for (i = 0; i < NFSP_ARM_SLOTS; i++) {
		struct arm *a = &s->arms[i];
		if (!a->armed) continue;
		if (a->is_edit) {
			if (a->edit.client == client && a->edit.backend == backend &&
			    a->edit.dir == (uint32_t)dir) {
				needs_walk = 1;
				has_edit = 1;
			}
		} else {
			if (a->rule.client == client && a->rule.backend == backend &&
			    a->rule.dir == (uint32_t)dir) {
				needs_walk = 1;
				has_v1 = 1;
			}
		}
	}
	if (!needs_walk) return 0;

	/* nfsp_walk() always returns 0 (see walk.h); the check mirrors the
	 * pre-existing defensive style rather than claiming a real failure
	 * mode. */
	if (nfsp_walk(record, len, &walk) != 0) {
		s->unknown_layout++;
		return 0;
	}
	first = nfsp_walk_find(&walk, NFSP_SR_FIRST_OPCODE);
	/* ctx identifies the INCOMING record and never changes as rules are
	 * applied below, for both engines: a predicate must match the record
	 * the caller actually sent, not an intermediate mutated state. */
	ctx = (struct nfsp_msg_ctx){(uint32_t)dir, backend, client,
		first == NULL ? NFSP_DELTA_OPCODE_ANY : get32(record + first->offset)};

	/* `record` is read-only (proxy.h); v1 rules patch in place, so they
	 * patch a working copy instead.  The walk above was computed from
	 * `record` and stays valid for this copy because v1 patches are
	 * same-width overwrites: they change byte VALUES, never the length or
	 * layout the walk described. */
	if (ensure_cap(&s->v1_buf, &s->v1_cap, len) != 0) return -1;
	memcpy(s->v1_buf, record, len);

	if (has_v1) {
		if (walk.status != NFSP_WALK_OK) {
			/* One counted reason for every v1 rule this record could
			 * have matched: the walk could not place either a typed
			 * slot or a raw region to check patch_allowed against. */
			s->unknown_layout++;
		} else {
			for (i = 0; i < NFSP_ARM_SLOTS; i++) {
				struct arm *a = &s->arms[i];
				uint32_t orig_diff, bounds;
				int rc;
				if (!a->armed || a->is_edit ||
				    a->rule.client != client || a->rule.backend != backend ||
				    a->rule.dir != (uint32_t)dir) continue;
				if (!patch_allowed(&walk, &a->rule)) {
					s->unknown_layout++;
					continue;
				}
				orig_diff = a->stats.refused_orig_diff;
				bounds = a->stats.refused_out_of_range;
				rc = nfsp_apply_rule(&a->rule, &ctx, s->v1_buf, len, &a->stats);
				if (rc < 0) return -1;
				s->refused_orig += a->stats.refused_orig_diff - orig_diff;
				s->refused_bounds += a->stats.refused_out_of_range - bounds;
				if (rc == 1) {
					s->applied++;
					if (a->writer != NULL && nfsp_delta_write_applied_count(
						a->writer, 0, a->stats.applied) != 0) return -1;
				}
			}
		}
	}

	/* Baseline: the record after any same-width v1 patches (or untouched,
	 * if none applied or none matched).  The edit pass below may replace
	 * this with a rebuilt record of a different length; if there is no
	 * edit arm for this tuple, this is the final answer. */
	*out = s->v1_buf;
	*out_len = len;
	if (!has_edit)
		return 0;

	for (i = 0; i < NFSP_ARM_SLOTS; i++) {
		struct arm *a = &s->arms[i];
		if (!a->armed || !a->is_edit || a->edit.client != client ||
		    a->edit.backend != backend || a->edit.dir != (uint32_t)dir)
			continue;
		edit_rules[nedit] = &a->edit;
		edit_stats_ptrs[nedit] = &a->edit_stats;
		edit_before[nedit] = a->edit_stats;
		edit_arm_index[nedit] = i;
		nedit++;
	}
	if (nedit == 0)
		return 0;

	{
		/* An upper bound on the rebuilt record: every candidate rule's
		 * inserted bytes, on top of the input length.  Generous on
		 * purpose (it does not subtract what DELETE/REPLACE remove, and
		 * it sizes for every candidate whether or not its predicate or
		 * verification ultimately lets it apply) so the edit pass below
		 * can never run out of room for a reason internal to this
		 * buffer; the proxy's own message-size ceiling is enforced
		 * afterwards, in proxy.c, against the connection's actual
		 * limit. */
		size_t out_cap = len;
		int rc;
		unsigned j;

		for (i = 0; i < (unsigned)nedit; i++)
			for (j = 0; j < edit_rules[i]->nedits; j++)
				out_cap += edit_rules[i]->edits[j].data_len;
		if (ensure_cap(&s->edit_buf, &s->edit_cap, out_cap) != 0) return -1;

		/* Anchors and offsets for the edit pass are read against
		 * s->v1_buf, i.e. AFTER any same-width v1 patches above: one
		 * proxy process produces one final record reflecting every
		 * armed rule, and a v2 edit is allowed to target a byte a v1
		 * rule on the same connection just set. */
		rc = nfsp_apply_edit_rules(edit_rules, edit_stats_ptrs, nedit, &ctx,
					   &walk, s->v1_buf, len, s->edit_buf,
					   s->edit_cap, out_len);
		if (rc < 0) return -1;
		for (i = 0; i < (unsigned)nedit; i++) {
			struct arm *a = &s->arms[edit_arm_index[i]];
			const struct nfsp_edit_stats *cur = &a->edit_stats;
			const struct nfsp_edit_stats *before = &edit_before[i];
			s->edit_applied += cur->applied - before->applied;
			s->edit_refused_orig += cur->refused_orig_diff - before->refused_orig_diff;
			s->edit_refused_bounds += cur->refused_out_of_range - before->refused_out_of_range;
			s->edit_refused_unknown += cur->refused_unknown_layout - before->refused_unknown_layout;
			s->edit_refused_overlap += cur->refused_overlap - before->refused_overlap;
			s->edit_refused_toobig += cur->refused_too_big - before->refused_too_big;
			if (cur->applied != before->applied && a->edit_writer != NULL &&
			    nfsp_edit_write_applied_count(a->edit_writer, 0,
				cur->applied) != 0)
				return -1;
		}
		if (rc > 0)
			*out = s->edit_buf;
		/* rc == 0: no edit rule applied (all refused or none matched);
		 * *out / *out_len keep the v1 baseline set above. */
	}
	return 0;
}

void nfsp_control_report(const struct nfsp_control *s)
{
	if (s == NULL) return;
	printf("control mode=%s armed=%u expired=%u applied=%u refused_orig=%u "
	       "refused_bounds=%u unknown_layout=%u invalid_arms=%u "
	       "edit_applied=%u edit_refused_orig=%u edit_refused_bounds=%u "
	       "edit_refused_unknown=%u edit_refused_overlap=%u edit_refused_toobig=%u\n",
	       s->replay ? "replay" : "live", s->registrations, s->expirations,
	       s->applied, s->refused_orig, s->refused_bounds, s->unknown_layout,
	       s->invalid_arms, s->edit_applied, s->edit_refused_orig,
	       s->edit_refused_bounds, s->edit_refused_unknown,
	       s->edit_refused_overlap, s->edit_refused_toobig);
	if (s->replay)
		for (unsigned i = 0; i < s->registrations; i++) {
			const struct arm *a = &s->arms[i];
			if (a->is_edit)
				printf("replay rule=%u edit=1 expected=%u applied=%u refused_orig=%u\n",
				       i, a->edit.applied_count, a->edit_stats.applied,
				       a->edit_stats.refused_orig_diff);
			else
				printf("replay rule=%u edit=0 expected=%u applied=%u refused_orig=%u\n",
				       i, a->rule.applied_count, a->stats.applied,
				       a->stats.refused_orig_diff);
		}
	fflush(stdout);
}

int nfsp_control_close(struct nfsp_control *s)
{
	int rc = 0;
	if (s == NULL) return 0;
	if (s->replay) {
		for (unsigned i = 0; i < s->registrations; i++) {
			const struct arm *a = &s->arms[i];
			if (a->is_edit) {
				if (a->edit_stats.applied != a->edit.applied_count ||
				    a->edit_stats.refused_orig_diff != 0) rc = -1;
			} else {
				if (a->stats.applied != a->rule.applied_count ||
				    a->stats.refused_orig_diff != 0) rc = -1;
			}
		}
	} else if (s->listener >= 0) {
		for (unsigned i = 0; i < NFSP_ARM_SLOTS; i++)
			if (s->arms[i].fd >= 0) release_arm(s, &s->arms[i]);
		close(s->listener);
		unlink(s->socket_path);
	}
	free(s->v1_buf);
	free(s->edit_buf);
	free(s);
	return rc;
}
