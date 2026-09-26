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

struct arm {
	int fd;
	int armed;
	struct nfsp_rule rule;
	struct nfsp_apply_stats stats;
	struct nfsp_delta_writer *writer;
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

static void release_arm(struct nfsp_control *s, struct arm *a)
{
	if (a->fd >= 0)
		close(a->fd);
	if (a->armed) {
		if (a->writer != NULL)
			(void)nfsp_delta_write_close(a->writer);
		s->expirations++;
	}
	memset(a, 0, sizeof(*a));
	a->fd = -1;
}

static int decode(const uint8_t *buf, size_t len, struct nfsp_rule *r)
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
		int rc;
		if (nfsp_delta_read_open(&rd, replay_path) != 0) goto fail;
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
	struct nfsp_delta_writer *writer = NULL;
	char path[PATH_MAX];
	uint8_t ack = 0;
	if (decode(buf, len, &rule) != 0) return -1;
	if (snprintf(path, sizeof(path), "%s/arm-%llu.delta", s->delta_dir,
		     (unsigned long long)s->next_id) >= (int)sizeof(path)) return -1;
	/* A fresh fixture directory and monotonically numbered filename keep
	 * separate arms separate; never overwrite an existing delta. */
	if (access(path, F_OK) == 0 || errno != ENOENT) return -1;
	if (nfsp_delta_write_open(&writer, path, 0) != 0) return -1;
	if (nfsp_delta_write_rule(writer, &rule) != 0 ||
	    send(a->fd, &ack, 1, MSG_NOSIGNAL | MSG_DONTWAIT) != 1) {
		(void)nfsp_delta_write_close(writer);
		unlink(path);
		return -1;
	}
	a->rule = rule;
	a->writer = writer;
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
		uint8_t buf[NFSP_ARM_WIRE_LEN];
		ssize_t n;
		if (a->fd < 0) continue;
		n = recv(a->fd, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
		if (n == (ssize_t)sizeof(buf) && !a->armed &&
		    arm_from_packet(s, a, buf, sizeof(buf)) == 0) continue;
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
			uint8_t *record, size_t len, void *state)
{
	struct nfsp_control *s = state;
	struct nfsp_walk walk;
	struct nfsp_msg_ctx ctx;
	const struct nfsp_slot *first;
	int needs_walk = 0;
	if (s == NULL) return 0;
	nfsp_control_tick(s);
	for (unsigned i = 0; i < NFSP_ARM_SLOTS; i++)
		if (s->arms[i].armed && s->arms[i].rule.client == client &&
		    s->arms[i].rule.backend == backend && s->arms[i].rule.dir == (uint32_t)dir)
			needs_walk = 1;
	if (!needs_walk) return 0;
	if (nfsp_walk(record, len, &walk) != 0 || walk.status != NFSP_WALK_OK) {
		s->unknown_layout++;
		return 0;
	}
	first = nfsp_walk_find(&walk, NFSP_SR_FIRST_OPCODE);
	ctx = (struct nfsp_msg_ctx){(uint32_t)dir, backend, client,
		first == NULL ? NFSP_DELTA_OPCODE_ANY : get32(record + first->offset)};
	for (unsigned i = 0; i < NFSP_ARM_SLOTS; i++) {
		struct arm *a = &s->arms[i];
		uint32_t orig_diff, bounds;
		int rc;
		if (!a->armed || a->rule.client != client || a->rule.backend != backend ||
		    a->rule.dir != (uint32_t)dir) continue;
		if (!patch_allowed(&walk, &a->rule)) {
			s->unknown_layout++;
			continue;
		}
		orig_diff = a->stats.refused_orig_diff;
		bounds = a->stats.refused_out_of_range;
		rc = nfsp_apply_rule(&a->rule, &ctx, record, len, &a->stats);
		if (rc < 0) return -1;
		s->refused_orig += a->stats.refused_orig_diff - orig_diff;
		s->refused_bounds += a->stats.refused_out_of_range - bounds;
		if (rc == 1) {
			s->applied++;
			if (a->writer != NULL && nfsp_delta_write_applied_count(
				a->writer, 0, a->stats.applied) != 0) return -1;
		}
	}
	return 0;
}

void nfsp_control_report(const struct nfsp_control *s)
{
	if (s == NULL) return;
	printf("control mode=%s armed=%u expired=%u applied=%u refused_orig=%u "
	       "refused_bounds=%u unknown_layout=%u invalid_arms=%u\n",
	       s->replay ? "replay" : "live", s->registrations, s->expirations,
	       s->applied, s->refused_orig, s->refused_bounds, s->unknown_layout,
	       s->invalid_arms);
	if (s->replay)
		for (unsigned i = 0; i < s->registrations; i++)
			printf("replay rule=%u expected=%u applied=%u refused_orig=%u\n",
			       i, s->arms[i].rule.applied_count, s->arms[i].stats.applied,
			       s->arms[i].stats.refused_orig_diff);
	fflush(stdout);
}

int nfsp_control_close(struct nfsp_control *s)
{
	int rc = 0;
	if (s == NULL) return 0;
	if (s->replay) {
		for (unsigned i = 0; i < s->registrations; i++)
			if (s->arms[i].stats.applied != s->arms[i].rule.applied_count ||
			    s->arms[i].stats.refused_orig_diff != 0) rc = -1;
	} else if (s->listener >= 0) {
		for (unsigned i = 0; i < NFSP_ARM_SLOTS; i++)
			if (s->arms[i].fd >= 0) release_arm(s, &s->arms[i]);
		close(s->listener);
		unlink(s->socket_path);
	}
	free(s);
	return rc;
}
