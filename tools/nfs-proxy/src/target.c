/* Target mode (M5).  See target.h. */
#define _POSIX_C_SOURCE 200809L
#include "target.h"

#include "activation.h"
#include "journal.h"
#include "jsonw.h"
#include "mutation_apply.h"
#include "resolver.h"
#include "rpc_decode.h"
#include "rule.h"
#include "semantic.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define NCOUNT		((size_t)NFSP_RESOLVE_STATUS_COUNT + 1u)
#define APPLY_FAILED	((size_t)NFSP_RESOLVE_STATUS_COUNT)
#define MAX_HOLDS	256u
#define MAX_CLIENTS	6u

_Static_assert(NFSP_TARGET_RULES_MAX == NFSP_RULESET_MAX_LEN,
	       "target.h mirrors rule.h");

/* What a journal answer is for: the kind in the top byte of the cookie. */
enum {
	CK_RULESET = 1,
	CK_BARRIER,
	CK_EXPOSURE,
	CK_REFUSAL,
	CK_FORWARD,
	CK_COMPLETE,
	CK_RUN
};
#define COOKIE(kind, id) (((uint64_t)(kind) << 56) | ((uint64_t)(id) & \
			  0x00ffffffffffffffull))
#define COOKIE_KIND(c)	((unsigned)((c) >> 56))
#define COOKIE_ID(c)	((c) & 0x00ffffffffffffffull)

enum ev_state { EV_PENDING = 0, EV_ACKED, EV_REJECTED, EV_LOST };

struct tgen {
	uint64_t generation;
	uint8_t digest[32];
	int draining_acked, complete_sent, drain_deadline_set;
	int open_sent;
	uint64_t open_seq, complete_seq;
	uint64_t drain_deadline;
	uint64_t exposures, evidence_failures, open_batches;
	uint64_t *counts;	/* nrules * NCOUNT */
	uint8_t *refusal;	/* per rule: an APPLY_REFUSAL was queued */
	uint64_t *refusal_seq;
};

enum batch_state { B_PENDING = 0, B_EXPOSED, B_FORWARDING, B_DONE, B_DEAD };

struct tbatch {
	uint64_t generation;
	uint64_t ei_seq;
	enum batch_state state;
	int dropped;
	uint8_t *out;
	size_t out_len;
	int is_call;
	struct nfsp_txn_key key;
};

struct thold {
	int used;
	uint64_t *deps;
	uint32_t ndeps;
	int64_t batch;
};

struct answer {
	int active;
	uint64_t barrier_id;
	uint32_t op;
	uint64_t generation;
	int client;
	void (*cb)(void *, uint32_t, uint64_t, uint32_t);
	void *cb_arg;
};

struct current {
	const struct nfsp_rpc_record *rec;
	const uint8_t *framed;
	size_t framed_len;
	uint64_t call_generation;
	enum nfsp_txn_result txn;
	int txn_seen;
	struct nfsp_relay_verdict *verdict;
	int action;
};

struct nfsp_target {
	const struct nfsp_schema_family *const *families;
	size_t nfamilies;
	uint8_t *rule_set;
	size_t rule_set_len;
	char rule_set_id[65];
	char session[NFSP_JOURNAL_SESSION_ID_MAX + 1];
	uint32_t lane_id;
	uint32_t drain_bound_ms;
	uint64_t (*clock_ms)(void *);
	void *clock_arg;

	struct nfsp_ruleset ruleset;
	int ruleset_loaded;
	struct nfsp_semantic sem;
	int sem_ready;
	struct nfsp_activation act;
	int act_ready;
	struct nfsp_journal *journal;

	uint8_t *ev;		/* enum ev_state by event_seq */
	size_t ev_cap;
	uint64_t ev_count;

	struct tgen *gens;
	size_t ngens, gens_cap;
	struct tbatch *batches;
	size_t nbatches, batches_cap;
	struct thold holds[MAX_HOLDS];

	/* activate(): the digest the gate callback records for G. */
	const uint8_t *opening_digest;
	struct answer answer;

	int listen_fd;
	char listen_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	int clients[MAX_CLIENTS];

	struct current cur;
	uint8_t *release;	/* output handed to the relay last time */
	enum { RUN_NOT_SENT = 0, RUN_SENT, RUN_SKIPPED } run_state;
	uint64_t run_seq;
	struct nfsp_target_stats stats;
};

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t now_ms(const struct nfsp_target *t)
{
	return t->clock_ms ? t->clock_ms(t->clock_arg) : monotonic_ms();
}

static void errf(char *err, size_t errlen, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static void errf(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (err == NULL || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* --- small lookups -------------------------------------------------------- */

static struct tgen *find_gen(struct nfsp_target *t, uint64_t generation)
{
	for (size_t i = 0; i < t->ngens; i++)
		if (t->gens[i].generation == generation)
			return &t->gens[i];
	return NULL;
}

static int rule_index(const struct nfsp_target *t, const char *rule_id)
{
	for (uint32_t i = 0; i < t->ruleset.nrules; i++)
		if (strcmp(t->ruleset.rules[i].rule_id, rule_id) == 0)
			return (int)i;
	return -1;
}

static enum ev_state ev_state(const struct nfsp_target *t, uint64_t seq)
{
	return seq < t->ev_count ? (enum ev_state)t->ev[seq] : EV_LOST;
}

static int ev_track(struct nfsp_target *t, uint64_t seq)
{
	if (seq != t->ev_count)
		return -1;
	if (t->ev_count == t->ev_cap) {
		size_t cap = t->ev_cap ? t->ev_cap * 2u : 256u;
		uint8_t *grown = realloc(t->ev, cap);

		if (grown == NULL)
			return -1;
		t->ev = grown;
		t->ev_cap = cap;
	}
	t->ev[t->ev_count++] = EV_PENDING;
	return 0;
}

static int submit(struct nfsp_target *t, const char *type,
		  const struct nfsp_jbuf *payload, uint64_t cookie,
		  uint64_t *seq_out)
{
	uint64_t seq;

#ifdef NFSP_TARGET_FAULT_INJECT
	/* Test builds only: fail every submit of the named event type, as an
	 * unrecordable event would. */
	const char *fail = getenv("NFSP_TARGET_FAIL_SUBMIT");

	if (fail != NULL && strcmp(fail, type) == 0) {
		t->stats.evidence_path_degraded = 1;
		return -1;
	}
#endif
	if (payload->failed ||
	    nfsp_journal_submit(t->journal, type, payload->p, payload->len,
				cookie, &seq) != 0) {
		/* An event the session owed is not in the journal. */
		t->stats.evidence_path_degraded = 1;
		return -1;
	}
	if (ev_track(t, seq) != 0) {
		/* The event is queued but cannot be followed: the session's
		 * bookkeeping is broken, so stop admitting anything. */
		t->stats.evidence_path_degraded = 1;
		return -1;
	}
	if (seq_out != NULL)
		*seq_out = seq;
	return 0;
}

/* --- JSON pieces ---------------------------------------------------------- */

static void j_correlation(struct nfsp_target *t, struct nfsp_jbuf *b,
			  const struct tgen *g, int first)
{
	nfsp_jb_key(b, "correlation", first);
	nfsp_jb_raw(b, "{");
	nfsp_jb_key(b, "kcov_generation", 1);
	nfsp_jb_u64(b, g->generation);
	nfsp_jb_key(b, "lane_id", 0);
	nfsp_jb_u64(b, t->lane_id);
	nfsp_jb_key(b, "program_digest", 0);
	nfsp_jb_hex(b, g->digest, sizeof(g->digest));
	nfsp_jb_key(b, "rule_set_id", 0);
	nfsp_jb_str(b, t->rule_set_id);
	nfsp_jb_raw(b, "}");
}

struct context {
	unsigned backend, client;
	uint64_t connection_id;
	int direction;
	int reply;
	uint32_t program, version, procedure, xid;
};

static void j_context(struct nfsp_jbuf *b, const struct context *c, int first)
{
	nfsp_jb_key(b, "record_context", first);
	nfsp_jb_raw(b, "{");
	nfsp_jb_key(b, "backend", 1);
	nfsp_jb_u64(b, c->backend);
	nfsp_jb_key(b, "client", 0);
	nfsp_jb_u64(b, c->client);
	nfsp_jb_key(b, "connection_id", 0);
	nfsp_jb_u64(b, c->connection_id);
	nfsp_jb_key(b, "direction", 0);
	nfsp_jb_str(b, c->direction == NFSP_DIR_C2S ? "c2s" : "s2c");
	nfsp_jb_key(b, "message_type", 0);
	nfsp_jb_str(b, c->reply ? "reply" : "call");
	nfsp_jb_key(b, "procedure", 0);
	nfsp_jb_u64(b, c->procedure);
	nfsp_jb_key(b, "program", 0);
	nfsp_jb_u64(b, c->program);
	nfsp_jb_key(b, "version", 0);
	nfsp_jb_u64(b, c->version);
	nfsp_jb_key(b, "xid", 0);
	nfsp_jb_u64(b, c->xid);
	nfsp_jb_raw(b, "}");
}

static const char *part_name(enum nfsp_rule_part p)
{
	switch (p) {
	case NFSP_PART_VALUE: return "value";
	case NFSP_PART_ENCODED: return "encoded";
	case NFSP_PART_LENGTH: return "length";
	case NFSP_PART_COUNT: return "count";
	case NFSP_PART_DISCRIMINANT: return "discriminant";
	case NFSP_PART_PADDING: return "padding";
	}
	return "value";
}

static const char *kind_name(enum nfsp_rule_mutation_kind k)
{
	switch (k) {
	case NFSP_MUT_REPLACE: return "replace";
	case NFSP_MUT_INSERT: return "insert";
	case NFSP_MUT_DELETE: return "delete";
	case NFSP_MUT_OP_APPEND: return "op_append";
	case NFSP_MUT_OP_PREPEND: return "op_prepend";
	}
	return "replace";
}

/* --- journal answers ------------------------------------------------------- */

static void forward_event(struct nfsp_target *t, struct tbatch *bt,
			  uint64_t batch_id, int complete, size_t written,
			  size_t len, const char *reason);

static void gen_failure(struct nfsp_target *t, uint64_t generation)
{
	struct tgen *g = find_gen(t, generation);

	t->stats.evidence_path_failures++;
	t->stats.evidence_path_degraded = 1;
	if (g != NULL)
		g->evidence_failures++;
}

static void send_packet(struct nfsp_target *t, int client, uint32_t op,
			uint64_t generation, uint32_t status)
{
	uint8_t pkt[NFSP_TARGET_ACK_LEN];

	if (client < 0 || client >= (int)MAX_CLIENTS || t->clients[client] < 0)
		return;
	memcpy(pkt, "NFSPACK1", 8);
	for (unsigned i = 0; i < 4; i++) {
		pkt[8 + i] = (uint8_t)(op >> (24u - 8u * i));
		pkt[12 + i] = (uint8_t)(status >> (24u - 8u * i));
	}
	for (unsigned i = 0; i < 8; i++)
		pkt[16 + i] = (uint8_t)(generation >> (56u - 8u * i));
	/* A lost answer is a lost ACK: the executor must not assume it. */
	(void)send(t->clients[client], pkt, sizeof(pkt), MSG_NOSIGNAL);
}

/* The deferred answer of the one pending barrier. */
static void send_answer(struct nfsp_target *t, uint32_t status)
{
	struct answer *a = &t->answer;

	if (!a->active)
		return;
	a->active = 0;
	if (a->cb != NULL)
		a->cb(a->cb_arg, a->op, a->generation, status);
	else
		send_packet(t, a->client, a->op, a->generation, status);
}

static void on_journal(void *arg, uint64_t seq, uint64_t cookie,
		       enum nfsp_journal_outcome outcome, const char *reason)
{
	struct nfsp_target *t = arg;
	uint64_t id = COOKIE_ID(cookie);

	(void)reason;
	if (seq < t->ev_count)
		t->ev[seq] = outcome == NFSP_JOURNAL_ACKED ? EV_ACKED :
			     outcome == NFSP_JOURNAL_REJECTED ? EV_REJECTED :
			     EV_LOST;
	if (outcome == NFSP_JOURNAL_REJECTED)
		t->stats.evidence_path_degraded = 1;
	switch (COOKIE_KIND(cookie)) {
	case CK_RULESET:
		t->stats.ruleset_state = outcome == NFSP_JOURNAL_ACKED ? 1 : -1;
		break;
	case CK_BARRIER: {
		enum nfsp_activation_gate_reply r =
			outcome == NFSP_JOURNAL_ACKED ?
				NFSP_ACTIVATION_GATE_ACCEPTED :
			outcome == NFSP_JOURNAL_REJECTED ?
				NFSP_ACTIVATION_GATE_REJECTED :
				NFSP_ACTIVATION_GATE_NO_ACK;
		uint64_t gen = t->answer.active &&
			       t->answer.barrier_id == id ?
			       t->answer.generation : 0;
		enum nfsp_activation_result res =
			nfsp_activation_barrier_complete(&t->act, id, r);
		struct nfsp_activation_generation_snapshot snap;

		/* The ACK that made G draining starts its drain bound. */
		if (res == NFSP_ACTIVATION_OK &&
		    t->act.pending_barrier.id != id) {
			for (size_t i = 0; i < t->ngens; i++) {
				struct tgen *g = &t->gens[i];

				if (nfsp_activation_get_generation(
					    &t->act, g->generation, &snap) !=
					    NFSP_ACTIVATION_OK ||
				    snap.draining_barrier_id != id ||
				    snap.draining_barrier !=
					    NFSP_BARRIER_ACCEPTED)
					continue;
				g->draining_acked = 1;
				g->drain_deadline_set = 1;
				g->drain_deadline = now_ms(t) + t->drain_bound_ms;
			}
		}
		if (gen != 0)
			send_answer(t, res == NFSP_ACTIVATION_OK ?
				    0u : (uint32_t)res);
		break;
	}
	case CK_EXPOSURE: {
		struct tbatch *bt = id < t->nbatches ? &t->batches[id] : NULL;

		if (bt == NULL)
			break;
		if (outcome == NFSP_JOURNAL_ACKED) {
			struct tgen *g = find_gen(t, bt->generation);

			if (g != NULL)
				g->exposures++;
			t->stats.exposures++;
			bt->state = B_EXPOSED;
			if (bt->dropped)
				forward_event(t, bt, id, 0, 0, 0,
					      "connection_closed");
		} else {
			if (outcome == NFSP_JOURNAL_REJECTED)
				t->stats.exposure_refused++;
			else
				t->stats.exposure_lost++;
			gen_failure(t, bt->generation);
			bt->state = B_DEAD;
			free(bt->out);
			bt->out = NULL;
			{
				struct tgen *g = find_gen(t, bt->generation);

				if (g != NULL && g->open_batches > 0)
					g->open_batches--;
			}
		}
		break;
	}
	case CK_REFUSAL:
	case CK_FORWARD:
	case CK_COMPLETE:
		if (outcome != NFSP_JOURNAL_ACKED)
			gen_failure(t, id);
		if (COOKIE_KIND(cookie) == CK_COMPLETE &&
		    outcome == NFSP_JOURNAL_ACKED)
			t->stats.generations_complete++;
		break;
	case CK_RUN:
		break;
	default:
		break;
	}
}

/* --- generation lifecycle --------------------------------------------------- */

static struct tgen *add_gen(struct nfsp_target *t, uint64_t generation,
			    const uint8_t digest[32])
{
	struct tgen *g;
	size_t n = t->ruleset.nrules ? t->ruleset.nrules : 1u;

	if (t->ngens == t->gens_cap) {
		size_t cap = t->gens_cap ? t->gens_cap * 2u : 8u;
		struct tgen *grown = realloc(t->gens, cap * sizeof(*grown));

		if (grown == NULL)
			return NULL;
		t->gens = grown;
		t->gens_cap = cap;
	}
	g = &t->gens[t->ngens];
	memset(g, 0, sizeof(*g));
	g->generation = generation;
	memcpy(g->digest, digest, 32);
	g->counts = calloc(n * NCOUNT, sizeof(*g->counts));
	g->refusal = calloc(n, 1);
	g->refusal_seq = calloc(n, sizeof(*g->refusal_seq));
	if (g->counts == NULL || g->refusal == NULL || g->refusal_seq == NULL) {
		free(g->counts);
		free(g->refusal);
		free(g->refusal_seq);
		return NULL;
	}
	t->ngens++;
	return g;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

static enum nfsp_activation_gate_reply
gate(void *arg, const struct nfsp_activation_gate_request *req)
{
	struct nfsp_target *t = arg;
	struct tgen *g = find_gen(t, req->barrier.generation);
	struct nfsp_jbuf b;
	int draining = req->barrier.event == NFSP_GATE_GENERATION_DRAINING;
	uint64_t seq = 0;
	int rc;

	if (!draining) {
		if (g != NULL || t->opening_digest == NULL)
			return NFSP_ACTIVATION_GATE_NO_ACK;
		g = add_gen(t, req->barrier.generation, t->opening_digest);
	}
	if (g == NULL)
		return NFSP_ACTIVATION_GATE_NO_ACK;
	nfsp_jb_init(&b, NFSP_JOURNAL_MAX_PAYLOAD);
	nfsp_jb_raw(&b, "{");
	j_correlation(t, &b, g, 1);
	if (!draining) {
		/* The host's draining set for this lane: G whose draining it
		 * ACKed and whose summary is not yet queued.  Barriers are one
		 * at a time, so every earlier DRAINING is already answered. */
		uint64_t *set = calloc(t->ngens ? t->ngens : 1u, sizeof(*set));
		size_t nset = 0;

		if (set == NULL) {
			nfsp_jb_free(&b);
			return NFSP_ACTIVATION_GATE_NO_ACK;
		}
		for (size_t i = 0; i < t->ngens; i++) {
			struct tgen *d = &t->gens[i];

			if (d != g && d->draining_acked && !d->complete_sent)
				set[nset++] = d->generation;
		}
		qsort(set, nset, sizeof(*set), cmp_u64);
		nfsp_jb_key(&b, "draining_generations", 0);
		nfsp_jb_raw(&b, "[");
		for (size_t i = 0; i < nset; i++) {
			if (i)
				nfsp_jb_raw(&b, ",");
			nfsp_jb_u64(&b, set[i]);
		}
		free(set);
		nfsp_jb_raw(&b, "]");
	}
	nfsp_jb_raw(&b, "}");
	rc = submit(t, draining ? "GENERATION_DRAINING" : "GENERATION_OPEN",
		    &b, COOKIE(CK_BARRIER, req->barrier.id), &seq);
	nfsp_jb_free(&b);
	if (rc == 0 && !draining) {
		g->open_sent = 1;
		g->open_seq = seq;
	}
	return rc == 0 ? NFSP_ACTIVATION_GATE_PENDING :
			 NFSP_ACTIVATION_GATE_NO_ACK;
}

static const char *closure_name(enum nfsp_activation_closure_reason r)
{
	switch (r) {
	case NFSP_CLOSURE_DRAINED: return "drained";
	case NFSP_CLOSURE_REPLY_UNRESOLVED: return "reply_unresolved";
	case NFSP_CLOSURE_ABORTED: return "aborted";
	case NFSP_CLOSURE_NONE: break;
	}
	return "aborted";
}

static uint64_t outside_window(const struct nfsp_target *t)
{
	return t->act.stats.outside_activation_window + t->stats.outside_replies;
}

static void complete_generation(struct nfsp_target *t, struct tgen *g,
				const struct nfsp_activation_generation_snapshot *s)
{
	struct nfsp_jbuf b;
	const char *names[NCOUNT];
	size_t order[NCOUNT];

	for (size_t k = 0; k < NCOUNT; k++) {
		names[k] = k == APPLY_FAILED ? "apply_precondition_failed" :
			nfsp_resolve_strstatus((enum nfsp_resolve_status)k);
		order[k] = k;
	}
	/* Canonical JSON: the counts object's keys in byte order. */
	for (size_t i = 1; i < NCOUNT; i++)
		for (size_t j = i; j > 0 &&
		     strcmp(names[order[j - 1]], names[order[j]]) > 0; j--) {
			size_t tmp = order[j];

			order[j] = order[j - 1];
			order[j - 1] = tmp;
		}
	nfsp_jb_init(&b, NFSP_JOURNAL_MAX_PAYLOAD);
	nfsp_jb_raw(&b, "{");
	nfsp_jb_key(&b, "closure", 1);
	nfsp_jb_raw(&b, "{");
	nfsp_jb_key(&b, "drain_bound_ms", 1);
	nfsp_jb_u64(&b, t->drain_bound_ms);
	nfsp_jb_key(&b, "reason", 0);
	nfsp_jb_str(&b, closure_name(s->closure_reason));
	nfsp_jb_key(&b, "reply_unresolved_count", 0);
	nfsp_jb_u64(&b, s->reply_unresolved_count);
	nfsp_jb_raw(&b, "}");
	j_correlation(t, &b, g, 0);
	nfsp_jb_key(&b, "evidence_path_failures", 0);
	nfsp_jb_u64(&b, g->evidence_failures);
	nfsp_jb_key(&b, "exposure_batch_count", 0);
	nfsp_jb_u64(&b, g->exposures);
	nfsp_jb_key(&b, "outside_activation_window", 0);
	nfsp_jb_u64(&b, outside_window(t));
	nfsp_jb_key(&b, "records_seen", 0);
	nfsp_jb_u64(&b, s->records_seen);
	nfsp_jb_key(&b, "resolver_summary", 0);
	nfsp_jb_raw(&b, "[");
	for (uint32_t r = 0; r < t->ruleset.nrules; r++) {
		int first = 1;

		if (r)
			nfsp_jb_raw(&b, ",");
		nfsp_jb_raw(&b, "{");
		nfsp_jb_key(&b, "counts", 1);
		nfsp_jb_raw(&b, "{");
		for (size_t k = 0; k < NCOUNT; k++) {
			uint64_t n = g->counts[(size_t)r * NCOUNT + order[k]];

			if (n == 0)
				continue;
			nfsp_jb_key(&b, names[order[k]], first);
			nfsp_jb_u64(&b, n);
			first = 0;
		}
		nfsp_jb_raw(&b, "}");
		nfsp_jb_key(&b, "rule_id", 0);
		nfsp_jb_str(&b, t->ruleset.rules[r].rule_id);
		nfsp_jb_raw(&b, "}");
	}
	nfsp_jb_raw(&b, "]}");
	if (submit(t, "GENERATION_COMPLETE", &b,
		   COOKIE(CK_COMPLETE, g->generation), &g->complete_seq) != 0)
		gen_failure(t, g->generation);
	nfsp_jb_free(&b);
	g->complete_sent = 1;
}

static void lifecycle(struct nfsp_target *t)
{
	uint64_t now = now_ms(t);

	for (size_t i = 0; i < t->ngens; i++) {
		struct tgen *g = &t->gens[i];
		struct nfsp_activation_generation_snapshot s;

		if (g->complete_sent ||
		    nfsp_activation_get_generation(&t->act, g->generation, &s) !=
			    NFSP_ACTIVATION_OK)
			continue;
		if (s.state == NFSP_GENERATION_DRAINING && g->drain_deadline_set &&
		    now >= g->drain_deadline) {
			nfsp_activation_force_close(&t->act, g->generation,
						    NFSP_FORCE_REPLY_UNRESOLVED);
			nfsp_activation_get_generation(&t->act, g->generation,
						       &s);
		}
		/* No summary for a generation that never closed (a barrier
		 * failed): the session end leaves it without one (01 §16). */
		if (s.state != NFSP_GENERATION_CLOSED || g->open_batches != 0)
			continue;
		complete_generation(t, g, &s);
	}
}

/* --- per record ----------------------------------------------------------- */

static int hard_status(size_t k)
{
	switch ((enum nfsp_resolve_status)k) {
	case NFSP_RESOLVE_SCHEMA_MISMATCH:
	case NFSP_RESOLVE_DECODE_UNAVAILABLE:
	case NFSP_RESOLVE_TRANSACTION_CONTEXT_MISSING:
	case NFSP_RESOLVE_TRANSACTION_CONTEXT_UNUSABLE:
	case NFSP_RESOLVE_TARGET_AMBIGUOUS:
	case NFSP_RESOLVE_PREDICATE_REFERENCE_AMBIGUOUS:
	case NFSP_RESOLVE_TRANSFORM_FAILED:
	case NFSP_RESOLVE_CONFLICT:
	case NFSP_RESOLVE_STRUCTURE_CONSTRAINT_FAILED:
		return 1;
	default:
		return k == APPLY_FAILED;
	}
}

static int new_hold(struct nfsp_target *t)
{
	for (unsigned i = 0; i < MAX_HOLDS; i++)
		if (!t->holds[i].used) {
			memset(&t->holds[i], 0, sizeof(t->holds[i]));
			t->holds[i].used = 1;
			t->holds[i].batch = -1;
			return (int)i;
		}
	return -1;
}

static int hold_dep(struct thold *h, uint64_t seq, uint32_t max)
{
	if (h->deps == NULL) {
		h->deps = calloc(max, sizeof(*h->deps));
		if (h->deps == NULL)
			return -1;
	}
	for (uint32_t i = 0; i < h->ndeps; i++)
		if (h->deps[i] == seq)
			return 0;
	if (h->ndeps >= max)
		return -1;
	h->deps[h->ndeps++] = seq;
	return 0;
}

static void free_hold(struct thold *h)
{
	free(h->deps);
	memset(h, 0, sizeof(*h));
}

static int add_batch(struct nfsp_target *t, uint64_t *id)
{
	if (t->nbatches == t->batches_cap) {
		size_t cap = t->batches_cap ? t->batches_cap * 2u : 64u;
		struct tbatch *grown = realloc(t->batches, cap * sizeof(*grown));

		if (grown == NULL)
			return -1;
		t->batches = grown;
		t->batches_cap = cap;
	}
	memset(&t->batches[t->nbatches], 0, sizeof(t->batches[0]));
	*id = t->nbatches++;
	return 0;
}

struct sig {
	const char *rule_id, *path;
	const char *part, *kind;
	uint32_t count;
};

static int sig_cmp(const struct sig *a, const struct sig *b)
{
	int c = strcmp(a->rule_id, b->rule_id);

	if (c == 0)
		c = strcmp(a->path, b->path);
	if (c == 0)
		c = strcmp(a->part, b->part);
	if (c == 0)
		c = strcmp(a->kind, b->kind);
	return c;
}

/* The EXPOSURE_INTENT payload of an applied batch (05 §10). */
static void exposure_payload(struct nfsp_target *t, struct nfsp_jbuf *b,
			     uint64_t batch_id, const struct tgen *g,
			     const struct context *ctx,
			     const struct nfsp_resolution *res,
			     const struct nfsp_mutation_batch *lowered,
			     const struct nfsp_mutation_output *out)
{
	struct sig sigs[NFSP_RESOLVED_MAX];
	uint32_t nsig = 0;
	uint8_t digest[NFSP_SHA256_LEN];

	nfsp_jb_raw(b, "{");
	nfsp_jb_key(b, "applications", 1);
	nfsp_jb_raw(b, "[");
	for (uint32_t m = 0; m < res->nmutations; m++) {
		const struct nfsp_resolved_mutation *rm = &res->mutations[m];
		int ri = rule_index(t, rm->rule_id);
		const struct nfsp_rule *rule = ri >= 0 ?
			&t->ruleset.rules[ri] : NULL;
		const char *kind = rule ? kind_name(rule->kind) : "replace";
		struct sig cur = { rm->rule_id, rm->semantic_path,
				   part_name(rm->part), kind, 1 };
		int first = 1, found = 0;

		for (uint32_t s = 0; s < nsig; s++)
			if (sig_cmp(&sigs[s], &cur) == 0) {
				sigs[s].count++;
				found = 1;
			}
		if (!found && nsig < NFSP_RESOLVED_MAX)
			sigs[nsig++] = cur;
		if (m)
			nfsp_jb_raw(b, ",");
		nfsp_jb_raw(b, "{");
		nfsp_jb_key(b, "concrete_edits", 1);
		nfsp_jb_raw(b, "[");
		for (size_t e = 0; e < lowered->concrete.nedits; e++) {
			const struct nfsp_concrete_edit *ce = &lowered->edits[e];

			if (lowered->mutation_index[e] != m)
				continue;
			if (!first)
				nfsp_jb_raw(b, ",");
			first = 0;
			nfsp_jb_raw(b, "{");
			nfsp_jb_key(b, "data", 1);
			nfsp_jb_hex(b, ce->data, ce->data_len);
			nfsp_jb_key(b, "flags", 0);
			nfsp_jb_u64(b, lowered->edit_flags[e]);
			nfsp_jb_key(b, "offset", 0);
			nfsp_jb_u64(b, ce->offset);
			nfsp_jb_key(b, "original", 0);
			nfsp_jb_hex(b, ce->original, ce->original ?
				    ce->remove_len : 0);
			nfsp_jb_raw(b, "}");
		}
		nfsp_jb_raw(b, "]");
		nfsp_jb_key(b, "field_index", 0);
		nfsp_jb_u64(b, rm->field_index);
		nfsp_jb_key(b, "kind", 0);
		nfsp_jb_str(b, kind);
		nfsp_jb_key(b, "mutated_value", 0);
		nfsp_jb_hex(b, rm->output.bytes, rm->output.len);
		nfsp_jb_key(b, "operation_index", 0);
		nfsp_jb_u64(b, rm->operation_index);
		nfsp_jb_key(b, "original_value", 0);
		nfsp_jb_hex(b, rm->current.bytes, rm->current.len);
		nfsp_jb_key(b, "part", 0);
		nfsp_jb_str(b, part_name(rm->part));
		nfsp_jb_key(b, "policy", 0);
		nfsp_jb_str(b, rm->policy == NFSP_POLICY_RAW ? "raw" : "preserve");
		nfsp_jb_key(b, "rule_id", 0);
		nfsp_jb_str(b, rm->rule_id);
		nfsp_jb_key(b, "semantic_path", 0);
		nfsp_jb_str(b, rm->semantic_path);
		nfsp_jb_raw(b, "}");
	}
	nfsp_jb_raw(b, "]");
	nfsp_jb_key(b, "batch_id", 0);
	nfsp_jb_u64(b, batch_id);
	j_correlation(t, b, g, 0);
	nfsp_jb_key(b, "output", 0);
	nfsp_jb_raw(b, "{");
	nfsp_jb_key(b, "final_record_length", 1);
	nfsp_jb_u64(b, out->framed_len);
	nfsp_jb_key(b, "output_sha256", 0);
	nfsp_sha256(out->framed_bytes, out->framed_len, digest);
	nfsp_jb_hex(b, digest, sizeof(digest));
	nfsp_jb_raw(b, "}");
	j_context(b, ctx, 0);
	/* The batch's semantic signature: a canonical multiset (05 §9). */
	for (uint32_t i = 1; i < nsig; i++)
		for (uint32_t j = i; j > 0 && sig_cmp(&sigs[j - 1], &sigs[j]) > 0;
		     j--) {
			struct sig tmp = sigs[j];

			sigs[j] = sigs[j - 1];
			sigs[j - 1] = tmp;
		}
	nfsp_jb_key(b, "semantic_signature", 0);
	nfsp_jb_raw(b, "[");
	for (uint32_t s = 0; s < nsig; s++) {
		if (s)
			nfsp_jb_raw(b, ",");
		nfsp_jb_raw(b, "{");
		nfsp_jb_key(b, "count", 1);
		nfsp_jb_u64(b, sigs[s].count);
		nfsp_jb_key(b, "kind", 0);
		nfsp_jb_str(b, sigs[s].kind);
		nfsp_jb_key(b, "part", 0);
		nfsp_jb_str(b, sigs[s].part);
		nfsp_jb_key(b, "rule_id", 0);
		nfsp_jb_str(b, sigs[s].rule_id);
		nfsp_jb_key(b, "semantic_path", 0);
		nfsp_jb_str(b, sigs[s].path);
		nfsp_jb_raw(b, "}");
	}
	nfsp_jb_raw(b, "]}");
}

/* Write ahead the first hard refusal of each rule; make the hold wait for
 * that event either way (05 §21).  -1: the record must not be relayed. */
static int refusals(struct nfsp_target *t, struct tgen *g,
		    const struct context *ctx, const uint8_t *hard_first,
		    const size_t *hard_status_of, struct thold *h)
{
	for (uint32_t r = 0; r < t->ruleset.nrules; r++) {
		struct nfsp_jbuf b;
		uint64_t seq;
		const char *name;

		if (!hard_first[r])
			continue;
		if (g->refusal[r]) {
			if (ev_state(t, g->refusal_seq[r]) == EV_PENDING) {
				t->stats.refusal_waits++;
				if (hold_dep(h, g->refusal_seq[r],
					     t->ruleset.nrules + 1u) != 0)
					return -1;
			}
			continue;
		}
		name = hard_status_of[r] == APPLY_FAILED ?
			"apply_precondition_failed" :
			nfsp_resolve_strstatus(
				(enum nfsp_resolve_status)hard_status_of[r]);
		nfsp_jb_init(&b, NFSP_JOURNAL_MAX_PAYLOAD);
		nfsp_jb_raw(&b, "{");
		j_correlation(t, &b, g, 1);
		j_context(&b, ctx, 0);
		nfsp_jb_key(&b, "refusal", 0);
		nfsp_jb_str(&b, name);
		nfsp_jb_key(&b, "rule_id", 0);
		nfsp_jb_str(&b, t->ruleset.rules[r].rule_id);
		nfsp_jb_raw(&b, "}");
		if (submit(t, "APPLY_REFUSAL", &b,
			   COOKIE(CK_REFUSAL, g->generation), &seq) != 0) {
			nfsp_jb_free(&b);
			return -1;
		}
		nfsp_jb_free(&b);
		t->stats.refusal_events++;
		g->refusal[r] = 1;
		g->refusal_seq[r] = seq;
		if (hold_dep(h, seq, t->ruleset.nrules + 1u) != 0)
			return -1;
	}
	return 0;
}

/* Resolve, apply and decide one eligible record. */
static void eligible(struct nfsp_target *t, const struct nfsp_semantic_event *ev,
		     uint64_t generation, const struct nfsp_txn_entry *entry)
{
	const struct nfsp_rpc_record *rec = ev->record;
	struct tgen *g = find_gen(t, generation);
	struct nfsp_resolver_record rr;
	struct nfsp_resolver_transaction tx;
	struct nfsp_resolution res;
	struct nfsp_reply_dispatch rd;
	struct nfsp_mutation_verify verify;
	struct nfsp_mutation_output out;
	struct nfsp_mutation_batch lowered;
	struct context ctx;
	uint8_t hard_first[NFSP_RULES_MAX];
	size_t hard_of[NFSP_RULES_MAX];
	int reply = ev->rpc->msg_type != NFSP_RPC_CALL;
	int hard_any = 0, apply_ok = 0;
	int hi;
	struct thold *h;

	if (g == NULL)
		return;
	t->stats.eligible++;
	memset(&rr, 0, sizeof(rr));
	memset(&tx, 0, sizeof(tx));
	memset(&res, 0, sizeof(res));
	memset(&out, 0, sizeof(out));
	memset(&lowered, 0, sizeof(lowered));
	memset(&verify, 0, sizeof(verify));
	rr.activation_generation = generation;
	rr.direction = rec->direction == NFSP_DIR_C2S ? NFSP_RULE_C2S :
						      NFSP_RULE_S2C;
	rr.backend = rec->conn.backend;
	rr.client = rec->conn.client;
	rr.payload = rec->rpc_payload;
	rr.payload_len = rec->rpc_payload_len;
	rr.message = ev->msg;
	memset(&ctx, 0, sizeof(ctx));
	ctx.backend = rec->conn.backend;
	ctx.client = rec->conn.client;
	ctx.connection_id = rec->conn.connection_id;
	ctx.direction = rec->direction;
	ctx.reply = reply;
	ctx.xid = ev->rpc->xid;
	if (reply) {
		tx.state = NFSP_RESOLVER_TXN_FOUND;
		tx.program = entry->program;
		tx.version = entry->version;
		tx.procedure = entry->procedure;
		rr.transaction = &tx;
		nfsp_txn_dispatch(entry, &rd);
		verify.reply_dispatch = &rd;
		ctx.program = entry->program;
		ctx.version = entry->version;
		ctx.procedure = entry->procedure;
	} else {
		ctx.program = ev->rpc->prog;
		ctx.version = ev->rpc->vers;
		ctx.procedure = ev->rpc->proc;
	}
	verify.families = t->families;
	verify.nfamilies = t->nfamilies;
	if (nfsp_resolve_rules(&t->ruleset, &rr, &res) != 0) {
		/* A resource failure is no semantic answer: refuse the
		 * record rather than relay it unexplained. */
		t->cur.action = NFSP_RELAY_REFUSE;
		return;
	}
	memset(hard_first, 0, sizeof(hard_first));
	for (uint32_t i = 0; i < res.nrules; i++) {
		int ri = rule_index(t, res.rules[i].rule_id);

		if (ri < 0)
			continue;
		for (size_t k = 0; k < (size_t)NFSP_RESOLVE_STATUS_COUNT; k++) {
			uint32_t n = res.rules[i].count[k];

			g->counts[(size_t)ri * NCOUNT + k] += n;
			if (n != 0 && hard_status(k) && !hard_first[ri]) {
				hard_first[ri] = 1;
				hard_of[ri] = k;
				hard_any = 1;
			}
		}
	}
	if (res.preflight == NFSP_PREFLIGHT_READY) {
		enum nfsp_mutation_status ms =
			nfsp_mutation_apply(&rr, &res, &verify, &out);

		if (ms == NFSP_MUTATION_OK &&
		    nfsp_mutation_lower(&rr, &res, &lowered) == NFSP_MUTATION_OK) {
			apply_ok = 1;
		} else {
			if (ms == NFSP_MUTATION_OK)
				nfsp_mutation_output_free(&out);
			for (uint32_t m = 0; m < res.nmutations; m++) {
				int ri = rule_index(t, res.mutations[m].rule_id);

				if (ri < 0)
					continue;
				g->counts[(size_t)ri * NCOUNT + APPLY_FAILED]++;
				if (!hard_first[ri]) {
					hard_first[ri] = 1;
					hard_of[ri] = APPLY_FAILED;
				}
				hard_any = 1;
			}
		}
	}
	if (!hard_any && !apply_ok) {
		nfsp_resolution_free(&res);
		return;
	}
	hi = new_hold(t);
	if (hi < 0) {
		t->cur.action = NFSP_RELAY_REFUSE;
		goto out;
	}
	h = &t->holds[hi];
	if (hard_any && refusals(t, g, &ctx, hard_first, hard_of, h) != 0) {
		free_hold(h);
		t->cur.action = NFSP_RELAY_REFUSE;
		goto out;
	}
	if (apply_ok) {
		struct nfsp_jbuf b;
		uint64_t batch_id, seq;
		struct tbatch *bt;

		if (add_batch(t, &batch_id) != 0) {
			gen_failure(t, generation);
		} else {
			nfsp_jb_init(&b, NFSP_JOURNAL_MAX_PAYLOAD);
			exposure_payload(t, &b, batch_id, g, &ctx, &res, &lowered,
					 &out);
			bt = &t->batches[batch_id];
			bt->generation = generation;
			if (submit(t, "EXPOSURE_INTENT", &b,
				   COOKIE(CK_EXPOSURE, batch_id), &seq) != 0) {
				/* Not recordable (for example too large):
				 * the record goes out unchanged (05 §11). */
				bt->state = B_DEAD;
				gen_failure(t, generation);
			} else {
				bt->state = B_PENDING;
				bt->ei_seq = seq;
				bt->out = malloc(out.framed_len);
				if (bt->out != NULL) {
					memcpy(bt->out, out.framed_bytes,
					       out.framed_len);
					bt->out_len = out.framed_len;
				}
				bt->is_call = !reply;
				bt->key.connection_id = rec->conn.connection_id;
				bt->key.call_direction = rec->direction;
				bt->key.xid = ev->rpc->xid;
				g->open_batches++;
				h->batch = (int64_t)batch_id;
				if (hold_dep(h, seq, t->ruleset.nrules + 1u) != 0)
					t->cur.action = NFSP_RELAY_REFUSE;
			}
			nfsp_jb_free(&b);
		}
	}
	if (t->cur.action == NFSP_RELAY_REFUSE || h->ndeps == 0) {
		free_hold(h);
	} else {
		t->cur.action = NFSP_RELAY_HOLD;
		t->cur.verdict->hold = (uint64_t)hi + 1u;
	}
out:
	if (apply_ok) {
		nfsp_mutation_output_free(&out);
		nfsp_mutation_batch_free(&lowered);
	}
	nfsp_resolution_free(&res);
}

static void decoded(const struct nfsp_semantic_event *ev, void *arg)
{
	struct nfsp_target *t = arg;

	if (ev->rpc_status != NFSP_RPC_OK || ev->rpc == NULL)
		return;
	t->cur.txn = ev->txn;
	t->cur.txn_seen = 1;
	if (ev->rpc->msg_type == NFSP_RPC_CALL) {
		if (t->cur.call_generation != 0)
			eligible(t, ev, t->cur.call_generation, NULL);
		return;
	}
	if (ev->txn != NFSP_TXN_FOUND || ev->entry == NULL)
		return;
	if (ev->entry->activation_generation == 0) {
		t->stats.outside_replies++;
		return;
	}
	if (nfsp_activation_account_reply(
		    &t->act, ev->entry->activation_generation,
		    ev->entry->replies > 1 ? NFSP_ACTIVATION_REPLY_DUPLICATE :
					     NFSP_ACTIVATION_REPLY_RESOLVED) !=
	    NFSP_ACTIVATION_OK)
		return;
	eligible(t, ev, ev->entry->activation_generation, ev->entry);
}

static void dropped(uint64_t generation, void *arg)
{
	struct nfsp_target *t = arg;

	nfsp_activation_account_connection_closed(&t->act, generation, 1);
}

static void release(struct nfsp_target *t)
{
	free(t->release);
	t->release = NULL;
}

static int relay(const struct nfsp_rpc_record *rec, const uint8_t *framed,
		 size_t len, struct nfsp_relay_verdict *v, void *arg)
{
	struct nfsp_target *t = arg;
	struct nfsp_rpc_envelope env;
	struct nfsp_activation_call_ticket ticket;

	release(t);
	t->stats.records++;
	memset(&t->cur, 0, sizeof(t->cur));
	memset(&ticket, 0, sizeof(ticket));
	t->cur.rec = rec;
	t->cur.framed = framed;
	t->cur.framed_len = len;
	t->cur.verdict = v;
	t->cur.action = NFSP_RELAY_FORWARD;
	if (nfsp_rpc_decode(rec->rpc_payload, rec->rpc_payload_len, &env) ==
		    NFSP_RPC_OK &&
	    env.msg_type == NFSP_RPC_CALL &&
	    nfsp_activation_call_generation(&t->act, &t->cur.call_generation,
					    &ticket) != NFSP_ACTIVATION_OK)
		t->cur.call_generation = 0;
	t->sem.call_generation = t->cur.call_generation;
	nfsp_semantic_record(rec, &t->sem);
	if (ticket.id != 0)
		nfsp_activation_account_call(
			&t->act, &ticket,
			!t->cur.txn_seen ? NFSP_ACTIVATION_CALL_NOT_INSERTED :
			t->cur.txn == NFSP_TXN_INSERTED ?
				NFSP_ACTIVATION_CALL_INSERTED :
			t->cur.txn == NFSP_TXN_DUPLICATE_EQUIVALENT ?
				NFSP_ACTIVATION_CALL_DUPLICATE :
				NFSP_ACTIVATION_CALL_NOT_INSERTED);
	return t->cur.action;
}

static int hold_decided(struct nfsp_target *t, uint64_t token,
			const uint8_t *framed, size_t len,
			struct nfsp_relay_verdict *v)
{
	struct thold *h;
	int exposed = 0;

	(void)framed;
	(void)len;
	if (token == 0 || token > MAX_HOLDS || !t->holds[token - 1].used)
		return NFSP_RELAY_REFUSE;
	h = &t->holds[token - 1];
	for (uint32_t i = 0; i < h->ndeps; i++) {
		enum ev_state s = ev_state(t, h->deps[i]);
		int is_exposure = h->batch >= 0 &&
			t->batches[h->batch].ei_seq == h->deps[i];

		if (s == EV_PENDING)
			return NFSP_RELAY_HOLD;
		/* A hard refusal needs an explicit host answer before the
		 * refused record moves (05 §21): a lost channel stalls it. */
		if (s == EV_LOST && !is_exposure)
			return NFSP_RELAY_HOLD;
	}
	if (h->batch >= 0) {
		struct tbatch *bt = &t->batches[h->batch];

		if (bt->state == B_EXPOSED && bt->out != NULL) {
			v->out = bt->out;
			v->out_len = bt->out_len;
			v->completion = (uint64_t)h->batch + 1u;
			bt->state = B_FORWARDING;
			t->release = bt->out;
			bt->out = NULL;
			exposed = 1;
			if (bt->is_call)
				/* The peer gets a changed CALL: its REPLY must
				 * not be decoded as the original's (txn.h). */
				nfsp_txn_mark_forwarded(&t->sem.txn, &bt->key,
							NFSP_TXN_FWD_UNKNOWN);
		} else if (bt->state == B_EXPOSED) {
			/* ACKed but its bytes are gone (no memory): never
			 * claim delivery; the original goes out. */
			forward_event(t, bt, (uint64_t)h->batch, 0, 0, 0,
				      "output_unavailable");
		}
	}
	(void)exposed;
	free_hold(h);
	return NFSP_RELAY_FORWARD;
}

static int on_hold(uint64_t token, const uint8_t *framed, size_t len,
		   struct nfsp_relay_verdict *v, void *arg)
{
	struct nfsp_target *t = arg;

	release(t);
	return hold_decided(t, token, framed, len, v);
}

static void forward_event(struct nfsp_target *t, struct tbatch *bt,
			  uint64_t batch_id, int complete, size_t written,
			  size_t len, const char *reason)
{
	struct tgen *g = find_gen(t, bt->generation);
	struct nfsp_jbuf b;

	if (bt->state == B_DONE || bt->state == B_DEAD || g == NULL)
		return;
	nfsp_jb_init(&b, NFSP_JOURNAL_MAX_PAYLOAD);
	nfsp_jb_raw(&b, "{");
	nfsp_jb_key(&b, "batch_id", 1);
	nfsp_jb_u64(&b, batch_id);
	if (complete) {
		j_correlation(t, &b, g, 0);
		nfsp_jb_key(&b, "forwarded_length", 0);
		nfsp_jb_u64(&b, len);
	} else {
		nfsp_jb_key(&b, "bytes_written", 0);
		nfsp_jb_u64(&b, written);
		j_correlation(t, &b, g, 0);
		nfsp_jb_key(&b, "reason", 0);
		nfsp_jb_str(&b, reason);
	}
	nfsp_jb_raw(&b, "}");
	if (submit(t, complete ? "FORWARD_COMPLETE" : "FORWARD_FAILED", &b,
		   COOKIE(CK_FORWARD, bt->generation), NULL) != 0)
		gen_failure(t, bt->generation);
	nfsp_jb_free(&b);
	if (complete)
		t->stats.forward_complete++;
	else
		t->stats.forward_failed++;
	bt->state = B_DONE;
	free(bt->out);
	bt->out = NULL;
	if (g->open_batches > 0)
		g->open_batches--;
}

static void on_hold_dropped(uint64_t token, void *arg)
{
	struct nfsp_target *t = arg;
	struct thold *h;

	if (token == 0 || token > MAX_HOLDS || !t->holds[token - 1].used)
		return;
	h = &t->holds[token - 1];
	t->stats.held_dropped++;
	if (h->batch >= 0) {
		struct tbatch *bt = &t->batches[h->batch];

		if (bt->state == B_PENDING)
			bt->dropped = 1;
		else if (bt->state == B_EXPOSED)
			forward_event(t, bt, (uint64_t)h->batch, 0, 0, 0,
				      "connection_closed");
	}
	free_hold(h);
}

static void on_forwarded(uint64_t completion, int complete, size_t written,
			 size_t len, void *arg)
{
	struct nfsp_target *t = arg;
	uint64_t id = completion - 1u;

	if (completion == 0 || id >= t->nbatches)
		return;
	forward_event(t, &t->batches[id], id, complete, written, len,
		      complete ? "" : written ? "partial_write" :
						"not_written");
}

static void on_connection(const struct nfsp_connection_ref *conn, int event,
			  void *arg)
{
	struct nfsp_target *t = arg;

	nfsp_semantic_connection(conn, event, &t->sem);
}

/* --- endpoint --------------------------------------------------------------- */

int nfsp_target_request(struct nfsp_target *t, uint32_t op,
			uint64_t generation, const uint8_t digest[32],
			const char *rule_set_id, uint32_t *status,
			void (*on_answer)(void *, uint32_t, uint64_t, uint32_t),
			void *answer_arg)
{
	struct nfsp_activation_barrier barrier;
	enum nfsp_activation_result r;

	*status = NFSP_ACTIVATION_INVALID_ARGUMENT;
	if (op == NFSP_TARGET_OP_ABORT) {
		r = nfsp_activation_force_close(&t->act, generation,
						NFSP_FORCE_ABORTED);
		*status = r == NFSP_ACTIVATION_OK ||
			  r == NFSP_ACTIVATION_IDEMPOTENT ? 0u : (uint32_t)r;
		lifecycle(t);
		return 0;
	}
	if (op == NFSP_TARGET_OP_ACTIVATE && t->stats.ruleset_state < 0) {
		*status = NFSP_TARGET_NOT_READY;
		return 0;
	}
	if (op == NFSP_TARGET_OP_ACTIVATE) {
		t->opening_digest = digest;
		r = nfsp_activation_activate(&t->act, rule_set_id, generation,
					     &barrier);
		t->opening_digest = NULL;
	} else if (op == NFSP_TARGET_OP_DEACTIVATE) {
		r = nfsp_activation_deactivate(&t->act, rule_set_id, generation,
					       &barrier);
	} else {
		return 0;
	}
	if (r == NFSP_ACTIVATION_BARRIER_PENDING) {
		t->answer.active = 1;
		t->answer.barrier_id = barrier.id;
		t->answer.op = op;
		t->answer.generation = generation;
		t->answer.client = -1;
		t->answer.cb = on_answer;
		t->answer.cb_arg = answer_arg;
		return 1;
	}
	*status = r == NFSP_ACTIVATION_OK || r == NFSP_ACTIVATION_IDEMPOTENT ?
		  0u : (uint32_t)r;
	return 0;
}

static uint64_t get64(const uint8_t *p)
{
	uint64_t v = 0;

	for (unsigned i = 0; i < 8; i++)
		v = v << 8 | p[i];
	return v;
}

static void endpoint_packet(struct nfsp_target *t, int client,
			    const uint8_t *p, size_t n)
{
	char rule_set_id[65];
	uint32_t op, status = NFSP_ACTIVATION_INVALID_ARGUMENT;
	uint64_t generation = 0;

	op = n >= 12 ? (uint32_t)p[8] << 24 | (uint32_t)p[9] << 16 |
		       (uint32_t)p[10] << 8 | p[11] : 0;
	if (n == NFSP_TARGET_REQ_LEN && memcmp(p, "NFSPACT1", 8) == 0 &&
	    p[12] == 0 && p[13] == 0 && p[14] == 0 && p[15] == 0) {
		generation = get64(p + 16);
		memcpy(rule_set_id, p + 56, 64);
		rule_set_id[64] = '\0';
		if (nfsp_target_request(t, op, generation, p + 24, rule_set_id,
					&status, NULL, NULL) == 1) {
			t->answer.client = client;
			return;
		}
	}
	/* Answered now; a barrier still pending keeps its own answer. */
	send_packet(t, client, op, generation, status);
}

static void endpoint_pump(struct nfsp_target *t)
{
	if (t->listen_fd < 0)
		return;
	for (;;) {
		int fd = accept(t->listen_fd, NULL, NULL);
		unsigned i;

		if (fd < 0)
			break;
		for (i = 0; i < MAX_CLIENTS; i++)
			if (t->clients[i] < 0)
				break;
		if (i == MAX_CLIENTS ||
		    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) != 0) {
			close(fd);
			continue;
		}
		t->clients[i] = fd;
	}
	for (unsigned i = 0; i < MAX_CLIENTS; i++) {
		uint8_t pkt[NFSP_TARGET_REQ_LEN + 1];

		while (t->clients[i] >= 0) {
			ssize_t n = recv(t->clients[i], pkt, sizeof(pkt), 0);

			if (n > 0) {
				endpoint_packet(t, (int)i, pkt, (size_t)n);
				continue;
			}
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
				      errno == EINTR))
				break;
			close(t->clients[i]);
			t->clients[i] = -1;
			if (t->answer.active && t->answer.cb == NULL &&
			    t->answer.client == (int)i)
				t->answer.client = -1;
		}
	}
}

static int endpoint_open(struct nfsp_target *t, const char *path, char *err,
			 size_t errlen)
{
	struct sockaddr_un sa;

	if (strlen(path) >= sizeof(sa.sun_path)) {
		errf(err, errlen, "activation path too long");
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, path);
	t->listen_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (t->listen_fd < 0 ||
	    bind(t->listen_fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(t->listen_fd, 4) != 0 ||
	    fcntl(t->listen_fd, F_SETFL,
		  fcntl(t->listen_fd, F_GETFL, 0) | O_NONBLOCK) != 0) {
		errf(err, errlen, "activation endpoint %s: %s", path,
		     strerror(errno));
		if (t->listen_fd >= 0)
			close(t->listen_fd);
		t->listen_fd = -1;
		return -1;
	}
	strcpy(t->listen_path, path);
	return 0;
}

/* --- proxy hooks -------------------------------------------------------------- */

static size_t poll_fds(struct pollfd *fds, size_t max, void *arg)
{
	struct nfsp_target *t = arg;
	size_t n = 0;

	if (n < max && nfsp_journal_fd(t->journal) >= 0) {
		fds[n].fd = nfsp_journal_fd(t->journal);
		fds[n].events = nfsp_journal_events(t->journal);
		fds[n++].revents = 0;
	}
	if (n < max && t->listen_fd >= 0) {
		fds[n].fd = t->listen_fd;
		fds[n].events = POLLIN;
		fds[n++].revents = 0;
	}
	for (unsigned i = 0; i < MAX_CLIENTS && n < max; i++)
		if (t->clients[i] >= 0) {
			fds[n].fd = t->clients[i];
			fds[n].events = POLLIN;
			fds[n++].revents = 0;
		}
	return n;
}

void nfsp_target_tick(void *arg)
{
	struct nfsp_target *t = arg;

	nfsp_journal_pump(t->journal);
	endpoint_pump(t);
	nfsp_semantic_tick(&t->sem);
	lifecycle(t);
	nfsp_journal_pump(t->journal);
}

void nfsp_target_install(struct nfsp_target *t, struct nfsp_proxy_cfg *cfg)
{
	cfg->on_relay = relay;
	cfg->on_hold = on_hold;
	cfg->on_hold_dropped = on_hold_dropped;
	cfg->on_forwarded = on_forwarded;
	cfg->poll_fds = poll_fds;
	cfg->relay_arg = t;
	cfg->on_connection = on_connection;
	cfg->on_connection_arg = t;
	cfg->on_rpc_record = NULL;
	cfg->on_record = NULL;
}

/* --- lifetime ----------------------------------------------------------------- */

int nfsp_target_check_rules(const uint8_t *rule_set, size_t len,
			    const struct nfsp_schema_family *const *families,
			    size_t nfamilies, FILE *out)
{
	struct nfsp_ruleset rs;
	struct nfsp_rule_error rerr;
	enum nfsp_rule_status status;
	uint8_t digest[NFSP_SHA256_LEN];
	char hex[65];

	nfsp_sha256(rule_set, len, digest);
	nfsp_sha256_hex(digest, hex);
	memset(&rs, 0, sizeof(rs));
	memset(&rerr, 0, sizeof(rerr));
	rerr.rule = rerr.predicate = NFSP_RULE_NONE;
	status = len > NFSP_RULESET_MAX_LEN ? NFSP_RULE_MALFORMED :
		 nfsp_ruleset_load(rule_set, len, families, nfamilies, &rs,
				   &rerr);
	if (status != NFSP_RULE_OK) {
		fprintf(out, "rules refused rule_set_id=%s status=%s", hex,
			nfsp_rule_strstatus(status));
		if (rerr.rule != NFSP_RULE_NONE)
			fprintf(out, " rule=%u", rerr.rule);
		if (rerr.predicate != NFSP_RULE_NONE)
			fprintf(out, " predicate=%u", rerr.predicate);
		fprintf(out, "\n");
		return -1;
	}
	fprintf(out, "rules ok rule_set_id=%s semantic_runtime_version=%u "
		"schema_id=%s rules=%u\n", hex, rs.semantic_runtime_version,
		rs.schema_id, rs.nrules);
	nfsp_ruleset_free(&rs);
	return 0;
}

int nfsp_target_open(struct nfsp_target **out,
		     const struct nfsp_target_cfg *cfg, char *err,
		     size_t errlen)
{
	struct nfsp_target *t;
	struct nfsp_activation_cfg acfg;
	struct nfsp_journal_cfg jcfg;
	struct nfsp_jbuf b;
	uint8_t digest[NFSP_SHA256_LEN];
	enum nfsp_rule_status rs;
	struct nfsp_rule_error rerr;
	int fd = cfg->journal_fd;

	*out = NULL;
	t = calloc(1, sizeof(*t));
	if (t == NULL) {
		if (fd >= 0)
			close(fd);
		errf(err, errlen, "no memory");
		return -1;
	}
	t->listen_fd = -1;
	for (unsigned i = 0; i < MAX_CLIENTS; i++)
		t->clients[i] = -1;
	t->families = cfg->families;
	t->nfamilies = cfg->nfamilies;
	t->lane_id = cfg->lane_id;
	t->drain_bound_ms = cfg->drain_bound_ms ? cfg->drain_bound_ms :
			    NFSP_TARGET_DEFAULT_DRAIN_MS;
	t->clock_ms = cfg->clock_ms;
	t->clock_arg = cfg->clock_arg;
	if (cfg->rule_set == NULL || cfg->rule_set_len == 0 ||
	    cfg->rule_set_len > NFSP_RULESET_MAX_LEN ||
	    cfg->proxy_session_id == NULL ||
	    strlen(cfg->proxy_session_id) > NFSP_JOURNAL_SESSION_ID_MAX) {
		errf(err, errlen, "bad rule set or session id");
		goto fail;
	}
	strcpy(t->session, cfg->proxy_session_id);
	t->rule_set = malloc(cfg->rule_set_len);
	if (t->rule_set == NULL) {
		errf(err, errlen, "no memory");
		goto fail;
	}
	memcpy(t->rule_set, cfg->rule_set, cfg->rule_set_len);
	t->rule_set_len = cfg->rule_set_len;
	nfsp_sha256(t->rule_set, t->rule_set_len, digest);
	nfsp_sha256_hex(digest, t->rule_set_id);
	rs = nfsp_ruleset_load(t->rule_set, t->rule_set_len, cfg->families,
			       cfg->nfamilies, &t->ruleset, &rerr);
	if (rs != NFSP_RULE_OK) {
		errf(err, errlen, "rule set refused: %s (rule %u predicate %u): %s",
		     nfsp_rule_strstatus(rs), rerr.rule, rerr.predicate,
		     rerr.detail ? rerr.detail : "");
		goto fail;
	}
	t->ruleset_loaded = 1;
	memset(&t->sem, 0, sizeof(t->sem));
	t->sem.families = cfg->families;
	t->sem.nfamilies = cfg->nfamilies;
	t->sem.forwarded = NFSP_TXN_FWD_ORIGINAL;
	t->sem.on_decoded = decoded;
	t->sem.on_decoded_arg = t;
	t->sem.on_dropped = dropped;
	t->sem.on_dropped_arg = t;
	t->sem.clock_ms = cfg->clock_ms;
	t->sem.clock_arg = cfg->clock_arg;
	if (nfsp_semantic_init(&t->sem, NULL) != 0) {
		errf(err, errlen, "semantic observer: no memory");
		goto fail;
	}
	t->sem_ready = 1;
	memset(&acfg, 0, sizeof(acfg));
	acfg.test_gate = gate;
	acfg.test_gate_arg = t;
	if (nfsp_activation_init(&t->act, &acfg) != 0 ||
	    nfsp_activation_install_rule_set(&t->act, t->rule_set_id) !=
		    NFSP_ACTIVATION_OK) {
		errf(err, errlen, "activation: no memory");
		goto fail;
	}
	t->act_ready = 1;
	memset(&jcfg, 0, sizeof(jcfg));
	jcfg.fd = fd;
	jcfg.proxy_session_id = cfg->proxy_session_id;
	jcfg.rule_set_id = t->rule_set_id;
	jcfg.retransmit_ms = cfg->retransmit_ms;
	jcfg.clock_ms = cfg->clock_ms;
	jcfg.clock_arg = cfg->clock_arg;
	jcfg.done = on_journal;
	jcfg.done_arg = t;
	if (nfsp_journal_open(&t->journal, &jcfg) != 0) {
		errf(err, errlen, "journal channel or session id refused");
		goto fail;
	}
	fd = -1;
	/* RULESET first: nothing can activate before the host has it. */
	nfsp_jb_init(&b, NFSP_JOURNAL_MAX_PAYLOAD);
	nfsp_jb_raw(&b, "{");
	nfsp_jb_key(&b, "candidate_id", 1);
	nfsp_jb_str(&b, t->ruleset.candidate_id);
	nfsp_jb_key(&b, "rule_set", 0);
	nfsp_jb_hex(&b, t->rule_set, t->rule_set_len);
	nfsp_jb_key(&b, "schema_id", 0);
	nfsp_jb_str(&b, t->ruleset.schema_id);
	nfsp_jb_key(&b, "semantic_runtime_version", 0);
	nfsp_jb_u64(&b, t->ruleset.semantic_runtime_version);
	nfsp_jb_raw(&b, "}");
	if (submit(t, "RULESET", &b, COOKIE(CK_RULESET, 0), NULL) != 0) {
		nfsp_jb_free(&b);
		errf(err, errlen, "RULESET could not be queued");
		goto fail;
	}
	nfsp_jb_free(&b);
	if (cfg->activation_path != NULL &&
	    endpoint_open(t, cfg->activation_path, err, errlen) != 0)
		goto fail;
	*out = t;
	return 0;
fail:
	if (fd >= 0)
		close(fd);
	nfsp_target_close(t);
	return -1;
}

/* Pump until nothing is owed or the deadline passes.  Answers can queue
 * more events (a batch's terminal, a generation's summary), so this runs
 * the lifecycle too and stops only when the queue stays empty. */
static void settle(struct nfsp_target *t, uint64_t deadline)
{
	for (;;) {
		struct pollfd pfd;

		nfsp_journal_pump(t->journal);
		lifecycle(t);
		nfsp_journal_pump(t->journal);
		if (nfsp_journal_failed(t->journal) ||
		    monotonic_ms() >= deadline)
			return;
		if (nfsp_journal_pending(t->journal) == 0) {
			int open = 0;

			/* A draining generation still closes at its bound. */
			for (size_t i = 0; i < t->ngens; i++)
				if (t->gens[i].draining_acked &&
				    !t->gens[i].complete_sent)
					open = 1;
			if (!open)
				return;
		}
		pfd.fd = nfsp_journal_fd(t->journal);
		pfd.events = nfsp_journal_events(t->journal);
		pfd.revents = 0;
		(void)poll(&pfd, 1, 20);
	}
}

/* RUN_COMPLETE claims the session ended cleanly: every event answered
 * with an ACK, no event the session owed went unrecorded, every
 * generation the host opened is summarized, every batch has its
 * terminal.  Anything less is left to the Runner's session end (05 §21).
 * `evidence_path_degraded` is the one dirty mark: a host rejection, a
 * local submit or tracking failure, or any evidence-path failure. */
static int clean(const struct nfsp_target *t)
{
	if (nfsp_journal_failed(t->journal) ||
	    nfsp_journal_pending(t->journal) != 0 ||
	    t->stats.ruleset_state != 1 || t->stats.evidence_path_degraded ||
	    t->stats.evidence_path_failures != 0)
		return 0;
	for (size_t i = 0; i < t->ngens; i++) {
		const struct tgen *g = &t->gens[i];

		if (!g->open_sent || ev_state(t, g->open_seq) != EV_ACKED ||
		    !g->complete_sent ||
		    ev_state(t, g->complete_seq) != EV_ACKED)
			return 0;
	}
	for (size_t i = 0; i < t->nbatches; i++)
		if (t->batches[i].state != B_DONE &&
		    t->batches[i].state != B_DEAD)
			return 0;
	return 1;
}

void nfsp_target_finish(struct nfsp_target *t, uint32_t wait_ms)
{
	uint64_t deadline = monotonic_ms() + wait_ms;
	struct nfsp_jbuf b;
	uint64_t batches = 0;

	if (t == NULL || t->run_state != RUN_NOT_SENT)
		return;
	settle(t, deadline);
	if (!clean(t)) {
		t->run_state = RUN_SKIPPED;
		return;
	}
	for (size_t i = 0; i < t->nbatches; i++)
		if (t->batches[i].state == B_DONE)
			batches++;
	nfsp_jb_init(&b, NFSP_JOURNAL_MAX_PAYLOAD);
	nfsp_jb_raw(&b, "{");
	nfsp_jb_key(&b, "batch_count", 1);
	nfsp_jb_u64(&b, batches);
	nfsp_jb_key(&b, "evidence_path_failures", 0);
	nfsp_jb_u64(&b, t->stats.evidence_path_failures);
	nfsp_jb_key(&b, "forward_complete_count", 0);
	nfsp_jb_u64(&b, t->stats.forward_complete);
	nfsp_jb_key(&b, "forward_failed_count", 0);
	nfsp_jb_u64(&b, t->stats.forward_failed);
	nfsp_jb_key(&b, "generations", 0);
	nfsp_jb_u64(&b, t->ngens);
	nfsp_jb_key(&b, "outside_activation_window", 0);
	nfsp_jb_u64(&b, outside_window(t));
	nfsp_jb_raw(&b, "}");
	if (submit(t, "RUN_COMPLETE", &b, COOKIE(CK_RUN, 0), &t->run_seq) == 0)
		t->run_state = RUN_SENT;
	else
		t->run_state = RUN_SKIPPED;
	nfsp_jb_free(&b);
	settle(t, deadline);
}

void nfsp_target_close(struct nfsp_target *t)
{
	if (t == NULL)
		return;
	nfsp_journal_close(t->journal);
	if (t->act_ready)
		nfsp_activation_free(&t->act);
	if (t->sem_ready)
		nfsp_semantic_free(&t->sem);
	if (t->ruleset_loaded)
		nfsp_ruleset_free(&t->ruleset);
	for (size_t i = 0; i < t->ngens; i++) {
		free(t->gens[i].counts);
		free(t->gens[i].refusal);
		free(t->gens[i].refusal_seq);
	}
	free(t->gens);
	for (size_t i = 0; i < t->nbatches; i++)
		free(t->batches[i].out);
	free(t->batches);
	for (unsigned i = 0; i < MAX_HOLDS; i++)
		free(t->holds[i].deps);
	for (unsigned i = 0; i < MAX_CLIENTS; i++)
		if (t->clients[i] >= 0)
			close(t->clients[i]);
	if (t->listen_fd >= 0) {
		close(t->listen_fd);
		unlink(t->listen_path);
	}
	free(t->ev);
	free(t->release);
	free(t->rule_set);
	free(t);
}

const struct nfsp_target_stats *nfsp_target_stats(const struct nfsp_target *t)
{
	return &t->stats;
}

void nfsp_target_report(const struct nfsp_target *t, FILE *out)
{
	const struct nfsp_target_stats *s = &t->stats;
	const struct nfsp_journal_stats *j = nfsp_journal_stats(t->journal);

	fprintf(out, "target ruleset=%s records=%llu eligible=%llu "
		"exposures=%llu exposure_refused=%llu exposure_lost=%llu "
		"refusal_events=%llu refusal_waits=%llu "
		"forward_complete=%llu forward_failed=%llu held_dropped=%llu "
		"evidence_path_failures=%llu evidence_path_degraded=%d "
		"outside_activation_window=%llu late_after_close=%llu "
		"generations=%zu generations_complete=%llu run_complete=%s\n",
		s->ruleset_state > 0 ? "acked" :
		s->ruleset_state < 0 ? "failed" : "pending",
		(unsigned long long)s->records,
		(unsigned long long)s->eligible,
		(unsigned long long)s->exposures,
		(unsigned long long)s->exposure_refused,
		(unsigned long long)s->exposure_lost,
		(unsigned long long)s->refusal_events,
		(unsigned long long)s->refusal_waits,
		(unsigned long long)s->forward_complete,
		(unsigned long long)s->forward_failed,
		(unsigned long long)s->held_dropped,
		(unsigned long long)s->evidence_path_failures,
		s->evidence_path_degraded,
		(unsigned long long)outside_window(t),
		(unsigned long long)t->act.stats.late_after_close,
		t->ngens,
		(unsigned long long)s->generations_complete,
		t->run_state == RUN_SKIPPED ? "skipped" :
		t->run_state == RUN_NOT_SENT ? "not_sent" :
		ev_state(t, t->run_seq) == EV_ACKED ? "acked" :
		ev_state(t, t->run_seq) == EV_PENDING ? "pending" : "failed");
	fprintf(out, "journal submitted=%llu sent=%llu retransmits=%llu "
		"acked=%llu rejected=%llu lost=%llu stale_answers=%llu "
		"pending=%zu channel=%s\n",
		(unsigned long long)j->submitted, (unsigned long long)j->sent,
		(unsigned long long)j->retransmits,
		(unsigned long long)j->acked, (unsigned long long)j->rejected,
		(unsigned long long)j->lost,
		(unsigned long long)j->stale_answers,
		nfsp_journal_pending(t->journal),
		nfsp_journal_failed(t->journal) ? "failed" : "open");
	nfsp_semantic_report(&t->sem, out);
}
