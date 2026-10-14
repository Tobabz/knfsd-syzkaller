/* Transaction Context table (design 03-nfs-proxy/03).
 *
 * LAYOUT
 *
 *   A fixed pool of max_outstanding + max_retained entries, allocated once,
 *   so a burst of CALLs can never grow memory.  A key hash with chains finds
 *   an entry.  Every used entry is on exactly one of two lists:
 *
 *     outstanding  awaiting a reply, or ambiguous and not yet answered;
 *                  ordered by last traffic, so the timeout scan stops at the
 *                  first entry that is still young
 *     retained     ended (replied, expired, ambiguous and answered); ordered
 *                  by when it ended, so the oldest is the one reclaimed
 *
 *   Only retained entries are ever reclaimed.  The pool has room for every
 *   outstanding entry the bound allows plus the retained ones, so admitting
 *   a CALL within the bound never needs a live entry's slot.
 */
#include "txn.h"

#include <stdlib.h>
#include <string.h>

#define NONE	(-1)

static uint32_t key_hash(const struct nfsp_txn_key *k)
{
	uint64_t h = k->connection_id * 0x9e3779b97f4a7c15ull;

	h ^= ((uint64_t)k->xid << 1) | (uint64_t)(k->call_direction & 1);
	h ^= h >> 31;
	h *= 0xbf58476d1ce4e5b9ull;
	h ^= h >> 29;
	return (uint32_t)h;
}

static int key_eq(const struct nfsp_txn_key *a, const struct nfsp_txn_key *b)
{
	return a->connection_id == b->connection_id &&
	       a->call_direction == b->call_direction && a->xid == b->xid;
}

/* Two independent 64-bit hashes of the whole CALL: a retransmission is the
 * same bytes, and anything else is a different CALL (design 03 §11, "a
 * complete request fingerprint").  Runtime data only, never an identity. */
static void fingerprint(const uint8_t *p, size_t n, uint64_t fp[2])
{
	uint64_t a = 0xcbf29ce484222325ull, b = 0x84222325cbf29ce4ull;

	for (size_t i = 0; i < n; i++) {
		a = (a ^ p[i]) * 0x100000001b3ull;
		b = (b ^ p[i]) * 0x9e3779b97f4a7c15ull;
		b = b << 31 | b >> 33;
	}
	fp[0] = a;
	fp[1] = b;
}

static struct nfsp_txn_entry *E(struct nfsp_txn *t, int32_t i)
{
	return &t->slots[i];
}

/* ---- lists ---- */

static void list_unlink(struct nfsp_txn *t, int32_t i)
{
	struct nfsp_txn_entry *e = E(t, i);
	int32_t *head = e->outstanding ? &t->out_head : &t->ret_head;
	int32_t *tail = e->outstanding ? &t->out_tail : &t->ret_tail;

	if (e->prev != NONE)
		E(t, e->prev)->next = e->next;
	else
		*head = e->next;
	if (e->next != NONE)
		E(t, e->next)->prev = e->prev;
	else
		*tail = e->prev;
	e->prev = e->next = NONE;
}

static void list_append(struct nfsp_txn *t, int32_t i)
{
	struct nfsp_txn_entry *e = E(t, i);
	int32_t *head = e->outstanding ? &t->out_head : &t->ret_head;
	int32_t *tail = e->outstanding ? &t->out_tail : &t->ret_tail;

	e->prev = *tail;
	e->next = NONE;
	if (*tail != NONE)
		E(t, *tail)->next = i;
	else
		*head = i;
	*tail = i;
}

/* ---- hash ---- */

static int32_t find(struct nfsp_txn *t, const struct nfsp_txn_key *k)
{
	int32_t i = t->buckets[key_hash(k) & (t->nbuckets - 1u)];

	while (i != NONE && !key_eq(&E(t, i)->key, k))
		i = E(t, i)->hnext;
	return i;
}

static void unhash(struct nfsp_txn *t, int32_t i)
{
	int32_t *p = &t->buckets[key_hash(&E(t, i)->key) & (t->nbuckets - 1u)];

	while (*p != i)
		p = &E(t, *p)->hnext;
	*p = E(t, i)->hnext;
}

/* ---- slots ---- */

static void free_slot(struct nfsp_txn *t, int32_t i)
{
	struct nfsp_txn_entry *e = E(t, i);

	list_unlink(t, i);
	unhash(t, i);
	if (e->outstanding)
		t->stats.outstanding--;
	else
		t->stats.retained--;
	e->used = 0;
	e->hnext = t->free_head;
	t->free_head = i;
}

/* Move an outstanding entry to the retained list; drop the oldest retained
 * one if that makes too many. */
static void retire(struct nfsp_txn *t, int32_t i, uint64_t now)
{
	struct nfsp_txn_entry *e = E(t, i);

	list_unlink(t, i);
	e->outstanding = 0;
	e->ended_ms = now;
	t->stats.outstanding--;
	t->stats.retained++;
	list_append(t, i);
	if (t->stats.retained > t->cfg.max_retained) {
		free_slot(t, t->ret_head);
		t->stats.reclaimed++;
	}
}

static uint32_t outstanding_on(struct nfsp_txn *t, uint64_t connection_id)
{
	uint32_t n = 0;

	for (int32_t i = t->out_head; i != NONE; i = E(t, i)->next)
		if (E(t, i)->key.connection_id == connection_id)
			n++;
	return n;
}

/* ---- public ---- */

int nfsp_txn_init(struct nfsp_txn *t, const struct nfsp_txn_cfg *cfg)
{
	struct nfsp_txn_cfg c = cfg ? *cfg : (struct nfsp_txn_cfg){0};
	uint64_t n;

	memset(t, 0, sizeof(*t));
	if (!c.max_outstanding)
		c.max_outstanding = NFSP_TXN_DEFAULT_MAX_OUTSTANDING;
	if (!c.max_per_connection)
		c.max_per_connection = NFSP_TXN_DEFAULT_MAX_PER_CONNECTION;
	if (!c.max_retained)
		c.max_retained = NFSP_TXN_DEFAULT_MAX_RETAINED;
	if (!c.timeout_ms)
		c.timeout_ms = NFSP_TXN_DEFAULT_TIMEOUT_MS;
	if (!c.retention_ms)
		c.retention_ms = NFSP_TXN_DEFAULT_RETENTION_MS;
	n = (uint64_t)c.max_outstanding + c.max_retained;
	if (n > (1u << 24))
		return -1;
	t->cfg = c;
	t->nslots = (uint32_t)n;
	t->nbuckets = 1;
	while (t->nbuckets < 2u * t->nslots)
		t->nbuckets <<= 1;
	t->slots = calloc(t->nslots, sizeof(*t->slots));
	t->buckets = malloc(t->nbuckets * sizeof(*t->buckets));
	if (!t->slots || !t->buckets) {
		nfsp_txn_free(t);
		return -1;
	}
	for (uint32_t b = 0; b < t->nbuckets; b++)
		t->buckets[b] = NONE;
	for (uint32_t i = 0; i < t->nslots; i++)
		t->slots[i].hnext = i + 1 < t->nslots ? (int32_t)(i + 1) : NONE;
	t->free_head = 0;
	t->out_head = t->out_tail = t->ret_head = t->ret_tail = NONE;
	return 0;
}

void nfsp_txn_free(struct nfsp_txn *t)
{
	free(t->slots);
	free(t->buckets);
	memset(t, 0, sizeof(*t));
}

void nfsp_txn_tick(struct nfsp_txn *t, uint64_t now)
{
	while (t->out_head != NONE &&
	       now - E(t, t->out_head)->last_seen_ms >= t->cfg.timeout_ms) {
		struct nfsp_txn_entry *e = E(t, t->out_head);

		e->state = NFSP_TXN_EXPIRED;
		e->expiry = NFSP_TXN_EXPIRED_TIMEOUT;
		t->stats.expired_timeout++;
		retire(t, t->out_head, now);
	}
	while (t->ret_head != NONE &&
	       now - E(t, t->ret_head)->ended_ms >= t->cfg.retention_ms) {
		free_slot(t, t->ret_head);
		t->stats.retired++;
	}
}

enum nfsp_txn_result nfsp_txn_call(struct nfsp_txn *t,
				   const struct nfsp_txn_key *key,
				   uint32_t program, uint32_t version,
				   uint32_t procedure, uint32_t cred_flavor,
				   uint64_t activation_generation,
				   enum nfsp_txn_forwarded forwarded,
				   const uint8_t *payload, size_t len,
				   uint64_t now, struct nfsp_txn_entry **entry)
{
	uint64_t fp[2];
	struct nfsp_txn_entry *e;
	int32_t i;

	*entry = NULL;
	nfsp_txn_tick(t, now);
	fingerprint(payload, len, fp);
	i = find(t, key);
	if (i != NONE && E(t, i)->outstanding) {
		/* A live key: never overwritten (design 03 §11). */
		e = E(t, i);
		e->duplicate_calls++;
		e->last_seen_ms = now;
		list_unlink(t, i);
		list_append(t, i);
		*entry = e;
		if (e->state == NFSP_TXN_AWAITING_REPLY &&
		    e->fp[0] == fp[0] && e->fp[1] == fp[1] &&
		    e->fp_len == len) {
			t->stats.duplicate_equivalent++;
			return NFSP_TXN_DUPLICATE_EQUIVALENT;
		}
		e->state = NFSP_TXN_AMBIGUOUS;
		t->stats.ambiguous_calls++;
		return NFSP_TXN_AMBIGUOUS_CALL;
	}
	if (i != NONE && E(t, i)->state != NFSP_TXN_REPLIED) {
		/* Ended without its one reply (expired, or ambiguous): a late
		 * reply may still come for the old CALL, so a new CALL on the
		 * key cannot own it.  The key stays ambiguous, and stays
		 * retained a full retention from now (§11, §13). */
		e = E(t, i);
		e->state = NFSP_TXN_AMBIGUOUS;
		e->duplicate_calls++;
		e->last_seen_ms = now;
		list_unlink(t, i);
		e->ended_ms = now;
		list_append(t, i);
		*entry = e;
		t->stats.ambiguous_calls++;
		return NFSP_TXN_AMBIGUOUS_CALL;
	}
	if (i != NONE) {
		/* Completed with its reply: the key may be used again (§12). */
		free_slot(t, i);
		t->stats.superseded++;
	}
	if (t->stats.outstanding >= t->cfg.max_outstanding ||
	    outstanding_on(t, key->connection_id) >=
	    t->cfg.max_per_connection) {
		t->stats.capacity_exhausted++;
		return NFSP_TXN_CAPACITY_EXHAUSTED;
	}
	if (t->free_head == NONE) {
		/* Only retained entries can hold the pool (see LAYOUT). */
		free_slot(t, t->ret_head);
		t->stats.reclaimed++;
	}
	i = t->free_head;
	e = E(t, i);
	t->free_head = e->hnext;
	memset(e, 0, sizeof(*e));
	e->key = *key;
	e->program = program;
	e->version = version;
	e->procedure = procedure;
	e->cred_flavor = cred_flavor;
	e->activation_generation = activation_generation;
	e->forwarded = forwarded;
	e->state = NFSP_TXN_AWAITING_REPLY;
	e->created_ms = e->last_seen_ms = now;
	e->fp[0] = fp[0];
	e->fp[1] = fp[1];
	e->fp_len = len;
	e->used = e->outstanding = 1;
	e->prev = e->next = NONE;
	{
		int32_t *b = &t->buckets[key_hash(key) & (t->nbuckets - 1u)];

		e->hnext = *b;
		*b = i;
	}
	list_append(t, i);
	t->stats.outstanding++;
	if (t->stats.outstanding > t->stats.peak_outstanding)
		t->stats.peak_outstanding = t->stats.outstanding;
	t->stats.inserted++;
	*entry = e;
	return NFSP_TXN_INSERTED;
}

void nfsp_txn_enrich(struct nfsp_txn *t, struct nfsp_txn_entry *e,
		     const struct nfsp_decoded_msg *m)
{
	struct nfsp_txn_request *r = &e->original;

	memset(r, 0, sizeof(*r));
	r->decoded = 1;
	r->status = m->status;
	r->has_minor = m->has_minor;
	r->minor_version = m->minor_version;
	if (m->status == NFSP_DECODE_DECODED ||
	    m->status == NFSP_DECODE_PARTIAL) {
		r->nops = m->nops < NFSP_TXN_MAX_OPS ? m->nops :
			  NFSP_TXN_MAX_OPS;
		r->ops_truncated = m->nops > NFSP_TXN_MAX_OPS;
		for (uint32_t k = 0; k < r->nops; k++)
			r->opcodes[k] = m->ops[k].opcode;
	}
	t->stats.enriched++;
}

enum nfsp_txn_result nfsp_txn_reply(struct nfsp_txn *t,
				    const struct nfsp_txn_key *key,
				    uint64_t now,
				    const struct nfsp_txn_entry **entry)
{
	struct nfsp_txn_entry *e;
	int32_t i;

	*entry = NULL;
	nfsp_txn_tick(t, now);
	i = find(t, key);
	if (i == NONE) {
		t->stats.missing++;
		return NFSP_TXN_MISSING;
	}
	e = E(t, i);
	*entry = e;
	e->replies++;
	switch (e->state) {
	case NFSP_TXN_AWAITING_REPLY:
		e->state = NFSP_TXN_REPLIED;
		e->reply_seen_ms = now;
		retire(t, i, now);
		t->stats.found++;
		return NFSP_TXN_FOUND;
	case NFSP_TXN_REPLIED:
		/* Another reply to the same CALL: still that CALL's. */
		t->stats.duplicate_replies++;
		t->stats.found++;
		return NFSP_TXN_FOUND;
	case NFSP_TXN_AMBIGUOUS:
		if (e->outstanding) {
			e->reply_seen_ms = now;
			retire(t, i, now);
		}
		t->stats.ambiguous_replies++;
		return NFSP_TXN_AMBIGUOUS_REPLY;
	case NFSP_TXN_EXPIRED:
		break;
	}
	t->stats.expired_replies++;
	return NFSP_TXN_EXPIRED_ENTRY;
}

void nfsp_txn_dispatch(const struct nfsp_txn_entry *e,
		       struct nfsp_reply_dispatch *rd)
{
	memset(rd, 0, sizeof(*rd));
	rd->program = e->program;
	rd->version = e->version;
	rd->procedure = e->procedure;
	rd->has_minor = e->original.has_minor;
	rd->minor_version = e->original.minor_version;
	rd->source = NFSP_DISPATCH_TRANSACTION_ENTRY;
	rd->cred_flavor = e->cred_flavor;
}

void nfsp_txn_connection_closed(struct nfsp_txn *t, uint64_t connection_id)
{
	for (uint32_t i = 0; i < t->nslots; i++) {
		struct nfsp_txn_entry *e = &t->slots[i];

		if (!e->used || e->key.connection_id != connection_id)
			continue;
		if (e->outstanding)
			t->stats.expired_connection_closed++;
		else
			t->stats.retired++;
		free_slot(t, (int32_t)i);
	}
}

const char *nfsp_txn_strresult(enum nfsp_txn_result r)
{
	switch (r) {
	case NFSP_TXN_INSERTED: return "inserted";
	case NFSP_TXN_DUPLICATE_EQUIVALENT: return "duplicate_equivalent";
	case NFSP_TXN_AMBIGUOUS_CALL: return "ambiguous_call";
	case NFSP_TXN_CAPACITY_EXHAUSTED: return "capacity_exhausted";
	case NFSP_TXN_FOUND: return "found";
	case NFSP_TXN_MISSING: return "missing";
	case NFSP_TXN_AMBIGUOUS_REPLY: return "ambiguous";
	case NFSP_TXN_EXPIRED_ENTRY: return "expired";
	}
	return "unknown";
}
