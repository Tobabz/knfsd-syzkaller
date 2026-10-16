#include "activation.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct nfsp_activation_generation {
	uint64_t generation;
	enum nfsp_generation_state state;
	int deactivation_requested;
	enum nfsp_activation_barrier_fact open_barrier;
	uint64_t open_barrier_id;
	enum nfsp_activation_barrier_fact draining_barrier;
	uint64_t draining_barrier_id;
	uint64_t records_seen;
	uint64_t eligible_calls;
	uint64_t admitted_calls;
	uint64_t duplicate_calls;
	uint64_t connection_closed_calls;
	uint64_t call_account_capacity_exhausted;
	uint32_t pending_call_accounts;
	uint32_t unaccounted_calls_at_closure;
	uint64_t eligible_replies;
	uint64_t resolved_replies;
	uint64_t duplicate_replies;
	uint64_t unresolved_replies;
	enum nfsp_activation_closure_reason closure_reason;
	uint64_t reply_unresolved_count;
};

struct nfsp_activation_call_account {
	uint64_t id;
	uint64_t generation;
	int used;
};

static int counter_has_room(uint64_t value)
{
	return value != UINT64_MAX;
}

static int counter_can_add(uint64_t value, uint64_t addend)
{
	return addend <= UINT64_MAX - value;
}

static enum nfsp_activation_result counter_failure(struct nfsp_activation *a)
{
	a->quarantined = 1;
	return NFSP_ACTIVATION_COUNTER_EXHAUSTED;
}

static int32_t find_generation(const struct nfsp_activation *a,
			       uint64_t generation)
{
	uint32_t i;

	for (i = 0; i < a->generation_count; i++) {
		if (a->generations[i].generation == generation)
			return (int32_t)i;
	}
	return -1;
}

static int32_t find_call_account(const struct nfsp_activation *a,
				 uint64_t ticket_id)
{
	uint32_t i;

	for (i = 0; i < a->cfg.max_pending_calls; i++) {
		if (a->call_accounts[i].used &&
		    a->call_accounts[i].id == ticket_id)
			return (int32_t)i;
	}
	return -1;
}

static int32_t free_call_account(const struct nfsp_activation *a)
{
	uint32_t i;

	for (i = 0; i < a->cfg.max_pending_calls; i++) {
		if (!a->call_accounts[i].used)
			return (int32_t)i;
	}
	return -1;
}

static int32_t call_accounting_generation(const struct nfsp_activation *a)
{
	uint32_t i;

	for (i = 0; i < a->generation_count; i++) {
		if (a->generations[i].state == NFSP_GENERATION_CALL_ACCOUNTING)
			return (int32_t)i;
	}
	return -1;
}

static uint32_t draining_count(const struct nfsp_activation *a)
{
	uint32_t count = 0;
	uint32_t i;

	for (i = 0; i < a->generation_count; i++) {
		enum nfsp_generation_state state = a->generations[i].state;

		if (state == NFSP_GENERATION_CALL_ACCOUNTING ||
		    state == NFSP_GENERATION_DRAIN_BARRIER ||
		    state == NFSP_GENERATION_DRAINING ||
		    (state == NFSP_GENERATION_QUARANTINED &&
		     a->generations[i].deactivation_requested))
			count++;
	}
	return count;
}

static uint32_t closed_count(const struct nfsp_activation *a)
{
	uint32_t count = 0;
	uint32_t i;

	for (i = 0; i < a->generation_count; i++) {
		if (a->generations[i].state == NFSP_GENERATION_CLOSED)
			count++;
	}
	return count;
}

static enum nfsp_activation_state activation_state(
	const struct nfsp_activation *a)
{
	uint32_t i;

	if (a->quarantined)
		return NFSP_ACTIVATION_QUARANTINED;
	if (!a->rule_set_installed)
		return NFSP_ACTIVATION_NO_RULESET;
	if (a->barrier_index >= 0 &&
	    a->pending_barrier.event == NFSP_GATE_GENERATION_OPEN)
		return NFSP_ACTIVATION_OPENING;
	if (a->admitting_index >= 0)
		return NFSP_ACTIVATION_ADMITTING;
	if (call_accounting_generation(a) >= 0)
		return NFSP_ACTIVATION_DRAINING;
	if (draining_count(a) != 0)
		return NFSP_ACTIVATION_DRAINING;
	for (i = 0; i < a->generation_count; i++) {
		if (a->generations[i].state == NFSP_GENERATION_CLOSED)
			return NFSP_ACTIVATION_CLOSED;
	}
	return NFSP_ACTIVATION_INACTIVE;
}

static int valid_rule_set_id(const char *rule_set_id, size_t *length)
{
	size_t n;

	if (!rule_set_id)
		return 0;
	for (n = 0; n <= NFSP_ACTIVATION_RULE_SET_ID_MAX; n++) {
		if (rule_set_id[n] == '\0')
			break;
	}
	if (n == 0 || n > NFSP_ACTIVATION_RULE_SET_ID_MAX)
		return 0;
	*length = n;
	return 1;
}

static enum nfsp_activation_result check_rule_set(
	const struct nfsp_activation *a, const char *rule_set_id)
{
	size_t ignored;

	if (!a->rule_set_installed)
		return NFSP_ACTIVATION_NO_RULE_SET;
	if (!valid_rule_set_id(rule_set_id, &ignored) ||
	    strcmp(a->rule_set_id, rule_set_id) != 0)
		return NFSP_ACTIVATION_RULE_SET_MISMATCH;
	return NFSP_ACTIVATION_OK;
}

static void clear_pending_barrier(struct nfsp_activation *a)
{
	memset(&a->pending_barrier, 0, sizeof(a->pending_barrier));
	a->barrier_index = -1;
}

static void set_barrier_output(const struct nfsp_activation *a,
			       struct nfsp_activation_barrier *barrier)
{
	if (barrier)
		*barrier = a->pending_barrier;
}

static void cancel_call_accounts(struct nfsp_activation *a, int32_t index)
{
	struct nfsp_activation_generation *g = &a->generations[index];
	uint32_t cancelled = 0;
	uint32_t i;

	for (i = 0; i < a->cfg.max_pending_calls; i++) {
		if (a->call_accounts[i].used &&
		    a->call_accounts[i].generation == g->generation) {
			memset(&a->call_accounts[i], 0,
			       sizeof(a->call_accounts[i]));
			cancelled++;
		}
	}
	if (cancelled != g->pending_call_accounts ||
	    cancelled > a->pending_call_account_count) {
		a->quarantined = 1;
		a->pending_call_account_count = 0;
	} else {
		a->pending_call_account_count -= cancelled;
	}
	g->pending_call_accounts = 0;
}

static void close_generation(struct nfsp_activation *a, int32_t index,
			     enum nfsp_activation_closure_reason reason,
			     uint32_t unaccounted_calls)
{
	struct nfsp_activation_generation *g = &a->generations[index];

	if (a->admitting_index == index)
		a->admitting_index = -1;
	if (a->barrier_index == index)
		clear_pending_barrier(a);
	g->state = NFSP_GENERATION_CLOSED;
	g->closure_reason = reason;
	g->unaccounted_calls_at_closure = unaccounted_calls;
	g->reply_unresolved_count = g->unresolved_replies + unaccounted_calls;
}

static enum nfsp_activation_result maybe_close_drained(
	struct nfsp_activation *a, int32_t index)
{
	struct nfsp_activation_generation *g = &a->generations[index];

	if (g->state != NFSP_GENERATION_DRAINING ||
	    g->draining_barrier != NFSP_BARRIER_ACCEPTED)
		return NFSP_ACTIVATION_CLOSURE_NOT_READY;
	if (g->pending_call_accounts != 0)
		return NFSP_ACTIVATION_CALL_ACCOUNT_PENDING;
	if (g->unresolved_replies != 0)
		return NFSP_ACTIVATION_CLOSURE_BLOCKED;
	close_generation(a, index, NFSP_CLOSURE_DRAINED, 0);
	return NFSP_ACTIVATION_OK;
}

static enum nfsp_activation_result complete_open(
	struct nfsp_activation *a, int32_t index,
	enum nfsp_activation_gate_reply reply)
{
	struct nfsp_activation_generation *g = &a->generations[index];

	if (reply == NFSP_ACTIVATION_GATE_ACCEPTED) {
		g->open_barrier = NFSP_BARRIER_ACCEPTED;
		g->state = NFSP_GENERATION_ADMITTING;
		a->admitting_index = index;
		clear_pending_barrier(a);
		return NFSP_ACTIVATION_OK;
	}
	if (reply == NFSP_ACTIVATION_GATE_REJECTED) {
		g->open_barrier = NFSP_BARRIER_REJECTED;
		g->state = NFSP_GENERATION_OPEN_FAILED;
		clear_pending_barrier(a);
		return NFSP_ACTIVATION_BARRIER_REJECTED;
	}
	g->open_barrier = NFSP_BARRIER_NO_ACK;
	g->state = NFSP_GENERATION_QUARANTINED;
	a->quarantined = 1;
	clear_pending_barrier(a);
	return NFSP_ACTIVATION_BARRIER_NO_ACK;
}

static enum nfsp_activation_result complete_draining(
	struct nfsp_activation *a, int32_t index,
	enum nfsp_activation_gate_reply reply)
{
	struct nfsp_activation_generation *g = &a->generations[index];

	if (reply == NFSP_ACTIVATION_GATE_ACCEPTED) {
		enum nfsp_activation_result result;

		g->draining_barrier = NFSP_BARRIER_ACCEPTED;
		g->state = NFSP_GENERATION_DRAINING;
		clear_pending_barrier(a);
		result = maybe_close_drained(a, index);
		if (result == NFSP_ACTIVATION_CLOSURE_BLOCKED)
			return NFSP_ACTIVATION_OK;
		return result;
	}
	if (reply == NFSP_ACTIVATION_GATE_REJECTED) {
		g->draining_barrier = NFSP_BARRIER_REJECTED;
		g->state = NFSP_GENERATION_QUARANTINED;
		a->quarantined = 1;
		clear_pending_barrier(a);
		return NFSP_ACTIVATION_BARRIER_REJECTED;
	}
	g->draining_barrier = NFSP_BARRIER_NO_ACK;
	g->state = NFSP_GENERATION_QUARANTINED;
	a->quarantined = 1;
	clear_pending_barrier(a);
	return NFSP_ACTIVATION_BARRIER_NO_ACK;
}

static enum nfsp_activation_result submit_gate(
	struct nfsp_activation *a, int32_t index,
	enum nfsp_activation_gate_event event,
	struct nfsp_activation_barrier *barrier)
{
	struct nfsp_activation_gate_request request;
	enum nfsp_activation_gate_reply reply;

	if (a->next_barrier_id == UINT64_MAX)
		return counter_failure(a);
	a->next_barrier_id++;
	a->pending_barrier.id = a->next_barrier_id;
	a->pending_barrier.generation = a->generations[index].generation;
	a->pending_barrier.event = event;
	a->barrier_index = index;
	if (event == NFSP_GATE_GENERATION_OPEN) {
		a->generations[index].open_barrier = NFSP_BARRIER_PENDING;
		a->generations[index].open_barrier_id = a->next_barrier_id;
	} else {
		a->generations[index].draining_barrier = NFSP_BARRIER_PENDING;
		a->generations[index].draining_barrier_id = a->next_barrier_id;
	}
	set_barrier_output(a, barrier);

	request.barrier = a->pending_barrier;
	request.rule_set_id = a->rule_set_id;
	reply = a->cfg.test_gate ?
		a->cfg.test_gate(a->cfg.test_gate_arg, &request) :
		NFSP_ACTIVATION_GATE_NO_ACK;
	if (reply == NFSP_ACTIVATION_GATE_PENDING)
		return NFSP_ACTIVATION_BARRIER_PENDING;
	if (reply != NFSP_ACTIVATION_GATE_ACCEPTED &&
	    reply != NFSP_ACTIVATION_GATE_REJECTED &&
	    reply != NFSP_ACTIVATION_GATE_NO_ACK)
		reply = NFSP_ACTIVATION_GATE_NO_ACK;
	if (event == NFSP_GATE_GENERATION_OPEN)
		return complete_open(a, index, reply);
	return complete_draining(a, index, reply);
}

int nfsp_activation_init(struct nfsp_activation *a,
			 const struct nfsp_activation_cfg *cfg)
{
	uint32_t max_generations;
	uint32_t max_draining;
	uint32_t max_pending_calls;

	if (!a)
		return -1;
	memset(a, 0, sizeof(*a));
	max_generations = cfg && cfg->max_generations ?
		cfg->max_generations : NFSP_ACTIVATION_DEFAULT_MAX_GENERATIONS;
	if (max_generations == 0 ||
	    max_generations > NFSP_ACTIVATION_MAX_GENERATIONS)
		return -1;
	max_draining = cfg && cfg->max_draining ? cfg->max_draining :
		(max_generations < NFSP_ACTIVATION_DEFAULT_MAX_DRAINING ?
		 max_generations : NFSP_ACTIVATION_DEFAULT_MAX_DRAINING);
	if (max_draining == 0 || max_draining > max_generations)
		return -1;
	max_pending_calls = cfg && cfg->max_pending_calls ?
		cfg->max_pending_calls :
		NFSP_ACTIVATION_DEFAULT_MAX_PENDING_CALLS;
	if (max_pending_calls == 0 ||
	    max_pending_calls > NFSP_ACTIVATION_MAX_PENDING_CALLS)
		return -1;
	a->generations = calloc(max_generations, sizeof(*a->generations));
	if (!a->generations)
		return -1;
	a->call_accounts = calloc(max_pending_calls,
				  sizeof(*a->call_accounts));
	if (!a->call_accounts) {
		free(a->generations);
		memset(a, 0, sizeof(*a));
		return -1;
	}
	a->cfg.max_generations = max_generations;
	a->cfg.max_draining = max_draining;
	a->cfg.max_pending_calls = max_pending_calls;
	if (cfg) {
		a->cfg.test_gate = cfg->test_gate;
		a->cfg.test_gate_arg = cfg->test_gate_arg;
	}
	a->admitting_index = -1;
	a->barrier_index = -1;
	return 0;
}

void nfsp_activation_free(struct nfsp_activation *a)
{
	if (!a)
		return;
	free(a->call_accounts);
	free(a->generations);
	memset(a, 0, sizeof(*a));
}

enum nfsp_activation_result
nfsp_activation_install_rule_set(struct nfsp_activation *a,
				 const char *rule_set_id)
{
	size_t length;

	if (!a || !a->generations || !valid_rule_set_id(rule_set_id, &length))
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	if (a->legacy_active)
		return NFSP_ACTIVATION_LEGACY_CONFLICT;
	if (a->rule_set_installed) {
		if (strcmp(a->rule_set_id, rule_set_id) == 0)
			return NFSP_ACTIVATION_IDEMPOTENT;
		return NFSP_ACTIVATION_RULE_SET_IMMUTABLE;
	}
	memcpy(a->rule_set_id, rule_set_id, length + 1u);
	a->rule_set_installed = 1;
	return NFSP_ACTIVATION_OK;
}

enum nfsp_activation_result
nfsp_activation_legacy_enable(struct nfsp_activation *a)
{
	if (!a || !a->generations)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	if (a->rule_set_installed)
		return NFSP_ACTIVATION_LEGACY_CONFLICT;
	if (a->legacy_active)
		return NFSP_ACTIVATION_IDEMPOTENT;
	a->legacy_active = 1;
	return NFSP_ACTIVATION_OK;
}

enum nfsp_activation_result
nfsp_activation_legacy_disable(struct nfsp_activation *a)
{
	if (!a || !a->generations)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	if (!a->legacy_active)
		return NFSP_ACTIVATION_IDEMPOTENT;
	a->legacy_active = 0;
	return NFSP_ACTIVATION_OK;
}

enum nfsp_activation_result
nfsp_activation_activate(struct nfsp_activation *a, const char *rule_set_id,
			 uint64_t generation,
			 struct nfsp_activation_barrier *barrier)
{
	enum nfsp_activation_result result;
	int32_t existing;
	int32_t index;
	struct nfsp_activation_generation *g;

	if (barrier)
		memset(barrier, 0, sizeof(*barrier));
	if (!a || !a->generations || generation == 0)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	result = check_rule_set(a, rule_set_id);
	if (result != NFSP_ACTIVATION_OK)
		return result;
	if (a->legacy_active)
		return NFSP_ACTIVATION_LEGACY_CONFLICT;
	if (a->quarantined)
		return NFSP_ACTIVATION_QUARANTINE;
	existing = find_generation(a, generation);
	if (existing >= 0) {
		g = &a->generations[existing];
		if (g->state == NFSP_GENERATION_OPENING &&
		    a->barrier_index == existing) {
			set_barrier_output(a, barrier);
			return NFSP_ACTIVATION_BARRIER_PENDING;
		}
		if (g->state == NFSP_GENERATION_ADMITTING &&
		    a->admitting_index == existing)
			return NFSP_ACTIVATION_IDEMPOTENT;
		if (g->state == NFSP_GENERATION_CALL_ACCOUNTING)
			return NFSP_ACTIVATION_CALL_ACCOUNT_PENDING;
		return NFSP_ACTIVATION_GENERATION_REUSED;
	}
	if (a->barrier_index >= 0)
		return NFSP_ACTIVATION_BARRIER_IN_PROGRESS;
	if (a->admitting_index >= 0)
		return NFSP_ACTIVATION_ONE_ADMITTING;
	if (call_accounting_generation(a) >= 0)
		return NFSP_ACTIVATION_CALL_ACCOUNT_PENDING;
	if (draining_count(a) >= a->cfg.max_draining)
		return NFSP_ACTIVATION_DRAINING_LIMIT;
	if (a->generation_count >= a->cfg.max_generations)
		return NFSP_ACTIVATION_GENERATION_CAPACITY;
	index = (int32_t)a->generation_count;
	a->generation_count++;
	g = &a->generations[index];
	memset(g, 0, sizeof(*g));
	g->generation = generation;
	g->state = NFSP_GENERATION_OPENING;
	return submit_gate(a, index, NFSP_GATE_GENERATION_OPEN, barrier);
}

enum nfsp_activation_result
nfsp_activation_deactivate(struct nfsp_activation *a,
			   const char *rule_set_id, uint64_t generation,
			   struct nfsp_activation_barrier *barrier)
{
	enum nfsp_activation_result result;
	int32_t index;
	struct nfsp_activation_generation *g;

	if (barrier)
		memset(barrier, 0, sizeof(*barrier));
	if (!a || !a->generations || generation == 0)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	result = check_rule_set(a, rule_set_id);
	if (result != NFSP_ACTIVATION_OK)
		return result;
	index = find_generation(a, generation);
	if (index < 0)
		return NFSP_ACTIVATION_UNKNOWN_GENERATION;
	g = &a->generations[index];
	if (g->state == NFSP_GENERATION_DRAIN_BARRIER &&
	    a->barrier_index == index) {
		set_barrier_output(a, barrier);
		return NFSP_ACTIVATION_BARRIER_PENDING;
	}
	if (g->state == NFSP_GENERATION_DRAINING)
		return NFSP_ACTIVATION_IDEMPOTENT;
	if (g->state == NFSP_GENERATION_CLOSED) {
		if (g->draining_barrier == NFSP_BARRIER_ACCEPTED)
			return NFSP_ACTIVATION_IDEMPOTENT;
		if (!g->deactivation_requested)
			return NFSP_ACTIVATION_ALREADY_CLOSED;
		return a->quarantined ? NFSP_ACTIVATION_QUARANTINE :
			NFSP_ACTIVATION_BARRIER_NO_ACK;
	}
	if (a->quarantined)
		return NFSP_ACTIVATION_QUARANTINE;
	if (g->state == NFSP_GENERATION_CALL_ACCOUNTING) {
		if (g->pending_call_accounts != 0)
			return NFSP_ACTIVATION_CALL_ACCOUNT_PENDING;
		if (a->barrier_index >= 0)
			return NFSP_ACTIVATION_BARRIER_IN_PROGRESS;
		g->state = NFSP_GENERATION_DRAIN_BARRIER;
		return submit_gate(a, index, NFSP_GATE_GENERATION_DRAINING,
				   barrier);
	}
	if (g->state != NFSP_GENERATION_ADMITTING ||
	    a->admitting_index != index)
		return NFSP_ACTIVATION_GENERATION_REUSED;
	if (a->barrier_index >= 0)
		return NFSP_ACTIVATION_BARRIER_IN_PROGRESS;
	/* Admission closes before the draining gate is submitted. */
	a->admitting_index = -1;
	g->deactivation_requested = 1;
	if (g->pending_call_accounts != 0) {
		g->state = NFSP_GENERATION_CALL_ACCOUNTING;
		return NFSP_ACTIVATION_CALL_ACCOUNT_PENDING;
	}
	g->state = NFSP_GENERATION_DRAIN_BARRIER;
	return submit_gate(a, index, NFSP_GATE_GENERATION_DRAINING, barrier);
}

enum nfsp_activation_result
nfsp_activation_barrier_complete(struct nfsp_activation *a,
				 uint64_t barrier_id,
				 enum nfsp_activation_gate_reply reply)
{
	int32_t index;
	enum nfsp_activation_gate_event event;

	if (!a || !a->generations || barrier_id == 0 ||
	    reply == NFSP_ACTIVATION_GATE_PENDING ||
	    (reply != NFSP_ACTIVATION_GATE_ACCEPTED &&
	     reply != NFSP_ACTIVATION_GATE_REJECTED &&
	     reply != NFSP_ACTIVATION_GATE_NO_ACK))
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	if (a->barrier_index < 0) {
		if (counter_has_room(a->stats.stale_barrier_acks))
			a->stats.stale_barrier_acks++;
		else
			return counter_failure(a);
		return NFSP_ACTIVATION_STALE_ACK;
	}
	if (a->pending_barrier.id != barrier_id) {
		if (barrier_id < a->pending_barrier.id) {
			if (counter_has_room(a->stats.stale_barrier_acks))
				a->stats.stale_barrier_acks++;
			else
				return counter_failure(a);
			return NFSP_ACTIVATION_STALE_ACK;
		}
		return NFSP_ACTIVATION_BARRIER_MISMATCH;
	}
	index = a->barrier_index;
	event = a->pending_barrier.event;
	if (event == NFSP_GATE_GENERATION_OPEN)
		return complete_open(a, index, reply);
	return complete_draining(a, index, reply);
}

static enum nfsp_activation_result account_outside_call(
	struct nfsp_activation *a)
{
	if (!counter_has_room(a->stats.outside_activation_window) ||
	    !counter_has_room(a->stats.outside_call_records))
		return counter_failure(a);
	a->stats.outside_activation_window++;
	a->stats.outside_call_records++;
	return NFSP_ACTIVATION_OUTSIDE_WINDOW;
}

enum nfsp_activation_result
nfsp_activation_call_generation(struct nfsp_activation *a,
				uint64_t *generation,
				struct nfsp_activation_call_ticket *ticket)
{
	struct nfsp_activation_generation *g;
	struct nfsp_activation_call_account *account;
	int32_t slot;

	if (generation)
		*generation = 0;
	if (ticket)
		memset(ticket, 0, sizeof(*ticket));
	if (!a || !a->generations || !a->call_accounts || !generation ||
	    !ticket)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	if (a->quarantined || a->admitting_index < 0)
		return account_outside_call(a);
	g = &a->generations[a->admitting_index];
	if (g->state != NFSP_GENERATION_ADMITTING ||
	    g->open_barrier != NFSP_BARRIER_ACCEPTED)
		return account_outside_call(a);
	if (a->pending_call_account_count >= a->cfg.max_pending_calls) {
		if (!counter_has_room(
			    a->stats.call_account_capacity_exhausted) ||
		    !counter_has_room(a->stats.eligible_call_records) ||
		    !counter_has_room(g->records_seen) ||
		    !counter_has_room(g->eligible_calls) ||
		    !counter_has_room(g->call_account_capacity_exhausted))
			return counter_failure(a);
		a->stats.call_account_capacity_exhausted++;
		a->stats.eligible_call_records++;
		g->records_seen++;
		g->eligible_calls++;
		g->call_account_capacity_exhausted++;
		return NFSP_ACTIVATION_CALL_ACCOUNT_CAPACITY;
	}
	slot = free_call_account(a);
	if (slot < 0 || a->next_call_ticket_id == UINT64_MAX)
		return counter_failure(a);
	if (!counter_has_room(a->stats.eligible_call_records) ||
	    !counter_has_room(g->records_seen) ||
	    !counter_has_room(g->eligible_calls))
		return counter_failure(a);
	a->next_call_ticket_id++;
	account = &a->call_accounts[slot];
	account->id = a->next_call_ticket_id;
	account->generation = g->generation;
	account->used = 1;
	a->pending_call_account_count++;
	g->pending_call_accounts++;
	a->stats.eligible_call_records++;
	g->records_seen++;
	g->eligible_calls++;
	*generation = g->generation;
	ticket->id = account->id;
	ticket->generation = account->generation;
	return NFSP_ACTIVATION_OK;
}

enum nfsp_activation_result
nfsp_activation_account_call(struct nfsp_activation *a,
			     const struct nfsp_activation_call_ticket *ticket,
			     enum nfsp_activation_call_outcome outcome)
{
	int32_t account_index;
	int32_t generation_index;
	struct nfsp_activation_call_account *account;
	struct nfsp_activation_generation *g;

	if (!a || !a->generations || !a->call_accounts || !ticket ||
	    ticket->id == 0 || ticket->generation == 0 ||
	    (outcome != NFSP_ACTIVATION_CALL_INSERTED &&
	     outcome != NFSP_ACTIVATION_CALL_DUPLICATE &&
	     outcome != NFSP_ACTIVATION_CALL_NOT_INSERTED))
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	account_index = find_call_account(a, ticket->id);
	if (account_index < 0) {
		if (ticket->id <= a->next_call_ticket_id)
			return NFSP_ACTIVATION_CALL_ACCOUNT_ALREADY_RESOLVED;
		return NFSP_ACTIVATION_CALL_ACCOUNT_UNKNOWN;
	}
	account = &a->call_accounts[account_index];
	if (account->generation != ticket->generation)
		return NFSP_ACTIVATION_CALL_ACCOUNT_MISMATCH;
	generation_index = find_generation(a, account->generation);
	if (generation_index < 0)
		return NFSP_ACTIVATION_CALL_ACCOUNT_MISMATCH;
	g = &a->generations[generation_index];
	if ((g->state != NFSP_GENERATION_ADMITTING &&
	     g->state != NFSP_GENERATION_CALL_ACCOUNTING) ||
	    g->pending_call_accounts == 0 ||
	    a->pending_call_account_count == 0)
		return NFSP_ACTIVATION_CALL_ACCOUNT_MISMATCH;
	if (outcome == NFSP_ACTIVATION_CALL_DUPLICATE) {
		if (!counter_has_room(g->duplicate_calls))
			return counter_failure(a);
		g->duplicate_calls++;
	} else if (outcome == NFSP_ACTIVATION_CALL_INSERTED) {
		if (!counter_has_room(g->admitted_calls) ||
		    !counter_has_room(g->unresolved_replies))
			return counter_failure(a);
		g->admitted_calls++;
		g->unresolved_replies++;
	}
	memset(account, 0, sizeof(*account));
	a->pending_call_account_count--;
	g->pending_call_accounts--;
	return NFSP_ACTIVATION_OK;
}

enum nfsp_activation_result
nfsp_activation_account_connection_closed(struct nfsp_activation *a,
					  uint64_t generation,
					  uint64_t call_count)
{
	int32_t index;
	struct nfsp_activation_generation *g;

	if (!a || !a->generations || generation == 0 || call_count == 0)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	index = find_generation(a, generation);
	if (index < 0)
		return NFSP_ACTIVATION_UNKNOWN_GENERATION;
	g = &a->generations[index];
	if (g->state == NFSP_GENERATION_CLOSED ||
	    g->state == NFSP_GENERATION_OPENING ||
	    g->state == NFSP_GENERATION_OPEN_FAILED ||
	    g->unresolved_replies < call_count)
		return NFSP_ACTIVATION_CALL_UNACCOUNTED;
	if (!counter_can_add(g->connection_closed_calls, call_count))
		return counter_failure(a);
	g->connection_closed_calls += call_count;
	g->unresolved_replies -= call_count;
	if (g->state == NFSP_GENERATION_DRAINING &&
	    g->unresolved_replies == 0)
		return maybe_close_drained(a, index);
	return NFSP_ACTIVATION_OK;
}

static enum nfsp_activation_result account_outside_reply(
	struct nfsp_activation *a, int closed, int unknown, int unaccounted)
{
	if (!counter_has_room(a->stats.outside_activation_window) ||
	    !counter_has_room(a->stats.outside_reply_records) ||
	    (closed && !counter_has_room(a->stats.late_after_close)) ||
	    (unknown &&
	     !counter_has_room(a->stats.unknown_generation_replies)) ||
	    (unaccounted && !counter_has_room(a->stats.unaccounted_replies)))
		return counter_failure(a);
	a->stats.outside_activation_window++;
	a->stats.outside_reply_records++;
	if (closed)
		a->stats.late_after_close++;
	if (unknown)
		a->stats.unknown_generation_replies++;
	if (unaccounted)
		a->stats.unaccounted_replies++;
	return unaccounted ? NFSP_ACTIVATION_REPLY_UNACCOUNTED :
		NFSP_ACTIVATION_OUTSIDE_WINDOW;
}

enum nfsp_activation_result
nfsp_activation_account_reply(struct nfsp_activation *a, uint64_t generation,
			      enum nfsp_activation_reply_outcome outcome)
{
	int32_t index;
	struct nfsp_activation_generation *g;
	int eligible;

	if (!a || !a->generations ||
	    (outcome != NFSP_ACTIVATION_REPLY_RESOLVED &&
	     outcome != NFSP_ACTIVATION_REPLY_DUPLICATE))
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	index = find_generation(a, generation);
	if (index < 0)
		return account_outside_reply(a, 0, 1, 0);
	g = &a->generations[index];
	if (g->state == NFSP_GENERATION_CLOSED)
		return account_outside_reply(a, 1, 0, 0);
	if (a->quarantined)
		return account_outside_reply(a, 0, 0, 0);
	/* Deactivation closes CALL admission only: a REPLY to a CALL G
	 * admitted is G's while G accounts its last CALLs, waits for the
	 * draining ACK, or drains (01 §16, 06 §27). */
	eligible = g->state == NFSP_GENERATION_ADMITTING ||
		   g->state == NFSP_GENERATION_CALL_ACCOUNTING ||
		   g->state == NFSP_GENERATION_DRAIN_BARRIER ||
		   g->state == NFSP_GENERATION_DRAINING;
	if (!eligible)
		return account_outside_reply(a, 0, 0, 0);
	if (outcome == NFSP_ACTIVATION_REPLY_RESOLVED &&
	    g->unresolved_replies == 0)
		return account_outside_reply(a, 0, 0, 1);
	if (!counter_has_room(a->stats.eligible_reply_records) ||
	    !counter_has_room(g->records_seen) ||
	    !counter_has_room(g->eligible_replies) ||
	    (outcome == NFSP_ACTIVATION_REPLY_RESOLVED &&
	     !counter_has_room(g->resolved_replies)) ||
	    (outcome == NFSP_ACTIVATION_REPLY_DUPLICATE &&
	     !counter_has_room(g->duplicate_replies)))
		return counter_failure(a);
	a->stats.eligible_reply_records++;
	g->records_seen++;
	g->eligible_replies++;
	if (outcome == NFSP_ACTIVATION_REPLY_DUPLICATE) {
		g->duplicate_replies++;
		return NFSP_ACTIVATION_OK;
	}
	g->resolved_replies++;
	g->unresolved_replies--;
	if (g->state == NFSP_GENERATION_DRAINING &&
	    g->unresolved_replies == 0)
		return maybe_close_drained(a, index);
	return NFSP_ACTIVATION_OK;
}

enum nfsp_activation_result
nfsp_activation_close_if_drained(struct nfsp_activation *a,
				 uint64_t generation)
{
	int32_t index;

	if (!a || !a->generations || generation == 0)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	index = find_generation(a, generation);
	if (index < 0)
		return NFSP_ACTIVATION_UNKNOWN_GENERATION;
	if (a->generations[index].state == NFSP_GENERATION_CLOSED)
		return NFSP_ACTIVATION_IDEMPOTENT;
	return maybe_close_drained(a, index);
}

enum nfsp_activation_result
nfsp_activation_force_close(struct nfsp_activation *a, uint64_t generation,
			    enum nfsp_activation_force_reason reason)
{
	int32_t index;
	uint32_t pending_calls;
	enum nfsp_activation_closure_reason closure_reason;
	struct nfsp_activation_generation *g;

	if (!a || !a->generations || generation == 0 ||
	    (reason != NFSP_FORCE_REPLY_UNRESOLVED &&
	     reason != NFSP_FORCE_ABORTED))
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	index = find_generation(a, generation);
	if (index < 0)
		return NFSP_ACTIVATION_UNKNOWN_GENERATION;
	g = &a->generations[index];
	closure_reason = reason == NFSP_FORCE_REPLY_UNRESOLVED ?
		NFSP_CLOSURE_REPLY_UNRESOLVED : NFSP_CLOSURE_ABORTED;
	if (g->state == NFSP_GENERATION_CLOSED) {
		if (g->closure_reason == closure_reason)
			return NFSP_ACTIVATION_IDEMPOTENT;
		return NFSP_ACTIVATION_ALREADY_CLOSED;
	}
	if (reason == NFSP_FORCE_REPLY_UNRESOLVED &&
	    (g->state != NFSP_GENERATION_DRAINING ||
	     g->draining_barrier != NFSP_BARRIER_ACCEPTED))
		return NFSP_ACTIVATION_CLOSURE_NOT_READY;
	pending_calls = g->pending_call_accounts;
	if (!counter_can_add(g->unresolved_replies, pending_calls))
		return counter_failure(a);
	if (g->state == NFSP_GENERATION_DRAIN_BARRIER) {
		g->draining_barrier = NFSP_BARRIER_NO_ACK;
		a->quarantined = 1;
	} else if (g->state == NFSP_GENERATION_OPENING) {
		g->open_barrier = NFSP_BARRIER_NO_ACK;
		a->quarantined = 1;
	}
	if (pending_calls != 0)
		cancel_call_accounts(a, index);
	close_generation(a, index, closure_reason, pending_calls);
	return NFSP_ACTIVATION_OK;
}

static void copy_generation_snapshot(
	struct nfsp_activation_generation_snapshot *out,
	const struct nfsp_activation_generation *in)
{
	memset(out, 0, sizeof(*out));
	out->generation = in->generation;
	out->state = in->state;
	out->deactivation_requested = in->deactivation_requested;
	out->open_barrier = in->open_barrier;
	out->open_barrier_id = in->open_barrier_id;
	out->draining_barrier = in->draining_barrier;
	out->draining_barrier_id = in->draining_barrier_id;
	out->records_seen = in->records_seen;
	out->eligible_calls = in->eligible_calls;
	out->admitted_calls = in->admitted_calls;
	out->duplicate_calls = in->duplicate_calls;
	out->connection_closed_calls = in->connection_closed_calls;
	out->call_account_capacity_exhausted =
		in->call_account_capacity_exhausted;
	out->pending_call_accounts = in->pending_call_accounts;
	out->unaccounted_calls_at_closure =
		in->unaccounted_calls_at_closure;
	out->eligible_replies = in->eligible_replies;
	out->resolved_replies = in->resolved_replies;
	out->duplicate_replies = in->duplicate_replies;
	out->unresolved_replies = in->unresolved_replies;
	out->closure_reason = in->closure_reason;
	out->reply_unresolved_count = in->reply_unresolved_count;
}

static void sort_snapshots(struct nfsp_activation_generation_snapshot *items,
			   size_t count)
{
	size_t i;

	for (i = 1; i < count; i++) {
		struct nfsp_activation_generation_snapshot item = items[i];
		size_t pos = i;

		while (pos > 0 && items[pos - 1u].generation > item.generation) {
			items[pos] = items[pos - 1u];
			pos--;
		}
		items[pos] = item;
	}
}

enum nfsp_activation_result
nfsp_activation_get_generation(
	const struct nfsp_activation *a, uint64_t generation,
	struct nfsp_activation_generation_snapshot *snapshot)
{
	int32_t index;

	if (!a || !a->generations || !snapshot || generation == 0)
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	index = find_generation(a, generation);
	if (index < 0)
		return NFSP_ACTIVATION_UNKNOWN_GENERATION;
	copy_generation_snapshot(snapshot, &a->generations[index]);
	return NFSP_ACTIVATION_OK;
}

enum nfsp_activation_result
nfsp_activation_get_snapshot(
	const struct nfsp_activation *a,
	struct nfsp_activation_snapshot *snapshot,
	struct nfsp_activation_generation_snapshot *generations,
	size_t generation_capacity, size_t *generation_count)
{
	uint32_t i;

	if (!a || !a->generations || !a->call_accounts || !snapshot ||
	    !generation_count ||
	    (generation_capacity != 0 && !generations))
		return NFSP_ACTIVATION_INVALID_ARGUMENT;
	*generation_count = a->generation_count;
	if (generation_capacity < a->generation_count)
		return NFSP_ACTIVATION_SNAPSHOT_TOO_SMALL;
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->state = activation_state(a);
	snapshot->rule_set_installed = a->rule_set_installed;
	memcpy(snapshot->rule_set_id, a->rule_set_id,
	       sizeof(snapshot->rule_set_id));
	snapshot->legacy_active = a->legacy_active;
	snapshot->quarantined = a->quarantined;
	if (a->admitting_index >= 0)
		snapshot->admitting_generation =
			a->generations[a->admitting_index].generation;
	snapshot->pending_barrier = a->pending_barrier;
	snapshot->generation_count = a->generation_count;
	snapshot->draining_generation_count = draining_count(a);
	snapshot->closed_generation_count = closed_count(a);
	snapshot->max_generations = a->cfg.max_generations;
	snapshot->max_draining = a->cfg.max_draining;
	snapshot->pending_call_account_count =
		a->pending_call_account_count;
	snapshot->max_pending_calls = a->cfg.max_pending_calls;
	snapshot->stats = a->stats;
	for (i = 0; i < a->generation_count; i++)
		copy_generation_snapshot(&generations[i], &a->generations[i]);
	sort_snapshots(generations, a->generation_count);
	return NFSP_ACTIVATION_OK;
}

const char *nfsp_activation_strresult(enum nfsp_activation_result result)
{
	switch (result) {
	case NFSP_ACTIVATION_OK: return "ok";
	case NFSP_ACTIVATION_IDEMPOTENT: return "idempotent";
	case NFSP_ACTIVATION_BARRIER_PENDING: return "barrier_pending";
	case NFSP_ACTIVATION_BARRIER_REJECTED: return "barrier_rejected";
	case NFSP_ACTIVATION_BARRIER_NO_ACK: return "barrier_no_ack";
	case NFSP_ACTIVATION_NO_RULE_SET: return "no_rule_set";
	case NFSP_ACTIVATION_RULE_SET_MISMATCH: return "rule_set_mismatch";
	case NFSP_ACTIVATION_RULE_SET_IMMUTABLE: return "rule_set_immutable";
	case NFSP_ACTIVATION_LEGACY_CONFLICT: return "legacy_conflict";
	case NFSP_ACTIVATION_INVALID_ARGUMENT: return "invalid_argument";
	case NFSP_ACTIVATION_GENERATION_REUSED: return "generation_reused";
	case NFSP_ACTIVATION_ONE_ADMITTING: return "one_admitting";
	case NFSP_ACTIVATION_DRAINING_LIMIT: return "draining_limit";
	case NFSP_ACTIVATION_GENERATION_CAPACITY: return "generation_capacity";
	case NFSP_ACTIVATION_BARRIER_IN_PROGRESS: return "barrier_in_progress";
	case NFSP_ACTIVATION_STALE_ACK: return "stale_ack";
	case NFSP_ACTIVATION_BARRIER_MISMATCH: return "barrier_mismatch";
	case NFSP_ACTIVATION_OUTSIDE_WINDOW: return "outside_activation_window";
	case NFSP_ACTIVATION_UNKNOWN_GENERATION: return "unknown_generation";
	case NFSP_ACTIVATION_CALL_ACCOUNT_PENDING:
		return "call_account_pending";
	case NFSP_ACTIVATION_CALL_ACCOUNT_CAPACITY:
		return "call_account_capacity";
	case NFSP_ACTIVATION_CALL_ACCOUNT_UNKNOWN:
		return "call_account_unknown";
	case NFSP_ACTIVATION_CALL_ACCOUNT_MISMATCH:
		return "call_account_mismatch";
	case NFSP_ACTIVATION_CALL_ACCOUNT_ALREADY_RESOLVED:
		return "call_account_already_resolved";
	case NFSP_ACTIVATION_CALL_UNACCOUNTED: return "call_unaccounted";
	case NFSP_ACTIVATION_REPLY_UNACCOUNTED: return "reply_unaccounted";
	case NFSP_ACTIVATION_CLOSURE_BLOCKED: return "closure_blocked";
	case NFSP_ACTIVATION_CLOSURE_NOT_READY: return "closure_not_ready";
	case NFSP_ACTIVATION_ALREADY_CLOSED: return "already_closed";
	case NFSP_ACTIVATION_COUNTER_EXHAUSTED: return "counter_exhausted";
	case NFSP_ACTIVATION_SNAPSHOT_TOO_SMALL: return "snapshot_too_small";
	case NFSP_ACTIVATION_QUARANTINE: return "quarantined";
	}
	return "unknown";
}
