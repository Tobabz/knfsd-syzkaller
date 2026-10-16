/* Target-rule activation windows and generation lifecycle (M4d).
 *
 * This is a single-threaded component for the proxy event loop.  It owns one
 * immutable rule_set_id for one proxy session, admits CALL records only while
 * one generation is active, and keeps deactivated generations eligible for
 * their transaction-correlated REPLY records until closure.
 *
 * The gate callback is deliberately named a test gate.  Its ACCEPTED result
 * models a future host acknowledgement in component tests; it is not a
 * durable journal acknowledgement and must not be wired to live target-mode
 * output.  M5/S1b supplies that host boundary.
 */
#ifndef NFSP_ACTIVATION_H
#define NFSP_ACTIVATION_H

#include <stddef.h>
#include <stdint.h>

#define NFSP_ACTIVATION_RULE_SET_ID_MAX	128u
#define NFSP_ACTIVATION_DEFAULT_MAX_GENERATIONS	256u
#define NFSP_ACTIVATION_DEFAULT_MAX_DRAINING	16u
#define NFSP_ACTIVATION_MAX_GENERATIONS	4096u
#define NFSP_ACTIVATION_DEFAULT_MAX_PENDING_CALLS	64u
#define NFSP_ACTIVATION_MAX_PENDING_CALLS	4096u

enum nfsp_activation_state {
	NFSP_ACTIVATION_NO_RULESET = 0,
	NFSP_ACTIVATION_INACTIVE,
	NFSP_ACTIVATION_OPENING,
	NFSP_ACTIVATION_ADMITTING,
	NFSP_ACTIVATION_DRAINING,
	NFSP_ACTIVATION_CLOSED,
	NFSP_ACTIVATION_QUARANTINED
};

enum nfsp_generation_state {
	NFSP_GENERATION_OPENING = 0,
	NFSP_GENERATION_ADMITTING,
	NFSP_GENERATION_CALL_ACCOUNTING,
	NFSP_GENERATION_DRAIN_BARRIER,
	NFSP_GENERATION_DRAINING,
	NFSP_GENERATION_CLOSED,
	NFSP_GENERATION_OPEN_FAILED,
	NFSP_GENERATION_QUARANTINED
};

enum nfsp_activation_gate_event {
	NFSP_GATE_GENERATION_OPEN = 0,
	NFSP_GATE_GENERATION_DRAINING
};

/* PENDING is completed later with nfsp_activation_barrier_complete().
 * NO_ACK is the explicit, clock-free timeout/missing-ack result. */
enum nfsp_activation_gate_reply {
	NFSP_ACTIVATION_GATE_ACCEPTED = 0,
	NFSP_ACTIVATION_GATE_REJECTED,
	NFSP_ACTIVATION_GATE_PENDING,
	NFSP_ACTIVATION_GATE_NO_ACK
};

enum nfsp_activation_barrier_fact {
	NFSP_BARRIER_NOT_REQUESTED = 0,
	NFSP_BARRIER_PENDING,
	NFSP_BARRIER_ACCEPTED,
	NFSP_BARRIER_REJECTED,
	NFSP_BARRIER_NO_ACK
};

enum nfsp_activation_closure_reason {
	NFSP_CLOSURE_NONE = 0,
	NFSP_CLOSURE_DRAINED,
	NFSP_CLOSURE_REPLY_UNRESOLVED,
	NFSP_CLOSURE_ABORTED
};

enum nfsp_activation_force_reason {
	NFSP_FORCE_REPLY_UNRESOLVED = 0,
	NFSP_FORCE_ABORTED
};

enum nfsp_activation_result {
	NFSP_ACTIVATION_OK = 0,
	NFSP_ACTIVATION_IDEMPOTENT,
	NFSP_ACTIVATION_BARRIER_PENDING,
	NFSP_ACTIVATION_BARRIER_REJECTED,
	NFSP_ACTIVATION_BARRIER_NO_ACK,
	NFSP_ACTIVATION_NO_RULE_SET,
	NFSP_ACTIVATION_RULE_SET_MISMATCH,
	NFSP_ACTIVATION_RULE_SET_IMMUTABLE,
	NFSP_ACTIVATION_LEGACY_CONFLICT,
	NFSP_ACTIVATION_INVALID_ARGUMENT,
	NFSP_ACTIVATION_GENERATION_REUSED,
	NFSP_ACTIVATION_ONE_ADMITTING,
	NFSP_ACTIVATION_DRAINING_LIMIT,
	NFSP_ACTIVATION_GENERATION_CAPACITY,
	NFSP_ACTIVATION_BARRIER_IN_PROGRESS,
	NFSP_ACTIVATION_STALE_ACK,
	NFSP_ACTIVATION_BARRIER_MISMATCH,
	NFSP_ACTIVATION_OUTSIDE_WINDOW,
	NFSP_ACTIVATION_UNKNOWN_GENERATION,
	NFSP_ACTIVATION_CALL_ACCOUNT_PENDING,
	NFSP_ACTIVATION_CALL_ACCOUNT_CAPACITY,
	NFSP_ACTIVATION_CALL_ACCOUNT_UNKNOWN,
	NFSP_ACTIVATION_CALL_ACCOUNT_MISMATCH,
	NFSP_ACTIVATION_CALL_ACCOUNT_ALREADY_RESOLVED,
	NFSP_ACTIVATION_CALL_UNACCOUNTED,
	NFSP_ACTIVATION_REPLY_UNACCOUNTED,
	NFSP_ACTIVATION_CLOSURE_BLOCKED,
	NFSP_ACTIVATION_CLOSURE_NOT_READY,
	NFSP_ACTIVATION_ALREADY_CLOSED,
	NFSP_ACTIVATION_COUNTER_EXHAUSTED,
	NFSP_ACTIVATION_SNAPSHOT_TOO_SMALL,
	NFSP_ACTIVATION_QUARANTINE
};

enum nfsp_activation_call_outcome {
	NFSP_ACTIVATION_CALL_INSERTED = 0,
	NFSP_ACTIVATION_CALL_DUPLICATE,
	NFSP_ACTIVATION_CALL_NOT_INSERTED
};

enum nfsp_activation_reply_outcome {
	NFSP_ACTIVATION_REPLY_RESOLVED = 0,
	NFSP_ACTIVATION_REPLY_DUPLICATE
};

struct nfsp_activation_barrier {
	uint64_t id;
	uint64_t generation;
	enum nfsp_activation_gate_event event;
};

struct nfsp_activation_call_ticket {
	uint64_t id;
	uint64_t generation;
};

struct nfsp_activation_gate_request {
	struct nfsp_activation_barrier barrier;
	const char *rule_set_id;
};

/* Component-test double only; ACCEPTED has no host durability meaning. */
typedef enum nfsp_activation_gate_reply
(*nfsp_activation_test_gate_fn)(void *arg,
				const struct nfsp_activation_gate_request *request);

struct nfsp_activation_cfg {
	uint32_t max_generations;	/* 0: default, hard max 4096 */
	uint32_t max_draining;		/* 0: min(default, max_generations) */
	uint32_t max_pending_calls;	/* 0: default, hard max 4096 */
	nfsp_activation_test_gate_fn test_gate;
	void *test_gate_arg;
};

struct nfsp_activation_stats {
	uint64_t eligible_call_records;
	uint64_t eligible_reply_records;
	uint64_t outside_activation_window;
	uint64_t outside_call_records;
	uint64_t outside_reply_records;
	uint64_t late_after_close;
	uint64_t unknown_generation_replies;
	uint64_t unaccounted_replies;
	uint64_t stale_barrier_acks;
	uint64_t call_account_capacity_exhausted;
};

struct nfsp_activation_generation_snapshot {
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

struct nfsp_activation_snapshot {
	enum nfsp_activation_state state;
	int rule_set_installed;
	char rule_set_id[NFSP_ACTIVATION_RULE_SET_ID_MAX + 1u];
	int legacy_active;
	int quarantined;
	uint64_t admitting_generation;
	struct nfsp_activation_barrier pending_barrier;
	uint32_t generation_count;
	uint32_t draining_generation_count;
	uint32_t closed_generation_count;
	uint32_t max_generations;
	uint32_t max_draining;
	uint32_t pending_call_account_count;
	uint32_t max_pending_calls;
	struct nfsp_activation_stats stats;
};

struct nfsp_activation_generation;
struct nfsp_activation_call_account;

struct nfsp_activation {
	struct nfsp_activation_cfg cfg;
	struct nfsp_activation_generation *generations;
	struct nfsp_activation_call_account *call_accounts;
	uint32_t generation_count;
	uint32_t pending_call_account_count;
	int32_t admitting_index;
	int32_t barrier_index;
	struct nfsp_activation_barrier pending_barrier;
	uint64_t next_barrier_id;
	uint64_t next_call_ticket_id;
	char rule_set_id[NFSP_ACTIVATION_RULE_SET_ID_MAX + 1u];
	int rule_set_installed;
	int legacy_active;
	int quarantined;
	struct nfsp_activation_stats stats;
};

int nfsp_activation_init(struct nfsp_activation *activation,
			 const struct nfsp_activation_cfg *cfg);
void nfsp_activation_free(struct nfsp_activation *activation);

/* The target rule set is immutable once installed.  Legacy registration may
 * exist before installation, but the two modes can never coexist. */
enum nfsp_activation_result
nfsp_activation_install_rule_set(struct nfsp_activation *activation,
				 const char *rule_set_id);
enum nfsp_activation_result
nfsp_activation_legacy_enable(struct nfsp_activation *activation);
enum nfsp_activation_result
nfsp_activation_legacy_disable(struct nfsp_activation *activation);

/* Activate/deactivate messages carry the rule_set_id and are checked against
 * the installed session value.  Duplicate in-flight or completed messages
 * are idempotent and do not submit another gate request. */
enum nfsp_activation_result
nfsp_activation_activate(struct nfsp_activation *activation,
			 const char *rule_set_id, uint64_t generation,
			 struct nfsp_activation_barrier *barrier);
enum nfsp_activation_result
nfsp_activation_deactivate(struct nfsp_activation *activation,
			   const char *rule_set_id, uint64_t generation,
			   struct nfsp_activation_barrier *barrier);

/* Complete a PENDING test-gate request.  `reply` must be ACCEPTED, REJECTED,
 * or NO_ACK.  Old or already-completed ids are refused as stale. */
enum nfsp_activation_result
nfsp_activation_barrier_complete(struct nfsp_activation *activation,
				 uint64_t barrier_id,
				 enum nfsp_activation_gate_reply reply);

/* Obtain the generation to pass to nfsp_txn_call() and a unique accounting
 * ticket.  After that call, consume the ticket with its result: INSERTED
 * creates one unresolved reply obligation; DUPLICATE and NOT_INSERTED do not.
 * Tickets are bounded and never reused.  Deactivation closes admission but
 * cannot submit its draining barrier until every issued ticket is consumed. */
enum nfsp_activation_result
nfsp_activation_call_generation(struct nfsp_activation *activation,
				uint64_t *generation,
				struct nfsp_activation_call_ticket *ticket);
enum nfsp_activation_result
nfsp_activation_account_call(struct nfsp_activation *activation,
			     const struct nfsp_activation_call_ticket *ticket,
			     enum nfsp_activation_call_outcome outcome);

/* Account admitted transaction entries removed because their connection
 * closed.  They satisfy clean draining without pretending a REPLY resolved;
 * timeout, ambiguity and capacity loss stay unresolved for forced closure. */
enum nfsp_activation_result
nfsp_activation_account_connection_closed(struct nfsp_activation *activation,
					  uint64_t generation,
					  uint64_t call_count);

/* Use the activation_generation stored in the transaction entry.  RESOLVED
 * accounts the entry once; DUPLICATE never changes the unresolved count. */
enum nfsp_activation_result
nfsp_activation_account_reply(struct nfsp_activation *activation,
			      uint64_t generation,
			      enum nfsp_activation_reply_outcome outcome);

enum nfsp_activation_result
nfsp_activation_close_if_drained(struct nfsp_activation *activation,
				 uint64_t generation);
enum nfsp_activation_result
nfsp_activation_force_close(struct nfsp_activation *activation,
			    uint64_t generation,
			    enum nfsp_activation_force_reason reason);

/* Generation snapshots are sorted by generation id, independent of internal
 * allocation and reply order.  If capacity is short, no generation element
 * is written and *generation_count reports the required count. */
enum nfsp_activation_result
nfsp_activation_get_snapshot(
	const struct nfsp_activation *activation,
	struct nfsp_activation_snapshot *snapshot,
	struct nfsp_activation_generation_snapshot *generations,
	size_t generation_capacity, size_t *generation_count);

const char *nfsp_activation_strresult(enum nfsp_activation_result result);

#endif /* NFSP_ACTIVATION_H */
