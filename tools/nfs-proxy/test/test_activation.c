/* M4d activation-window and generation-lifecycle component tests.
 *
 * Every barrier outcome is injected synchronously or completed by token.  A
 * timeout is the explicit NO_ACK result, so these tests never sleep or depend
 * on a scheduler or wall clock.
 */
#include "activation.h"

#include <stdio.h>
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

#define TEST_MAX_GATE_REQUESTS 32u
#define TEST_MAX_GENERATIONS 16u

struct gate_script {
	struct nfsp_activation *activation;
	enum nfsp_activation_gate_reply replies[TEST_MAX_GATE_REQUESTS];
	struct nfsp_activation_gate_request requests[TEST_MAX_GATE_REQUESTS];
	enum nfsp_activation_state observed_state[TEST_MAX_GATE_REQUESTS];
	uint64_t observed_admitting[TEST_MAX_GATE_REQUESTS];
	uint32_t reply_count;
	uint32_t calls;
	enum nfsp_activation_gate_reply default_reply;
};

static enum nfsp_activation_gate_reply
script_gate(void *arg, const struct nfsp_activation_gate_request *request)
{
	struct gate_script *script = arg;
	uint32_t call = script->calls;

	if (call < TEST_MAX_GATE_REQUESTS) {
		struct nfsp_activation_snapshot snapshot;
		struct nfsp_activation_generation_snapshot
			generations[TEST_MAX_GENERATIONS];
		size_t count = 0;

		script->requests[call] = *request;
		if (script->activation &&
		    nfsp_activation_get_snapshot(script->activation, &snapshot,
			generations, TEST_MAX_GENERATIONS, &count) ==
		    NFSP_ACTIVATION_OK) {
			script->observed_state[call] = snapshot.state;
			script->observed_admitting[call] =
				snapshot.admitting_generation;
		}
	}
	script->calls++;
	if (call < script->reply_count)
		return script->replies[call];
	return script->default_reply;
}

static void script_init(struct gate_script *script,
			enum nfsp_activation_gate_reply default_reply)
{
	memset(script, 0, sizeof(*script));
	script->default_reply = default_reply;
}

static void script_add(struct gate_script *script,
		       enum nfsp_activation_gate_reply reply)
{
	CHECK(script->reply_count < TEST_MAX_GATE_REQUESTS,
	      "gate script has room");
	if (script->reply_count < TEST_MAX_GATE_REQUESTS) {
		script->replies[script->reply_count] = reply;
		script->reply_count++;
	}
}

static void init_activation_limits(struct nfsp_activation *activation,
			   struct gate_script *script,
			   uint32_t max_generations,
			   uint32_t max_draining,
			   uint32_t max_pending_calls)
{
	struct nfsp_activation_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.max_generations = max_generations;
	cfg.max_draining = max_draining;
	cfg.max_pending_calls = max_pending_calls;
	if (script) {
		cfg.test_gate = script_gate;
		cfg.test_gate_arg = script;
		script->activation = activation;
	}
	CHECK(nfsp_activation_init(activation, &cfg) == 0, "activation init");
}

static void init_activation(struct nfsp_activation *activation,
			    struct gate_script *script, uint32_t max_generations,
			    uint32_t max_draining)
{
	init_activation_limits(activation, script, max_generations,
			       max_draining, 0);
}

static struct nfsp_activation_snapshot
snapshot(struct nfsp_activation *activation,
	 struct nfsp_activation_generation_snapshot *generations,
	 size_t capacity, size_t *count)
{
	struct nfsp_activation_snapshot result;

	memset(&result, 0xa5, sizeof(result));
	CHECK(nfsp_activation_get_snapshot(activation, &result, generations,
					   capacity, count) ==
	      NFSP_ACTIVATION_OK, "snapshot");
	return result;
}

static void install(struct nfsp_activation *activation)
{
	CHECK(nfsp_activation_install_rule_set(activation, "rules-A") ==
	      NFSP_ACTIVATION_OK, "install rules-A");
}

static void admit_call(struct nfsp_activation *activation,
		       uint64_t expected_generation)
{
	uint64_t generation = 0;
	struct nfsp_activation_call_ticket ticket;

	CHECK(nfsp_activation_call_generation(activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OK && generation == expected_generation,
	      "CALL admitted to generation %llu",
	      (unsigned long long)expected_generation);
	CHECK(nfsp_activation_account_call(activation, &ticket,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_OK, "CALL insertion accounted");
}

static void test_init_ruleset_and_legacy(void)
{
	struct nfsp_activation activation;
	struct nfsp_activation invalid;
	struct nfsp_activation_cfg cfg;
	struct nfsp_activation_snapshot s;
	struct nfsp_activation_call_ticket ticket;
	size_t count = 99;
	uint64_t generation = 99;
	char too_long[NFSP_ACTIVATION_RULE_SET_ID_MAX + 2u];

	memset(&cfg, 0, sizeof(cfg));
	cfg.max_generations = NFSP_ACTIVATION_MAX_GENERATIONS + 1u;
	CHECK(nfsp_activation_init(&invalid, &cfg) == -1,
	      "hard generation bound");
	memset(&cfg, 0, sizeof(cfg));
	cfg.max_generations = 2;
	cfg.max_draining = 3;
	CHECK(nfsp_activation_init(&invalid, &cfg) == -1,
	      "draining cannot exceed generation capacity");
	memset(&cfg, 0, sizeof(cfg));
	cfg.max_pending_calls = NFSP_ACTIVATION_MAX_PENDING_CALLS + 1u;
	CHECK(nfsp_activation_init(&invalid, &cfg) == -1,
	      "hard pending CALL-account bound");

	init_activation(&activation, NULL, 4, 2);
	s = snapshot(&activation, NULL, 0, &count);
	CHECK(s.state == NFSP_ACTIVATION_NO_RULESET && count == 0,
	      "initial state has no rule set");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW && generation == 0,
	      "CALL before installation is outside");
	CHECK(nfsp_activation_legacy_enable(&activation) == NFSP_ACTIVATION_OK,
	      "legacy may register first");
	CHECK(nfsp_activation_legacy_enable(&activation) ==
	      NFSP_ACTIVATION_IDEMPOTENT, "duplicate legacy registration");
	CHECK(nfsp_activation_install_rule_set(&activation, "rules-A") ==
	      NFSP_ACTIVATION_LEGACY_CONFLICT,
	      "target and legacy cannot coexist");
	CHECK(nfsp_activation_legacy_disable(&activation) == NFSP_ACTIVATION_OK,
	      "legacy release");
	CHECK(nfsp_activation_legacy_disable(&activation) ==
	      NFSP_ACTIVATION_IDEMPOTENT, "duplicate legacy release");

	memset(too_long, 'x', sizeof(too_long));
	too_long[sizeof(too_long) - 1u] = '\0';
	CHECK(nfsp_activation_install_rule_set(&activation, "") ==
	      NFSP_ACTIVATION_INVALID_ARGUMENT, "empty rule id refused");
	CHECK(nfsp_activation_install_rule_set(&activation, too_long) ==
	      NFSP_ACTIVATION_INVALID_ARGUMENT, "overlong rule id refused");
	install(&activation);
	CHECK(nfsp_activation_install_rule_set(&activation, "rules-A") ==
	      NFSP_ACTIVATION_IDEMPOTENT, "same immutable set is idempotent");
	CHECK(nfsp_activation_install_rule_set(&activation, "rules-B") ==
	      NFSP_ACTIVATION_RULE_SET_IMMUTABLE, "replacement refused");
	CHECK(nfsp_activation_legacy_enable(&activation) ==
	      NFSP_ACTIVATION_LEGACY_CONFLICT,
	      "legacy refused after target installation");
	s = snapshot(&activation, NULL, 0, &count);
	CHECK(s.state == NFSP_ACTIVATION_INACTIVE && s.rule_set_installed &&
	      strcmp(s.rule_set_id, "rules-A") == 0 &&
	      s.stats.outside_activation_window == 1,
	      "installed inactive snapshot and outside counter");
	nfsp_activation_free(&activation);
}

static void test_success_and_window_edges(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_barrier open_barrier, drain_barrier;
	struct nfsp_activation_generation_snapshot generations[4];
	struct nfsp_activation_snapshot s;
	struct nfsp_activation_call_ticket ticket;
	uint64_t generation = 0;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	init_activation(&activation, &gate, 4, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "wrong", 101,
				       &open_barrier) ==
	      NFSP_ACTIVATION_RULE_SET_MISMATCH, "activation checks rule id");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 0,
				       &open_barrier) ==
	      NFSP_ACTIVATION_INVALID_ARGUMENT, "generation zero refused");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 101,
				       &open_barrier) == NFSP_ACTIVATION_OK,
	      "open gate accepted");
	CHECK(open_barrier.id == 1 && open_barrier.generation == 101 &&
	      open_barrier.event == NFSP_GATE_GENERATION_OPEN,
	      "open barrier identity");
	CHECK(gate.calls == 1 &&
	      gate.observed_state[0] == NFSP_ACTIVATION_OPENING &&
	      gate.observed_admitting[0] == 0,
	      "OPEN callback observes non-admitting opening state");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 101, NULL) ==
	      NFSP_ACTIVATION_IDEMPOTENT && gate.calls == 1,
	      "duplicate activation does not resubmit gate");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 102, NULL) ==
	      NFSP_ACTIVATION_ONE_ADMITTING,
	      "second admitting generation refused");

	CHECK(nfsp_activation_call_generation(&activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OK && generation == 101,
	      "CALL receives activation_generation");
	CHECK(nfsp_activation_account_call(&activation, &ticket,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_OK, "inserted CALL accounted");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_call(&activation, &ticket,
					   NFSP_ACTIVATION_CALL_DUPLICATE) ==
	      NFSP_ACTIVATION_OK, "duplicate CALL is not admitted twice");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_call(&activation, &ticket,
					   NFSP_ACTIVATION_CALL_NOT_INSERTED) ==
	      NFSP_ACTIVATION_OK, "refused transaction insertion adds no debt");
	CHECK(nfsp_activation_account_reply(&activation, 101,
					    NFSP_ACTIVATION_REPLY_DUPLICATE) ==
	      NFSP_ACTIVATION_OK, "duplicate REPLY changes no debt");

	CHECK(nfsp_activation_deactivate(&activation, "wrong", 101, NULL) ==
	      NFSP_ACTIVATION_RULE_SET_MISMATCH,
	      "deactivation checks rule id");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 101,
					 &drain_barrier) == NFSP_ACTIVATION_OK,
	      "draining gate accepted");
	CHECK(drain_barrier.id == 2 && drain_barrier.generation == 101 &&
	      drain_barrier.event == NFSP_GATE_GENERATION_DRAINING,
	      "draining barrier identity");
	CHECK(gate.calls == 2 &&
	      gate.observed_state[1] == NFSP_ACTIVATION_DRAINING &&
	      gate.observed_admitting[1] == 0,
	      "CALL admission closes before DRAINING callback");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW && generation == 0,
	      "new CALL refused while draining");
	CHECK(nfsp_activation_close_if_drained(&activation, 101) ==
	      NFSP_ACTIVATION_CLOSURE_BLOCKED,
	      "deactivation alone cannot close unresolved generation");
	CHECK(nfsp_activation_account_reply(&activation, 101,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "draining REPLY remains eligible and closes");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 101, NULL) ==
	      NFSP_ACTIVATION_IDEMPOTENT,
	      "duplicate deactivation after closure is idempotent");
	CHECK(nfsp_activation_account_reply(&activation, 101,
					    NFSP_ACTIVATION_REPLY_DUPLICATE) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW, "closed REPLY refused");
	CHECK(nfsp_activation_account_reply(&activation, 999,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW, "unknown REPLY refused");
	CHECK(nfsp_activation_account_reply(&activation, 0,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW,
	      "transaction generation zero is outside the window");
	CHECK(nfsp_activation_barrier_complete(&activation, open_barrier.id,
					       NFSP_ACTIVATION_GATE_ACCEPTED) ==
	      NFSP_ACTIVATION_STALE_ACK, "completed OPEN ACK is stale");

	s = snapshot(&activation, generations, 4, &count);
	CHECK(count == 1 && s.state == NFSP_ACTIVATION_CLOSED &&
	      s.closed_generation_count == 1 &&
	      s.draining_generation_count == 0,
	      "normal closure state");
	CHECK(s.stats.eligible_call_records == 3 &&
	      s.stats.eligible_reply_records == 2 &&
	      s.stats.outside_activation_window == 4 &&
	      s.stats.outside_call_records == 1 &&
	      s.stats.outside_reply_records == 3 &&
	      s.stats.late_after_close == 1 &&
	      s.stats.unknown_generation_replies == 2 &&
	      s.stats.stale_barrier_acks == 1,
	      "session window counters");
	CHECK(generations[0].state == NFSP_GENERATION_CLOSED &&
	      generations[0].open_barrier == NFSP_BARRIER_ACCEPTED &&
	      generations[0].draining_barrier == NFSP_BARRIER_ACCEPTED &&
	      generations[0].deactivation_requested &&
	      generations[0].records_seen == 5 &&
	      generations[0].eligible_calls == 3 &&
	      generations[0].admitted_calls == 1 &&
	      generations[0].duplicate_calls == 1 &&
	      generations[0].eligible_replies == 2 &&
	      generations[0].resolved_replies == 1 &&
	      generations[0].duplicate_replies == 1 &&
	      generations[0].unresolved_replies == 0 &&
	      generations[0].closure_reason == NFSP_CLOSURE_DRAINED &&
	      generations[0].reply_unresolved_count == 0,
	      "generation counters and barrier facts");
	nfsp_activation_free(&activation);
}

static void test_pending_timeout_and_stale_ack(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_barrier open1, open2, drain1, drain2;
	struct nfsp_activation_generation_snapshot generations[4];
	struct nfsp_activation_snapshot s;
	struct nfsp_activation_call_ticket ticket;
	uint64_t generation = 0;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_PENDING);
	script_add(&gate, NFSP_ACTIVATION_GATE_PENDING);
	init_activation(&activation, &gate, 4, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 7, &open1) ==
	      NFSP_ACTIVATION_BARRIER_PENDING, "OPEN may wait for ACK");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW && generation == 0,
	      "opening is fail-closed for CALLs");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 7, &open2) ==
	      NFSP_ACTIVATION_BARRIER_PENDING && open2.id == open1.id &&
	      gate.calls == 1, "duplicate pending activation is idempotent");
	CHECK(nfsp_activation_barrier_complete(&activation, open1.id + 1u,
					       NFSP_ACTIVATION_GATE_ACCEPTED) ==
	      NFSP_ACTIVATION_BARRIER_MISMATCH, "future ACK cannot match");
	CHECK(nfsp_activation_barrier_complete(&activation, open1.id,
					       NFSP_ACTIVATION_GATE_ACCEPTED) ==
	      NFSP_ACTIVATION_OK, "pending OPEN accepted");
	CHECK(nfsp_activation_barrier_complete(&activation, open1.id,
					       NFSP_ACTIVATION_GATE_ACCEPTED) ==
	      NFSP_ACTIVATION_STALE_ACK, "duplicate OPEN ACK is stale");
	admit_call(&activation, 7);

	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 7, &drain1) ==
	      NFSP_ACTIVATION_BARRIER_PENDING, "DRAINING may wait for ACK");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &ticket) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW,
	      "admission closes while draining ACK is pending");
	CHECK(nfsp_activation_account_reply(&activation, 7,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK,
	      "REPLY to an admitted CALL is G's while the drain ACK waits");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 7, &drain2) ==
	      NFSP_ACTIVATION_BARRIER_PENDING && drain2.id == drain1.id &&
	      gate.calls == 2, "duplicate pending deactivation is idempotent");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 8, NULL) ==
	      NFSP_ACTIVATION_BARRIER_IN_PROGRESS,
	      "next generation waits for pending draining barrier");
	CHECK(nfsp_activation_barrier_complete(&activation, drain1.id,
					       NFSP_ACTIVATION_GATE_NO_ACK) ==
	      NFSP_ACTIVATION_BARRIER_NO_ACK, "draining timeout is typed");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 8, NULL) ==
	      NFSP_ACTIVATION_QUARANTINE,
	      "unconfirmed drain permanently quarantines lane");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 7, NULL) ==
	      NFSP_ACTIVATION_QUARANTINE,
	      "failed drain never reopens or retries admission");
	CHECK(nfsp_activation_barrier_complete(&activation, drain1.id,
					       NFSP_ACTIVATION_GATE_ACCEPTED) ==
	      NFSP_ACTIVATION_STALE_ACK, "late drain ACK cannot revive state");
	s = snapshot(&activation, generations, 4, &count);
	CHECK(s.state == NFSP_ACTIVATION_QUARANTINED && s.quarantined &&
	      s.admitting_generation == 0 && count == 1,
	      "quarantined snapshot");
	CHECK(generations[0].state == NFSP_GENERATION_QUARANTINED &&
	      generations[0].draining_barrier == NFSP_BARRIER_NO_ACK &&
	      generations[0].resolved_replies == 1 &&
	      generations[0].unresolved_replies == 0,
	      "timeout preserves generation reply facts");
	CHECK(nfsp_activation_force_close(&activation, 7,
					  NFSP_FORCE_ABORTED) == NFSP_ACTIVATION_OK,
	      "explicit abort can record closure after quarantine");
	s = snapshot(&activation, generations, 4, &count);
	CHECK(s.state == NFSP_ACTIVATION_QUARANTINED &&
	      generations[0].closure_reason == NFSP_CLOSURE_ABORTED &&
	      generations[0].reply_unresolved_count == 0,
	      "forced closure does not clear lane quarantine");
	nfsp_activation_free(&activation);
}

static void test_gate_rejection_and_missing_ack(void)
{
	struct nfsp_activation activation;
	struct nfsp_activation no_gate;
	struct gate_script gate;
	struct nfsp_activation_generation_snapshot generations[4];
	struct nfsp_activation_snapshot s;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_REJECTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_REJECTED);
	init_activation(&activation, &gate, 4, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 1, NULL) ==
	      NFSP_ACTIVATION_BARRIER_REJECTED, "OPEN rejection is typed");
	s = snapshot(&activation, generations, 4, &count);
	CHECK(s.state == NFSP_ACTIVATION_INACTIVE && count == 1 &&
	      generations[0].state == NFSP_GENERATION_OPEN_FAILED &&
	      generations[0].open_barrier == NFSP_BARRIER_REJECTED,
	      "rejected generation never admits");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 1, NULL) ==
	      NFSP_ACTIVATION_GENERATION_REUSED,
	      "rejected generation id cannot be reused");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 2, NULL) ==
	      NFSP_ACTIVATION_OK, "definitive OPEN rejection permits new id");
	admit_call(&activation, 2);
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 2, NULL) ==
	      NFSP_ACTIVATION_BARRIER_REJECTED,
	      "DRAINING rejection is typed");
	s = snapshot(&activation, generations, 4, &count);
	CHECK(s.state == NFSP_ACTIVATION_QUARANTINED && count == 2 &&
	      generations[1].state == NFSP_GENERATION_QUARANTINED &&
	      generations[1].draining_barrier == NFSP_BARRIER_REJECTED,
	      "rejected drain quarantines and preserves debt");
	nfsp_activation_free(&activation);

	init_activation(&no_gate, NULL, 2, 1);
	install(&no_gate);
	CHECK(nfsp_activation_activate(&no_gate, "rules-A", 11, NULL) ==
	      NFSP_ACTIVATION_BARRIER_NO_ACK,
	      "missing test gate cannot synthesize OPEN ACK");
	s = snapshot(&no_gate, generations, 4, &count);
	CHECK(s.state == NFSP_ACTIVATION_QUARANTINED && count == 1 &&
	      generations[0].state == NFSP_GENERATION_QUARANTINED &&
	      generations[0].open_barrier == NFSP_BARRIER_NO_ACK,
	      "missing OPEN ACK is non-admitting and quarantined");
	nfsp_activation_free(&no_gate);
}

static void test_multiple_draining_and_bound(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_generation_snapshot generations[6];
	struct nfsp_activation_snapshot s;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	init_activation(&activation, &gate, 6, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 20, NULL) ==
	      NFSP_ACTIVATION_OK, "activate G20");
	admit_call(&activation, 20);
	admit_call(&activation, 20);
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 20, NULL) ==
	      NFSP_ACTIVATION_OK, "G20 draining");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 10, NULL) ==
	      NFSP_ACTIVATION_OK, "activate G10 while G20 drains");
	admit_call(&activation, 10);
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 10, NULL) ==
	      NFSP_ACTIVATION_OK, "G10 draining alongside G20");
	s = snapshot(&activation, generations, 6, &count);
	CHECK(s.state == NFSP_ACTIVATION_DRAINING &&
	      s.draining_generation_count == 2 && count == 2,
	      "two bounded draining generations");
	CHECK(generations[0].generation == 10 &&
	      generations[1].generation == 20,
	      "snapshot sorted by generation, not activation order");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 30, NULL) ==
	      NFSP_ACTIVATION_DRAINING_LIMIT,
	      "new admission refused when its future drain slot is unavailable");
	CHECK(nfsp_activation_account_reply(&activation, 10,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "G10 draining reply closes only G10");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 30, NULL) ==
	      NFSP_ACTIVATION_OK, "closed drain slot permits G30");
	admit_call(&activation, 30);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 40, NULL) ==
	      NFSP_ACTIVATION_ONE_ADMITTING,
	      "one-admitting invariant with old drain");
	CHECK(nfsp_activation_account_reply(&activation, 20,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&activation, 20,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "G20 replies retain G20 while G30 admits");
	s = snapshot(&activation, generations, 6, &count);
	CHECK(s.state == NFSP_ACTIVATION_ADMITTING &&
	      s.admitting_generation == 30 &&
	      s.draining_generation_count == 0 &&
	      s.closed_generation_count == 2,
	      "new current window and old closures remain distinct");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 30, NULL) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&activation, 30,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "G30 drains and closes");
	nfsp_activation_free(&activation);
}

static void test_forced_closure(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_generation_snapshot generations[6];
	struct nfsp_activation_snapshot s;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	init_activation(&activation, &gate, 6, 3);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 50, NULL) ==
	      NFSP_ACTIVATION_OK, "activate forced-drain fixture");
	admit_call(&activation, 50);
	admit_call(&activation, 50);
	admit_call(&activation, 50);
	CHECK(nfsp_activation_force_close(&activation, 50,
					  NFSP_FORCE_REPLY_UNRESOLVED) ==
	      NFSP_ACTIVATION_CLOSURE_NOT_READY,
	      "reply-unresolved closure requires accepted deactivation");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 50, NULL) ==
	      NFSP_ACTIVATION_OK, "fixture drains");
	CHECK(nfsp_activation_account_reply(&activation, 50,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "one of three replies resolves");
	CHECK(nfsp_activation_close_if_drained(&activation, 50) ==
	      NFSP_ACTIVATION_CLOSURE_BLOCKED,
	      "no-reply closure remains blocked");
	CHECK(nfsp_activation_force_close(&activation, 50,
					  NFSP_FORCE_REPLY_UNRESOLVED) ==
	      NFSP_ACTIVATION_OK, "drain-bound closure is explicit");
	CHECK(nfsp_activation_force_close(&activation, 50,
					  NFSP_FORCE_REPLY_UNRESOLVED) ==
	      NFSP_ACTIVATION_IDEMPOTENT, "same forced close is idempotent");
	CHECK(nfsp_activation_force_close(&activation, 50,
					  NFSP_FORCE_ABORTED) ==
	      NFSP_ACTIVATION_ALREADY_CLOSED,
	      "closure reason cannot be replaced");
	CHECK(nfsp_activation_account_reply(&activation, 50,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW,
	      "late reply cannot change forced snapshot");

	CHECK(nfsp_activation_activate(&activation, "rules-A", 60, NULL) ==
	      NFSP_ACTIVATION_OK, "activate abort fixture");
	admit_call(&activation, 60);
	CHECK(nfsp_activation_force_close(&activation, 60,
					  NFSP_FORCE_ABORTED) ==
	      NFSP_ACTIVATION_OK, "explicit abort closes admission");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 61, NULL) ==
	      NFSP_ACTIVATION_OK, "new generation can follow recorded abort");
	s = snapshot(&activation, generations, 6, &count);
	CHECK(count == 3 && generations[0].generation == 50 &&
	      generations[0].closure_reason ==
		NFSP_CLOSURE_REPLY_UNRESOLVED &&
	      generations[0].unresolved_replies == 2 &&
	      generations[0].reply_unresolved_count == 2,
	      "forced unresolved closure records exact debt");
	CHECK(generations[1].generation == 60 &&
	      generations[1].closure_reason == NFSP_CLOSURE_ABORTED &&
	      generations[1].reply_unresolved_count == 1 &&
	      s.admitting_generation == 61,
	      "abort reason and unresolved count are immutable");
	nfsp_activation_free(&activation);
}

static void test_call_account_tickets(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_call_ticket first, second, extra, bad;
	struct nfsp_activation_generation_snapshot generations[5];
	struct nfsp_activation_snapshot s;
	uint64_t generation = 0;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	init_activation_limits(&activation, &gate, 5, 2, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 90, NULL) ==
	      NFSP_ACTIVATION_OK, "activate ticket fixture");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &first) ==
	      NFSP_ACTIVATION_OK && generation == 90 && first.id != 0 &&
	      first.generation == 90, "first CALL gets accounting ticket");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &second) ==
	      NFSP_ACTIVATION_OK && generation == 90 &&
	      second.id == first.id + 1u && second.generation == 90,
	      "second CALL gets distinct monotonic ticket");
	generation = 123;
	memset(&extra, 0x5a, sizeof(extra));
	CHECK(nfsp_activation_call_generation(&activation, &generation, &extra) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_CAPACITY && generation == 0 &&
	      extra.id == 0 && extra.generation == 0,
	      "bounded ticket capacity refuses CALL before untracked admission");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 90, NULL) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_PENDING && gate.calls == 1,
	      "omitted accounting blocks draining gate submission");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &extra) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW && generation == 0,
	      "blocked deactivation has already closed new CALL admission");
	CHECK(nfsp_activation_close_if_drained(&activation, 90) ==
	      NFSP_ACTIVATION_CLOSURE_NOT_READY,
	      "unaccounted CALL cannot produce clean closure");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 91, NULL) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_PENDING,
	      "next generation waits for CALL accounting and drain barrier");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 90, NULL) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_PENDING && gate.calls == 1,
	      "duplicate deactivation remains blocked without gate side effects");
	s = snapshot(&activation, generations, 5, &count);
	CHECK(s.state == NFSP_ACTIVATION_DRAINING &&
	      s.admitting_generation == 0 &&
	      s.pending_call_account_count == 2 &&
	      s.pending_barrier.id == 0 && count == 1 &&
	      generations[0].state == NFSP_GENERATION_CALL_ACCOUNTING &&
	      generations[0].pending_call_accounts == 2 &&
	      generations[0].draining_barrier == NFSP_BARRIER_NOT_REQUESTED,
	      "snapshot exposes fail-closed accounting state");

	bad = second;
	bad.generation++;
	CHECK(nfsp_activation_account_call(&activation, &bad,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_MISMATCH,
	      "ticket generation mismatch is typed and leaves ticket pending");
	bad = second;
	bad.id += 100u;
	CHECK(nfsp_activation_account_call(&activation, &bad,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_UNKNOWN,
	      "never-issued ticket is refused");
	CHECK(nfsp_activation_account_call(&activation, &first,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_OK, "first ticket records one reply obligation");
	CHECK(nfsp_activation_account_call(&activation, &first,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_ALREADY_RESOLVED,
	      "duplicate accounting cannot create false reply debt");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 90, NULL) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_PENDING && gate.calls == 1,
	      "one remaining ticket still blocks deactivation");
	CHECK(nfsp_activation_account_call(&activation, &second,
					   NFSP_ACTIVATION_CALL_NOT_INSERTED) ==
	      NFSP_ACTIVATION_OK, "non-inserted CALL consumes its ticket");
	CHECK(nfsp_activation_account_call(&activation, &second,
					   NFSP_ACTIVATION_CALL_DUPLICATE) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_ALREADY_RESOLVED,
	      "consumed non-insert ticket is not reusable");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 90, NULL) ==
	      NFSP_ACTIVATION_OK && gate.calls == 2 &&
	      gate.requests[1].barrier.event == NFSP_GATE_GENERATION_DRAINING,
	      "retry submits draining gate only after all tickets resolve");
	CHECK(nfsp_activation_account_reply(&activation, 90,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "known inserted CALL resolves and closes");
	s = snapshot(&activation, generations, 5, &count);
	CHECK(s.state == NFSP_ACTIVATION_CLOSED &&
	      s.pending_call_account_count == 0 && s.max_pending_calls == 2 &&
	      s.stats.call_account_capacity_exhausted == 1 &&
	      generations[0].admitted_calls == 1 &&
	      generations[0].resolved_replies == 1 &&
	      generations[0].call_account_capacity_exhausted == 1 &&
	      generations[0].pending_call_accounts == 0 &&
	      generations[0].unaccounted_calls_at_closure == 0 &&
	      generations[0].closure_reason == NFSP_CLOSURE_DRAINED,
	      "fully accounted generation closes cleanly exactly once");

	CHECK(nfsp_activation_activate(&activation, "rules-A", 91, NULL) ==
	      NFSP_ACTIVATION_OK, "activate forced-abort ticket fixture");
	CHECK(nfsp_activation_call_generation(&activation, &generation, &first) ==
	      NFSP_ACTIVATION_OK && generation == 91,
	      "issue ticket that will remain unaccounted");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 91, NULL) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_PENDING,
	      "unaccounted abort fixture closes admission");
	CHECK(nfsp_activation_force_close(&activation, 91,
					  NFSP_FORCE_ABORTED) ==
	      NFSP_ACTIVATION_OK, "forced abort cancels pending ticket");
	CHECK(nfsp_activation_account_call(&activation, &first,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_ALREADY_RESOLVED,
	      "cancelled ticket cannot mutate forced closure");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 92, NULL) ==
	      NFSP_ACTIVATION_OK,
	      "typed forced abort permits a later generation");
	s = snapshot(&activation, generations, 5, &count);
	CHECK(s.pending_call_account_count == 0 && !s.quarantined && count == 3 &&
	      generations[1].generation == 91 &&
	      generations[1].closure_reason == NFSP_CLOSURE_ABORTED &&
	      generations[1].pending_call_accounts == 0 &&
	      generations[1].unaccounted_calls_at_closure == 1 &&
	      generations[1].reply_unresolved_count == 1,
	      "abort snapshot conservatively records omitted CALL accounting");
	nfsp_activation_free(&activation);
}

static void test_forced_abort_cannot_bypass_barrier(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_barrier drain;
	struct nfsp_activation_generation_snapshot generations[3];
	struct nfsp_activation_snapshot s;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_PENDING);
	init_activation(&activation, &gate, 3, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 80, NULL) ==
	      NFSP_ACTIVATION_OK, "activate pending-force fixture");
	admit_call(&activation, 80);
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 80, &drain) ==
	      NFSP_ACTIVATION_BARRIER_PENDING, "draining barrier pending");
	CHECK(nfsp_activation_force_close(&activation, 80,
					  NFSP_FORCE_ABORTED) ==
	      NFSP_ACTIVATION_OK, "explicit abort records closure");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 81, NULL) ==
	      NFSP_ACTIVATION_QUARANTINE,
	      "forced closure cannot bypass unconfirmed draining barrier");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 80, NULL) ==
	      NFSP_ACTIVATION_QUARANTINE,
	      "duplicate deactivation cannot synthesize missing ACK");
	CHECK(nfsp_activation_barrier_complete(&activation, drain.id,
					       NFSP_ACTIVATION_GATE_ACCEPTED) ==
	      NFSP_ACTIVATION_STALE_ACK,
	      "ACK after forced abort is stale");
	CHECK(nfsp_activation_account_reply(&activation, 80,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OUTSIDE_WINDOW,
	      "closed quarantined generation still counts a late reply");
	s = snapshot(&activation, generations, 3, &count);
	CHECK(s.state == NFSP_ACTIVATION_QUARANTINED &&
	      s.stats.late_after_close == 1 && count == 1 &&
	      generations[0].state == NFSP_GENERATION_CLOSED &&
	      generations[0].draining_barrier == NFSP_BARRIER_NO_ACK &&
	      generations[0].closure_reason == NFSP_CLOSURE_ABORTED &&
	      generations[0].reply_unresolved_count == 1,
	      "forced abort preserves unconfirmed barrier and closure facts");
	nfsp_activation_free(&activation);
}

static void test_connection_close_accounting(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_generation_snapshot generations[3];
	struct nfsp_activation_snapshot s;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	init_activation(&activation, &gate, 3, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 70, NULL) ==
	      NFSP_ACTIVATION_OK, "activate connection-close fixture");
	admit_call(&activation, 70);
	admit_call(&activation, 70);
	CHECK(nfsp_activation_account_connection_closed(&activation, 70, 3) ==
	      NFSP_ACTIVATION_CALL_UNACCOUNTED,
	      "cannot account more closed entries than admitted debt");
	CHECK(nfsp_activation_account_connection_closed(&activation, 70, 1) ==
	      NFSP_ACTIVATION_OK,
	      "connection close accounts one transaction without a reply");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 70, NULL) ==
	      NFSP_ACTIVATION_OK, "remaining transaction keeps drain open");
	CHECK(nfsp_activation_close_if_drained(&activation, 70) ==
	      NFSP_ACTIVATION_CLOSURE_BLOCKED, "one reply remains unresolved");
	CHECK(nfsp_activation_account_reply(&activation, 70,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "last reply closes cleanly");
	s = snapshot(&activation, generations, 3, &count);
	CHECK(s.state == NFSP_ACTIVATION_CLOSED && count == 1 &&
	      generations[0].admitted_calls == 2 &&
	      generations[0].resolved_replies == 1 &&
	      generations[0].connection_closed_calls == 1 &&
	      generations[0].unresolved_replies == 0 &&
	      generations[0].closure_reason == NFSP_CLOSURE_DRAINED,
	      "admitted = resolved + connection-closed + unresolved");
	CHECK(nfsp_activation_account_connection_closed(&activation, 70, 1) ==
	      NFSP_ACTIVATION_CALL_UNACCOUNTED,
	      "closed summary cannot be changed by a late connection event");
	nfsp_activation_free(&activation);
}

static void test_capacity_and_snapshot_preflight(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_generation_snapshot generations[2];
	struct nfsp_activation_generation_snapshot sentinel;
	struct nfsp_activation_snapshot s;
	struct nfsp_activation_snapshot before;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_REJECTED);
	init_activation(&activation, &gate, 2, 1);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 1, NULL) ==
	      NFSP_ACTIVATION_BARRIER_REJECTED,
	      "failed OPEN consumes generation id and slot");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 2, NULL) ==
	      NFSP_ACTIVATION_OK, "second and final slot activates");
	admit_call(&activation, 2);
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 2, NULL) ==
	      NFSP_ACTIVATION_OK, "second slot draining");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 3, NULL) ==
	      NFSP_ACTIVATION_DRAINING_LIMIT,
	      "draining bound precedes lifetime capacity");
	CHECK(nfsp_activation_account_reply(&activation, 2,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "free draining allowance");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 3, NULL) ==
	      NFSP_ACTIVATION_GENERATION_CAPACITY,
	      "closed ids are retained, so lifetime capacity is exact");
	CHECK(nfsp_activation_activate(&activation, "rules-A", 1, NULL) ==
	      NFSP_ACTIVATION_GENERATION_REUSED, "old failed id not reusable");

	memset(&before, 0x5a, sizeof(before));
	s = before;
	memset(&sentinel, 0x6b, sizeof(sentinel));
	generations[0] = sentinel;
	CHECK(nfsp_activation_get_snapshot(&activation, &s, generations, 1,
					   &count) ==
	      NFSP_ACTIVATION_SNAPSHOT_TOO_SMALL && count == 2,
	      "snapshot reports required capacity");
	CHECK(memcmp(&s, &before, sizeof(s)) == 0 &&
	      memcmp(&generations[0], &sentinel, sizeof(sentinel)) == 0,
	      "short snapshot writes no partial result");
	s = snapshot(&activation, generations, 2, &count);
	CHECK(s.max_generations == 2 && s.max_draining == 1 &&
	      s.generation_count == 2,
	      "configured limits exposed deterministically");
	nfsp_activation_free(&activation);
}

static void build_permutation_fixture(
	struct nfsp_activation *activation, struct gate_script *gate)
{
	script_init(gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	init_activation(activation, gate, 6, 3);
	install(activation);
	CHECK(nfsp_activation_activate(activation, "rules-A", 20, NULL) ==
	      NFSP_ACTIVATION_OK, "permutation G20 activate");
	admit_call(activation, 20);
	admit_call(activation, 20);
	CHECK(nfsp_activation_deactivate(activation, "rules-A", 20, NULL) ==
	      NFSP_ACTIVATION_OK, "permutation G20 drain");
	CHECK(nfsp_activation_activate(activation, "rules-A", 10, NULL) ==
	      NFSP_ACTIVATION_OK, "permutation G10 activate");
	admit_call(activation, 10);
	admit_call(activation, 10);
	CHECK(nfsp_activation_deactivate(activation, "rules-A", 10, NULL) ==
	      NFSP_ACTIVATION_OK, "permutation G10 drain");
}

static void test_permutation_determinism(void)
{
	struct nfsp_activation a, b;
	struct gate_script gate_a, gate_b;
	struct nfsp_activation_generation_snapshot ga[6], gb[6];
	struct nfsp_activation_snapshot sa, sb;
	size_t ca = 0, cb = 0;

	build_permutation_fixture(&a, &gate_a);
	build_permutation_fixture(&b, &gate_b);
	CHECK(nfsp_activation_account_reply(&a, 20,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&a, 10,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&a, 20,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&a, 10,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "reply permutation A");
	CHECK(nfsp_activation_account_reply(&b, 10,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&b, 20,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&b, 10,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK &&
	      nfsp_activation_account_reply(&b, 20,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "reply permutation B");
	sa = snapshot(&a, ga, 6, &ca);
	sb = snapshot(&b, gb, 6, &cb);
	CHECK(ca == cb && memcmp(&sa, &sb, sizeof(sa)) == 0 &&
	      memcmp(ga, gb, ca * sizeof(*ga)) == 0,
	      "reply order yields byte-identical sorted snapshots");
	CHECK(ga[0].generation == 10 && ga[1].generation == 20 &&
	      ga[0].closure_reason == NFSP_CLOSURE_DRAINED &&
	      ga[1].closure_reason == NFSP_CLOSURE_DRAINED,
	      "deterministic snapshots retain generation identity");
	nfsp_activation_free(&a);
	nfsp_activation_free(&b);
}

static void test_typed_results(void)
{
	CHECK(strcmp(nfsp_activation_strresult(NFSP_ACTIVATION_OK), "ok") == 0,
	      "OK result string");
	CHECK(strcmp(nfsp_activation_strresult(NFSP_ACTIVATION_BARRIER_NO_ACK),
		     "barrier_no_ack") == 0, "barrier result string");
	CHECK(strcmp(nfsp_activation_strresult(NFSP_ACTIVATION_OUTSIDE_WINDOW),
		     "outside_activation_window") == 0,
	      "window result string");
	CHECK(strcmp(nfsp_activation_strresult(NFSP_ACTIVATION_QUARANTINE),
		     "quarantined") == 0, "quarantine result string");
	CHECK(strcmp(nfsp_activation_strresult(
		     (enum nfsp_activation_result)999), "unknown") == 0,
	      "unknown result string");
}

/* A REPLY to an admitted CALL that arrives while the draining ACK waits,
 * or while G still accounts a CALL, settles G's reply debt (PR #34 X-P2-2). */
static void test_reply_while_drain_barrier_or_call_accounting(void)
{
	struct nfsp_activation activation;
	struct gate_script gate;
	struct nfsp_activation_barrier open, drain;
	struct nfsp_activation_generation_snapshot generations[4];
	struct nfsp_activation_call_ticket pending;
	uint64_t generation = 0;
	size_t count = 0;

	script_init(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_ACCEPTED);
	script_add(&gate, NFSP_ACTIVATION_GATE_PENDING);
	init_activation(&activation, &gate, 4, 2);
	install(&activation);
	CHECK(nfsp_activation_activate(&activation, "rules-A", 7, &open) ==
	      NFSP_ACTIVATION_OK, "G7 open");
	admit_call(&activation, 7);
	CHECK(nfsp_activation_call_generation(&activation, &generation,
					      &pending) ==
	      NFSP_ACTIVATION_OK && generation == 7, "second CALL ticket");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 7, NULL) ==
	      NFSP_ACTIVATION_CALL_ACCOUNT_PENDING, "G7 accounts its CALLs");
	CHECK(nfsp_activation_account_reply(&activation, 7,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "REPLY during CALL_ACCOUNTING is G7's");
	CHECK(nfsp_activation_account_call(&activation, &pending,
					   NFSP_ACTIVATION_CALL_INSERTED) ==
	      NFSP_ACTIVATION_OK, "pending CALL accounted");
	CHECK(nfsp_activation_deactivate(&activation, "rules-A", 7, &drain) ==
	      NFSP_ACTIVATION_BARRIER_PENDING, "draining ACK pending");
	CHECK(nfsp_activation_account_reply(&activation, 7,
					    NFSP_ACTIVATION_REPLY_RESOLVED) ==
	      NFSP_ACTIVATION_OK, "REPLY during DRAIN_BARRIER is G7's");
	CHECK(nfsp_activation_barrier_complete(&activation, drain.id,
					       NFSP_ACTIVATION_GATE_ACCEPTED) ==
	      NFSP_ACTIVATION_OK, "draining ACK accepted");
	(void)snapshot(&activation, generations, 4, &count);
	CHECK(count == 1 && generations[0].state == NFSP_GENERATION_CLOSED &&
	      generations[0].closure_reason == NFSP_CLOSURE_DRAINED &&
	      generations[0].resolved_replies == 2 &&
	      generations[0].reply_unresolved_count == 0,
	      "both REPLYs settled: G7 closes drained");
	nfsp_activation_free(&activation);
}

int main(void)
{
	test_init_ruleset_and_legacy();
	test_success_and_window_edges();
	test_pending_timeout_and_stale_ack();
	test_gate_rejection_and_missing_ack();
	test_multiple_draining_and_bound();
	test_forced_closure();
	test_call_account_tickets();
	test_forced_abort_cannot_bypass_barrier();
	test_connection_close_accounting();
	test_capacity_and_snapshot_preflight();
	test_permutation_determinism();
	test_typed_results();
	test_reply_while_drain_barrier_or_call_accounting();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
