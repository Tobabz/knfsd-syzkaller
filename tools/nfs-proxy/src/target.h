/* Target mode: semantic rules applied live, gated by the host journal (M5).
 *
 * WHAT IT CONNECTS
 *
 *   relay record -> RPC envelope -> activation admission (CALL) or the
 *   CALL's generation (REPLY) -> Transaction Context + decode (semantic.c)
 *   -> Resolver (resolver.c) -> batch apply (mutation_apply.c)
 *   -> journal event (journal.c) -> host ACK -> relay
 *
 * THE RULES IT ENFORCES (05-mutation-delta-replay.md §6-§11, §16-§21,
 * 01-architecture.md §16)
 *
 *   - RULESET is the session's first event.  A generation can only open
 *     after it (the host refuses GENERATION_OPEN otherwise).
 *   - activation(G) is ACKed to the executor only after the host ACKed
 *     GENERATION_OPEN(G); deactivation(G) only after GENERATION_DRAINING(G).
 *     A refused or lost barrier is never ACKed (activation.c quarantines).
 *   - Mutated bytes reach the peer only after the host ACKed the batch's
 *     EXPOSURE_INTENT.  A refused or lost intent forwards the record
 *     unchanged and counts an evidence path failure.
 *   - The first hard refusal per (generation, rule) is written ahead as
 *     APPLY_REFUSAL; that record, and any later record with the same hard
 *     refusal while the event is unanswered, is relayed only after an
 *     explicit host answer.  Without one (the channel failed) it is never
 *     relayed: traffic on that connection and direction stops.
 *   - Only the record's own connection and direction waits.  Other
 *     connections keep relaying records that need no event; events go to
 *     the host one at a time in event_seq order.
 *   - FORWARD_COMPLETE / FORWARD_FAILED follow the relay's full-write or
 *     loss report.  GENERATION_COMPLETE(G) is G's last event, after G is
 *     closed and all of its batches have a forward event.
 *
 * ACTIVATION ENDPOINT
 *
 *   A Unix SOCK_SEQPACKET socket for the executor (S1a).  Its path must be
 *   outside anything a fuzzed program can reach (01 §16).  One 120-byte
 *   request per packet, all integers big-endian:
 *
 *     0   8  "NFSPACT1"
 *     8   4  op: 1 activate, 2 deactivate, 3 abort
 *     12  4  zero
 *     16  8  generation (kcov generation, nonzero)
 *     24 32  program digest (SHA-256 of the program; activate only)
 *     56 64  rule_set_id, lowercase hex
 *
 *   One 24-byte answer: "NFSPACK1", op, status (0 = ACK, otherwise an
 *   nfsp_activation_result or NFSP_TARGET_NOT_READY), generation.  An
 *   activate/deactivate answer is sent when its barrier is decided.
 */
#ifndef NFSP_TARGET_H
#define NFSP_TARGET_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "proxy.h"
#include "schema.h"

#define NFSP_TARGET_REQ_LEN		120u
#define NFSP_TARGET_ACK_LEN		24u
#define NFSP_TARGET_OP_ACTIVATE		1u
#define NFSP_TARGET_OP_DEACTIVATE	2u
#define NFSP_TARGET_OP_ABORT		3u
#define NFSP_TARGET_NOT_READY		1000u
#define NFSP_TARGET_DEFAULT_DRAIN_MS	5000u
#define NFSP_TARGET_RULES_MAX		(1u << 20)	/* NFSP_RULESET_MAX_LEN */

struct nfsp_target_cfg {
	const struct nfsp_schema_family *const *families;
	size_t nfamilies;
	const uint8_t *rule_set;	/* NFSPRUL1 bytes, copied */
	size_t rule_set_len;
	int journal_fd;			/* owned from open, even on failure */
	const char *proxy_session_id;
	uint32_t lane_id;
	uint32_t drain_bound_ms;	/* 0: default */
	uint32_t retransmit_ms;		/* 0: journal default */
	const char *activation_path;	/* NULL: drive nfsp_target_request */
	uint64_t (*clock_ms)(void *arg);	/* NULL: CLOCK_MONOTONIC */
	void *clock_arg;
};

struct nfsp_target_stats {
	uint64_t records, eligible, exposures, exposure_refused,
		 exposure_lost, refusal_events, refusal_waits,
		 evidence_path_failures, forward_complete, forward_failed,
		 held_dropped, outside_replies, generations_complete;
	int ruleset_state;	/* 0 pending, 1 acked, -1 refused or lost */
	int evidence_path_degraded;
};

struct nfsp_target;

/* 0, or -1 with a message in err. */
int nfsp_target_open(struct nfsp_target **out,
		     const struct nfsp_target_cfg *cfg, char *err,
		     size_t errlen);
void nfsp_target_close(struct nfsp_target *t);

/* Install these on struct nfsp_proxy_cfg with arg = the target. */
void nfsp_target_install(struct nfsp_target *t, struct nfsp_proxy_cfg *cfg);
void nfsp_target_tick(void *arg);

/* The endpoint's handling of one request, for tests without a socket.
 * Returns 1 when the answer is deferred to a barrier (then `on_answer` gets
 * it later), else 0 with *status set. */
int nfsp_target_request(struct nfsp_target *t, uint32_t op,
			uint64_t generation, const uint8_t digest[32],
			const char *rule_set_id, uint32_t *status,
			void (*on_answer)(void *arg, uint32_t op,
					  uint64_t generation,
					  uint32_t status),
			void *answer_arg);

/* Queue RUN_COMPLETE and wait up to wait_ms for every answer. */
void nfsp_target_finish(struct nfsp_target *t, uint32_t wait_ms);

const struct nfsp_target_stats *nfsp_target_stats(const struct nfsp_target *t);
void nfsp_target_report(const struct nfsp_target *t, FILE *out);

#endif /* NFSP_TARGET_H */
