/* Delta Recorder transport to the Runner's host journal sink (M5/S1b).
 *
 * WHAT IT GUARANTEES (05-mutation-delta-replay.md §6, §11, §21, §45)
 *
 *   Events of one Proxy session go to the host one at a time, in event_seq
 *   order, each as one NFSPJNL1 kind-1 frame whose payload is the canonical
 *   JSON request.  The next event is not sent while one has no host answer.
 *   An answer is accepted only when it names the outstanding request: an ACK
 *   (kind 3) with this session's proxy_session_id and rule_set_id, the
 *   event_seq and the request's SHA-256, or a host rejection (kind 2) with
 *   the same digest.  An ACK for an earlier event (the answer to a
 *   retransmission) is ignored.  Without an answer the same bytes are sent
 *   again after `retransmit_ms`; the host re-answers an identical request
 *   without appending it twice.
 *
 *   ACKED means the host appended the event before answering: that is the
 *   durability point (D).  REJECTED means the host refused it and recorded
 *   the refusal.  LOST means the channel failed (EOF, I/O error, a frame
 *   that is not a valid answer): no answer will ever come, which is neither
 *   success nor a host refusal.
 *
 * Single-threaded: the proxy event loop polls the fd and calls pump().  The
 * done callback runs only from pump(), never from submit().
 */
#ifndef NFSP_JOURNAL_H
#define NFSP_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#define NFSP_JOURNAL_HEADER_LEN		80u
#define NFSP_JOURNAL_MAX_PAYLOAD	(4u << 20)
/* A request is stored inside the host's envelope, which must still fit one
 * frame: journal_sink.py MAX_REQUEST_BYTES. */
#define NFSP_JOURNAL_MAX_REQUEST	(NFSP_JOURNAL_MAX_PAYLOAD - (64u << 10))
#define NFSP_JOURNAL_DEFAULT_RETRANSMIT_MS	1000u
#define NFSP_JOURNAL_SESSION_ID_MAX	256u
#define NFSP_JOURNAL_REASON_MAX		64u

enum nfsp_journal_outcome {
	NFSP_JOURNAL_ACKED = 0,
	NFSP_JOURNAL_REJECTED,
	NFSP_JOURNAL_LOST
};

typedef void (*nfsp_journal_done_fn)(void *arg, uint64_t event_seq,
				     uint64_t cookie,
				     enum nfsp_journal_outcome outcome,
				     const char *reason);

struct nfsp_journal_cfg {
	int fd;				/* owned: closed by nfsp_journal_close */
	const char *proxy_session_id;	/* [A-Za-z0-9_.:/-], 1-256 */
	const char *rule_set_id;	/* 64 lowercase hex */
	uint32_t retransmit_ms;		/* 0: default */
	uint64_t (*clock_ms)(void *arg);	/* NULL: CLOCK_MONOTONIC */
	void *clock_arg;
	nfsp_journal_done_fn done;
	void *done_arg;
};

struct nfsp_journal_stats {
	uint64_t submitted, sent, retransmits;
	uint64_t acked, rejected, lost, stale_answers;
};

struct nfsp_journal;

int nfsp_journal_open(struct nfsp_journal **out,
		      const struct nfsp_journal_cfg *cfg);
void nfsp_journal_close(struct nfsp_journal *j);

/* Queue one event whose payload is a canonical JSON object.  Assigns the
 * next event_seq.  -1 only for bad arguments, an oversized request or no
 * memory; nothing is queued then and no seq is used. */
int nfsp_journal_submit(struct nfsp_journal *j, const char *event_type,
			const char *payload_json, size_t payload_len,
			uint64_t cookie, uint64_t *event_seq);

/* poll(2) interest; 0 once the channel failed. */
int nfsp_journal_fd(const struct nfsp_journal *j);
short nfsp_journal_events(const struct nfsp_journal *j);
/* Nonblocking writes, reads, retransmission and callbacks. */
void nfsp_journal_pump(struct nfsp_journal *j);

size_t nfsp_journal_pending(const struct nfsp_journal *j);
int nfsp_journal_failed(const struct nfsp_journal *j);
const struct nfsp_journal_stats *nfsp_journal_stats(
	const struct nfsp_journal *j);

/* Build one NFSPJNL1 frame (header + payload) of `kind`; caller frees. */
uint8_t *nfsp_journal_frame(uint16_t kind, const uint8_t *payload,
			    size_t len, size_t *frame_len);

#endif /* NFSP_JOURNAL_H */
