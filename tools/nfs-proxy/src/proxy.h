#ifndef NFSP_PROXY_H
#define NFSP_PROXY_H

#include <poll.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "rpc_record.h"

#define NFSP_CLIENTS 2u
#define NFSP_BACKENDS 2u
#define NFSP_DIR_C2S 0
#define NFSP_DIR_S2C 1

/* ConnectionRef lifecycle events (on_connection). */
#define NFSP_CONN_OPENED 0
#define NFSP_CONN_CLOSED 1

/* Target-mode relay decisions (M5).  FORWARD sends `out` (by default the
 * record as received); HOLD keeps the record, and every later record of
 * the same connection and direction, until on_hold decides; REFUSE closes
 * the connection without forwarding. */
#define NFSP_RELAY_FORWARD	0
#define NFSP_RELAY_HOLD		1
#define NFSP_RELAY_REFUSE	(-1)

struct nfsp_relay_verdict {
	/* FORWARD: the framed record to send.  Set on entry to the record as
	 * received; a different buffer must stay valid until the next call
	 * of any relay hook. */
	const uint8_t *out;
	size_t out_len;
	/* FORWARD: nonzero asks for on_forwarded once these bytes were all
	 * written to the peer socket, or are known not to be (§16-§18). */
	uint64_t completion;
	/* HOLD: the token on_hold and on_hold_dropped are given back. */
	uint64_t hold;
};

/* One listening address per backend.  Routing is the accepting listener,
 * never arrival order or an RPC field.  Both client source addresses must be
 * explicit: otherwise a four-connection test could all be one client. */
struct nfsp_route {
	const char *listen_ip;
	uint16_t listen_port;
	const char *backend_ip;
	uint16_t backend_port;
};

struct nfsp_proxy_stats {
	uint16_t bound_port[NFSP_BACKENDS];
	uint32_t accepted[NFSP_CLIENTS][NFSP_BACKENDS];
	uint32_t connected[NFSP_CLIENTS][NFSP_BACKENDS];
	uint32_t connect_failed[NFSP_CLIENTS][NFSP_BACKENDS];
	uint32_t records[NFSP_CLIENTS][NFSP_BACKENDS][2];
	uint32_t delivered[NFSP_CLIENTS][NFSP_BACKENDS][2];
	uint32_t framing_errors, relay_errors, mutation_errors, rejected_client;
	uint32_t active, peak_active;
	/* records the on_rpc_record observer refused, or could not be given */
	uint32_t record_refused;
};

struct nfsp_proxy_cfg {
	struct nfsp_route route[NFSP_BACKENDS];
	const char *client_ip[NFSP_CLIENTS];
	size_t msg_limit;  /* zero chooses NFSP_MSG_LIMIT_DEFAULT */
	unsigned connect_timeout_ms; /* zero chooses a finite default */
	_Atomic int *stop;
	/* The only place a complete record can be changed.
	 *
	 * On entry *out == record and *out_len == len (the relay default).  The
	 * callback forwards record unchanged by leaving them alone, or forwards a
	 * different, possibly longer or shorter, record by pointing *out at a
	 * buffer it owns and setting *out_len.  That buffer must stay valid until
	 * the next call.  `record` itself is read-only and must not be modified.
	 *
	 * The length may change because an edit can add an operation or resize a
	 * field; the callback is responsible for rebuilding the record marker.
	 * Returns 0 on success, negative to refuse this record and close this
	 * connection without forwarding unverified bytes.  NULL is pure relay. */
	int (*on_record)(unsigned client, unsigned backend, int dir,
			 const uint8_t *record, size_t len,
			 const uint8_t **out, size_t *out_len, void *arg);
	void *on_record_arg;
	/* The target-path view of the same record (M1): its ConnectionRef,
	 * direction and marker-free rpc_payload (rpc_record.h).  It runs before
	 * on_record, sees the record exactly as received, and cannot change
	 * it; the legacy on_record contract above is untouched.  Returns 0 to
	 * continue, negative to refuse the record and close this connection
	 * without forwarding it.  NULL skips canonicalisation entirely, so the
	 * legacy path pays nothing for it. */
	int (*on_rpc_record)(const struct nfsp_rpc_record *record, void *arg);
	void *on_rpc_record_arg;
	/* ConnectionRef lifecycle: NFSP_CONN_OPENED when a client connection is
	 * accepted onto a route (before any of its records), NFSP_CONN_CLOSED
	 * exactly once when it is torn down for any reason, including relay
	 * shutdown.  A connection whose backend connect fails is opened and
	 * then closed.  The pointer is valid only during the call. */
	void (*on_connection)(const struct nfsp_connection_ref *conn, int event,
			      void *arg);
	void *on_connection_arg;
	/* Called by the relay event loop, never from a signal handler.  The
	 * pointer is an in-thread snapshot; do not retain it after return. */
	void (*on_stats)(const struct nfsp_proxy_stats *, void *arg);
	void *on_stats_arg;
	/* Control IPC is pumped by the same event loop that invokes on_record.
	 * Thus an arm ACK is a registration barrier with no cross-thread race. */
	void (*on_tick)(void *arg);
	void *on_tick_arg;

	/* Target mode (M5).  When on_relay is set it replaces on_rpc_record
	 * and on_record: it sees the record's ConnectionRef, direction and
	 * canonical rpc_payload together with the framed bytes, and returns
	 * an NFSP_RELAY_* action.  A held record is offered to on_hold (with
	 * the same framed bytes) on every loop iteration until it returns
	 * FORWARD or REFUSE; meanwhile nothing more is read or relayed in
	 * that connection and direction, while every other one keeps
	 * relaying.  on_hold_dropped reports a held record whose connection
	 * closed: it never reached the peer.  on_forwarded reports each
	 * completion token exactly once: complete (all len bytes written to
	 * the peer socket) or not, with how many of them were written.
	 * poll_fds adds descriptors that wake the loop (the journal channel,
	 * the activation endpoint); on_tick runs after every wake. */
	int (*on_relay)(const struct nfsp_rpc_record *record,
			const uint8_t *framed, size_t len,
			struct nfsp_relay_verdict *verdict, void *arg);
	int (*on_hold)(uint64_t hold, const uint8_t *framed, size_t len,
		       struct nfsp_relay_verdict *verdict, void *arg);
	void (*on_hold_dropped)(uint64_t hold, void *arg);
	void (*on_forwarded)(uint64_t completion, int complete,
			     size_t written, size_t len, void *arg);
	size_t (*poll_fds)(struct pollfd *fds, size_t max, void *arg);
	void *relay_arg;
};

/* on_ready runs after BOTH listeners bind.  Its stats pointer is valid until
 * run returns; callers must synchronize before reading counters concurrently. */
int nfsp_proxy_run(const struct nfsp_proxy_cfg *cfg,
		   struct nfsp_proxy_stats *stats,
		   void (*on_ready)(const struct nfsp_proxy_stats *, void *),
		   void *ready_arg);

#endif
