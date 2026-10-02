#ifndef NFSP_PROXY_H
#define NFSP_PROXY_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define NFSP_CLIENTS 2u
#define NFSP_BACKENDS 2u
#define NFSP_DIR_C2S 0
#define NFSP_DIR_S2C 1

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
	/* Called by the relay event loop, never from a signal handler.  The
	 * pointer is an in-thread snapshot; do not retain it after return. */
	void (*on_stats)(const struct nfsp_proxy_stats *, void *arg);
	void *on_stats_arg;
	/* Control IPC is pumped by the same event loop that invokes on_record.
	 * Thus an arm ACK is a registration barrier with no cross-thread race. */
	void (*on_tick)(void *arg);
	void *on_tick_arg;
};

/* on_ready runs after BOTH listeners bind.  Its stats pointer is valid until
 * run returns; callers must synchronize before reading counters concurrently. */
int nfsp_proxy_run(const struct nfsp_proxy_cfg *cfg,
		   struct nfsp_proxy_stats *stats,
		   void (*on_ready)(const struct nfsp_proxy_stats *, void *),
		   void *ready_arg);

#endif
