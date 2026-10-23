#define _POSIX_C_SOURCE 200809L
#include "proxy.h"
#include "rpc_decode.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static unsigned checks, failures;
#define CHECK(x, ...) do { checks++; if (!(x)) { failures++; \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

static void stamp(uint8_t *p, uint32_t body)
{
	uint32_t h = htonl(body | 0x80000000u);
	memcpy(p, &h, sizeof(h));
}

static int exact(int fd, uint8_t *p, size_t n)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = recv(fd, p + got, n - got, 0);
		if (r == 0) return -1;
		if (r < 0) { if (errno == EINTR) continue; return -1; }
		got += (size_t)r;
	}
	return 0;
}

static void timeout_socket(int fd)
{
	struct timeval tv = {3, 0};
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

struct conn_event { struct nfsp_connection_ref ref; int event; };

/* Written only by the proxy thread; nev is published after the entry. */
struct conn_log {
	struct conn_event ev[64];
	_Atomic unsigned nev, nclosed;
};

struct fixture;
struct fake {
	struct fixture *parent;
	unsigned backend;
	int listener;
	uint16_t port;
	_Atomic int stop;
	pthread_t thread, workers[16];
	unsigned nworkers;
	unsigned nrecords;
	_Atomic unsigned accepted, received[2];
	_Atomic uint32_t peer_addr[2];
};

struct fixture {
	struct nfsp_proxy_cfg cfg;
	struct nfsp_proxy_stats stats;
	_Atomic int stop;
	int ready, done, rc;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t proxy_thread;
	struct fake fake[2];
	int dead_fd;
	uint16_t port[2];
	int rendezvous;
	unsigned arrived;
	pthread_mutex_t rendezvous_mutex;
	pthread_cond_t rendezvous_cond;
	_Atomic unsigned mutations;
	_Atomic unsigned target_seen[2][2];
	_Atomic unsigned target_nlm_seen;
	struct conn_log conns;
};

struct job { struct fake *backend; int fd; };

/* THE FIXTURE TOPOLOGY
 *
 *   Each proxy listener has its own loopback address and each client its own
 *   source address, so the four (client, backend) tuples are four distinct TCP
 *   4-tuples, as in the guest lane topology.  Linux routes all of 127/8 to the
 *   loopback device and binds these with no setup.  main() checks that the
 *   topology works before starting any thread. */
static const char *const fixture_listen_ip[2] = {"127.0.0.2", "127.0.0.3"};
static const char *const fixture_client_ip[2] = {"127.0.0.10", "127.0.0.11"};

/* Connect from `client_ip` to a listener on `listen_ip` and check that the
 * accepted peer is `client_ip`.  bind() alone proves nothing: with the
 * loopback device down, Linux still binds 127/8 addresses and every connect
 * then fails.  The kernel completes the handshake into the backlog, so this
 * needs no thread. */
static int pair_works(const char *listen_ip, const char *client_ip,
		      char *why, size_t whylen)
{
	struct sockaddr_in la = {0}, ca = {0}, peer = {0};
	socklen_t len = sizeof(la);
	struct pollfd p;
	int lfd = -1, cfd = -1, afd = -1, err = 0, ok = 0, n;
	const char *step = "parse";

	la.sin_family = ca.sin_family = AF_INET;
	if (inet_pton(AF_INET, listen_ip, &la.sin_addr) != 1 ||
	    inet_pton(AF_INET, client_ip, &ca.sin_addr) != 1)
		goto out;
	step = "socket";
	if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
	    (cfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		goto fail;
	step = "bind listener";
	if (bind(lfd, (struct sockaddr *)&la, sizeof(la)) != 0)
		goto fail;
	step = "listen";
	if (listen(lfd, 1) != 0 ||
	    getsockname(lfd, (struct sockaddr *)&la, &len) != 0)
		goto fail;
	step = "bind client";
	if (bind(cfd, (struct sockaddr *)&ca, sizeof(ca)) != 0)
		goto fail;
	step = "connect";
	timeout_socket(cfd);
	if (connect(cfd, (struct sockaddr *)&la, sizeof(la)) != 0)
		goto fail;
	step = "accept";
	p.fd = lfd;
	p.events = POLLIN;
	p.revents = 0;
	n = poll(&p, 1, 3000);
	if (n == 0)
		errno = ETIMEDOUT;
	len = sizeof(peer);
	if (n != 1 || (afd = accept(lfd, (struct sockaddr *)&peer, &len)) < 0)
		goto fail;
	step = "peer is not the client address";
	ok = peer.sin_addr.s_addr == ca.sin_addr.s_addr;
	goto out;
fail:
	err = errno;
out:
	if (!ok)
		(void)snprintf(why, whylen, "%s -> %s: %s%s%s", client_ip,
			       listen_ip, step, err ? ": " : "",
			       err ? strerror(err) : "");
	if (afd >= 0) close(afd);
	if (cfd >= 0) close(cfd);
	if (lfd >= 0) close(lfd);
	return ok;
}

/* 1 when every client address reaches every listener address, else 0 with the
 * first reason in `why`.  `simulate` reports failure without probing, so that
 * build.sh can check on every run that the refusal in main() still happens. */
static int fixture_addresses_usable(int simulate, char *why, size_t whylen)
{
	if (simulate) {
		(void)snprintf(why, whylen, "simulated");
		return 0;
	}
	for (unsigned l = 0; l < 2; l++)
		for (unsigned c = 0; c < 2; c++)
			if (!pair_works(fixture_listen_ip[l],
					fixture_client_ip[c], why, whylen))
				return 0;
	return 1;
}

static void *serve(void *arg)
{
	struct job *job = arg;
	struct fake *b = job->backend;
	struct fixture *f = b->parent;
	int fd = job->fd;
	struct sockaddr_in peer = {0};
	socklen_t peer_len = sizeof(peer);
	uint8_t h[4], body[16], reply[6];
	free(job);
	timeout_socket(fd);
	(void)getpeername(fd, (struct sockaddr *)&peer, &peer_len);
	for (unsigned i = 0; i < b->nrecords; i++) {
		uint32_t word;
		unsigned client;
		if (exact(fd, h, 4) != 0) break;
		memcpy(&word, h, 4);
		if (ntohl(word) != 0x80000002u || exact(fd, body, 2) != 0) break;
		client = (unsigned)(body[0] >> 4);
		if (client >= 2 || body[1] != (uint8_t)('0' + b->backend)) break;
		atomic_store(&b->peer_addr[client], peer.sin_addr.s_addr);
		atomic_fetch_add(&b->received[client], 1u);
		if (f->rendezvous) {
			pthread_mutex_lock(&f->rendezvous_mutex);
			f->arrived++;
			pthread_cond_broadcast(&f->rendezvous_cond);
			while (f->arrived < 4u)
				pthread_cond_wait(&f->rendezvous_cond, &f->rendezvous_mutex);
			pthread_mutex_unlock(&f->rendezvous_mutex);
		}
		stamp(reply, 2);
		reply[4] = body[0];
		reply[5] = body[1];
		if (send(fd, reply, sizeof(reply), MSG_NOSIGNAL) != (ssize_t)sizeof(reply)) break;
	}
	close(fd);
	return NULL;
}

static void *fake_main(void *arg)
{
	struct fake *b = arg;
	while (!atomic_load(&b->stop)) {
		struct pollfd p = {b->listener, POLLIN, 0};
		int fd;
		struct job *job;
		if (poll(&p, 1, 25) <= 0 || (p.revents & POLLIN) == 0) continue;
		fd = accept(b->listener, NULL, NULL);
		if (fd < 0) continue;
		atomic_fetch_add(&b->accepted, 1u);
		if (b->nworkers == 16u) { close(fd); continue; }
		job = malloc(sizeof(*job));
		if (job == NULL) { close(fd); continue; }
		job->backend = b;
		job->fd = fd;
		if (pthread_create(&b->workers[b->nworkers], NULL, serve, job) != 0) {
			close(fd); free(job); continue;
		}
		b->nworkers++;
	}
	return NULL;
}

static int start_fake(struct fixture *f, unsigned backend, unsigned nrecords)
{
	struct sockaddr_in sa = {0};
	socklen_t len = sizeof(sa);
	struct fake *b = &f->fake[backend];
	b->parent = f;
	b->backend = backend;
	b->nrecords = nrecords;
	b->listener = socket(AF_INET, SOCK_STREAM, 0);
	if (b->listener < 0) return -1;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(b->listener, (struct sockaddr *)&sa, len) != 0 ||
	    listen(b->listener, 16) != 0 ||
	    getsockname(b->listener, (struct sockaddr *)&sa, &len) != 0)
		return -1;
	b->port = ntohs(sa.sin_port);
	return pthread_create(&b->thread, NULL, fake_main, b);
}

static void ready(const struct nfsp_proxy_stats *st, void *arg)
{
	struct fixture *f = arg;
	(void)st;
	pthread_mutex_lock(&f->mutex);
	f->ready = 1;
	pthread_cond_broadcast(&f->cond);
	pthread_mutex_unlock(&f->mutex);
}

static void *run_proxy(void *arg)
{
	struct fixture *f = arg;
	int rc = nfsp_proxy_run(&f->cfg, &f->stats, ready, f);
	pthread_mutex_lock(&f->mutex);
	f->rc = rc;
	f->done = 1;
	pthread_cond_broadcast(&f->cond);
	pthread_mutex_unlock(&f->mutex);
	return NULL;
}

static int mutate(unsigned client, unsigned backend, int dir,
		  const uint8_t *msg, size_t len, const uint8_t **out,
		  size_t *out_len, void *arg)
{
	struct fixture *f = arg;
	static uint8_t scratch[6];	/* the record is read-only: edit a copy */
	if (backend == 1u &&
	    ((client == 1u && dir == NFSP_DIR_S2C) ||
	     (client == 0u && dir == NFSP_DIR_C2S))) {
		if (len != 6u) return -1;
		memcpy(scratch, msg, sizeof(scratch));
		scratch[4] = dir == NFSP_DIR_S2C ? 0xee : 0x09;
		*out = scratch;
		*out_len = sizeof(scratch);
		atomic_fetch_add(&f->mutations, 1u);
	}
	return 0;
}

static void log_conn(const struct nfsp_connection_ref *ref, int event, void *arg)
{
	struct conn_log *l = arg;
	unsigned n = atomic_load(&l->nev);
	if (n < 64u) {
		l->ev[n].ref = *ref;
		l->ev[n].event = event;
		atomic_store(&l->nev, n + 1u);
	}
	if (event == NFSP_CONN_CLOSED) atomic_fetch_add(&l->nclosed, 1u);
}

static int target_passthrough(const struct nfsp_rpc_record *record,
			      const uint8_t *framed, size_t len,
			      struct nfsp_relay_verdict *verdict, void *arg)
{
	struct fixture *f = arg;
	if (record->conn.backend != 0 || record->conn.client >= 2 ||
	    (record->conn.route != NFSP_ROUTE_NFS &&
	     record->conn.route != NFSP_ROUTE_NLM) ||
	    record->direction < 0 || record->direction > 1 ||
	    record->rpc_payload_len != 2 || len != 6 || framed == NULL ||
	    verdict->out != framed || verdict->out_len != len)
		return NFSP_RELAY_REFUSE;
	atomic_fetch_add(&f->target_seen[record->conn.client][record->direction], 1u);
	if (record->conn.route == NFSP_ROUTE_NLM)
		atomic_fetch_add(&f->target_nlm_seen, 1u);
	return NFSP_RELAY_FORWARD;
}

static int fixture_up_routes(struct fixture *f, int dead, int rendezvous,
			     unsigned nrecords, int nlm)
{
	struct sockaddr_in sa = {0};
	socklen_t len = sizeof(sa);
	memset(f, 0, sizeof(*f));
	f->dead_fd = -1;
	f->rendezvous = rendezvous;
	pthread_mutex_init(&f->mutex, NULL);
	pthread_cond_init(&f->cond, NULL);
	pthread_mutex_init(&f->rendezvous_mutex, NULL);
	pthread_cond_init(&f->rendezvous_cond, NULL);
	if (start_fake(f, 0, nrecords) != 0 || start_fake(f, 1, nrecords) != 0)
		return -1;
	f->cfg.client_ip[0] = fixture_client_ip[0];
	f->cfg.client_ip[1] = fixture_client_ip[1];
	f->cfg.route[0] = (struct nfsp_route){fixture_listen_ip[0], 0, "127.0.0.1", f->fake[0].port};
	f->cfg.route[1] = (struct nfsp_route){fixture_listen_ip[1], 0, "127.0.0.1", f->fake[1].port};
	if (nlm)
		f->cfg.nlm_route = (struct nfsp_route){fixture_listen_ip[0], 0,
						"127.0.0.1", f->fake[0].port};
	if (nlm)
		f->cfg.nlm_preserve_client_ip = 1;
	if (dead) {
		f->dead_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (f->dead_fd < 0) return -1;
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(f->dead_fd, (struct sockaddr *)&sa, len) != 0 ||
		    getsockname(f->dead_fd, (struct sockaddr *)&sa, &len) != 0)
			return -1;
		f->cfg.route[1].backend_port = ntohs(sa.sin_port);
	}
	f->cfg.stop = &f->stop;
	/* Deliberately smaller than three coalesced six-byte records: the
	 * relay must drain one record at a time, not misclassify a valid read as
	 * exceeding its per-record memory budget. */
	f->cfg.msg_limit = 8;
	f->cfg.connect_timeout_ms = 250;
	f->cfg.on_record = mutate;
	f->cfg.on_record_arg = f;
	if (nlm) {
		f->cfg.on_relay = target_passthrough;
		f->cfg.relay_arg = f;
	}
	f->cfg.on_connection = log_conn;
	f->cfg.on_connection_arg = &f->conns;
	if (pthread_create(&f->proxy_thread, NULL, run_proxy, f) != 0) return -1;
	pthread_mutex_lock(&f->mutex);
	while (!f->ready && !f->done)
		pthread_cond_wait(&f->cond, &f->mutex);
	if (f->ready && !f->done) {
		f->port[0] = f->stats.bound_port[0];
		f->port[1] = f->stats.bound_port[1];
	}
	pthread_mutex_unlock(&f->mutex);
	return f->ready && f->port[0] && f->port[1] &&
		(!nlm || f->stats.nlm_bound_port) ? 0 : -1;
}

static int fixture_up(struct fixture *f, int dead, int rendezvous, unsigned nrecords)
{
	return fixture_up_routes(f, dead, rendezvous, nrecords, 0);
}

static void fixture_down(struct fixture *f)
{
	atomic_store(&f->stop, 1);
	pthread_join(f->proxy_thread, NULL);
	for (unsigned b = 0; b < 2; b++) {
		struct fake *be = &f->fake[b];
		atomic_store(&be->stop, 1);
		pthread_join(be->thread, NULL);
		for (unsigned i = 0; i < be->nworkers; i++) pthread_join(be->workers[i], NULL);
		close(be->listener);
	}
	if (f->dead_fd >= 0) close(f->dead_fd);
	pthread_mutex_destroy(&f->mutex);
	pthread_cond_destroy(&f->cond);
	pthread_mutex_destroy(&f->rendezvous_mutex);
	pthread_cond_destroy(&f->rendezvous_cond);
}

static int client_socket(struct fixture *f, unsigned client, unsigned backend)
{
	struct sockaddr_in src = {0}, dst = {0};
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	timeout_socket(fd);
	src.sin_family = dst.sin_family = AF_INET;
	if (inet_pton(AF_INET, f->cfg.client_ip[client], &src.sin_addr) != 1) goto fail;
	if (inet_pton(AF_INET, f->cfg.route[backend].listen_ip, &dst.sin_addr) != 1)
		goto fail;
	dst.sin_port = htons(f->port[backend]);
	if (bind(fd, (struct sockaddr *)&src, sizeof(src)) != 0 ||
	    connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) goto fail;
	return fd;
fail:
	close(fd);
	return -1;
}

static int nlm_client_socket(struct fixture *f, unsigned client)
{
	struct sockaddr_in src = {0}, dst = {0};
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	timeout_socket(fd);
	src.sin_family = dst.sin_family = AF_INET;
	if (inet_pton(AF_INET, f->cfg.client_ip[client], &src.sin_addr) != 1 ||
	    inet_pton(AF_INET, f->cfg.nlm_route.listen_ip, &dst.sin_addr) != 1)
		goto fail;
	dst.sin_port = htons(f->stats.nlm_bound_port);
	if (bind(fd, (struct sockaddr *)&src, sizeof(src)) != 0 ||
	    connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) goto fail;
	return fd;
fail:
	close(fd);
	return -1;
}

static int request(int fd, unsigned client, unsigned backend, unsigned serial)
{
	uint8_t msg[6];
	stamp(msg, 2);
	msg[4] = (uint8_t)((client << 4) | serial);
	msg[5] = (uint8_t)('0' + backend);
	return send(fd, msg, sizeof(msg), MSG_NOSIGNAL) == (ssize_t)sizeof(msg) ? 0 : -1;
}

static int reply(int fd, unsigned client, unsigned backend, unsigned serial)
{
	uint8_t msg[6];
	if (exact(fd, msg, sizeof(msg)) != 0) return -1;
	if (memcmp(msg, "\x80\0\0\2", 4) != 0 || msg[5] != (uint8_t)('0' + backend))
		return -1;
	if (client == 1u && backend == 1u) return msg[4] == 0xee ? 0 : -1;
	if (client == 0u && backend == 1u) return msg[4] == 0x09 ? 0 : -1;
	return msg[4] == (uint8_t)((client << 4) | serial) ? 0 : -1;
}

static void test_four(void)
{
	struct fixture f;
	int fd[2][2] = {{-1,-1},{-1,-1}};
	printf("four client/backend tuples, all at the backend before any reply\n");
	if (fixture_up(&f, 0, 1, 1) != 0) { CHECK(0,"fixture setup"); return; }
	for (unsigned c = 0; c < 2; c++) for (unsigned b = 0; b < 2; b++) {
		fd[c][b] = client_socket(&f, c, b);
		CHECK(fd[c][b] >= 0, "client%u backend%u connect", c, b);
		if (fd[c][b] >= 0)
			CHECK(request(fd[c][b], c, b, 1) == 0, "client%u backend%u send", c, b);
	}
	for (unsigned c = 0; c < 2; c++) for (unsigned b = 0; b < 2; b++) {
		if (fd[c][b] < 0) continue;
		CHECK(reply(fd[c][b], c, b, 1) == 0, "wrong response for (%u,%u)", c, b);
		close(fd[c][b]);
	}
	fixture_down(&f);
	CHECK(f.arrived == 4, "fake backend observed %u/4 overlapping requests", f.arrived);
	CHECK(f.stats.peak_active >= 4, "only %u proxy connections overlapped", f.stats.peak_active);
	for (unsigned c = 0; c < 2; c++) for (unsigned b = 0; b < 2; b++) {
		CHECK(f.stats.connected[c][b] == 1 && f.stats.records[c][b][0] == 1 &&
		      f.stats.records[c][b][1] == 1 &&
		      atomic_load(&f.fake[b].received[c]) == 1,
		      "tuple (%u,%u) was not served exactly once", c, b);
	}
	CHECK(atomic_load(&f.mutations) == 2, "one C2S and one S2C should mutate, got %u",
	      atomic_load(&f.mutations));
	{
		unsigned n = atomic_load(&f.conns.nev), opened = 0;
		for (unsigned i = 0; i < n; i++) {
			if (f.conns.ev[i].event != NFSP_CONN_OPENED) continue;
			opened++;
			for (unsigned j = 0; j < i; j++)
				CHECK(f.conns.ev[j].event != NFSP_CONN_OPENED ||
				      f.conns.ev[j].ref.connection_id !=
				      f.conns.ev[i].ref.connection_id,
				      "two concurrent connections share id %llu",
				      (unsigned long long)f.conns.ev[i].ref.connection_id);
		}
		CHECK(opened == 4 && atomic_load(&f.conns.nclosed) == 4,
		      "ConnectionRef events opened=%u closed=%u, want 4/4", opened,
		      atomic_load(&f.conns.nclosed));
	}
	CHECK(f.stats.relay_errors == 0 && f.stats.framing_errors == 0,
	      "unexpected relay/framing error: %u/%u",
	      f.stats.relay_errors, f.stats.framing_errors);
}

static void test_nlm_route_shares_identity(void)
{
	struct fixture f;
	int nfs, nlm;
	unsigned opened = 0;
	uint64_t ids[2] = {0, 0};
	printf("optional NLM route shares the NFS relay identity domain\n");
	if (fixture_up_routes(&f, 0, 0, 2, 1) != 0) {
		CHECK(0, "NLM fixture setup"); return;
	}
	nfs = client_socket(&f, 0, 0);
	nlm = nlm_client_socket(&f, 1);
	CHECK(nfs >= 0 && nlm >= 0, "NFS and NLM routes connect");
	if (nfs >= 0) {
		CHECK(request(nfs, 0, 0, 1) == 0 && reply(nfs, 0, 0, 1) == 0,
		      "NFS route relays");
		close(nfs);
	}
	if (nlm >= 0) {
		CHECK(request(nlm, 1, 0, 2) == 0 && reply(nlm, 1, 0, 2) == 0,
		      "NLM route relays through knfsd backend");
		close(nlm);
	}
	fixture_down(&f);
	for (unsigned i = 0; i < atomic_load(&f.conns.nev); i++) {
		const struct conn_event *event = &f.conns.ev[i];
		if (event->event != NFSP_CONN_OPENED) continue;
		if (opened < 2) ids[opened] = event->ref.connection_id;
		CHECK(event->ref.backend == 0, "NLM must retain knfsd backend identity");
		CHECK(event->ref.route == (event->ref.client == 1 ?
		      NFSP_ROUTE_NLM : NFSP_ROUTE_NFS),
		      "connection has wrong transport route");
		opened++;
	}
	CHECK(opened == 2 && ids[0] != 0 && ids[1] != 0 && ids[0] != ids[1],
	      "connections do not share or reuse an identity");
	CHECK(atomic_load(&f.conns.nclosed) == 2, "both connections close once");
	CHECK(atomic_load(&f.target_nlm_seen) == 2,
	      "NLM call and reply retain transport route");
	CHECK(f.stats.accepted[0][0] == 1 && f.stats.accepted[1][0] == 1 &&
	      atomic_load(&f.fake[0].received[0]) == 1 &&
	      atomic_load(&f.fake[0].received[1]) == 1,
	      "both routes reach the same knfsd backend");
	struct in_addr nlm_source;
	CHECK(inet_pton(AF_INET, fixture_client_ip[1], &nlm_source) == 1,
	      "fixture NLM client address parses");
	CHECK(atomic_load(&f.fake[0].peer_addr[1]) == nlm_source.s_addr,
	      "NLM backend must see the original client IP");
	for (unsigned c = 0; c < 2; c++)
		for (unsigned d = 0; d < 2; d++)
			CHECK(atomic_load(&f.target_seen[c][d]) == 1,
			      "target hook missed route client=%u direction=%u", c, d);
	CHECK(f.stats.relay_errors == 0 && f.stats.framing_errors == 0,
	      "NLM route introduced a relay error");
}

static void test_dead(void)
{
	struct fixture f;
	int healthy, broken;
	uint8_t byte;
	printf("dead backend cannot block or substitute a healthy backend\n");
	if (fixture_up(&f, 1, 0, 1) != 0) { CHECK(0,"fixture setup"); return; }
	broken = client_socket(&f, 1, 1);
	healthy = client_socket(&f, 0, 0);
	CHECK(broken >= 0 && healthy >= 0, "both clients can reach the proxy");
	if (healthy >= 0) {
		CHECK(request(healthy, 0, 0, 2) == 0, "healthy send");
		CHECK(reply(healthy, 0, 0, 2) == 0, "healthy reply stalled by dead route");
		close(healthy);
	}
	if (broken >= 0) {
		CHECK(recv(broken, &byte, 1, 0) <= 0, "dead route returned traffic");
		close(broken);
	}
	fixture_down(&f);
	CHECK(f.stats.connect_failed[1][1] == 1 && f.stats.connected[1][1] == 0,
	      "dead backend was not refused distinctly");
	CHECK(atomic_load(&f.fake[1].accepted) == 0 &&
	      atomic_load(&f.fake[0].received[0]) == 1,
	      "dead backend was substituted or healthy backend stalled");
}

static void test_three_coalesced_and_split(void)
{
	struct fixture f;
	int fd;
	uint8_t messages[18];
	printf("coalesced records and a split header share a single connection\n");
	if (fixture_up(&f, 0, 0, 3) != 0) { CHECK(0,"fixture setup"); return; }
	fd = client_socket(&f, 0, 0);
	CHECK(fd >= 0, "connect");
	if (fd >= 0) {
		for (unsigned i = 0; i < 3; i++) {
			stamp(messages + i*6u, 2);
			messages[i*6u + 4u] = (uint8_t)i;
			messages[i*6u + 5u] = '0';
		}
		CHECK(send(fd, messages, 2, MSG_NOSIGNAL) == 2, "send split header");
		CHECK(send(fd, messages+2, sizeof(messages)-2, MSG_NOSIGNAL) ==
		      (ssize_t)(sizeof(messages)-2), "send coalesced remainder");
		for (unsigned i = 0; i < 3; i++)
			CHECK(reply(fd, 0, 0, i) == 0, "record %u reordered or lost", i);
		close(fd);
	}
	fixture_down(&f);
	CHECK(f.stats.records[0][0][0] == 3 && f.stats.records[0][0][1] == 3,
	      "record counts c2s=%u s2c=%u", f.stats.records[0][0][0],
	      f.stats.records[0][0][1]);
	CHECK(f.stats.delivered[0][0][0] == 3 && f.stats.delivered[0][0][1] == 3,
	      "queues did not drain all three records");
}

static void watchdog(int sig)
{
	ssize_t ignored;
	(void)sig;
	ignored = write(2, "proxy test watchdog\n", 20);
	(void)ignored;
	_exit(97);
}

/* ---- variable-length forwarding -----------------------------------------
 *
 * The callback may return a record of a different length than it was given.
 * The risk is not the grown record itself but what follows it: if the relay
 * advanced by the wrong length, or forwarded stale bytes, the NEXT record would
 * arrive misframed.  So the two records are sent coalesced in one write and the
 * backend must see the grown first record, then the second one intact. */

struct raw_backend {
	int listener;
	uint16_t port;
	uint8_t got[256];
	size_t got_len;
	size_t want;		/* bytes to wait for; zero means 16 */
	pthread_t thread;
};

static void *raw_backend_main(void *arg)
{
	struct raw_backend *b = arg;
	int fd = accept(b->listener, NULL, NULL);
	if (fd < 0) return NULL;
	timeout_socket(fd);
	for (;;) {
		ssize_t n = recv(fd, b->got + b->got_len, sizeof(b->got) - b->got_len, 0);
		if (n <= 0) break;
		b->got_len += (size_t)n;
		if (b->got_len >= (b->want ? b->want : 16u)) break;	/* default: 10 grown + 6 intact */
	}
	close(fd);
	return NULL;
}

/* Grow the first C2S record from client 0 by four bytes and rebuild its marker;
 * leave every other record alone (fwd stays the original). */
static int grow_first(unsigned client, unsigned backend, int dir,
		      const uint8_t *msg, size_t len, const uint8_t **out,
		      size_t *out_len, void *arg)
{
	static uint8_t grown[10];
	_Atomic unsigned *seen = arg;
	(void)backend;
	if (client != 0u || dir != NFSP_DIR_C2S) return 0;
	if (atomic_fetch_add(seen, 1u) != 0u) return 0;
	if (len != 6u) return -1;
	memcpy(grown, msg, 6);
	memset(grown + 6, 0xAB, 4);
	stamp(grown, 6);		/* marker now covers the 6 body bytes */
	*out = grown;
	*out_len = sizeof(grown);
	return 0;
}

static void test_resize_keeps_stream_in_sync(void)
{
	struct raw_backend rb = {0};
	struct nfsp_proxy_cfg cfg = {0};
	struct nfsp_proxy_stats stats;
	struct fixture f;		/* only for the proxy thread plumbing */
	struct sockaddr_in sa = {0};
	socklen_t slen = sizeof(sa);
	_Atomic unsigned seen = 0;
	uint8_t two[12];
	int fd;

	printf("a grown record keeps the next coalesced record framed\n");
	memset(&f, 0, sizeof(f));
	pthread_mutex_init(&f.mutex, NULL);
	pthread_cond_init(&f.cond, NULL);

	rb.listener = socket(AF_INET, SOCK_STREAM, 0);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK(rb.listener >= 0 && bind(rb.listener, (struct sockaddr *)&sa, slen) == 0 &&
	      listen(rb.listener, 4) == 0 &&
	      getsockname(rb.listener, (struct sockaddr *)&sa, &slen) == 0,
	      "raw backend setup");
	rb.port = ntohs(sa.sin_port);
	CHECK(pthread_create(&rb.thread, NULL, raw_backend_main, &rb) == 0, "backend thread");

	cfg.client_ip[0] = fixture_client_ip[0];
	cfg.client_ip[1] = fixture_client_ip[1];
	cfg.route[0] = (struct nfsp_route){fixture_listen_ip[0], 0, "127.0.0.1", rb.port};
	cfg.route[1] = (struct nfsp_route){fixture_listen_ip[1], 0, "127.0.0.1", rb.port};
	cfg.stop = &f.stop;
	cfg.msg_limit = 64;
	cfg.connect_timeout_ms = 500;
	cfg.on_record = grow_first;
	cfg.on_record_arg = &seen;
	f.cfg = cfg;
	CHECK(pthread_create(&f.proxy_thread, NULL, run_proxy, &f) == 0, "proxy thread");
	pthread_mutex_lock(&f.mutex);
	while (!f.ready && !f.done) pthread_cond_wait(&f.cond, &f.mutex);
	if (f.ready && !f.done) { f.port[0] = f.stats.bound_port[0]; f.port[1] = f.stats.bound_port[1]; }
	pthread_mutex_unlock(&f.mutex);
	CHECK(f.ready && f.port[0] != 0, "proxy ready");

	fd = f.port[0] ? client_socket(&f, 0, 0) : -1;
	CHECK(fd >= 0, "client connect");
	if (fd >= 0) {
		/* two 6-byte records, one TCP write */
		stamp(two, 2); two[4] = 0x11; two[5] = 0x22;
		stamp(two + 6, 2); two[10] = 0x33; two[11] = 0x44;
		CHECK(send(fd, two, sizeof(two), MSG_NOSIGNAL) == (ssize_t)sizeof(two), "send");
	}
	pthread_join(rb.thread, NULL);
	if (fd >= 0) close(fd);
	atomic_store(&f.stop, 1);
	pthread_join(f.proxy_thread, NULL);
	stats = f.stats;
	close(rb.listener);
	pthread_mutex_destroy(&f.mutex);
	pthread_cond_destroy(&f.cond);

	CHECK(rb.got_len == 16u, "backend received %zu bytes, want 16", rb.got_len);
	if (rb.got_len == 16u) {
		/* record 1: marker for 6 body bytes, original body, four 0xAB */
		CHECK(memcmp(rb.got, "\x80\0\0\6", 4) == 0, "grown marker wrong");
		CHECK(rb.got[4] == 0x11 && rb.got[5] == 0x22, "grown body wrong");
		CHECK(rb.got[6] == 0xAB && rb.got[9] == 0xAB, "appended bytes wrong");
		/* record 2 begins exactly at offset 10 and is untouched */
		CHECK(memcmp(rb.got + 10, "\x80\0\0\2", 4) == 0, "next record misframed");
		CHECK(rb.got[14] == 0x33 && rb.got[15] == 0x44, "next record body wrong");
	}
	CHECK(stats.records[0][0][0] == 2u, "records counted %u, want 2", stats.records[0][0][0]);
	CHECK(stats.mutation_errors == 0u && stats.framing_errors == 0u && stats.relay_errors == 0u,
	      "unexpected errors m=%u f=%u r=%u", stats.mutation_errors,
	      stats.framing_errors, stats.relay_errors);
}

static int bad_output(unsigned client, unsigned backend, int dir,
		      const uint8_t *msg, size_t len, const uint8_t **out,
		      size_t *out_len, void *arg)
{
	(void)client; (void)backend; (void)dir; (void)msg; (void)len; (void)arg;
	*out = msg;
	*out_len = 2;		/* shorter than a record marker */
	return 0;
}

/* A callback that returns something the peer could not frame must close the
 * connection as a mutation error, never forward it. */
static void test_unframeable_output_refused(void)
{
	struct raw_backend rb = {0};
	struct fixture f;
	struct sockaddr_in sa = {0};
	socklen_t slen = sizeof(sa);
	uint8_t one[6];
	int fd;

	printf("an unframeable rewritten record is refused, not forwarded\n");
	memset(&f, 0, sizeof(f));
	pthread_mutex_init(&f.mutex, NULL);
	pthread_cond_init(&f.cond, NULL);
	rb.listener = socket(AF_INET, SOCK_STREAM, 0);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK(rb.listener >= 0 && bind(rb.listener, (struct sockaddr *)&sa, slen) == 0 &&
	      listen(rb.listener, 4) == 0 &&
	      getsockname(rb.listener, (struct sockaddr *)&sa, &slen) == 0,
	      "raw backend setup");
	rb.port = ntohs(sa.sin_port);
	CHECK(pthread_create(&rb.thread, NULL, raw_backend_main, &rb) == 0, "backend thread");
	f.cfg.client_ip[0] = fixture_client_ip[0];
	f.cfg.client_ip[1] = fixture_client_ip[1];
	f.cfg.route[0] = (struct nfsp_route){fixture_listen_ip[0], 0, "127.0.0.1", rb.port};
	f.cfg.route[1] = (struct nfsp_route){fixture_listen_ip[1], 0, "127.0.0.1", rb.port};
	f.cfg.stop = &f.stop;
	f.cfg.msg_limit = 64;
	f.cfg.connect_timeout_ms = 500;
	f.cfg.on_record = bad_output;
	CHECK(pthread_create(&f.proxy_thread, NULL, run_proxy, &f) == 0, "proxy thread");
	pthread_mutex_lock(&f.mutex);
	while (!f.ready && !f.done) pthread_cond_wait(&f.cond, &f.mutex);
	if (f.ready && !f.done) { f.port[0] = f.stats.bound_port[0]; f.port[1] = f.stats.bound_port[1]; }
	pthread_mutex_unlock(&f.mutex);
	fd = f.port[0] ? client_socket(&f, 0, 0) : -1;
	CHECK(fd >= 0, "client connect");
	if (fd >= 0) {
		stamp(one, 2); one[4] = 1; one[5] = 2;
		CHECK(send(fd, one, sizeof(one), MSG_NOSIGNAL) == (ssize_t)sizeof(one), "send");
		/* the proxy must close the connection; the backend sees nothing */
		{
			uint8_t sink;
			ssize_t n = recv(fd, &sink, 1, 0);
			CHECK(n == 0 || n < 0, "connection should be closed, recv=%zd", n);
		}
		close(fd);
	}
	atomic_store(&f.stop, 1);
	pthread_join(f.proxy_thread, NULL);
	shutdown(rb.listener, SHUT_RDWR);
	close(rb.listener);
	pthread_join(rb.thread, NULL);
	CHECK(rb.got_len == 0u, "backend received %zu bytes of an unframeable record", rb.got_len);
	CHECK(f.stats.mutation_errors == 1u, "mutation_errors=%u, want 1", f.stats.mutation_errors);
	pthread_mutex_destroy(&f.mutex);
	pthread_cond_destroy(&f.cond);
}

/* ---- ConnectionRef and the canonical RpcRecord (M1) ----------------------
 *
 * The Transaction Context keys on connection_id, so an id that came back
 * after a reconnect would let a late REPLY find an old connection's CALL. */

static int wait_closed(struct conn_log *l, unsigned want)
{
	struct timespec ts = {0, 5 * 1000 * 1000};
	for (unsigned i = 0; i < 400u; i++) {
		if (atomic_load(&l->nclosed) >= want) return 0;
		nanosleep(&ts, NULL);
	}
	return -1;
}

/* A configuration refused before any listener exists opens nothing, so it
 * must report no lifecycle events at all. */
static void test_refused_config_reports_no_connections(void)
{
	struct nfsp_proxy_cfg cfg = {0};
	struct nfsp_proxy_stats stats;
	struct conn_log log;
	_Atomic int stop = 0;
	int rc;
	printf("a refused configuration emits no connection events\n");
	memset(&log, 0, sizeof(log));
	cfg.client_ip[0] = fixture_client_ip[0];
	cfg.client_ip[1] = fixture_client_ip[1];
	cfg.route[0] = (struct nfsp_route){fixture_listen_ip[0], 0, "127.0.0.1", 1};
	cfg.route[1] = (struct nfsp_route){fixture_listen_ip[1], 0, "127.0.0.1", 1};
	cfg.stop = &stop;
	cfg.msg_limit = 1;	/* below one record marker: refused */
	cfg.on_connection = log_conn;
	cfg.on_connection_arg = &log;
	rc = nfsp_proxy_run(&cfg, &stats, NULL, NULL);
	CHECK(rc == -1, "msg_limit=1 must be refused, rc=%d", rc);
	CHECK(atomic_load(&log.nev) == 0,
	      "%u lifecycle events for a run that opened nothing",
	      atomic_load(&log.nev));
}

static void test_connection_id_not_reused(void)
{
	struct fixture f;
	uint64_t ids[3] = {0, 0, 0};
	unsigned n;
	printf("a reconnect on a reused slot gets a new connection_id\n");
	if (fixture_up(&f, 0, 0, 1) != 0) { CHECK(0, "fixture setup"); return; }
	for (unsigned i = 0; i < 3; i++) {
		int fd = client_socket(&f, 0, 0);
		CHECK(fd >= 0, "connect %u", i);
		if (fd < 0) break;
		CHECK(request(fd, 0, 0, i) == 0 && reply(fd, 0, 0, i) == 0,
		      "round trip %u", i);
		close(fd);
		/* Wait for the proxy to free the slot before reconnecting, so
		 * the next accept takes the same conns[] slot, the first free
		 * one. */
		CHECK(wait_closed(&f.conns, i + 1u) == 0, "connection %u never closed", i);
	}
	fixture_down(&f);
	n = atomic_load(&f.conns.nev);
	CHECK(n == 6, "%u lifecycle events, want 6", n);
	for (unsigned i = 0; i < 3 && 2u * i + 1u < n; i++) {
		const struct conn_event *o = &f.conns.ev[2u * i];
		const struct conn_event *c = &f.conns.ev[2u * i + 1u];
		CHECK(o->event == NFSP_CONN_OPENED && c->event == NFSP_CONN_CLOSED,
		      "connection %u: events must be opened then closed", i);
		CHECK(o->ref.connection_id == c->ref.connection_id &&
		      o->ref.client == 0 && o->ref.backend == 0,
		      "connection %u: close names a different ConnectionRef", i);
		ids[i] = o->ref.connection_id;
	}
	CHECK(ids[0] != 0 && ids[0] < ids[1] && ids[1] < ids[2],
	      "ids %llu %llu %llu must be nonzero and strictly increasing",
	      (unsigned long long)ids[0], (unsigned long long)ids[1],
	      (unsigned long long)ids[2]);
}

struct observed {
	unsigned n;
	struct {
		uint64_t connection_id;
		unsigned client, backend;
		int dir;
		uint32_t nfrags, xid;
		size_t len;
		enum nfsp_rpc_status st;
		uint8_t payload[64];
	} rec[4];
	int refuse;
};

static int observe_record(const struct nfsp_rpc_record *r, void *arg)
{
	struct observed *o = arg;
	struct nfsp_rpc_envelope e;
	if (o->refuse) return -1;
	if (o->n < 4u) {
		o->rec[o->n].connection_id = r->conn.connection_id;
		o->rec[o->n].client = r->conn.client;
		o->rec[o->n].backend = r->conn.backend;
		o->rec[o->n].dir = r->direction;
		o->rec[o->n].nfrags = r->nfrags;
		o->rec[o->n].len = r->rpc_payload_len;
		o->rec[o->n].st = nfsp_rpc_decode(r->rpc_payload, r->rpc_payload_len, &e);
		o->rec[o->n].xid = e.xid;
		memcpy(o->rec[o->n].payload, r->rpc_payload,
		       r->rpc_payload_len < 64u ? r->rpc_payload_len : 64u);
		o->n++;
	}
	return 0;
}

/* A 40-byte NFSv4 COMPOUND CALL envelope with AUTH_NONE cred and verifier. */
static void rpc_call(uint8_t *p, uint32_t xid)
{
	const uint32_t w[10] = {xid, 0, 2, 100003, 4, 1, 0, 0, 0, 0};
	for (unsigned i = 0; i < 10; i++) {
		uint32_t be = htonl(w[i]);
		memcpy(p + 4u * i, &be, 4);
	}
}

struct holder;
static void holder_install(struct nfsp_proxy_cfg *cfg, struct holder *h);

/* One raw backend behind both routes, observed by observe_record, or by the
 * target-mode relay hooks of `h` when it is not NULL. */
static int raw_proxy_up(struct fixture *f, struct raw_backend *rb, struct observed *o,
			struct holder *h)
{
	struct sockaddr_in sa = {0};
	socklen_t slen = sizeof(sa);
	memset(f, 0, sizeof(*f));
	pthread_mutex_init(&f->mutex, NULL);
	pthread_cond_init(&f->cond, NULL);
	rb->listener = socket(AF_INET, SOCK_STREAM, 0);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (rb->listener < 0 || bind(rb->listener, (struct sockaddr *)&sa, slen) != 0 ||
	    listen(rb->listener, 4) != 0 ||
	    getsockname(rb->listener, (struct sockaddr *)&sa, &slen) != 0)
		return -1;
	rb->port = ntohs(sa.sin_port);
	if (pthread_create(&rb->thread, NULL, raw_backend_main, rb) != 0) return -1;
	f->cfg.client_ip[0] = fixture_client_ip[0];
	f->cfg.client_ip[1] = fixture_client_ip[1];
	f->cfg.route[0] = (struct nfsp_route){fixture_listen_ip[0], 0, "127.0.0.1", rb->port};
	f->cfg.route[1] = (struct nfsp_route){fixture_listen_ip[1], 0, "127.0.0.1", rb->port};
	f->cfg.stop = &f->stop;
	f->cfg.msg_limit = 128;
	f->cfg.connect_timeout_ms = 500;
	f->cfg.on_rpc_record = observe_record;
	f->cfg.on_rpc_record_arg = o;
	if (h != NULL)
		holder_install(&f->cfg, h);
	f->cfg.on_connection = log_conn;
	f->cfg.on_connection_arg = &f->conns;
	if (pthread_create(&f->proxy_thread, NULL, run_proxy, f) != 0) return -1;
	pthread_mutex_lock(&f->mutex);
	while (!f->ready && !f->done) pthread_cond_wait(&f->cond, &f->mutex);
	if (f->ready && !f->done) f->port[0] = f->stats.bound_port[0];
	pthread_mutex_unlock(&f->mutex);
	return f->port[0] ? 0 : -1;
}

/* Stop the proxy first, so the backend's accept or recv ends, then join it. */
static void raw_proxy_down(struct fixture *f, struct raw_backend *rb)
{
	atomic_store(&f->stop, 1);
	pthread_join(f->proxy_thread, NULL);
	shutdown(rb->listener, SHUT_RDWR);
	close(rb->listener);
	pthread_join(rb->thread, NULL);
	pthread_mutex_destroy(&f->mutex);
	pthread_cond_destroy(&f->cond);
}

/* A three-fragment CALL and a one-fragment CALL in one write: the observer
 * must see two marker-free 40-byte payloads under the connection's id, and
 * the backend must still receive the original bytes, markers and all. */
static void test_rpc_record_observer(void)
{
	struct raw_backend rb = {0};
	struct fixture f;
	struct observed o = {0};
	const size_t cut[3] = {16, 16, 8};
	uint8_t call_a[40], call_b[40], wire[96];
	size_t off = 0, src = 0;
	int fd;

	printf("the observer gets canonical payloads; the wire stays byte-identical\n");
	rpc_call(call_a, 0xa1a2a3a4u);
	rpc_call(call_b, 0xb1b2b3b4u);
	for (unsigned i = 0; i < 3; i++) {
		uint32_t h = htonl((uint32_t)cut[i] | (i == 2 ? 0x80000000u : 0u));
		memcpy(wire + off, &h, 4);
		memcpy(wire + off + 4, call_a + src, cut[i]);
		off += 4 + cut[i];
		src += cut[i];
	}
	stamp(wire + off, 40);
	memcpy(wire + off + 4, call_b, 40);
	off += 44;
	rb.want = off;

	if (raw_proxy_up(&f, &rb, &o, NULL) != 0) { CHECK(0, "proxy setup"); return; }
	fd = client_socket(&f, 1, 0);
	CHECK(fd >= 0, "client connect");
	if (fd >= 0)
		CHECK(send(fd, wire, off, MSG_NOSIGNAL) == (ssize_t)off, "send");
	/* The backend returns once it has `want` bytes (or times out), and only
	 * then is the proxy stopped, so a stop cannot race the relay. */
	pthread_join(rb.thread, NULL);
	if (fd >= 0) close(fd);
	atomic_store(&f.stop, 1);
	pthread_join(f.proxy_thread, NULL);
	close(rb.listener);
	pthread_mutex_destroy(&f.mutex);
	pthread_cond_destroy(&f.cond);

	CHECK(rb.got_len == off && memcmp(rb.got, wire, off) == 0,
	      "backend got %zu/%zu bytes or different bytes", rb.got_len, off);
	CHECK(o.n == 2, "observer saw %u records, want 2", o.n);
	CHECK(atomic_load(&f.conns.nev) >= 1 &&
	      f.conns.ev[0].event == NFSP_CONN_OPENED, "no opened event");
	for (unsigned i = 0; i < o.n && i < 2; i++) {
		const uint8_t *want = i == 0 ? call_a : call_b;
		CHECK(o.rec[i].len == 40 && memcmp(o.rec[i].payload, want, 40) == 0,
		      "record %u payload is not the marker-free CALL", i);
		CHECK(o.rec[i].nfrags == (i == 0 ? 3u : 1u), "record %u nfrags %u",
		      i, o.rec[i].nfrags);
		CHECK(o.rec[i].st == NFSP_RPC_OK &&
		      o.rec[i].xid == (i == 0 ? 0xa1a2a3a4u : 0xb1b2b3b4u),
		      "record %u: %s xid %08x", i, nfsp_rpc_strerror(o.rec[i].st),
		      o.rec[i].xid);
		CHECK(o.rec[i].connection_id == f.conns.ev[0].ref.connection_id &&
		      o.rec[i].client == 1 && o.rec[i].backend == 0 &&
		      o.rec[i].dir == NFSP_DIR_C2S,
		      "record %u carries the wrong ConnectionRef or direction", i);
	}
	CHECK(f.stats.record_refused == 0 && f.stats.framing_errors == 0,
	      "unexpected refused=%u framing=%u", f.stats.record_refused,
	      f.stats.framing_errors);
}

/* An observer refusal closes the connection and forwards nothing. */
static void test_rpc_record_refusal(void)
{
	struct raw_backend rb = {0};
	struct fixture f;
	struct observed o = {0};
	uint8_t wire[44];
	int fd;

	printf("a refused record is not forwarded and closes the connection\n");
	o.refuse = 1;
	stamp(wire, 40);
	rpc_call(wire + 4, 1);
	if (raw_proxy_up(&f, &rb, &o, NULL) != 0) { CHECK(0, "proxy setup"); return; }
	fd = client_socket(&f, 0, 0);
	CHECK(fd >= 0, "client connect");
	if (fd >= 0) {
		uint8_t sink;
		ssize_t n;
		CHECK(send(fd, wire, sizeof(wire), MSG_NOSIGNAL) == (ssize_t)sizeof(wire),
		      "send");
		n = recv(fd, &sink, 1, 0);
		CHECK(n <= 0, "connection should be closed, recv=%zd", n);
		close(fd);
	}
	raw_proxy_down(&f, &rb);
	CHECK(rb.got_len == 0, "backend received %zu bytes of a refused record",
	      rb.got_len);
	CHECK(f.stats.record_refused == 1 && f.stats.records[0][0][0] == 0,
	      "record_refused=%u records=%u", f.stats.record_refused,
	      f.stats.records[0][0][0]);
	CHECK(atomic_load(&f.conns.nclosed) == 1, "refusal did not close the ConnectionRef");
}


/* Target-mode relay hooks (M5): the first C2S record is held until the test
 * releases it through a descriptor the loop polls, then forwarded changed
 * with a completion token.  The records behind it in the same direction
 * must wait for it, in order, and the peer must see nothing before. */
static void sleep_ms(long ms)
{
	struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

struct holder {
	int pipe[2];
	_Atomic int released;
	_Atomic unsigned relayed, holds_offered, forwarded, complete;
	_Atomic uint64_t completion;
	_Atomic size_t written;
	uint8_t changed[44];
	int drop;		/* second test: refuse on release instead */
	_Atomic unsigned dropped;
};

static int holder_relay(const struct nfsp_rpc_record *r, const uint8_t *framed,
			size_t len, struct nfsp_relay_verdict *v, void *arg)
{
	struct holder *h = arg;
	unsigned n = atomic_fetch_add(&h->relayed, 1u);
	(void)r;
	if (n != 0 || len != sizeof(h->changed))
		return NFSP_RELAY_FORWARD;
	memcpy(h->changed, framed, len);
	h->changed[4] ^= 0xffu;		/* the xid's first byte */
	v->hold = 7;
	return NFSP_RELAY_HOLD;
}

static int holder_hold(uint64_t token, const uint8_t *framed, size_t len,
		       struct nfsp_relay_verdict *v, void *arg)
{
	struct holder *h = arg;
	(void)framed;
	atomic_fetch_add(&h->holds_offered, 1u);
	if (token != 7 || len != sizeof(h->changed))
		return NFSP_RELAY_REFUSE;
	if (!atomic_load(&h->released))
		return NFSP_RELAY_HOLD;
	if (h->drop)
		return NFSP_RELAY_REFUSE;
	v->out = h->changed;
	v->out_len = sizeof(h->changed);
	v->completion = 42;
	return NFSP_RELAY_FORWARD;
}

static void holder_dropped(uint64_t token, void *arg)
{
	struct holder *h = arg;
	if (token == 7)
		atomic_fetch_add(&h->dropped, 1u);
}

static void holder_forwarded(uint64_t completion, int complete, size_t written,
			     size_t len, void *arg)
{
	struct holder *h = arg;
	(void)len;
	atomic_store(&h->completion, completion);
	atomic_store(&h->written, written);
	atomic_fetch_add(&h->forwarded, 1u);
	if (complete)
		atomic_fetch_add(&h->complete, 1u);
}

static size_t holder_fds(struct pollfd *fds, size_t max, void *arg)
{
	struct holder *h = arg;
	if (max == 0)
		return 0;
	fds[0].fd = h->pipe[0];
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	return 1;
}

static void holder_tick(void *arg)
{
	struct holder *h = arg;
	char c;
	if (read(h->pipe[0], &c, 1) == 1)
		atomic_store(&h->released, 1);
}

static void holder_install(struct nfsp_proxy_cfg *cfg, struct holder *h)
{
	cfg->on_rpc_record = NULL;
	cfg->on_relay = holder_relay;
	cfg->on_hold = holder_hold;
	cfg->on_hold_dropped = holder_dropped;
	cfg->on_forwarded = holder_forwarded;
	cfg->poll_fds = holder_fds;
	cfg->relay_arg = h;
	cfg->on_tick = holder_tick;
	cfg->on_tick_arg = h;
}

static void hold_case(int drop)
{
	struct raw_backend rb = {0};
	struct fixture f;
	struct observed o = {0};
	struct holder h;
	uint8_t wire[3 * 44], want[3 * 44];
	int fd;

	printf("a held record blocks its direction until decided (%s)\n",
	       drop ? "refused" : "forwarded changed");
	memset(&h, 0, sizeof(h));
	h.drop = drop;
	if (pipe(h.pipe) != 0) { CHECK(0, "pipe"); return; }
	(void)fcntl(h.pipe[0], F_SETFL, O_NONBLOCK);
	for (unsigned i = 0; i < 3; i++) {
		stamp(wire + 44 * i, 40);
		rpc_call(wire + 44 * i + 4, 0x10u + i);
	}
	rb.want = drop ? 1 : sizeof(wire);
	if (raw_proxy_up(&f, &rb, &o, &h) != 0) { CHECK(0, "proxy setup"); return; }
	fd = client_socket(&f, 0, 0);
	CHECK(fd >= 0, "client connect");
	if (fd >= 0)
		CHECK(send(fd, wire, sizeof(wire), MSG_NOSIGNAL) == (ssize_t)sizeof(wire),
		      "send");
	sleep_ms(200);
	CHECK(rb.got_len == 0, "peer got %zu bytes while the first record was held",
	      rb.got_len);
	CHECK(atomic_load(&h.relayed) == 1, "%u records relayed behind a hold",
	      atomic_load(&h.relayed));
	CHECK(write(h.pipe[1], "x", 1) == 1, "release");
	if (drop && fd >= 0) {
		uint8_t sink;
		CHECK(recv(fd, &sink, 1, 0) <= 0, "a refused hold must close");
	}
	pthread_join(rb.thread, NULL);
	if (fd >= 0) close(fd);
	atomic_store(&f.stop, 1);
	pthread_join(f.proxy_thread, NULL);
	close(rb.listener);
	pthread_mutex_destroy(&f.mutex);
	pthread_cond_destroy(&f.cond);
	close(h.pipe[0]);
	close(h.pipe[1]);

	if (drop) {
		CHECK(rb.got_len == 0, "peer got %zu bytes of a refused hold", rb.got_len);
		CHECK(atomic_load(&h.forwarded) == 0, "completion for nothing sent");
		return;
	}
	memcpy(want, h.changed, 44);
	memcpy(want + 44, wire + 44, 88);
	CHECK(rb.got_len == sizeof(want) && memcmp(rb.got, want, sizeof(want)) == 0,
	      "peer got %zu bytes, or not changed-first-then-in-order", rb.got_len);
	CHECK(atomic_load(&h.relayed) == 3, "relayed %u", atomic_load(&h.relayed));
	CHECK(atomic_load(&h.forwarded) == 1 && atomic_load(&h.complete) == 1 &&
	      atomic_load(&h.completion) == 42 && atomic_load(&h.written) == 44,
	      "completion: forwarded=%u complete=%u token=%llu written=%zu",
	      atomic_load(&h.forwarded), atomic_load(&h.complete),
	      (unsigned long long)atomic_load(&h.completion),
	      atomic_load(&h.written));
	CHECK(atomic_load(&h.dropped) == 0, "a forwarded hold was reported dropped");
}

static void test_relay_hold(void)
{
	hold_case(0);
	hold_case(1);
}

/* A held record whose connection closes is reported dropped, never sent. */
static void test_relay_hold_dropped(void)
{
	struct raw_backend rb = {0};
	struct fixture f;
	struct observed o = {0};
	struct holder h;
	uint8_t wire[44];
	int fd;

	printf("a held record of a closed connection is reported dropped\n");
	memset(&h, 0, sizeof(h));
	if (pipe(h.pipe) != 0) { CHECK(0, "pipe"); return; }
	(void)fcntl(h.pipe[0], F_SETFL, O_NONBLOCK);
	stamp(wire, 40);
	rpc_call(wire + 4, 0x55u);
	rb.want = 1;
	if (raw_proxy_up(&f, &rb, &o, &h) != 0) { CHECK(0, "proxy setup"); return; }
	fd = client_socket(&f, 0, 0);
	CHECK(fd >= 0, "client connect");
	if (fd >= 0) {
		CHECK(send(fd, wire, sizeof(wire), MSG_NOSIGNAL) == (ssize_t)sizeof(wire),
		      "send");
		sleep_ms(100);
		close(fd);
	}
	for (int i = 0; i < 100 && atomic_load(&h.dropped) == 0; i++)
		sleep_ms(10);
	raw_proxy_down(&f, &rb);
	close(h.pipe[0]);
	close(h.pipe[1]);
	CHECK(atomic_load(&h.dropped) == 1, "dropped=%u", atomic_load(&h.dropped));
	CHECK(rb.got_len == 0, "peer got %zu bytes", rb.got_len);
}

/* Exit status: 0 pass, 1 a check failed, 2 usage, 3 the fixture topology does
 * not work on this host (no test was run), 97 the watchdog fired.
 * --simulate-unusable-addresses runs as if the topology did not work. */
int main(int argc, char **argv)
{
	char why[160];
	int simulate = 0;

	if (argc == 2 && strcmp(argv[1], "--simulate-unusable-addresses") == 0) {
		simulate = 1;
	} else if (argc != 1) {
		fprintf(stderr, "usage: %s [--simulate-unusable-addresses]\n",
			argv[0]);
		return 2;
	}
	signal(SIGALRM, watchdog);
	alarm(20);
	/* Before any thread exists.  Otherwise a host without the topology fails
	 * inside a test with backend threads running, and a backend blocked in
	 * accept() leaves a join that only the watchdog ends. */
	if (!fixture_addresses_usable(simulate, why, sizeof(why))) {
		fprintf(stderr, "FAIL: fixture addresses unusable: %s; "
			"no test thread was started\n", why);
		return 3;
	}
	test_four();
	test_nlm_route_shares_identity();
	test_dead();
	test_three_coalesced_and_split();
	test_resize_keeps_stream_in_sync();
	test_unframeable_output_refused();
	test_refused_config_reports_no_connections();
	test_connection_id_not_reused();
	test_rpc_record_observer();
	test_rpc_record_refusal();
	test_relay_hold();
	test_relay_hold_dropped();
	printf("%u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
