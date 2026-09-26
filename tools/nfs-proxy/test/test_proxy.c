#define _POSIX_C_SOURCE 200809L
#include "proxy.h"

#include <arpa/inet.h>
#include <errno.h>
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
};

struct job { struct fake *backend; int fd; };

static void *serve(void *arg)
{
	struct job *job = arg;
	struct fake *b = job->backend;
	struct fixture *f = b->parent;
	int fd = job->fd;
	uint8_t h[4], body[16], reply[6];
	free(job);
	timeout_socket(fd);
	for (unsigned i = 0; i < b->nrecords; i++) {
		uint32_t word;
		unsigned client;
		if (exact(fd, h, 4) != 0) break;
		memcpy(&word, h, 4);
		if (ntohl(word) != 0x80000002u || exact(fd, body, 2) != 0) break;
		client = (unsigned)(body[0] >> 4);
		if (client >= 2 || body[1] != (uint8_t)('0' + b->backend)) break;
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
		  uint8_t *msg, size_t len, void *arg)
{
	struct fixture *f = arg;
	if (backend == 1u &&
	    ((client == 1u && dir == NFSP_DIR_S2C) ||
	     (client == 0u && dir == NFSP_DIR_C2S))) {
		if (len != 6u) return -1;
		msg[4] = dir == NFSP_DIR_S2C ? 0xee : 0x09;
		atomic_fetch_add(&f->mutations, 1u);
	}
	return 0;
}

static int fixture_up(struct fixture *f, int dead, int rendezvous, unsigned nrecords)
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
	f->cfg.client_ip[0] = "127.0.0.10";
	f->cfg.client_ip[1] = "127.0.0.11";
	f->cfg.route[0] = (struct nfsp_route){"127.0.0.2", 0, "127.0.0.1", f->fake[0].port};
	f->cfg.route[1] = (struct nfsp_route){"127.0.0.3", 0, "127.0.0.1", f->fake[1].port};
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
	if (pthread_create(&f->proxy_thread, NULL, run_proxy, f) != 0) return -1;
	pthread_mutex_lock(&f->mutex);
	while (!f->ready && !f->done)
		pthread_cond_wait(&f->cond, &f->mutex);
	if (f->ready && !f->done) {
		f->port[0] = f->stats.bound_port[0];
		f->port[1] = f->stats.bound_port[1];
	}
	pthread_mutex_unlock(&f->mutex);
	return f->ready && f->port[0] && f->port[1] ? 0 : -1;
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
	CHECK(f.stats.relay_errors == 0 && f.stats.framing_errors == 0,
	      "unexpected relay/framing error: %u/%u",
	      f.stats.relay_errors, f.stats.framing_errors);
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

int main(void)
{
	signal(SIGALRM, watchdog);
	alarm(20);
	test_four();
	test_dead();
	test_three_coalesced_and_split();
	printf("%u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
