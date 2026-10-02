#define _POSIX_C_SOURCE 200809L
#include "proxy.h"
#include "framing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NFSP_MAX_CONNS 64u
#define NFSP_READ_CHUNK 16384u
#define NFSP_DEFAULT_CONNECT_MS 2000u

struct queue {
	uint8_t *buf;
	size_t len, off, cap;
	uint32_t pending_records;
};

struct conn {
	int client_fd, backend_fd;
	unsigned client, backend;
	int connecting, connected;
	uint64_t connect_deadline_ms;
	int client_eof, backend_eof, client_wr_closed, backend_wr_closed;
	struct nfsp_framing c2s, s2c;
	struct queue to_backend, to_client;
};

struct state {
	const struct nfsp_proxy_cfg *cfg;
	struct nfsp_proxy_stats *stats;
	struct conn conns[NFSP_MAX_CONNS];
	int listeners[NFSP_BACKENDS];
	struct in_addr clients[NFSP_CLIENTS];
	size_t limit;
};

static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int tcp_nodelay(int fd)
{
	int one = 1;
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static int address(const char *ip, uint16_t port, struct sockaddr_in *out)
{
	if (ip == NULL) return -1;
	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;
	out->sin_port = htons(port);
	return inet_pton(AF_INET, ip, &out->sin_addr) == 1 ? 0 : -1;
}

static int listener(const struct nfsp_route *r, uint16_t *bound)
{
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);
	int fd = -1, one = 1;
	if (address(r->listen_ip, r->listen_port, &sa) != 0) return -1;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
	    bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(fd, 64) != 0 ||
	    getsockname(fd, (struct sockaddr *)&sa, &len) != 0 ||
	    nonblock(fd) != 0) {
		close(fd);
		return -1;
	}
	*bound = ntohs(sa.sin_port);
	return fd;
}

/* A stalled or filtered local backend must not stall the other route. */
static int start_backend(const struct nfsp_route *r, int *connecting)
{
	struct sockaddr_in sa;
	int fd;
	if (address(r->backend_ip, r->backend_port, &sa) != 0) return -1;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	if (nonblock(fd) != 0 || tcp_nodelay(fd) != 0) {
		close(fd);
		return -1;
	}
	if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) == 0) {
		*connecting = 0;
		return fd;
	}
	if (errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	*connecting = 1;
	return fd;
}

static void conn_close(struct state *s, struct conn *c)
{
	if (c->client_fd < 0) return;
	close(c->client_fd);
	if (c->backend_fd >= 0) close(c->backend_fd);
	nfsp_framing_free(&c->c2s);
	nfsp_framing_free(&c->s2c);
	free(c->to_backend.buf);
	free(c->to_client.buf);
	if (c->connected) s->stats->active--;
	c->client_fd = -1;
	c->backend_fd = -1;
}

static int enqueue(struct queue *q, const uint8_t *p, size_t n, size_t max)
{
	uint8_t *grown;
	size_t cap;
	if (q->len > max || n > max - q->len) return -1;
	if (q->len + n > q->cap) {
		cap = q->cap ? q->cap : 4096u;
		while (cap < q->len + n) {
			if (cap > max / 2u) { cap = max; break; }
			cap *= 2u;
		}
		grown = realloc(q->buf, cap);
		if (grown == NULL) return -1;
		q->buf = grown;
		q->cap = cap;
	}
	memcpy(q->buf + q->len, p, n);
	q->len += n;
	q->pending_records++;
	return 0;
}

static int flush(struct state *s, struct conn *c, int dir)
{
	struct queue *q = dir == NFSP_DIR_C2S ? &c->to_backend : &c->to_client;
	int fd = dir == NFSP_DIR_C2S ? c->backend_fd : c->client_fd;
	while (q->off < q->len) {
		ssize_t n = send(fd, q->buf + q->off, q->len - q->off, MSG_NOSIGNAL);
		if (n > 0) { q->off += (size_t)n; continue; }
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
		s->stats->relay_errors++;
		return -1;
	}
	if (q->len != 0) {
		s->stats->delivered[c->client][c->backend][dir] += q->pending_records;
		q->len = q->off = 0;
		q->pending_records = 0;
	}
	return 0;
}

/* Feed at most the framing budget at a time.  A TCP read may contain several
 * complete records, and a previous read may have left an almost-full record.
 * Drain after EACH bounded append instead of treating coalescing as corruption. */
static int feed(struct state *s, struct conn *c, int dir,
		const uint8_t *data, size_t size)
{
	struct nfsp_framing *f = dir == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	struct queue *q = dir == NFSP_DIR_C2S ? &c->to_backend : &c->to_client;
	size_t pos = 0, ceiling = s->limit + NFSP_FRAG_HEADER_LEN;
	while (pos < size) {
		size_t take = size - pos, room;
		if (f->len >= ceiling) goto bad_frame;
		room = ceiling - f->len;
		if (take > room) take = room;
		if (nfsp_framing_append(f, data + pos, take) != 0) goto bad_frame;
		pos += take;
		for (;;) {
			size_t len = 0;
			int rc = nfsp_framing_peek(f, &len, NULL, NULL);
			if (rc < 0) goto bad_frame;
			if (rc == 0) break;
			const uint8_t *fwd = f->buf;
			size_t fwd_len = len;
			/* Default: forward the record exactly as received.  The callback
			 * may redirect to a rebuilt record of a different length; framing
			 * is consumed by the ORIGINAL length either way, since that is
			 * what was read. */
			if (s->cfg->on_record != NULL &&
			    s->cfg->on_record(c->client, c->backend, dir, f->buf, len,
					      &fwd, &fwd_len, s->cfg->on_record_arg) != 0) {
				s->stats->mutation_errors++;
				return -1;
			}
			/* A rebuilt record must still be a whole, in-bounds record.
			 * Anything else would put bytes on the wire the peer cannot
			 * frame, so it is a mutation error and closes only this
			 * connection. */
			if (fwd == NULL || fwd_len < NFSP_FRAG_HEADER_LEN ||
			    fwd_len > ceiling) {
				s->stats->mutation_errors++;
				return -1;
			}
			if (enqueue(q, fwd, fwd_len, ceiling + NFSP_READ_CHUNK) != 0) {
				s->stats->relay_errors++;
				return -1;
			}
			s->stats->records[c->client][c->backend][dir]++;
			nfsp_framing_consume(f, len);
		}
	}
	return 0;
bad_frame:
	s->stats->framing_errors++;
	return -1;
}

static int read_side(struct state *s, struct conn *c, int side)
{
	uint8_t buf[NFSP_READ_CHUNK];
	int fd = side == NFSP_DIR_C2S ? c->client_fd : c->backend_fd;
	struct nfsp_framing *f = side == NFSP_DIR_C2S ? &c->c2s : &c->s2c;
	ssize_t n = recv(fd, buf, sizeof(buf), 0);
	if (n > 0) return feed(s, c, side, buf, (size_t)n);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return 0;
	if (n < 0) { s->stats->relay_errors++; return -1; }
	if (f->len != 0) { s->stats->framing_errors++; return -1; }
	if (side == NFSP_DIR_C2S) c->client_eof = 1;
	else c->backend_eof = 1;
	return 0;
}

static void half_close(struct conn *c)
{
	if (c->client_eof && c->to_backend.len == 0 && !c->backend_wr_closed) {
		shutdown(c->backend_fd, SHUT_WR);
		c->backend_wr_closed = 1;
	}
	if (c->backend_eof && c->to_client.len == 0 && !c->client_wr_closed) {
		shutdown(c->client_fd, SHUT_WR);
		c->client_wr_closed = 1;
	}
}

static void accept_route(struct state *s, unsigned backend)
{
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);
	struct conn *c = NULL;
	unsigned client;
	size_t i;
	int cfd = accept(s->listeners[backend], (struct sockaddr *)&peer, &plen);
	if (cfd < 0) return;
	for (client = 0; client < NFSP_CLIENTS; client++)
		if (peer.sin_addr.s_addr == s->clients[client].s_addr) break;
	if (client == NFSP_CLIENTS) {
		s->stats->rejected_client++;
		close(cfd);
		return;
	}
	for (i = 0; i < NFSP_MAX_CONNS; i++)
		if (s->conns[i].client_fd < 0) { c = &s->conns[i]; break; }
	if (c == NULL || nonblock(cfd) != 0 || tcp_nodelay(cfd) != 0) {
		s->stats->relay_errors++;
		close(cfd);
		return;
	}
	memset(c, 0, sizeof(*c));
	c->client_fd = cfd;
	c->backend_fd = -1;
	c->client = client;
	c->backend = backend;
	nfsp_framing_init(&c->c2s, s->limit);
	nfsp_framing_init(&c->s2c, s->limit);
	s->stats->accepted[client][backend]++;
	c->backend_fd = start_backend(&s->cfg->route[backend], &c->connecting);
	if (c->backend_fd < 0) {
		s->stats->connect_failed[client][backend]++;
		conn_close(s, c);
		return;
	}
	if (c->connecting) {
		unsigned ms = s->cfg->connect_timeout_ms ?
			s->cfg->connect_timeout_ms : NFSP_DEFAULT_CONNECT_MS;
		c->connect_deadline_ms = now_ms() + ms;
	} else {
		c->connected = 1;
		s->stats->connected[client][backend]++;
		s->stats->active++;
		if (s->stats->active > s->stats->peak_active)
			s->stats->peak_active = s->stats->active;
	}
}

static int finish_connect(struct state *s, struct conn *c)
{
	int err = 0;
	socklen_t len = sizeof(err);
	if (getsockopt(c->backend_fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
		s->stats->connect_failed[c->client][c->backend]++;
		return -1;
	}
	c->connecting = 0;
	c->connected = 1;
	s->stats->connected[c->client][c->backend]++;
	s->stats->active++;
	if (s->stats->active > s->stats->peak_active)
		s->stats->peak_active = s->stats->active;
	return 0;
}

int nfsp_proxy_run(const struct nfsp_proxy_cfg *cfg,
		   struct nfsp_proxy_stats *stats,
		   void (*on_ready)(const struct nfsp_proxy_stats *, void *),
		   void *ready_arg)
{
	struct state *s;
	unsigned b;
	size_t i;
	int rc = -1;
	if (cfg == NULL || stats == NULL || cfg->stop == NULL) return -1;
	s = calloc(1, sizeof(*s));
	if (s == NULL) return -1;
	s->cfg = cfg;
	s->stats = stats;
	s->limit = cfg->msg_limit ? cfg->msg_limit : NFSP_MSG_LIMIT_DEFAULT;
	if (s->limit > SIZE_MAX - NFSP_FRAG_HEADER_LEN - NFSP_READ_CHUNK ||
	    s->limit < NFSP_FRAG_HEADER_LEN) goto out;
	memset(stats, 0, sizeof(*stats));
	for (b = 0; b < NFSP_BACKENDS; b++) s->listeners[b] = -1;
	for (i = 0; i < NFSP_MAX_CONNS; i++) s->conns[i].client_fd = -1;
	for (b = 0; b < NFSP_CLIENTS; b++)
		if (cfg->client_ip[b] == NULL ||
		    inet_pton(AF_INET, cfg->client_ip[b], &s->clients[b]) != 1) goto out;
	if (s->clients[0].s_addr == s->clients[1].s_addr) goto out;
	for (b = 0; b < NFSP_BACKENDS; b++) {
		s->listeners[b] = listener(&cfg->route[b], &stats->bound_port[b]);
		if (s->listeners[b] < 0) goto out;
	}
	if (on_ready != NULL) on_ready(stats, ready_arg);
	rc = 0;
	while (!atomic_load(cfg->stop)) {
		struct pollfd pfd[NFSP_BACKENDS + 2u * NFSP_MAX_CONNS];
		int owner[NFSP_BACKENDS + 2u * NFSP_MAX_CONNS];
		int side[NFSP_BACKENDS + 2u * NFSP_MAX_CONNS];
		nfds_t count = 0;
		int n;
		uint64_t now = now_ms();
		if (cfg->on_tick != NULL)
			cfg->on_tick(cfg->on_tick_arg);
		if (cfg->on_stats != NULL)
			cfg->on_stats(stats, cfg->on_stats_arg);
		for (b = 0; b < NFSP_BACKENDS; b++) {
			pfd[count] = (struct pollfd){s->listeners[b], POLLIN, 0};
			owner[count] = -1;
			side[count++] = (int)b;
		}
		for (i = 0; i < NFSP_MAX_CONNS; i++) {
			struct conn *c = &s->conns[i];
			short ce = 0, be = 0;
			if (c->client_fd < 0) continue;
			if (c->connecting && now >= c->connect_deadline_ms) {
				stats->connect_failed[c->client][c->backend]++;
				conn_close(s, c);
				continue;
			}
			if (c->connecting) be = POLLOUT;
			else {
				if (!c->client_eof && c->to_backend.len == 0) ce |= POLLIN;
				if (!c->backend_eof && c->to_client.len == 0) be |= POLLIN;
				if (c->to_client.len) ce |= POLLOUT;
				if (c->to_backend.len) be |= POLLOUT;
			}
			pfd[count] = (struct pollfd){c->client_fd, ce, 0};
			owner[count] = (int)i;
			side[count++] = NFSP_DIR_C2S;
			pfd[count] = (struct pollfd){c->backend_fd, be, 0};
			owner[count] = (int)i;
			side[count++] = NFSP_DIR_S2C;
		}
		n = poll(pfd, count, 50);
		if (n < 0) {
			if (errno == EINTR) continue;
			stats->relay_errors++;
			rc = -1;
			break;
		}
		if (n == 0) continue;
		for (nfds_t k = 0; k < count; k++) {
			struct conn *c;
			short ev = pfd[k].revents;
			if (ev == 0) continue;
			if (owner[k] < 0) {
				if (ev & POLLIN) accept_route(s, (unsigned)side[k]);
				else { stats->relay_errors++; rc = -1; }
				continue;
			}
			c = &s->conns[(size_t)owner[k]];
			if (c->client_fd < 0) continue;
			if (c->connecting) {
				if (side[k] == NFSP_DIR_S2C && ev != 0 &&
				    finish_connect(s, c) != 0) conn_close(s, c);
				continue;
			}
			if (ev & (POLLERR | POLLNVAL)) {
				stats->relay_errors++;
				conn_close(s, c);
				continue;
			}
			if (ev & POLLOUT) {
				int dir = side[k] == NFSP_DIR_C2S ? NFSP_DIR_S2C : NFSP_DIR_C2S;
				if (flush(s, c, dir) != 0) { conn_close(s, c); continue; }
			}
			if ((ev & (POLLIN | POLLHUP)) &&
			    ((side[k] == NFSP_DIR_C2S && !c->client_eof && c->to_backend.len == 0) ||
			     (side[k] == NFSP_DIR_S2C && !c->backend_eof && c->to_client.len == 0))) {
				if (read_side(s, c, side[k]) != 0) { conn_close(s, c); continue; }
			}
			half_close(c);
			if (c->client_eof && c->backend_eof &&
			    c->to_backend.len == 0 && c->to_client.len == 0)
				conn_close(s, c);
		}
		if (rc != 0) break;
	}
out:
	for (i = 0; i < NFSP_MAX_CONNS; i++)
		if (s->conns[i].client_fd >= 0) conn_close(s, &s->conns[i]);
	for (b = 0; b < NFSP_BACKENDS; b++)
		if (s->listeners[b] >= 0) close(s->listeners[b]);
	free(s);
	return rc;
}
