#define _POSIX_C_SOURCE 200809L
#include "proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Atomic int stop_requested;

static void stop_signal(int sig)
{
	(void)sig;
	atomic_store(&stop_requested, 1);
}

static int endpoint(const char *arg, char ip[INET_ADDRSTRLEN], uint16_t *port)
{
	const char *colon = strchr(arg, ':');
	struct in_addr addr;
	char *end;
	unsigned long n;
	size_t len;
	if (colon == NULL || strchr(colon + 1, ':') != NULL) return -1;
	len = (size_t)(colon - arg);
	if (len == 0 || len >= INET_ADDRSTRLEN) return -1;
	memcpy(ip, arg, len);
	ip[len] = '\0';
	if (inet_pton(AF_INET, ip, &addr) != 1 || !colon[1]) return -1;
	errno = 0;
	n = strtoul(colon + 1, &end, 10);
	if (errno != 0 || *end != '\0' || n == 0 || n > 65535u) return -1;
	*port = (uint16_t)n;
	return 0;
}

static void ready(const struct nfsp_proxy_stats *stats, void *arg)
{
	(void)arg;
	printf("relay ready: knfsd=%u ganesha=%u\n",
	       stats->bound_port[0], stats->bound_port[1]);
	fflush(stdout);
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s CLIENT0_IP CLIENT1_IP K_LISTEN_IP:PORT "
		"G_LISTEN_IP:PORT K_BACKEND_IP:PORT G_BACKEND_IP:PORT\n"
		"Relay-only stage: one listener per backend; client identity is "
		"the TCP source IP.\n", program);
}

int main(int argc, char **argv)
{
	struct nfsp_proxy_cfg cfg = {0};
	struct nfsp_proxy_stats stats;
	char ips[4][INET_ADDRSTRLEN];
	struct in_addr src[2];
	int rc;
	if (argc != 7) { usage(argv[0]); return 2; }
	if (inet_pton(AF_INET, argv[1], &src[0]) != 1 ||
	    inet_pton(AF_INET, argv[2], &src[1]) != 1 ||
	    src[0].s_addr == src[1].s_addr ||
	    endpoint(argv[3], ips[0], &cfg.route[0].listen_port) != 0 ||
	    endpoint(argv[4], ips[1], &cfg.route[1].listen_port) != 0 ||
	    endpoint(argv[5], ips[2], &cfg.route[0].backend_port) != 0 ||
	    endpoint(argv[6], ips[3], &cfg.route[1].backend_port) != 0) {
		usage(argv[0]);
		return 2;
	}
	cfg.client_ip[0] = argv[1];
	cfg.client_ip[1] = argv[2];
	cfg.route[0].listen_ip = ips[0];
	cfg.route[1].listen_ip = ips[1];
	cfg.route[0].backend_ip = ips[2];
	cfg.route[1].backend_ip = ips[3];
	cfg.stop = &stop_requested;
	if (!atomic_is_lock_free(&stop_requested)) {
		fprintf(stderr, "signal stop flag must be lock-free on this host\n");
		return 2;
	}
	signal(SIGINT, stop_signal);
	signal(SIGTERM, stop_signal);
	rc = nfsp_proxy_run(&cfg, &stats, ready, NULL);
	if (rc != 0) { fprintf(stderr, "proxy setup or poll failed\n"); return 1; }
	for (unsigned c = 0; c < NFSP_CLIENTS; c++) {
		for (unsigned b = 0; b < NFSP_BACKENDS; b++) {
			printf("client=%u backend=%u accepted=%u connected=%u "
			       "failed=%u c2s=%u s2c=%u sent_c2s=%u sent_s2c=%u\n",
			       c, b, stats.accepted[c][b], stats.connected[c][b],
			       stats.connect_failed[c][b], stats.records[c][b][0],
			       stats.records[c][b][1], stats.delivered[c][b][0],
			       stats.delivered[c][b][1]);
		}
	}
	printf("peak_active=%u framing_errors=%u relay_errors=%u "
	       "mutation_errors=%u rejected_client=%u\n",
	       stats.peak_active, stats.framing_errors, stats.relay_errors,
	       stats.mutation_errors, stats.rejected_client);
	return 0;
}
