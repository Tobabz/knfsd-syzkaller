#define _POSIX_C_SOURCE 200809L
#include "proxy.h"
#include "control.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Atomic int stop_requested;
static _Atomic int snapshot_requested;

static void stop_signal(int sig)
{
	(void)sig;
	atomic_store(&stop_requested, 1);
}

static void snapshot_signal(int sig)
{
	(void)sig;
	atomic_store(&snapshot_requested, 1);
}

static void print_stats(const struct nfsp_proxy_stats *stats, const char *phase)
{
	printf("stats_begin %s\n", phase);
	for (unsigned c = 0; c < NFSP_CLIENTS; c++) {
		for (unsigned b = 0; b < NFSP_BACKENDS; b++) {
			printf("client=%u backend=%u accepted=%u connected=%u "
			       "failed=%u c2s=%u s2c=%u sent_c2s=%u sent_s2c=%u\n",
			       c, b, stats->accepted[c][b], stats->connected[c][b],
			       stats->connect_failed[c][b], stats->records[c][b][0],
			       stats->records[c][b][1], stats->delivered[c][b][0],
			       stats->delivered[c][b][1]);
		}
	}
	printf("peak_active=%u active=%u framing_errors=%u relay_errors=%u "
	       "mutation_errors=%u rejected_client=%u\n",
	       stats->peak_active, stats->active, stats->framing_errors,
	       stats->relay_errors, stats->mutation_errors, stats->rejected_client);
	printf("stats_end %s\n", phase);
	fflush(stdout);
}

static void maybe_snapshot(const struct nfsp_proxy_stats *stats, void *arg)
{
	if (atomic_exchange(&snapshot_requested, 0)) {
		print_stats(stats, "snapshot");
		nfsp_control_report((struct nfsp_control *)arg);
	}
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
		"G_LISTEN_IP:PORT K_BACKEND_IP:PORT G_BACKEND_IP:PORT "
		"[--control PATH --delta-dir DIR | --replay DELTA_FILE]\n"
		"One listener per backend; client identity is the TCP source IP. "
		"An arm rule is active only while its control FD remains open.\n", program);
}

int main(int argc, char **argv)
{
	struct nfsp_proxy_cfg cfg = {0};
	struct nfsp_proxy_stats stats;
	struct nfsp_control *control = NULL;
	const char *control_path = NULL, *delta_dir = NULL, *replay = NULL;
	char ips[4][INET_ADDRSTRLEN];
	struct in_addr src[2];
	int rc;
	if (argc != 7 && argc != 9 && argc != 11) {
		usage(argv[0]); return 2;
	}
	for (int i = 7; i < argc; i += 2) {
		if (i + 1 >= argc) { usage(argv[0]); return 2; }
		if (strcmp(argv[i], "--control") == 0 && control_path == NULL)
			control_path = argv[i + 1];
		else if (strcmp(argv[i], "--delta-dir") == 0 && delta_dir == NULL)
			delta_dir = argv[i + 1];
		else if (strcmp(argv[i], "--replay") == 0 && replay == NULL)
			replay = argv[i + 1];
		else { usage(argv[0]); return 2; }
	}
	if ((control_path == NULL) != (delta_dir == NULL) ||
	    (replay != NULL && control_path != NULL)) { usage(argv[0]); return 2; }
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
	cfg.on_stats = maybe_snapshot;
	if (control_path != NULL || replay != NULL) {
		if (nfsp_control_open(&control, control_path, delta_dir, replay) != 0) {
			perror("open control or replay"); return 1;
		}
		cfg.on_tick = nfsp_control_tick;
		cfg.on_tick_arg = control;
		cfg.on_record = nfsp_control_record;
		cfg.on_record_arg = control;
	}
	cfg.on_stats_arg = control;
	if (!atomic_is_lock_free(&stop_requested) ||
	    !atomic_is_lock_free(&snapshot_requested)) {
		fprintf(stderr, "signal stop flag must be lock-free on this host\n");
		return 2;
	}
	signal(SIGINT, stop_signal);
	signal(SIGTERM, stop_signal);
	signal(SIGUSR1, snapshot_signal);
	rc = nfsp_proxy_run(&cfg, &stats, ready, NULL);
	print_stats(&stats, "final");
	nfsp_control_report(control);
	if (nfsp_control_close(control) != 0) rc = -1;
	if (rc != 0) { fprintf(stderr, "proxy setup, poll or replay failed\n"); return 1; }
	return 0;
}
