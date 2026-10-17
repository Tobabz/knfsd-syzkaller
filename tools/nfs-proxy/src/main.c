#define _POSIX_C_SOURCE 200809L
#include "proxy.h"
#include "control.h"
#include "semantic.h"
#include "target.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static _Atomic int stop_requested;
static _Atomic int snapshot_requested;

extern const struct nfsp_schema_family nfsp_schema_family_nfs4;
extern const struct nfsp_schema_family nfsp_schema_family_nfs3;

static const struct nfsp_schema_family *const families[] = {
	&nfsp_schema_family_nfs4,
	&nfsp_schema_family_nfs3,
};

/* What the event loop's hooks share: either part may be absent. */
struct app {
	struct nfsp_control *control;
	struct nfsp_semantic *semantic;
	struct nfsp_target *target;
};

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

static void report(const struct nfsp_proxy_stats *stats, const char *phase,
		   const struct app *app)
{
	print_stats(stats, phase);
	nfsp_control_report(app->control);
	if (app->semantic != NULL) {
		nfsp_semantic_report(app->semantic, stdout);
		fflush(stdout);
	}
	if (app->target != NULL) {
		nfsp_target_report(app->target, stdout);
		fflush(stdout);
	}
}

static void maybe_snapshot(const struct nfsp_proxy_stats *stats, void *arg)
{
	if (atomic_exchange(&snapshot_requested, 0))
		report(stats, "snapshot", arg);
}

static void tick(void *arg)
{
	struct app *app = arg;

	if (app->control != NULL)
		nfsp_control_tick(app->control);
	if (app->semantic != NULL)
		nfsp_semantic_tick(app->semantic);
	if (app->target != NULL)
		nfsp_target_tick(app->target);
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

/* The journal channel: a Unix stream socket (host tests) or a character
 * device such as a virtio-serial port (/dev/virtio-ports/NAME in a guest). */
static int open_journal(const char *path)
{
	struct stat st;
	struct sockaddr_un sa;
	int fd;

	if (stat(path, &st) != 0)
		return -1;
	if (!S_ISSOCK(st.st_mode))
		return open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (strlen(path) >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
		int saved = errno;

		close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}

static uint8_t *read_file(const char *path, size_t max, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	size_t n;

	if (f == NULL)
		return NULL;
	buf = malloc(max + 1u);
	if (buf == NULL) {
		fclose(f);
		return NULL;
	}
	n = fread(buf, 1, max + 1u, f);
	if (ferror(f) || n == 0 || n > max) {
		fclose(f);
		free(buf);
		errno = EINVAL;
		return NULL;
	}
	fclose(f);
	*len = n;
	return buf;
}

static int parse_u32(const char *arg, uint32_t *out)
{
	char *end;
	unsigned long n;

	errno = 0;
	n = strtoul(arg, &end, 10);
	if (errno != 0 || *arg == '\0' || *end != '\0' || n > 0xffffffffu)
		return -1;
	*out = (uint32_t)n;
	return 0;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s CLIENT0_IP CLIENT1_IP K_LISTEN_IP:PORT "
		"G_LISTEN_IP:PORT K_BACKEND_IP:PORT G_BACKEND_IP:PORT "
		"[--control PATH --delta-dir DIR | --replay DELTA_FILE] "
		"[--semantic]\n"
		"       %s ... --target RULES --session-id ID --journal PATH "
		"--lane N [--activation PATH] [--drain-bound-ms MS]\n"
		"       %s --check-rules RULES\n"
		"One listener per backend; client identity is the TCP source IP. "
		"An arm rule is active only while its control FD remains open.\n"
		"--semantic decodes every record and correlates each REPLY with "
		"its CALL (observe only; never changes or refuses a record).\n"
		"--target applies the NFSPRUL1 rule set RULES to records of an "
		"activated generation; every mutation is recorded on the host "
		"journal at PATH (Unix socket or virtio-serial port) before it "
		"is forwarded.  The executor drives activation on the "
		"SOCK_SEQPACKET endpoint --activation (target.h).\n"
		"--check-rules loads RULES as --target would and reports, on "
		"one line, whether this runtime accepts it (exit 0) or refuses "
		"it (exit 3): the semantic replay compatibility gate.\n",
		program, program, program);
}

/* Semantic replay's compatibility gate: see nfsp_target_check_rules. */
static int check_rules(const char *path)
{
	uint8_t *rules;
	size_t len = 0;
	int rc;

	rules = read_file(path, NFSP_TARGET_RULES_MAX, &len);
	if (rules == NULL) {
		perror("read rule set");
		return 1;
	}
	rc = nfsp_target_check_rules(rules, len, families,
				     sizeof(families) / sizeof(families[0]),
				     stdout);
	free(rules);
	return rc == 0 ? 0 : 3;
}

int main(int argc, char **argv)
{
	struct nfsp_proxy_cfg cfg = {0};
	struct nfsp_proxy_stats stats;
	struct nfsp_control *control = NULL;
	struct nfsp_semantic semantic;
	struct app app = {0};
	int semantic_on = 0;
	const char *control_path = NULL, *delta_dir = NULL, *replay = NULL;
	const char *rules_path = NULL, *session_id = NULL, *journal_path = NULL;
	const char *activation_path = NULL, *lane_arg = NULL, *drain_arg = NULL;
	struct nfsp_target_cfg tcfg;
	char ips[4][INET_ADDRSTRLEN];
	struct in_addr src[2];
	int rc;
	if (argc == 3 && strcmp(argv[1], "--check-rules") == 0)
		return check_rules(argv[2]);
	if (argc < 7) {
		usage(argv[0]); return 2;
	}
	for (int i = 7; i < argc; i += 2) {
		if (strcmp(argv[i], "--semantic") == 0 && !semantic_on) {
			semantic_on = 1;
			i--;
			continue;
		}
		if (i + 1 >= argc) { usage(argv[0]); return 2; }
		if (strcmp(argv[i], "--control") == 0 && control_path == NULL)
			control_path = argv[i + 1];
		else if (strcmp(argv[i], "--delta-dir") == 0 && delta_dir == NULL)
			delta_dir = argv[i + 1];
		else if (strcmp(argv[i], "--replay") == 0 && replay == NULL)
			replay = argv[i + 1];
		else if (strcmp(argv[i], "--target") == 0 && rules_path == NULL)
			rules_path = argv[i + 1];
		else if (strcmp(argv[i], "--session-id") == 0 && session_id == NULL)
			session_id = argv[i + 1];
		else if (strcmp(argv[i], "--journal") == 0 && journal_path == NULL)
			journal_path = argv[i + 1];
		else if (strcmp(argv[i], "--lane") == 0 && lane_arg == NULL)
			lane_arg = argv[i + 1];
		else if (strcmp(argv[i], "--activation") == 0 &&
			 activation_path == NULL)
			activation_path = argv[i + 1];
		else if (strcmp(argv[i], "--drain-bound-ms") == 0 &&
			 drain_arg == NULL)
			drain_arg = argv[i + 1];
		else { usage(argv[0]); return 2; }
	}
	if ((control_path == NULL) != (delta_dir == NULL) ||
	    (replay != NULL && control_path != NULL)) { usage(argv[0]); return 2; }
	memset(&tcfg, 0, sizeof(tcfg));
	if (rules_path != NULL) {
		/* Target mode owns the relay's rewrite and observer hooks. */
		if (session_id == NULL || journal_path == NULL ||
		    lane_arg == NULL || control_path != NULL ||
		    replay != NULL || semantic_on ||
		    parse_u32(lane_arg, &tcfg.lane_id) != 0 ||
		    (drain_arg != NULL &&
		     (parse_u32(drain_arg, &tcfg.drain_bound_ms) != 0 ||
		      tcfg.drain_bound_ms == 0))) {
			usage(argv[0]);
			return 2;
		}
	} else if (session_id != NULL || journal_path != NULL ||
		   lane_arg != NULL || activation_path != NULL ||
		   drain_arg != NULL) {
		usage(argv[0]);
		return 2;
	}
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
		cfg.on_record = nfsp_control_record;
		cfg.on_record_arg = control;
	}
	app.control = control;
	if (semantic_on) {
		memset(&semantic, 0, sizeof(semantic));
		semantic.families = families;
		semantic.nfamilies = sizeof(families) / sizeof(families[0]);
		/* The observer runs before on_record: once a rewrite hook is
		 * installed, what the peer was given is not known here, so
		 * REPLYs get no dispatch (semantic.h). */
		semantic.forwarded = cfg.on_record != NULL ?
				     NFSP_TXN_FWD_UNKNOWN : NFSP_TXN_FWD_ORIGINAL;
		if (nfsp_semantic_init(&semantic, NULL) != 0) {
			fprintf(stderr, "semantic observer: no memory\n");
			nfsp_control_close(control);
			return 1;
		}
		app.semantic = &semantic;
		cfg.on_rpc_record = nfsp_semantic_record;
		cfg.on_rpc_record_arg = &semantic;
		cfg.on_connection = nfsp_semantic_connection;
		cfg.on_connection_arg = &semantic;
	}
	if (rules_path != NULL) {
		char err[256];
		uint8_t *rules;
		size_t rules_len = 0;

		rules = read_file(rules_path, NFSP_TARGET_RULES_MAX, &rules_len);
		if (rules == NULL) {
			perror("read rule set");
			return 1;
		}
		tcfg.families = families;
		tcfg.nfamilies = sizeof(families) / sizeof(families[0]);
		tcfg.rule_set = rules;
		tcfg.rule_set_len = rules_len;
		tcfg.proxy_session_id = session_id;
		tcfg.activation_path = activation_path;
		tcfg.journal_fd = open_journal(journal_path);
		if (tcfg.journal_fd < 0) {
			perror("open journal channel");
			free(rules);
			return 1;
		}
		rc = nfsp_target_open(&app.target, &tcfg, err, sizeof(err));
		free(rules);
		if (rc != 0) {
			fprintf(stderr, "target mode: %s\n", err);
			return 1;
		}
		nfsp_target_install(app.target, &cfg);
	}
	if (app.control != NULL || app.semantic != NULL || app.target != NULL) {
		cfg.on_tick = tick;
		cfg.on_tick_arg = &app;
	}
	cfg.on_stats_arg = &app;
	if (!atomic_is_lock_free(&stop_requested) ||
	    !atomic_is_lock_free(&snapshot_requested)) {
		fprintf(stderr, "signal stop flag must be lock-free on this host\n");
		return 2;
	}
	signal(SIGINT, stop_signal);
	signal(SIGTERM, stop_signal);
	signal(SIGUSR1, snapshot_signal);
	rc = nfsp_proxy_run(&cfg, &stats, ready, NULL);
	/* Every answer still owed, then RUN_COMPLETE if the session is clean.
	 * The wait covers a draining generation's bound. */
	nfsp_target_finish(app.target,
			   (tcfg.drain_bound_ms ? tcfg.drain_bound_ms :
			    NFSP_TARGET_DEFAULT_DRAIN_MS) + 5000u);
	report(&stats, "final", &app);
	nfsp_target_close(app.target);
	if (app.semantic != NULL)
		nfsp_semantic_free(app.semantic);
	if (nfsp_control_close(control) != 0) rc = -1;
	if (rc != 0) { fprintf(stderr, "proxy setup, poll or replay failed\n"); return 1; }
	return 0;
}
