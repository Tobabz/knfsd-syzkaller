#define _GNU_SOURCE
#include "cld.h"
#include "lifecycle.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* This binary is also the fake nfsdcld.  Executed through a symlink named
 * nfsdcld it behaves like the daemon the broker validates: it daemonizes,
 * holds the CLD pipe named by FAKE_CLD_PIPE open, and waits for a signal.
 * FAKE_CLD_MODE selects a failure: "fail" (launcher exits 3), "noopen"
 * (never opens the pipe) or "ignoreterm" (ignores SIGTERM).
 * FAKE_CLD_FAIL_ONCE names a file whose presence makes one launch fail. */

static int checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

extern char **environ;

static int fake_daemon(void)
{
	const char *mode = getenv("FAKE_CLD_MODE");
	const char *pipe_path = getenv("FAKE_CLD_PIPE");
	const char *once = getenv("FAKE_CLD_FAIL_ONCE");
	int ready[2];
	pid_t child;
	char byte = 0;

	if (mode == NULL)
		mode = "";
	if (once != NULL && unlink(once) == 0)
		_exit(4);
	if (strcmp(mode, "fail") == 0 || pipe_path == NULL || pipe(ready) != 0)
		_exit(3);
	child = fork();
	if (child < 0)
		_exit(5);
	if (child == 0) {
		(void)setsid();
		close(ready[0]);
		if (strcmp(mode, "ignoreterm") == 0)
			(void)signal(SIGTERM, SIG_IGN);
		if (strcmp(mode, "noopen") != 0 &&
		    open(pipe_path, O_RDWR) < 0)
			_exit(6);
		if (write(ready[1], "r", 1) != 1)
			_exit(7);
		close(ready[1]);
		for (;;)
			pause();
	}
	close(ready[1]);
	_exit(read(ready[0], &byte, 1) == 1 ? 0 : 8);
}

struct server_context {
	const char *socket_path;
	struct nfsp_cld *cld;
	_Atomic int stop;
	int rc;
};

static char exe_path[PATH_MAX], link_path[PATH_MAX];

static void sleep_ms(long ms)
{
	struct timespec delay = {.tv_sec = ms / 1000,
				 .tv_nsec = (ms % 1000) * 1000000L};

	while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
		;
}

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static int launch(char *const argv[], int new_netns)
{
	int status;
	pid_t child = fork();

	if (child < 0)
		return -1;
	if (child == 0) {
		if (new_netns && unshare(CLONE_NEWNET) != 0)
			_exit(100);
		execve(link_path, argv, environ);
		_exit(101);
	}
	if (waitpid(child, &status, 0) != child)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

static int launch_default(void)
{
	char arg0[] = "nfsdcld";
	char *const argv[] = {arg0, NULL};

	return launch(argv, 0);
}

static char process_state(pid_t pid)
{
	char path[64], data[512], *p;
	FILE *in;
	size_t n;

	(void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	in = fopen(path, "r");
	if (in == NULL)
		return 0;
	n = fread(data, 1, sizeof(data) - 1u, in);
	fclose(in);
	data[n] = '\0';
	p = strrchr(data, ')');
	return p != NULL && p[1] == ' ' ? p[2] : 0;
}

static int is_fake(pid_t pid)
{
	char path[64], target[PATH_MAX], comm[32];
	ssize_t n;
	FILE *in;

	(void)snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
	in = fopen(path, "r");
	if (in == NULL)
		return 0;
	if (fgets(comm, sizeof(comm), in) == NULL) {
		fclose(in);
		return 0;
	}
	fclose(in);
	if (strcmp(comm, "nfsdcld\n") != 0)
		return 0;
	(void)snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
	n = readlink(path, target, sizeof(target) - 1u);
	if (n < 0)
		return 0;
	target[n] = '\0';
	return strcmp(target, exe_path) == 0;
}

/* Live (not zombie) fake daemons, any namespace. */
static unsigned live_fakes(pid_t *pids, unsigned max)
{
	DIR *directory = opendir("/proc");
	struct dirent *entry;
	unsigned count = 0;

	if (directory == NULL)
		return 0;
	while ((entry = readdir(directory)) != NULL) {
		long value = strtol(entry->d_name, NULL, 10);
		char state;

		if (value <= 0 || !is_fake((pid_t)value))
			continue;
		state = process_state((pid_t)value);
		if (state == 0 || state == 'Z' || state == 'X')
			continue;
		if (count < max)
			pids[count] = (pid_t)value;
		count++;
	}
	closedir(directory);
	return count;
}

static void kill_fakes(void)
{
	pid_t pids[16];
	unsigned count = live_fakes(pids, 16);

	for (unsigned i = 0; i < count && i < 16u; i++) {
		(void)kill(pids[i], SIGKILL);
	}
	for (unsigned tries = 0; tries < 200u && live_fakes(pids, 16) != 0u;
	     tries++)
		sleep_ms(10);
}

static int real_daemon_present(void)
{
	DIR *directory = opendir("/proc");
	struct dirent *entry;
	int found = 0;

	if (directory == NULL)
		return 0;
	while (!found && (entry = readdir(directory)) != NULL) {
		char path[300], comm[32];
		FILE *in;

		(void)snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
		in = fopen(path, "r");
		if (in == NULL)
			continue;
		if (fgets(comm, sizeof(comm), in) != NULL &&
		    strcmp(comm, "nfsdcld\n") == 0) {
			/* A killed fake from an earlier run may linger as a
			 * zombie until its reaper collects it. */
			char state = process_state(
				(pid_t)strtol(entry->d_name, NULL, 10));

			found = state != 0 && state != 'Z' && state != 'X';
		}
		fclose(in);
	}
	closedir(directory);
	return found;
}

static int state_value(const char *path, const char *key, char *out,
		       size_t size)
{
	char line[256];
	size_t key_len = strlen(key);
	FILE *in = fopen(path, "r");
	int found = 0;

	if (in == NULL)
		return 0;
	while (!found && fgets(line, sizeof(line), in) != NULL) {
		if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
			(void)snprintf(out, size, "%s", line + key_len + 1);
			out[strcspn(out, "\n")] = '\0';
			found = 1;
		}
	}
	fclose(in);
	return found;
}

static int state_is(const char *path, const char *key, const char *value)
{
	char got[128];

	return state_value(path, key, got, sizeof(got)) &&
	       strcmp(got, value) == 0;
}

static int wait_state(const char *path, const char *key, const char *value,
		      long timeout_ms)
{
	for (long waited = 0; waited <= timeout_ms; waited += 10) {
		if (state_is(path, key, value))
			return 1;
		sleep_ms(10);
	}
	return 0;
}

static void *server_thread(void *arg)
{
	struct server_context *context = arg;

	context->rc = nfsp_lifecycle_serve_cld(context->socket_path,
					       "/nonexistent-clients", 3,
					       context->cld, &context->stop);
	return NULL;
}

static int transact(const char *path, uint32_t operation, uint32_t client,
		    uint8_t reply[NFSP_LIFECYCLE_REPLY_LEN])
{
	struct sockaddr_un address;
	uint8_t request[NFSP_LIFECYCLE_REQUEST_LEN];
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	memcpy(request, NFSP_LIFECYCLE_REQUEST_MAGIC, 8);
	put32(request + 8, operation);
	put32(request + 12, client);
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
	    send(fd, request, sizeof(request), 0) != (ssize_t)sizeof(request) ||
	    recv(fd, reply, NFSP_LIFECYCLE_REPLY_LEN, 0) !=
		(ssize_t)NFSP_LIFECYCLE_REPLY_LEN) {
		close(fd);
		return -1;
	}
	return close(fd);
}

static int wait_socket(const char *path)
{
	for (unsigned i = 0; i < 200u; i++) {
		struct stat st;

		if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode))
			return 0;
		sleep_ms(10);
	}
	return -1;
}

static struct nfsp_cld_config base_config(const char *pipe_path,
					  const char *state_path)
{
	struct nfsp_cld_config config = {
		.proc_root = "/proc",
		.pipe_path = pipe_path,
		.daemon_path = link_path,
		.state_path = state_path,
		.require_pipefs = 0,
		.hold_ms = 300,
		.down_ms = 300,
		.stop_timeout_ms = 1000,
		.start_timeout_ms = 2000,
	};
	return config;
}

static void identity_checks(const char *dir, const char *pipe_path,
			    const char *state_path)
{
	struct nfsp_cld cld;
	struct nfsp_cld_identity identity;
	struct nfsp_cld_config config = base_config(pipe_path, state_path);
	char other[PATH_MAX], moved[PATH_MAX];
	pid_t pids[4];
	char arg0[] = "nfsdcld", arg1[] = "-F";
	char *const extra_argv[] = {arg0, arg1, NULL};
	char *const plain_argv[] = {arg0, NULL};
	int rc;

	errno = 0;
	CHECK(nfsp_cld_init(&cld, &config) != 0 && errno == ENOENT,
	      "no daemon is ENOENT (errno=%d)", errno);

	CHECK(launch_default() == 0, "launch fake daemon");
	CHECK(nfsp_cld_init(&cld, &config) == 0, "init validates daemon: %s",
	      strerror(errno));
	CHECK(live_fakes(pids, 4) == 1u && pids[0] == cld.current.pid,
	      "identity names the live daemon");
	CHECK(state_is(state_path, "state", "idle") &&
	      state_is(state_path, "seq", "0"), "state file written");

	/* A pipe the daemon does not hold, and a stale pathname. */
	(void)snprintf(other, sizeof(other), "%s/other", dir);
	CHECK(mkfifo(other, 0600) == 0, "mkfifo other");
	config.pipe_path = other;
	errno = 0;
	CHECK(nfsp_cld_init(&cld, &config) != 0 && errno == ESTALE,
	      "foreign pipe is ESTALE (errno=%d)", errno);
	config.pipe_path = pipe_path;
	CHECK(nfsp_cld_init(&cld, &config) == 0, "re-init");
	(void)snprintf(moved, sizeof(moved), "%s/moved", dir);
	CHECK(rename(pipe_path, moved) == 0 && mkfifo(pipe_path, 0600) == 0,
	      "replace pipe path");
	errno = 0;
	CHECK(nfsp_cld_find(&cld, 0, &identity) != 0 && errno == ESTALE,
	      "stale pathname is ESTALE (errno=%d)", errno);
	CHECK(rename(moved, pipe_path) == 0, "restore pipe inode");
	CHECK(nfsp_cld_find(&cld, 0, &identity) == 0, "restored pipe validates");

	/* Another executable. */
	config.daemon_path = "/bin/sh";
	errno = 0;
	CHECK(nfsp_cld_init(&cld, &config) != 0 && errno == ESTALE,
	      "wrong executable is ESTALE (errno=%d)", errno);
	config.daemon_path = link_path;

	/* Two daemons in the namespaces are ambiguous. */
	CHECK(launch_default() == 0, "launch second fake daemon");
	errno = 0;
	CHECK(nfsp_cld_find(&cld, 0, &identity) != 0 && errno == EEXIST,
	      "two daemons are EEXIST (errno=%d)", errno);
	kill_fakes();

	/* Wrong argv. */
	CHECK(launch(extra_argv, 0) == 0, "launch daemon with extra argv");
	errno = 0;
	CHECK(nfsp_cld_find(&cld, 0, &identity) != 0 && errno == ESTALE,
	      "argv mismatch is ESTALE (errno=%d)", errno);
	kill_fakes();

	/* A daemon in another network namespace is not this lane's. */
	rc = launch(plain_argv, 1);
	if (rc == 100) {
		printf("  note: unshare(CLONE_NEWNET) not permitted; "
		       "namespace check skipped\n");
	} else {
		CHECK(rc == 0, "launch daemon in a new netns (rc=%d)", rc);
		errno = 0;
		CHECK(nfsp_cld_find(&cld, 0, &identity) != 0 && errno == ENOENT,
		      "foreign-netns daemon is ignored (errno=%d)", errno);
	}
	kill_fakes();

	/* A stopped daemon is not a valid idle daemon. */
	CHECK(launch_default() == 0, "launch fake daemon");
	CHECK(nfsp_cld_init(&cld, &config) == 0, "init");
	CHECK(kill(cld.current.pid, SIGSTOP) == 0, "stop daemon externally");
	for (unsigned i = 0; i < 100u && process_state(cld.current.pid) != 'T';
	     i++)
		sleep_ms(10);
	errno = 0;
	CHECK(nfsp_cld_find(&cld, 0, &identity) != 0 && errno == EAGAIN,
	      "stopped daemon is EAGAIN (errno=%d)", errno);
	CHECK(nfsp_cld_begin(&cld, NFSP_LIFECYCLE_OP_CLD_RECONNECT, &identity) ==
	      EAGAIN && cld.state == NFSP_CLD_IDLE &&
	      cld.counters.refused_identity == 1u,
	      "begin refuses a stopped daemon");
	(void)kill(cld.current.pid, SIGCONT);

	/* A replaced daemon (new PID and start time) is refused. */
	kill_fakes();
	CHECK(launch_default() == 0, "launch replacement externally");
	CHECK(nfsp_cld_begin(&cld, NFSP_LIFECYCLE_OP_CLD_DOWN, &identity) ==
	      ESTALE && cld.state == NFSP_CLD_IDLE &&
	      cld.counters.refused_identity == 2u && cld.counters.down_fail == 1u,
	      "begin refuses a daemon this broker did not validate");
	CHECK(live_fakes(pids, 4) == 1u && process_state(pids[0]) != 'T',
	      "refusal leaves the daemon running");
	kill_fakes();
}

static void start_server(struct server_context *context, pthread_t *thread)
{
	atomic_store(&context->stop, 0);
	context->rc = -1;
	CHECK(pthread_create(thread, NULL, server_thread, context) == 0,
	      "create server thread");
	CHECK(wait_socket(context->socket_path) == 0, "socket ready");
}

static void stop_server(struct server_context *context, pthread_t thread)
{
	atomic_store(&context->stop, 1);
	CHECK(pthread_join(thread, NULL) == 0 && context->rc == 0,
	      "server stopped cleanly");
}

static void protocol_checks(const char *dir, const char *pipe_path,
			    const char *state_path)
{
	struct nfsp_cld cld;
	struct nfsp_cld_config config = base_config(pipe_path, state_path);
	struct server_context context = {0};
	char socket_path[PATH_MAX], once[PATH_MAX];
	uint8_t reply[NFSP_LIFECYCLE_REPLY_LEN];
	pthread_t thread;
	pid_t old, pids[4];

	(void)snprintf(socket_path, sizeof(socket_path), "%s/lifecycle.sock", dir);
	context.socket_path = socket_path;
	context.cld = &cld;

	CHECK(launch_default() == 0, "launch fake daemon");
	CHECK(nfsp_cld_init(&cld, &config) == 0, "init");
	start_server(&context, &thread);

	/* RECONNECT: held now, killed and replaced after the hold. */
	old = cld.current.pid;
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_RECONNECT, 0, reply) == 0 &&
	      memcmp(reply, NFSP_LIFECYCLE_REPLY_MAGIC, 8) == 0 &&
	      get32(reply + 8) == 0 && get32(reply + 12) == 2u &&
	      get32(reply + 16) == 1u && get32(reply + 20) == (uint32_t)old,
	      "reconnect armed (status %u)", get32(reply + 8));
	CHECK(process_state(old) == 'T', "daemon stopped while held");
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_RECONNECT, 0, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)EBUSY, "overlapping CLD op is EBUSY");
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_EXPIRE, 0, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)EBUSY, "expiry while held is EBUSY");
	CHECK(wait_state(state_path, "state", "idle", 3000) &&
	      state_is(state_path, "seq", "1") &&
	      state_is(state_path, "reconnect_ok", "1") &&
	      state_is(state_path, "daemon_start_ok", "1") &&
	      state_is(state_path, "refused_busy", "2"),
	      "reconnect completed with typed counters");
	CHECK(live_fakes(pids, 4) == 1u && pids[0] != old &&
	      pids[0] == cld.current.pid && process_state(pids[0]) != 'T',
	      "exactly one fresh daemon remains");

	/* DOWN: exited on reply, replaced after the window. */
	old = cld.current.pid;
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_DOWN, 0, reply) == 0 &&
	      get32(reply + 8) == 0 && get32(reply + 12) == 3u &&
	      get32(reply + 16) == 2u, "down armed (status %u)",
	      get32(reply + 8));
	CHECK(live_fakes(pids, 4) == 0u, "no daemon while down");
	CHECK(wait_state(state_path, "state", "idle", 3000) &&
	      state_is(state_path, "down_ok", "1") &&
	      state_is(state_path, "daemon_stop_ok", "2"),
	      "down completed");
	CHECK(live_fakes(pids, 4) == 1u && pids[0] != old, "down restarted daemon");

	/* Malformed requests change nothing. */
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_DOWN, 1, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)EINVAL, "selector is EINVAL");
	CHECK(transact(socket_path, 99, 0, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)EOPNOTSUPP, "unknown op");
	CHECK(state_is(state_path, "seq", "2"), "refusals open no transaction");

	/* One failed start is restored. */
	(void)snprintf(once, sizeof(once), "%s/fail-once", dir);
	CHECK(close(open(once, O_CREAT | O_WRONLY | O_CLOEXEC, 0600)) == 0,
	      "create fail-once marker");
	CHECK(setenv("FAKE_CLD_FAIL_ONCE", once, 1) == 0, "setenv");
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_RECONNECT, 0, reply) == 0 &&
	      get32(reply + 8) == 0, "reconnect armed");
	CHECK(wait_state(state_path, "restore_ok", "1", 5000) &&
	      state_is(state_path, "state", "idle") &&
	      state_is(state_path, "daemon_start_fail", "1") &&
	      state_is(state_path, "reconnect_fail", "1"),
	      "failed start restored and counted as a failed reconnect");
	CHECK(live_fakes(pids, 4) == 1u && process_state(pids[0]) != 'T',
	      "restored daemon running");
	(void)unsetenv("FAKE_CLD_FAIL_ONCE");

	/* Shutdown completes a pending transaction instead of leaving the
	 * daemon stopped. */
	old = cld.current.pid;
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_RECONNECT, 0, reply) == 0 &&
	      get32(reply + 8) == 0, "reconnect armed before shutdown");
	stop_server(&context, thread);
	CHECK(cld.state == NFSP_CLD_IDLE && state_is(state_path, "state", "idle"),
	      "shutdown completed the transaction");
	CHECK(access(socket_path, F_OK) != 0, "socket removed");
	CHECK(live_fakes(pids, 4) == 1u && pids[0] != old &&
	      process_state(pids[0]) != 'T', "no held daemon after shutdown");

	/* Persistent start failure is terminal and refuses everything. */
	start_server(&context, &thread);
	CHECK(setenv("FAKE_CLD_MODE", "noopen", 1) == 0, "setenv noopen");
	cld.config.start_timeout_ms = 300;
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_DOWN, 0, reply) == 0 &&
	      get32(reply + 8) == 0, "down armed");
	CHECK(wait_state(state_path, "state", "failed", 5000) &&
	      state_is(state_path, "restore_fail", "1"), "start timeout is failed");
	CHECK(live_fakes(pids, 4) == 0u, "failed starts leave no daemon behind");
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_RECONNECT, 0, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)EIO, "failed broker refuses CLD ops");
	(void)unsetenv("FAKE_CLD_MODE");
	stop_server(&context, thread);
	kill_fakes();

	/* A daemon that ignores SIGTERM is killed and replaced; DOWN fails. */
	CHECK(setenv("FAKE_CLD_MODE", "ignoreterm", 1) == 0, "setenv ignoreterm");
	CHECK(launch_default() == 0, "launch SIGTERM-ignoring daemon");
	(void)unsetenv("FAKE_CLD_MODE");
	config.stop_timeout_ms = 300;
	CHECK(nfsp_cld_init(&cld, &config) == 0, "init");
	start_server(&context, &thread);
	old = cld.current.pid;
	CHECK(transact(socket_path, NFSP_LIFECYCLE_OP_CLD_DOWN, 0, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)ETIMEDOUT,
	      "graceful stop timeout fails the transaction (status %u)",
	      get32(reply + 8));
	CHECK(state_is(state_path, "state", "idle") &&
	      state_is(state_path, "daemon_stop_fail", "1") &&
	      state_is(state_path, "restore_ok", "1"), "daemon was replaced");
	CHECK(live_fakes(pids, 4) == 1u && pids[0] != old, "replacement running");
	stop_server(&context, thread);
	kill_fakes();
}

int main(int argc, char **argv)
{
	char temporary[] = "/tmp/nfsp-cld-XXXXXX";
	char bin[256], pipe_path[PATH_MAX], state_path[PATH_MAX];
	const char *base;

	(void)argc;
	base = strrchr(argv[0], '/');
	base = base != NULL ? base + 1 : argv[0];
	if (strcmp(base, "nfsdcld") == 0)
		return fake_daemon();

	if (real_daemon_present()) {
		printf("cld checks skipped: a process named nfsdcld is running\n");
		return 0;
	}
	if (realpath("/proc/self/exe", exe_path) == NULL ||
	    mkdtemp(temporary) == NULL)
		return 2;
	(void)snprintf(bin, sizeof(bin), "%s/bin", temporary);
	(void)snprintf(link_path, sizeof(link_path), "%s/nfsdcld", bin);
	(void)snprintf(pipe_path, sizeof(pipe_path), "%s/cld", temporary);
	(void)snprintf(state_path, sizeof(state_path), "%s/cld.state", temporary);
	CHECK(mkdir(bin, 0700) == 0 && symlink(exe_path, link_path) == 0,
	      "fake daemon link");
	CHECK(mkfifo(pipe_path, 0600) == 0, "mkfifo");
	CHECK(setenv("FAKE_CLD_PIPE", pipe_path, 1) == 0, "setenv");
	(void)unsetenv("FAKE_CLD_MODE");
	(void)unsetenv("FAKE_CLD_FAIL_ONCE");

	identity_checks(temporary, pipe_path, state_path);
	protocol_checks(temporary, pipe_path, state_path);
	kill_fakes();

	{
		char path[PATH_MAX];

		(void)unlink(link_path);
		(void)rmdir(bin);
		(void)unlink(pipe_path);
		(void)unlink(state_path);
		(void)snprintf(path, sizeof(path), "%s/other", temporary);
		(void)unlink(path);
		(void)snprintf(path, sizeof(path), "%s/fail-once", temporary);
		(void)unlink(path);
		(void)rmdir(temporary);
	}
	printf("cld checks=%d failures=%d\n", checks, failures);
	return failures ? 1 : 0;
}
