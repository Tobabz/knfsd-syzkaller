#define _GNU_SOURCE
#include "cld.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

/* RPCAUTH_GSSMAGIC: the superblock magic of rpc_pipefs. */
#define RPC_PIPEFS_MAGIC 0x67596969L
#define POLL_STEP_MS 20u

extern char **environ;

static uint64_t now_ms(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void sleep_ms(unsigned ms)
{
	struct timespec delay = {.tv_sec = (time_t)(ms / 1000u),
				 .tv_nsec = (long)(ms % 1000u) * 1000000L};

	while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
		;
}

static int proc_file(char *out, size_t size, const char *root, pid_t pid,
		     const char *name)
{
	int n = snprintf(out, size, "%s/%ld/%s", root, (long)pid, name);

	if (n < 0 || (size_t)n >= size) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static ssize_t read_small(const char *path, char *buffer, size_t size)
{
	size_t used = 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

	if (fd < 0)
		return -1;
	while (used + 1u < size) {
		ssize_t n = read(fd, buffer + used, size - 1u - used);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			int saved = errno;

			close(fd);
			errno = saved;
			return -1;
		}
		if (n == 0)
			break;
		used += (size_t)n;
	}
	close(fd);
	buffer[used] = '\0';
	return (ssize_t)used;
}

/* Field 3 (state) and field 22 (starttime) of /proc/PID/stat.  comm may
 * contain spaces or parentheses, so fields are counted after the last ')'. */
static int read_stat(const char *root, pid_t pid, char *state,
		     uint64_t *starttime)
{
	char path[PATH_MAX], data[1024];
	char *p, *end;
	unsigned field;
	unsigned long long value;

	if (proc_file(path, sizeof(path), root, pid, "stat") != 0 ||
	    read_small(path, data, sizeof(data)) < 0)
		return -1;
	p = strrchr(data, ')');
	if (p == NULL || p[1] != ' ' || p[2] == '\0') {
		errno = EPROTO;
		return -1;
	}
	*state = p[2];
	p += 2;
	/* p is at field 3; advance to field 22. */
	for (field = 3; field < 22u; field++) {
		p = strchr(p, ' ');
		if (p == NULL) {
			errno = EPROTO;
			return -1;
		}
		p++;
	}
	errno = 0;
	value = strtoull(p, &end, 10);
	if (errno != 0 || end == p || (*end != ' ' && *end != '\n' &&
				       *end != '\0')) {
		errno = EPROTO;
		return -1;
	}
	*starttime = (uint64_t)value;
	return 0;
}

static int same_inode(const char *a, const char *b)
{
	struct stat sa, sb;

	if (stat(a, &sa) != 0 || stat(b, &sb) != 0)
		return -1;
	return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static int numeric_name(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;

	if (*p == '\0')
		return 0;
	for (; *p != '\0'; p++)
		if (*p < (unsigned char)'0' || *p > (unsigned char)'9')
			return 0;
	return 1;
}

/* A candidate is any live process named nfsdcld in the broker's network and
 * mount namespaces.  Daemons of other lanes live in other namespaces. */
static int is_candidate(const struct nfsp_cld *cld, pid_t pid)
{
	char path[PATH_MAX], self[PATH_MAX], comm[64], state;
	uint64_t starttime;
	static const char *const spaces[] = {"ns/net", "ns/mnt"};

	if (proc_file(path, sizeof(path), cld->config.proc_root, pid, "comm") != 0 ||
	    read_small(path, comm, sizeof(comm)) < 0 ||
	    strcmp(comm, NFSP_CLD_COMM "\n") != 0)
		return 0;
	if (read_stat(cld->config.proc_root, pid, &state, &starttime) != 0 ||
	    state == 'Z' || state == 'X' || state == 'x')
		return 0;
	for (size_t i = 0; i < sizeof(spaces) / sizeof(spaces[0]); i++) {
		int n = snprintf(self, sizeof(self), "%s/self/%s",
				 cld->config.proc_root, spaces[i]);

		if (n < 0 || (size_t)n >= sizeof(self) ||
		    proc_file(path, sizeof(path), cld->config.proc_root, pid,
			      spaces[i]) != 0 ||
		    same_inode(path, self) != 1)
			return 0;
	}
	return 1;
}

static int resolve_pipe(const struct nfsp_cld *cld, uint64_t *dev,
			uint64_t *ino)
{
	struct stat st;

	if (stat(cld->config.pipe_path, &st) != 0)
		return -1;
	if (!S_ISFIFO(st.st_mode)) {
		errno = ESTALE;
		return -1;
	}
	if (cld->config.require_pipefs) {
		struct statfs fs;

		if (statfs(cld->config.pipe_path, &fs) != 0)
			return -1;
		if ((long)fs.f_type != RPC_PIPEFS_MAGIC) {
			errno = ESTALE;
			return -1;
		}
	}
	*dev = (uint64_t)st.st_dev;
	*ino = (uint64_t)st.st_ino;
	return 0;
}

static int owns_pipe(const struct nfsp_cld *cld, pid_t pid, uint64_t dev,
		     uint64_t ino)
{
	char path[PATH_MAX];
	DIR *directory;
	struct dirent *entry;
	int found = 0, dir_fd;

	if (proc_file(path, sizeof(path), cld->config.proc_root, pid, "fd") != 0)
		return 0;
	directory = opendir(path);
	if (directory == NULL)
		return 0;
	dir_fd = dirfd(directory);
	while (!found && (entry = readdir(directory)) != NULL) {
		struct stat st;

		if (!numeric_name(entry->d_name))
			continue;
		if (fstatat(dir_fd, entry->d_name, &st, 0) == 0 &&
		    S_ISFIFO(st.st_mode) && (uint64_t)st.st_dev == dev &&
		    (uint64_t)st.st_ino == ino)
			found = 1;
	}
	closedir(directory);
	return found;
}

static int verify(const struct nfsp_cld *cld, pid_t pid, int allow_stopped,
		  uint64_t pipe_dev, uint64_t pipe_ino,
		  struct nfsp_cld_identity *identity)
{
	char path[PATH_MAX], target[PATH_MAX], expected[PATH_MAX], cmdline[64];
	ssize_t n;
	char state;
	uint64_t starttime;

	if (realpath(cld->config.daemon_path, expected) == NULL)
		return -1;
	if (proc_file(path, sizeof(path), cld->config.proc_root, pid, "exe") != 0)
		return -1;
	n = readlink(path, target, sizeof(target) - 1u);
	if (n < 0)
		return -1;
	target[n] = '\0';
	if (strcmp(target, expected) != 0)
		goto stale;
	if (proc_file(path, sizeof(path), cld->config.proc_root, pid,
		      "cmdline") != 0)
		return -1;
	n = read_small(path, cmdline, sizeof(cmdline));
	if (n != (ssize_t)sizeof(NFSP_CLD_COMM) ||
	    memcmp(cmdline, NFSP_CLD_COMM, sizeof(NFSP_CLD_COMM)) != 0)
		goto stale;
	if (read_stat(cld->config.proc_root, pid, &state, &starttime) != 0)
		return -1;
	if ((state == 'T' || state == 't') && !allow_stopped) {
		errno = EAGAIN;
		return -1;
	}
	if (!owns_pipe(cld, pid, pipe_dev, pipe_ino))
		goto stale;
	identity->pid = pid;
	identity->starttime = starttime;
	identity->pipe_dev = pipe_dev;
	identity->pipe_ino = pipe_ino;
	return 0;

stale:
	errno = ESTALE;
	return -1;
}

int nfsp_cld_find(const struct nfsp_cld *cld, int allow_stopped,
		  struct nfsp_cld_identity *identity)
{
	DIR *directory;
	struct dirent *entry;
	pid_t selected = 0;
	unsigned candidates = 0;
	uint64_t dev, ino;

	if (resolve_pipe(cld, &dev, &ino) != 0)
		return -1;
	directory = opendir(cld->config.proc_root);
	if (directory == NULL)
		return -1;
	while ((entry = readdir(directory)) != NULL) {
		long value;

		if (!numeric_name(entry->d_name))
			continue;
		value = strtol(entry->d_name, NULL, 10);
		if (value <= 0 || value > INT_MAX)
			continue;
		if (is_candidate(cld, (pid_t)value)) {
			candidates++;
			selected = (pid_t)value;
		}
	}
	closedir(directory);
	if (candidates == 0u) {
		errno = ENOENT;
		return -1;
	}
	if (candidates > 1u) {
		errno = EEXIST;
		return -1;
	}
	return verify(cld, selected, allow_stopped, dev, ino, identity);
}

static int pidfd_for(const struct nfsp_cld *cld,
		     const struct nfsp_cld_identity *identity)
{
	char state;
	uint64_t starttime;
	int fd = (int)syscall(SYS_pidfd_open, identity->pid, 0);

	if (fd < 0)
		return -1;
	/* The pidfd pins the process; if the start time still matches, the
	 * signals below cannot reach a reused PID. */
	if (read_stat(cld->config.proc_root, identity->pid, &state,
		      &starttime) != 0 || starttime != identity->starttime) {
		close(fd);
		errno = ESTALE;
		return -1;
	}
	return fd;
}

static int pidfd_signal(int fd, int sig)
{
	return (int)syscall(SYS_pidfd_send_signal, fd, sig, NULL, 0);
}

static int wait_exit(int pidfd, unsigned timeout_ms)
{
	uint64_t deadline = now_ms() + timeout_ms;

	for (;;) {
		struct pollfd p = {.fd = pidfd, .events = POLLIN};
		uint64_t now = now_ms();
		int rc;

		if (now >= deadline) {
			errno = ETIMEDOUT;
			return -1;
		}
		rc = poll(&p, 1, (int)(deadline - now));
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc < 0)
			return -1;
		if (rc > 0 && (p.revents & POLLIN) != 0)
			return 0;
	}
}

static int wait_stopped(const struct nfsp_cld *cld, pid_t pid,
			unsigned timeout_ms)
{
	uint64_t deadline = now_ms() + timeout_ms;

	for (;;) {
		char state;
		uint64_t starttime;

		if (read_stat(cld->config.proc_root, pid, &state, &starttime) != 0)
			return -1;
		if (state == 'T' || state == 't')
			return 0;
		if (now_ms() >= deadline) {
			errno = ETIMEDOUT;
			return -1;
		}
		sleep_ms(POLL_STEP_MS);
	}
}

const char *nfsp_cld_state_name(enum nfsp_cld_state state)
{
	switch (state) {
	case NFSP_CLD_IDLE: return "idle";
	case NFSP_CLD_HELD: return "held";
	case NFSP_CLD_DOWN: return "down";
	case NFSP_CLD_FAILED: return "failed";
	}
	return "invalid";
}

static const char *op_name(uint32_t op)
{
	switch (op) {
	case NFSP_LIFECYCLE_OP_CLD_RECONNECT: return "reconnect";
	case NFSP_LIFECYCLE_OP_CLD_DOWN: return "down";
	default: return "none";
	}
}

static void log_event(const struct nfsp_cld *cld, const char *event,
		      const struct nfsp_cld_identity *identity, int error)
{
	printf("cld event seq=%" PRIu64 " op=%s event=%s state=%s pid=%ld "
	       "starttime=%" PRIu64 " errno=%d\n", cld->seq, op_name(cld->op),
	       event, nfsp_cld_state_name(cld->state),
	       identity != NULL ? (long)identity->pid : 0L,
	       identity != NULL ? identity->starttime : 0u, error);
	fflush(stdout);
}

static void write_state(const struct nfsp_cld *cld)
{
	char tmp[PATH_MAX];
	const struct nfsp_cld_counters *c = &cld->counters;
	FILE *out;
	int n, fd, failed;

	if (cld->config.state_path == NULL)
		return;
	n = snprintf(tmp, sizeof(tmp), "%s.tmp", cld->config.state_path);
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
		  0600);
	if (fd < 0)
		return;
	out = fdopen(fd, "w");
	if (out == NULL) {
		close(fd);
		(void)unlink(tmp);
		return;
	}
	fprintf(out,
		"state=%s\nseq=%" PRIu64 "\nop=%s\npid=%ld\nstarttime=%" PRIu64
		"\npipe=%" PRIu64 ":%" PRIu64 "\nerrno=%d\n",
		nfsp_cld_state_name(cld->state), cld->seq, op_name(cld->op),
		(long)cld->current.pid, cld->current.starttime,
		cld->current.pipe_dev, cld->current.pipe_ino, cld->last_errno);
	fprintf(out,
		"reconnect_attempts=%" PRIu64 "\nreconnect_ok=%" PRIu64
		"\nreconnect_fail=%" PRIu64 "\ndown_attempts=%" PRIu64
		"\ndown_ok=%" PRIu64 "\ndown_fail=%" PRIu64
		"\ndaemon_stop_ok=%" PRIu64 "\ndaemon_stop_fail=%" PRIu64
		"\ndaemon_start_ok=%" PRIu64 "\ndaemon_start_fail=%" PRIu64
		"\nrefused_busy=%" PRIu64 "\nrefused_identity=%" PRIu64
		"\nrestore_ok=%" PRIu64 "\nrestore_fail=%" PRIu64 "\n",
		c->reconnect_attempts, c->reconnect_ok, c->reconnect_fail,
		c->down_attempts, c->down_ok, c->down_fail, c->daemon_stop_ok,
		c->daemon_stop_fail, c->daemon_start_ok, c->daemon_start_fail,
		c->refused_busy, c->refused_identity, c->restore_ok,
		c->restore_fail);
	failed = fflush(out) != 0 || fsync(fileno(out)) != 0;
	if (fclose(out) != 0 || failed ||
	    rename(tmp, cld->config.state_path) != 0)
		(void)unlink(tmp);
}

static unsigned count_candidates(const struct nfsp_cld *cld, int kill_them)
{
	DIR *directory = opendir(cld->config.proc_root);
	struct dirent *entry;
	unsigned count = 0;

	if (directory == NULL)
		return 0;
	while ((entry = readdir(directory)) != NULL) {
		long value;

		if (!numeric_name(entry->d_name))
			continue;
		value = strtol(entry->d_name, NULL, 10);
		if (value <= 0 || value > INT_MAX ||
		    !is_candidate(cld, (pid_t)value))
			continue;
		count++;
		if (kill_them) {
			int fd = (int)syscall(SYS_pidfd_open, (pid_t)value, 0);

			if (fd >= 0) {
				if (pidfd_signal(fd, SIGKILL) == 0)
					(void)wait_exit(fd,
						cld->config.stop_timeout_ms);
				close(fd);
			}
		}
	}
	closedir(directory);
	return count;
}

static int start_daemon_once(struct nfsp_cld *cld,
			     struct nfsp_cld_identity *out);

/* Start one replacement with the fixed argv and wait until exactly one
 * validated daemon owns the CLD pipe.  A launch that does not reach that
 * state leaves no daemon of this namespace behind. */
static int start_daemon(struct nfsp_cld *cld, struct nfsp_cld_identity *out)
{
	int saved;

	/* The previous daemon is gone; anything else is not ours. */
	if (count_candidates(cld, 0) != 0u) {
		errno = EEXIST;
		return -1;
	}
	if (start_daemon_once(cld, out) == 0)
		return 0;
	saved = errno;
	(void)count_candidates(cld, 1);
	memset(out, 0, sizeof(*out));
	errno = saved;
	return -1;
}

static int start_daemon_once(struct nfsp_cld *cld,
			     struct nfsp_cld_identity *out)
{
	uint64_t deadline = now_ms() + cld->config.start_timeout_ms;
	char arg0[] = NFSP_CLD_COMM;
	char *const argv[] = {arg0, NULL};
	int status = 0, saved;
	pid_t child;

	fflush(stdout);
	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		int null = open("/dev/null", O_RDWR | O_CLOEXEC);

		if (null < 0 || dup2(null, 0) < 0 || dup2(null, 1) < 0 ||
		    dup2(null, 2) < 0)
			_exit(126);
		execve(cld->config.daemon_path, argv, environ);
		_exit(127);
	}
	/* nfsdcld daemonizes: the launcher exits once the daemon is up. */
	for (;;) {
		pid_t done = waitpid(child, &status, WNOHANG);

		if (done == child)
			break;
		if (done < 0 && errno != EINTR)
			return -1;
		if (now_ms() >= deadline) {
			(void)kill(child, SIGKILL);
			(void)waitpid(child, &status, 0);
			errno = ETIMEDOUT;
			return -1;
		}
		sleep_ms(POLL_STEP_MS);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = ECHILD;
		return -1;
	}
	for (;;) {
		if (nfsp_cld_find(cld, 0, out) == 0)
			return 0;
		saved = errno;
		if (now_ms() >= deadline) {
			errno = saved == ENOENT ? ETIMEDOUT : saved;
			return -1;
		}
		sleep_ms(POLL_STEP_MS);
	}
}

int nfsp_cld_init(struct nfsp_cld *cld, const struct nfsp_cld_config *config)
{
	if (cld == NULL || config == NULL || config->proc_root == NULL ||
	    config->pipe_path == NULL || config->daemon_path == NULL ||
	    config->daemon_path[0] != '/' || config->hold_ms == 0u ||
	    config->down_ms == 0u || config->stop_timeout_ms == 0u ||
	    config->start_timeout_ms == 0u) {
		errno = EINVAL;
		return -1;
	}
	memset(cld, 0, sizeof(*cld));
	cld->config = *config;
	cld->pidfd = -1;
	cld->state = NFSP_CLD_IDLE;
	if (nfsp_cld_find(cld, 0, &cld->current) != 0)
		return -1;
	log_event(cld, "ready", &cld->current, 0);
	write_state(cld);
	return 0;
}

int nfsp_cld_pending(const struct nfsp_cld *cld)
{
	return cld->state == NFSP_CLD_HELD || cld->state == NFSP_CLD_DOWN;
}

int nfsp_cld_due_in_ms(const struct nfsp_cld *cld)
{
	uint64_t now;

	if (!nfsp_cld_pending(cld))
		return -1;
	now = now_ms();
	if (now >= cld->deadline_ms)
		return 0;
	if (cld->deadline_ms - now > (uint64_t)INT_MAX)
		return INT_MAX;
	return (int)(cld->deadline_ms - now);
}

static void fail_counter(struct nfsp_cld *cld)
{
	if (cld->op == NFSP_LIFECYCLE_OP_CLD_RECONNECT)
		cld->counters.reconnect_fail++;
	else
		cld->counters.down_fail++;
}

uint32_t nfsp_cld_begin(struct nfsp_cld *cld, uint32_t op,
			struct nfsp_cld_identity *identity)
{
	struct nfsp_cld_identity found = {0};
	int error;

	memset(identity, 0, sizeof(*identity));
	if (op != NFSP_LIFECYCLE_OP_CLD_RECONNECT &&
	    op != NFSP_LIFECYCLE_OP_CLD_DOWN)
		return EOPNOTSUPP;
	if (nfsp_cld_pending(cld)) {
		cld->counters.refused_busy++;
		write_state(cld);
		return EBUSY;
	}
	if (cld->state == NFSP_CLD_FAILED)
		return EIO;
	cld->seq++;
	cld->op = op;
	if (op == NFSP_LIFECYCLE_OP_CLD_RECONNECT)
		cld->counters.reconnect_attempts++;
	else
		cld->counters.down_attempts++;
	if (nfsp_cld_find(cld, 0, &found) != 0) {
		error = errno;
		goto refused;
	}
	/* The daemon this broker last validated, not merely some daemon. */
	if (found.pid != cld->current.pid ||
	    found.starttime != cld->current.starttime ||
	    found.pipe_dev != cld->current.pipe_dev ||
	    found.pipe_ino != cld->current.pipe_ino) {
		error = ESTALE;
		goto refused;
	}
	cld->pidfd = pidfd_for(cld, &found);
	if (cld->pidfd < 0) {
		error = errno;
		goto refused;
	}
	*identity = found;
	if (op == NFSP_LIFECYCLE_OP_CLD_RECONNECT) {
		if (pidfd_signal(cld->pidfd, SIGSTOP) != 0 ||
		    wait_stopped(cld, found.pid, cld->config.stop_timeout_ms) != 0) {
			error = errno;
			(void)pidfd_signal(cld->pidfd, SIGCONT);
			cld->counters.daemon_stop_fail++;
			goto failed;
		}
		cld->state = NFSP_CLD_HELD;
		cld->deadline_ms = now_ms() + cld->config.hold_ms;
		log_event(cld, "held", &found, 0);
	} else {
		if (pidfd_signal(cld->pidfd, SIGTERM) != 0) {
			error = errno;
			cld->counters.daemon_stop_fail++;
			goto failed;
		}
		if (wait_exit(cld->pidfd, cld->config.stop_timeout_ms) != 0) {
			/* Never leave a half-stopped daemon behind: the
			 * transaction fails and the daemon is replaced. */
			error = errno;
			cld->counters.daemon_stop_fail++;
			(void)pidfd_signal(cld->pidfd, SIGKILL);
			if (wait_exit(cld->pidfd, cld->config.stop_timeout_ms) != 0) {
				cld->state = NFSP_CLD_FAILED;
				cld->last_errno = error;
				fail_counter(cld);
				log_event(cld, "stop_failed", &found, error);
				write_state(cld);
				return (uint32_t)error;
			}
			goto restart_after_failure;
		}
		cld->counters.daemon_stop_ok++;
		cld->state = NFSP_CLD_DOWN;
		cld->deadline_ms = now_ms() + cld->config.down_ms;
		log_event(cld, "stopped", &found, 0);
	}
	cld->last_errno = 0;
	write_state(cld);
	return 0;

restart_after_failure:
	close(cld->pidfd);
	cld->pidfd = -1;
	if (start_daemon(cld, &found) == 0) {
		cld->counters.restore_ok++;
		cld->current = found;
		cld->state = NFSP_CLD_IDLE;
	} else {
		cld->counters.restore_fail++;
		cld->state = NFSP_CLD_FAILED;
	}
	cld->last_errno = error;
	fail_counter(cld);
	log_event(cld, "restored", &found, error);
	write_state(cld);
	return (uint32_t)error;

failed:
	close(cld->pidfd);
	cld->pidfd = -1;
	cld->last_errno = error;
	fail_counter(cld);
	log_event(cld, "stop_failed", &found, error);
	write_state(cld);
	return (uint32_t)error;

refused:
	cld->counters.refused_identity++;
	cld->last_errno = error;
	fail_counter(cld);
	log_event(cld, "refused", NULL, error);
	write_state(cld);
	return (uint32_t)error;
}

void nfsp_cld_tick(struct nfsp_cld *cld, int force)
{
	struct nfsp_cld_identity next = {0};
	int error = 0;

	if (!nfsp_cld_pending(cld) || (!force && now_ms() < cld->deadline_ms))
		return;
	if (cld->state == NFSP_CLD_HELD) {
		/* Killing the stopped reader closes the CLD pipe; the kernel
		 * fails queued upcalls with -EAGAIN and requeues them. */
		if (pidfd_signal(cld->pidfd, SIGKILL) != 0 ||
		    wait_exit(cld->pidfd, cld->config.stop_timeout_ms) != 0) {
			error = errno;
			cld->counters.daemon_stop_fail++;
			(void)pidfd_signal(cld->pidfd, SIGCONT);
			close(cld->pidfd);
			cld->pidfd = -1;
			cld->state = NFSP_CLD_FAILED;
			cld->last_errno = error;
			fail_counter(cld);
			log_event(cld, "kill_failed", &cld->current, error);
			write_state(cld);
			return;
		}
		cld->counters.daemon_stop_ok++;
		log_event(cld, "killed", &cld->current, 0);
	}
	close(cld->pidfd);
	cld->pidfd = -1;
	if (start_daemon(cld, &next) == 0) {
		cld->counters.daemon_start_ok++;
		if (cld->op == NFSP_LIFECYCLE_OP_CLD_RECONNECT)
			cld->counters.reconnect_ok++;
		else
			cld->counters.down_ok++;
		cld->current = next;
		cld->state = NFSP_CLD_IDLE;
		cld->last_errno = 0;
		log_event(cld, "started", &next, 0);
		write_state(cld);
		return;
	}
	error = errno;
	cld->counters.daemon_start_fail++;
	fail_counter(cld);
	/* One bounded restore attempt; a second failure is terminal. */
	if (start_daemon(cld, &next) == 0) {
		cld->counters.restore_ok++;
		cld->current = next;
		cld->state = NFSP_CLD_IDLE;
	} else {
		cld->counters.restore_fail++;
		cld->state = NFSP_CLD_FAILED;
	}
	cld->last_errno = error;
	log_event(cld, "start_failed", &next, error);
	write_state(cld);
}

void nfsp_cld_close(struct nfsp_cld *cld)
{
	if (cld == NULL)
		return;
	nfsp_cld_tick(cld, 1);
	if (cld->pidfd >= 0) {
		close(cld->pidfd);
		cld->pidfd = -1;
	}
}
