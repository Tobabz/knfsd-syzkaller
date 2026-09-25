// SPDX-License-Identifier: GPL-2.0
/*
 * Frozen Baseline Phase 4 guest probe.
 *
 * The parent owns a KCOV common handle whose value is its PID and opens the
 * matching program Generation through the Phase 4 debugfs ABI.  The child
 * inherits that handle, enables normal KCOV, and issues real NFS syscalls.
 * This is deliberately not a debugfs-only lifecycle test.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/kcov.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#define KCOV_ENTRIES (256U << 10)
#define PHASE3_CONTROL "/sys/kernel/debug/sunrpc_fuzz/phase3_control"
#define PHASE4_CONTROL "/sys/kernel/debug/sunrpc_fuzz/phase4_control"

/* Kept local so the probe can be built by the stock Debian guest compiler. */
struct kcov_remote_generation {
	uint64_t generation;
	uint32_t timeout_ms;
	uint32_t flags;
};

#define KCOV_REMOTE_GENERATION_BEGIN \
	_IOWR('c', 109, struct kcov_remote_generation)
#define KCOV_REMOTE_GENERATION_BIND \
	_IOW('c', 110, struct kcov_remote_generation)
#define KCOV_REMOTE_GENERATION_FINISH \
	_IOW('c', 111, struct kcov_remote_generation)
#define KCOV_REMOTE_GENERATION_ABORT \
	_IOW('c', 112, struct kcov_remote_generation)

struct kcov_session {
	int fd;
	unsigned long *area;
	size_t bytes;
};

static void die(const char *operation)
{
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
}

static void write_all(int fd, const void *buffer, size_t length)
{
	const char *cursor = buffer;

	while (length) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			die("write");
		}
		if (!written) {
			errno = EIO;
			die("short write");
		}
		cursor += written;
		length -= (size_t)written;
	}
}

static void control(const char *path, const char *format, unsigned long owner)
{
	char command[128];
	int length;
	int fd;

	length = snprintf(command, sizeof(command), format, owner);
	if (length < 0 || (size_t)length >= sizeof(command)) {
		errno = EOVERFLOW;
		die("format control command");
	}
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		die(path);
	write_all(fd, command, (size_t)length);
	if (close(fd))
		die("close control");
}

static unsigned long long stat_value(const char *name)
{
	char counter[96];
	unsigned long long value;
	FILE *stream;

	stream = fopen("/sys/kernel/debug/sunrpc_fuzz/phase4_stats", "re");
	if (!stream)
		die("open phase4_stats");
	while (fscanf(stream, "%95s %llu", counter, &value) == 2) {
		if (!strcmp(counter, name)) {
			if (fclose(stream))
				die("close phase4_stats");
			return value;
		}
	}
	fclose(stream);
	errno = EPROTO;
	die("missing phase4 counter");
	return 0;
}

static void wait_stat_after(const char *name, unsigned long long before)
{
	struct timespec delay = {
		.tv_sec = 0,
		.tv_nsec = 10000000,
	};

	for (unsigned int attempt = 0; attempt < 500; attempt++) {
		if (stat_value(name) > before)
			return;
		nanosleep(&delay, NULL);
	}
	errno = ETIMEDOUT;
	die("wait for phase4 counter");
}

static struct kcov_session kcov_owner_start(unsigned long owner)
{
	struct kcov_session session = {
		.fd = -1,
		.area = MAP_FAILED,
		.bytes = KCOV_ENTRIES * sizeof(unsigned long),
	};
	struct kcov_remote_arg remote = {
		.trace_mode = KCOV_TRACE_PC,
		.area_size = KCOV_ENTRIES,
		.num_handles = 0,
		.common_handle = (uint32_t)owner,
	};

	session.fd = open("/sys/kernel/debug/kcov", O_RDWR | O_CLOEXEC);
	if (session.fd < 0)
		die("open owner KCOV");
	if (ioctl(session.fd, KCOV_INIT_TRACE, KCOV_ENTRIES))
		die("owner KCOV_INIT_TRACE");
	session.area = mmap(NULL, session.bytes, PROT_READ | PROT_WRITE,
			    MAP_SHARED, session.fd, 0);
	if (session.area == MAP_FAILED)
		die("mmap owner KCOV");
	if (ioctl(session.fd, KCOV_REMOTE_ENABLE, &remote))
		die("KCOV_REMOTE_ENABLE common owner");
	return session;
}

static struct kcov_session kcov_start(void)
{
	struct kcov_session session = {
		.fd = -1,
		.area = MAP_FAILED,
		.bytes = KCOV_ENTRIES * sizeof(unsigned long),
	};

	session.fd = open("/sys/kernel/debug/kcov", O_RDWR | O_CLOEXEC);
	if (session.fd < 0)
		die("open KCOV");
	if (ioctl(session.fd, KCOV_INIT_TRACE, KCOV_ENTRIES))
		die("KCOV_INIT_TRACE");
	session.area = mmap(NULL, session.bytes, PROT_READ | PROT_WRITE,
			    MAP_SHARED, session.fd, 0);
	if (session.area == MAP_FAILED)
		die("mmap KCOV");
	session.area[0] = 0;
	if (ioctl(session.fd, KCOV_ENABLE, KCOV_TRACE_PC))
		die("KCOV_ENABLE");
	return session;
}

static unsigned long kcov_stop(struct kcov_session *session, bool owner)
{
	unsigned long entries = 0;

	if (!owner)
		entries = __atomic_load_n(&session->area[0], __ATOMIC_ACQUIRE);
	if (ioctl(session->fd, KCOV_DISABLE, 0))
		die("KCOV_DISABLE");
	if (munmap(session->area, session->bytes))
		die("munmap KCOV");
	if (close(session->fd))
		die("close KCOV");
	return entries;
}

static uint64_t generation_begin(int fd)
{
	struct kcov_remote_generation request = {};

	if (ioctl(fd, KCOV_REMOTE_GENERATION_BEGIN, &request))
		die("KCOV_REMOTE_GENERATION_BEGIN");
	if (!request.generation) {
		errno = EPROTO;
		die("zero kernel generation");
	}
	return request.generation;
}

static int generation_bind(int fd, uint64_t generation)
{
	struct kcov_remote_generation request = {
		.generation = generation,
	};

	return ioctl(fd, KCOV_REMOTE_GENERATION_BIND, &request);
}

static void generation_finish(int fd, uint64_t generation)
{
	struct kcov_remote_generation request = {
		.generation = generation,
		.timeout_ms = 5000,
	};

	if (ioctl(fd, KCOV_REMOTE_GENERATION_FINISH, &request))
		die("KCOV_REMOTE_GENERATION_FINISH");
}

static void generation_abort(int fd, uint64_t generation)
{
	struct kcov_remote_generation request = {
		.generation = generation,
	};

	if (ioctl(fd, KCOV_REMOTE_GENERATION_ABORT, &request))
		die("KCOV_REMOTE_GENERATION_ABORT");
}

static void exercise_nfs(int rootfd, unsigned int iteration)
{
	char original[96];
	char renamed[96];
	char payload[160];
	char received[sizeof(payload)];
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
	};
	ssize_t count;
	int fd;

	snprintf(original, sizeof(original), "phase4-%ld-%u.tmp",
		 (long)getpid(), iteration);
	snprintf(renamed, sizeof(renamed), "phase4-%ld-%u.done",
		 (long)getpid(), iteration);
	snprintf(payload, sizeof(payload), "phase4 owner=%ld iteration=%u\n",
		 (long)getppid(), iteration);
	fd = openat(rootfd, original, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
		    0600);
	if (fd < 0)
		die("openat NFS file");
	write_all(fd, payload, strlen(payload));
	if (fsync(fd))
		die("fsync NFS file");
	if (fcntl(fd, F_SETLK, &lock))
		die("lock NFS file");
	lock.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &lock))
		die("unlock NFS file");
	if (lseek(fd, 0, SEEK_SET) < 0)
		die("lseek NFS file");
	count = read(fd, received, sizeof(received));
	if (count < 0 || (size_t)count != strlen(payload) ||
	    memcmp(received, payload, (size_t)count)) {
		errno = EIO;
		die("verify NFS file");
	}
	if (close(fd))
		die("close NFS file");
	if (renameat(rootfd, original, rootfd, renamed))
		die("renameat NFS file");
	if (unlinkat(rootfd, renamed, 0))
		die("unlinkat NFS file");
}

static unsigned int parse_iterations(const char *argument)
{
	char *end = NULL;
	unsigned long value;

	errno = 0;
	value = strtoul(argument, &end, 10);
	if (errno || !end || *end || value < 2 || value > 1000) {
		fprintf(stderr, "iterations must be in 2..1000\n");
		exit(EXIT_FAILURE);
	}
	return (unsigned int)value;
}

static void byte_write(int fd)
{
	const char value = '1';

	write_all(fd, &value, 1);
}

static void byte_read(int fd)
{
	char value;
	ssize_t count;

	do {
		count = read(fd, &value, 1);
	} while (count < 0 && errno == EINTR);
	if (count != 1) {
		if (!count)
			errno = EPIPE;
		die("read synchronization byte");
	}
}

static unsigned long ownerless_nfs_worker(const char *mount,
		unsigned int iterations)
{
	unsigned long entries;
	int result_pipe[2];
	int status;
	pid_t child;

	if (pipe2(result_pipe, O_CLOEXEC))
		die("pipe2 ownerless worker");
	child = fork();
	if (child < 0)
		die("fork ownerless worker");
	if (!child) {
		struct kcov_session local_session = kcov_start();
		int rootfd = open(mount, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

		close(result_pipe[0]);
		if (rootfd < 0)
			die("open ownerless NFS mount root");
		for (unsigned int i = 0; i < iterations; i++)
			exercise_nfs(rootfd, i);
		if (close(rootfd))
			die("close ownerless NFS mount root");
		entries = kcov_stop(&local_session, false);
		write_all(result_pipe[1], &entries, sizeof(entries));
		_exit(EXIT_SUCCESS);
	}
	close(result_pipe[1]);
	if (read(result_pipe[0], &entries, sizeof(entries)) != sizeof(entries)) {
		errno = EIO;
		die("read ownerless worker result");
	}
	if (waitpid(child, &status, 0) != child)
		die("waitpid ownerless worker");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		errno = ECHILD;
		die("ownerless NFS worker failed");
	}
	return entries;
}

static int begin_orphan_scenario(struct kcov_session *owner_session,
		unsigned long owner, const char *mount, unsigned int iterations)
{
	unsigned long long entered;
	unsigned long entries;
	int status;
	pid_t child;

	entered = stat_value("generation_begin_publish_gap_entered");
	control(PHASE4_CONTROL,
		"fault-arm begin-before-publish %lu 0\n", owner);
	child = fork();
	if (child < 0)
		die("fork BEGIN orphan child");
	if (!child) {
		(void)generation_begin(owner_session->fd);
		_exit(77);
	}
	wait_stat_after("generation_begin_publish_gap_entered", entered);
	if (kill(child, SIGKILL))
		die("kill BEGIN orphan child");
	if (waitpid(child, &status, 0) != child)
		die("waitpid BEGIN orphan child");
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		errno = ECHILD;
		die("BEGIN orphan child was not killed");
	}
	/* The child is gone before the shared-fd current-generation fallback. */
	generation_abort(owner_session->fd, 0);
	entries = ownerless_nfs_worker(mount, iterations);
	kcov_stop(owner_session, true);
	printf("{\"status\":\"pass\",\"scenario\":\"begin-orphan\","
	       "\"owner\":%lu,\"generation\":0,\"old_generation\":0,"
	       "\"iterations\":%u,\"kcov_entries\":%lu}\n",
	       owner, iterations, entries);
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	struct kcov_session owner_session;
	unsigned int iterations;
	unsigned long owner;
	unsigned long entries;
	uint64_t old_generation = 0;
	uint64_t generation;
	bool automatic;
	bool abort_scenario;
	bool stale;
	int child_to_parent[2];
	int parent_to_child[2];
	int result_pipe[2];
	int status;
	pid_t child;

	if (argc != 4 ||
	    (strcmp(argv[1], "finish") && strcmp(argv[1], "inherited") &&
	     strcmp(argv[1], "begin-orphan") &&
	     strcmp(argv[1], "abort") &&
	     strcmp(argv[1], "closing-retry") &&
	     strcmp(argv[1], "abort-retry") &&
	     strcmp(argv[1], "connection-close") &&
	     strcmp(argv[1], "unbound") && strcmp(argv[1], "stale"))) {
		fprintf(stderr,
			"usage: %s finish|inherited|begin-orphan|abort|closing-retry|"
			"abort-retry|"
			"connection-close|unbound|stale "
			"MOUNT ITERATIONS\n", argv[0]);
		return EXIT_FAILURE;
	}
	iterations = parse_iterations(argv[3]);
	owner = (unsigned long)getpid();
	owner_session = kcov_owner_start(owner);
	if (!strcmp(argv[1], "begin-orphan"))
		return begin_orphan_scenario(&owner_session, owner, argv[2],
				iterations);
	generation = generation_begin(owner_session.fd);
	stale = !strcmp(argv[1], "stale");
	if (stale) {
		old_generation = generation;
		generation_finish(owner_session.fd, old_generation);
		generation = generation_begin(owner_session.fd);
		if (generation <= old_generation) {
			errno = EPROTO;
			die("non-monotonic kernel generation");
		}
	}
	automatic = !strcmp(argv[1], "closing-retry") ||
		    !strcmp(argv[1], "abort-retry");
	abort_scenario = !strcmp(argv[1], "abort");
	if (automatic) {
		char command[160];
		int length = snprintf(command, sizeof(command),
			!strcmp(argv[1], "closing-retry") ?
			"fault-arm closing-on-first-child %lu %llu\n" :
			"fault-arm abort-on-first-child %lu %llu\n",
			owner, (unsigned long long)generation);
		int fd;

		if (length < 0 || (size_t)length >= sizeof(command)) {
			errno = EOVERFLOW;
			die("format fault command");
		}
		fd = open(PHASE4_CONTROL, O_WRONLY | O_CLOEXEC);
		if (fd < 0)
			die(PHASE4_CONTROL);
		write_all(fd, command, (size_t)length);
		if (close(fd))
			die("close phase4 fault control");
		control(PHASE3_CONTROL, "fault-arm sunrpc-retry\n", 0);
	}
	if (pipe2(child_to_parent, O_CLOEXEC) ||
	    pipe2(parent_to_child, O_CLOEXEC) ||
	    pipe2(result_pipe, O_CLOEXEC))
		die("pipe2");
	child = fork();
	if (child < 0)
		die("fork");
	if (!child) {
		struct kcov_session local_session;
		int rootfd;

		close(child_to_parent[0]);
		close(parent_to_child[1]);
		close(result_pipe[0]);
		if (!strcmp(argv[1], "unbound")) {
			/* Explicit unbind succeeds, but leaves subsequent work ownerless. */
			if (generation_bind(owner_session.fd, 0))
				die("explicit generation unbind");
		} else if (stale) {
			errno = 0;
			if (!generation_bind(owner_session.fd, old_generation) ||
			    errno != ESTALE) {
				errno = EPROTO;
				die("stale generation BIND accepted");
			}
		} else if (strcmp(argv[1], "inherited") &&
			   generation_bind(owner_session.fd, generation)) {
			die("KCOV_REMOTE_GENERATION_BIND");
		}
		local_session = kcov_start();
		rootfd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (rootfd < 0)
			die("open NFS mount root");
		exercise_nfs(rootfd, 0);
		byte_write(child_to_parent[1]);
		byte_read(parent_to_child[0]);
		for (unsigned int i = 1; i < iterations; i++)
			exercise_nfs(rootfd, i);
		if (close(rootfd))
			die("close NFS mount root");
		entries = kcov_stop(&local_session, false);
		write_all(result_pipe[1], &entries, sizeof(entries));
		_exit(EXIT_SUCCESS);
	}
	close(child_to_parent[1]);
	close(parent_to_child[0]);
	close(result_pipe[1]);
	byte_read(child_to_parent[0]);
	if (!automatic && strcmp(argv[1], "unbound") && !stale) {
		if (abort_scenario)
			generation_abort(owner_session.fd, generation);
		else
			generation_finish(owner_session.fd, generation);
	}
	byte_write(parent_to_child[1]);
	if (read(result_pipe[0], &entries, sizeof(entries)) != sizeof(entries)) {
		errno = EIO;
		die("read child coverage result");
	}
	if (waitpid(child, &status, 0) != child)
		die("waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		fprintf(stderr, "NFS worker failed\n");
		return EXIT_FAILURE;
	}
	if (automatic) {
		if (!strcmp(argv[1], "closing-retry"))
			generation_finish(owner_session.fd, generation);
		else
			generation_abort(owner_session.fd, generation);
	} else if (!strcmp(argv[1], "unbound") || stale) {
		generation_finish(owner_session.fd, generation);
	}
	kcov_stop(&owner_session, true);
	printf("{\"status\":\"pass\",\"scenario\":\"%s\","
	       "\"owner\":%lu,\"generation\":%llu,"
	       "\"old_generation\":%llu,\"iterations\":%u,"
	       "\"kcov_entries\":%lu}\n",
	       argv[1], owner, (unsigned long long)generation,
	       (unsigned long long)old_generation, iterations, entries);
	return EXIT_SUCCESS;
}
