// SPDX-License-Identifier: GPL-2.0
/* Frozen Baseline Phase 5 real-NFS remote-admission probe. */

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
#include <time.h>
#include <unistd.h>

#define KCOV_ENTRIES (256U << 10)
#define PHASE5_CONTROL "/sys/kernel/debug/sunrpc_fuzz/phase5_control"
#define PHASE5_STATS "/sys/kernel/debug/sunrpc_fuzz/phase5_stats"

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

static struct kcov_session kcov_local_start(void)
{
	struct kcov_session session = {
		.fd = -1,
		.area = MAP_FAILED,
		.bytes = KCOV_ENTRIES * sizeof(unsigned long),
	};

	session.fd = open("/sys/kernel/debug/kcov", O_RDWR | O_CLOEXEC);
	if (session.fd < 0)
		die("open local KCOV");
	if (ioctl(session.fd, KCOV_INIT_TRACE, KCOV_ENTRIES))
		die("local KCOV_INIT_TRACE");
	session.area = mmap(NULL, session.bytes, PROT_READ | PROT_WRITE,
			    MAP_SHARED, session.fd, 0);
	if (session.area == MAP_FAILED)
		die("mmap local KCOV");
	session.area[0] = 0;
	if (ioctl(session.fd, KCOV_ENABLE, KCOV_TRACE_PC))
		die("local KCOV_ENABLE");
	return session;
}

static unsigned long kcov_stop(struct kcov_session *session, bool owner)
{
	unsigned long entries = owner ? 0 :
		__atomic_load_n(&session->area[0], __ATOMIC_ACQUIRE);

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
		die("zero generation");
	}
	return request.generation;
}

static void generation_bind(int fd, uint64_t generation)
{
	struct kcov_remote_generation request = { .generation = generation };

	if (ioctl(fd, KCOV_REMOTE_GENERATION_BIND, &request))
		die("KCOV_REMOTE_GENERATION_BIND");
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
	struct kcov_remote_generation request = { .generation = generation };

	if (ioctl(fd, KCOV_REMOTE_GENERATION_ABORT, &request))
		die("KCOV_REMOTE_GENERATION_ABORT");
}

static void control_write(const char *command)
{
	int fd = open(PHASE5_CONTROL, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		die(PHASE5_CONTROL);
	write_all(fd, command, strlen(command));
	if (close(fd))
		die("close phase5_control");
}

static unsigned long long stat_value(const char *name)
{
	char counter[96];
	unsigned long long value;
	FILE *stream = fopen(PHASE5_STATS, "re");

	if (!stream)
		die(PHASE5_STATS);
	while (fscanf(stream, "%95s %llu", counter, &value) == 2) {
		if (!strcmp(counter, name)) {
			if (fclose(stream))
				die("close phase5_stats");
			return value;
		}
	}
	fclose(stream);
	errno = EPROTO;
	die("missing phase5 counter");
	return 0;
}

static void wait_stat_after(const char *name, unsigned long long before)
{
	struct timespec delay = { .tv_nsec = 10000000 };

	for (unsigned int attempt = 0; attempt < 500; attempt++) {
		if (stat_value(name) > before)
			return;
		nanosleep(&delay, NULL);
	}
	errno = ETIMEDOUT;
	die("wait phase5 fault counter");
}

static void exercise_nfs(int rootfd, unsigned int iteration)
{
	char original[96];
	char renamed[96];
	char payload[128];
	char received[sizeof(payload)];
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};
	ssize_t count;
	int fd;

	snprintf(original, sizeof(original), "phase5-%ld-%u.tmp",
		 (long)getpid(), iteration);
	snprintf(renamed, sizeof(renamed), "phase5-%ld-%u.done",
		 (long)getpid(), iteration);
	snprintf(payload, sizeof(payload), "phase5 pid=%ld iteration=%u\n",
		 (long)getpid(), iteration);
	fd = openat(rootfd, original, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
		    0600);
	if (fd < 0)
		die("openat NFS file");
	write_all(fd, payload, strlen(payload));
	if (fsync(fd) || fcntl(fd, F_SETLK, &lock))
		die("fsync/lock NFS file");
	lock.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &lock) || lseek(fd, 0, SEEK_SET) < 0)
		die("unlock/lseek NFS file");
	count = read(fd, received, sizeof(received));
	if (count < 0 || (size_t)count != strlen(payload) ||
	    memcmp(received, payload, (size_t)count)) {
		errno = EIO;
		die("verify NFS file");
	}
	if (close(fd) || renameat(rootfd, original, rootfd, renamed) ||
	    unlinkat(rootfd, renamed, 0))
		die("close/rename/unlink NFS file");
}

static unsigned int parse_iterations(const char *argument)
{
	char *end = NULL;
	unsigned long value;

	errno = 0;
	value = strtoul(argument, &end, 10);
	if (errno || !end || *end || !value || value > 1000) {
		fprintf(stderr, "iterations must be in 1..1000\n");
		exit(EXIT_FAILURE);
	}
	return (unsigned int)value;
}

static unsigned long run_worker(int owner_fd, uint64_t generation,
		const char *mount, unsigned int iterations)
{
	unsigned long entries;
	int result_pipe[2];
	int status;
	pid_t child;

	if (pipe2(result_pipe, O_CLOEXEC))
		die("pipe2 result");
	child = fork();
	if (child < 0)
		die("fork NFS worker");
	if (!child) {
		struct kcov_session local;
		int rootfd;

		close(result_pipe[0]);
		generation_bind(owner_fd, generation);
		local = kcov_local_start();
		rootfd = open(mount, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (rootfd < 0)
			die("open NFS root");
		for (unsigned int i = 0; i < iterations; i++)
			exercise_nfs(rootfd, i);
		if (close(rootfd))
			die("close NFS root");
		entries = kcov_stop(&local, false);
		write_all(result_pipe[1], &entries, sizeof(entries));
		_exit(EXIT_SUCCESS);
	}
	close(result_pipe[1]);
	if (read(result_pipe[0], &entries, sizeof(entries)) != sizeof(entries)) {
		errno = EIO;
		die("read NFS worker result");
	}
	if (waitpid(child, &status, 0) != child)
		die("waitpid NFS worker");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		errno = ECHILD;
		die("NFS worker failed");
	}
	return entries;
}

static int run_participant(const char *role, const char *mount,
		const char *sync_dir, unsigned int iterations)
{
	struct kcov_session owner_session;
	char identity_path[256];
	char go_path[256];
	char temporary[272];
	char identity[128];
	unsigned long owner = (unsigned long)getpid();
	unsigned long entries;
	uint64_t generation;
	int length;
	int fd;

	owner_session = kcov_owner_start(owner);
	generation = generation_begin(owner_session.fd);
	snprintf(identity_path, sizeof(identity_path), "%s/%s.id", sync_dir, role);
	snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", identity_path,
		 (long)getpid());
	snprintf(go_path, sizeof(go_path), "%s/go", sync_dir);
	length = snprintf(identity, sizeof(identity), "%lu %llu\n", owner,
			  (unsigned long long)generation);
	if (length < 0 || (size_t)length >= sizeof(identity)) {
		errno = EOVERFLOW;
		die("format participant identity");
	}
	fd = open(temporary, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0)
		die("create participant identity");
	write_all(fd, identity, (size_t)length);
	if (close(fd) || rename(temporary, identity_path))
		die("publish participant identity");
	for (unsigned int attempt = 0; access(go_path, F_OK); attempt++) {
		if (attempt >= 500) {
			errno = ETIMEDOUT;
			die("wait nested-cross go");
		}
		usleep(10000);
	}
	entries = run_worker(owner_session.fd, generation, mount, iterations);
	generation_finish(owner_session.fd, generation);
	kcov_stop(&owner_session, true);
	printf("{\"status\":\"pass\",\"scenario\":\"nested-cross\","
	       "\"role\":\"%s\",\"owner\":%lu,\"generation\":%llu,"
	       "\"kcov_entries\":%lu}\n", role, owner,
	       (unsigned long long)generation, entries);
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	struct kcov_session owner_session;
	char command[192];
	unsigned long long paused = 0;
	unsigned long entries;
	unsigned long owner;
	unsigned int iterations;
	uint64_t generation;
	int length;

	if (argc == 6 && !strcmp(argv[1], "cross-participant"))
		return run_participant(argv[2], argv[3], argv[4],
				       parse_iterations(argv[5]));
	if (argc != 4 ||
	    (strcmp(argv[1], "normal") && strcmp(argv[1], "start-fail") &&
	     strcmp(argv[1], "pause-abort") &&
	     strcmp(argv[1], "nested-same"))) {
		fprintf(stderr, "usage: %s normal|start-fail|pause-abort|"
			"nested-same MOUNT ITERATIONS\n", argv[0]);
		return EXIT_FAILURE;
	}
	iterations = parse_iterations(argv[3]);
	owner = (unsigned long)getpid();
	owner_session = kcov_owner_start(owner);
	generation = generation_begin(owner_session.fd);
	if (strcmp(argv[1], "normal")) {
		const char *fault = !strcmp(argv[1], "start-fail") ?
			"start-fail" : (!strcmp(argv[1], "pause-abort") ?
			"pause-after-grant" : "nested-same");

		length = snprintf(command, sizeof(command),
				  "fault-arm %s %lu %llu\n", fault, owner,
				  (unsigned long long)generation);
		if (length < 0 || (size_t)length >= sizeof(command)) {
			errno = EOVERFLOW;
			die("format Phase5 fault");
		}
		control_write(command);
	}
	if (!strcmp(argv[1], "pause-abort")) {
		int sync_pipe[2];
		pid_t child;
		int status;

		paused = stat_value("fault_pause_after_grant_entered");
		if (pipe2(sync_pipe, O_CLOEXEC))
			die("pipe2 pause result");
		child = fork();
		if (child < 0)
			die("fork pause worker");
		if (!child) {
			unsigned long child_entries;

			close(sync_pipe[0]);
			child_entries = run_worker(owner_session.fd, generation,
						   argv[2], iterations);
			write_all(sync_pipe[1], &child_entries,
				  sizeof(child_entries));
			_exit(EXIT_SUCCESS);
		}
		close(sync_pipe[1]);
		wait_stat_after("fault_pause_after_grant_entered", paused);
		generation_abort(owner_session.fd, generation);
		control_write("fault-release pause-after-grant\n");
		if (read(sync_pipe[0], &entries, sizeof(entries)) != sizeof(entries)) {
			errno = EIO;
			die("read pause worker result");
		}
		if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
		    WEXITSTATUS(status) != EXIT_SUCCESS) {
			errno = ECHILD;
			die("pause worker failed");
		}
	} else {
		entries = run_worker(owner_session.fd, generation, argv[2],
				     iterations);
		generation_finish(owner_session.fd, generation);
	}
	kcov_stop(&owner_session, true);
	printf("{\"status\":\"pass\",\"scenario\":\"%s\","
	       "\"owner\":%lu,\"generation\":%llu,"
	       "\"kcov_entries\":%lu}\n", argv[1], owner,
	       (unsigned long long)generation, entries);
	return EXIT_SUCCESS;
}
