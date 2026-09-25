// SPDX-License-Identifier: GPL-2.0
/*
 * Frozen Baseline Phase 2 guest probe.
 *
 * The owner opens an explicit program Generation before fork.  The freshly
 * forked per-program worker inherits the exact {handle, generation} pair and
 * enables normal KCOV in the same task that issues the NFS syscalls.  This
 * gives the kernel a real syscall-origin KCOV owner to capture; val-only
 * attribution is deliberately not supported.
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
#include <unistd.h>

#define KCOV_ENTRIES (256U << 10)

struct kcov_session {
	int fd;
	unsigned long *area;
	size_t bytes;
};

/* Kept local so the probe also builds against the disposable guest headers. */
struct kcov_remote_generation {
	uint64_t generation;
	uint32_t timeout_ms;
	uint32_t flags;
};

#define KCOV_REMOTE_GENERATION_BEGIN \
	_IOWR('c', 109, struct kcov_remote_generation)
#define KCOV_REMOTE_GENERATION_FINISH \
	_IOW('c', 111, struct kcov_remote_generation)
#define KCOV_REMOTE_GENERATION_ABORT \
	_IOW('c', 112, struct kcov_remote_generation)

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

static struct kcov_session kcov_start(void)
{
	struct kcov_session session = {
		.fd = -1,
		.area = MAP_FAILED,
		.bytes = KCOV_ENTRIES * sizeof(unsigned long),
	};

	session.fd = open("/sys/kernel/debug/kcov", O_RDWR | O_CLOEXEC);
	if (session.fd < 0)
		die("open /sys/kernel/debug/kcov");
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

static unsigned long kcov_stop(struct kcov_session *session)
{
	unsigned long entries = __atomic_load_n(&session->area[0],
						__ATOMIC_ACQUIRE);

	if (ioctl(session->fd, KCOV_DISABLE, 0))
		die("KCOV_DISABLE");
	if (munmap(session->area, session->bytes))
		die("munmap KCOV");
	if (close(session->fd))
		die("close KCOV");
	session->area = MAP_FAILED;
	session->fd = -1;
	return entries;
}

static struct kcov_session kcov_owner_start(void)
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
		/* Common subsystem is zero; instance must be nonzero. */
		.common_handle = (uint32_t)getpid() ?: 1,
	};

	session.fd = open("/sys/kernel/debug/kcov", O_RDWR | O_CLOEXEC);
	if (session.fd < 0)
		die("open owner /sys/kernel/debug/kcov");
	if (ioctl(session.fd, KCOV_INIT_TRACE, KCOV_ENTRIES))
		die("owner KCOV_INIT_TRACE");
	session.area = mmap(NULL, session.bytes, PROT_READ | PROT_WRITE,
			    MAP_SHARED, session.fd, 0);
	if (session.area == MAP_FAILED)
		die("mmap owner KCOV");
	session.area[0] = 0;
	if (ioctl(session.fd, KCOV_REMOTE_ENABLE, &remote))
		die("KCOV_REMOTE_ENABLE common owner");
	return session;
}

static void kcov_owner_stop(struct kcov_session *session)
{
	if (ioctl(session->fd, KCOV_DISABLE, 0))
		die("owner KCOV_DISABLE");
	if (munmap(session->area, session->bytes))
		die("munmap owner KCOV");
	if (close(session->fd))
		die("close owner KCOV");
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
	char payload[256];
	char received[sizeof(payload)];
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
	};
	int fd;
	ssize_t count;

	snprintf(original, sizeof(original), "phase2-%ld-%u.tmp",
		 (long)getpid(), iteration);
	snprintf(renamed, sizeof(renamed), "phase2-%ld-%u.done",
		 (long)getpid(), iteration);
	snprintf(payload, sizeof(payload),
		 "frozen-phase2 pid=%ld iteration=%u\n", (long)getpid(),
		 iteration);

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
	if (count < 0)
		die("read NFS file");
	if ((size_t)count != strlen(payload) ||
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
	if (errno || !end || *end || !value || value > 10000) {
		fprintf(stderr, "iterations must be in 1..10000\n");
		exit(EXIT_FAILURE);
	}
	return (unsigned int)value;
}

int main(int argc, char **argv)
{
	struct kcov_session session = {
		.fd = -1,
		.area = MAP_FAILED,
	};
	unsigned long coverage_entries = 0;
	unsigned int iterations;
	uint64_t generation = 0;
	bool attributed;
	int rootfd;

	if (argc != 4 ||
	    (strcmp(argv[1], "attributed") &&
	     strcmp(argv[1], "unattributed"))) {
		fprintf(stderr,
			"usage: %s attributed|unattributed MOUNT ITERATIONS\n",
			argv[0]);
		return EXIT_FAILURE;
	}
	attributed = !strcmp(argv[1], "attributed");
	iterations = parse_iterations(argv[3]);

	/*
	 * KCOV_ENABLE alone does not install a common handle.  The parent owns
	 * a remote-enabled KCOV descriptor, and fork causes kcov_task_init() to
	 * copy that common handle into the child.  The child then enables normal
	 * KCOV and issues the NFS calls, exactly like an executor worker.
	 */
	if (attributed) {
		struct kcov_session owner = kcov_owner_start();
		pid_t child;
		int status;

		generation = generation_begin(owner.fd);
		child = fork();
		if (child < 0)
			die("fork attributed worker");
		if (child > 0) {
			if (waitpid(child, &status, 0) != child)
				die("waitpid attributed worker");
			if (WIFEXITED(status) &&
			    WEXITSTATUS(status) == EXIT_SUCCESS)
				generation_finish(owner.fd, generation);
			else
				generation_abort(owner.fd, generation);
			kcov_owner_stop(&owner);
			if (!WIFEXITED(status)) {
				fprintf(stderr, "attributed worker terminated abnormally\n");
				return EXIT_FAILURE;
			}
			return WEXITSTATUS(status);
		}
	}

	rootfd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		die("open NFS mount root");

	if (attributed)
		session = kcov_start();
	for (unsigned int i = 0; i < iterations; i++)
		exercise_nfs(rootfd, i);
	if (attributed)
		coverage_entries = kcov_stop(&session);
	if (close(rootfd))
		die("close NFS mount root");

	printf("{\"status\":\"pass\",\"mode\":\"%s\","
	       "\"iterations\":%u,\"generation\":%llu,"
	       "\"kcov_entries\":%lu}\n",
	       attributed ? "attributed" : "unattributed", iterations,
	       (unsigned long long)generation, coverage_entries);
	return EXIT_SUCCESS;
}
