// SPDX-License-Identifier: GPL-2.0
/* Frozen Baseline Phase 8 real deferred-replay and async-COPY probe. */

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

#define KCOV_ENTRIES (1U << 20)
#define COPY_BYTES (4U << 20)
#define IO_BYTES (64U << 10)
#define PHASE8_CONTROL "/sys/kernel/debug/sunrpc_fuzz/phase8_control"
#define PHASE8_STATS "/sys/kernel/debug/sunrpc_fuzz/phase8_stats"

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

struct child_result {
	uint64_t operation_bytes;
	uint64_t content_hash;
	unsigned long local_entries;
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

static void read_all(int fd, void *buffer, size_t length)
{
	char *cursor = buffer;

	while (length) {
		ssize_t received = read(fd, cursor, length);

		if (received < 0) {
			if (errno == EINTR)
				continue;
			die("read");
		}
		if (!received) {
			errno = EIO;
			die("short read");
		}
		cursor += received;
		length -= (size_t)received;
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
	session.area[0] = 0;
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
	int fd = open(PHASE8_CONTROL, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		die(PHASE8_CONTROL);
	write_all(fd, command, strlen(command));
	if (close(fd))
		die("close phase8_control");
}

static unsigned long long stat_value(const char *name)
{
	char counter[96];
	unsigned long long value;
	FILE *stream = fopen(PHASE8_STATS, "re");

	if (!stream)
		die(PHASE8_STATS);
	while (fscanf(stream, "%95s %llu", counter, &value) == 2) {
		if (!strcmp(counter, name)) {
			if (fclose(stream))
				die("close phase8_stats");
			return value;
		}
	}
	fclose(stream);
	errno = EPROTO;
	die("missing phase8 counter");
	return 0;
}

static void wait_stat_after(const char *name, unsigned long long before)
{
	struct timespec delay = { .tv_nsec = 10000000 };

	for (unsigned int attempt = 0; attempt < 6000; attempt++) {
		if (stat_value(name) > before)
			return;
		nanosleep(&delay, NULL);
	}
	errno = ETIMEDOUT;
	die("wait phase8 fault counter");
}

static uint64_t hash_bytes(uint64_t hash, const unsigned char *data,
		size_t length)
{
	for (size_t i = 0; i < length; i++) {
		hash ^= data[i];
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

static void fill_pattern(unsigned char *buffer, size_t length, size_t offset)
{
	for (size_t i = 0; i < length; i++)
		buffer[i] = (unsigned char)(((offset + i) * 131U +
					 ((offset + i) >> 7) + 0x5aU) & 0xffU);
}

static uint64_t prepare_copy(const char *source, const char *destination)
{
	unsigned char *buffer = malloc(IO_BYTES);
	uint64_t hash = UINT64_C(1469598103934665603);
	int source_fd;
	int destination_fd;

	if (!buffer)
		die("malloc copy buffer");
	source_fd = open(source, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (source_fd < 0)
		die("create COPY source");
	for (size_t offset = 0; offset < COPY_BYTES; offset += IO_BYTES) {
		fill_pattern(buffer, IO_BYTES, offset);
		write_all(source_fd, buffer, IO_BYTES);
		hash = hash_bytes(hash, buffer, IO_BYTES);
	}
	if (fsync(source_fd) || close(source_fd))
		die("sync COPY source");
	destination_fd = open(destination,
		O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (destination_fd < 0)
		die("create COPY destination");
	if (close(destination_fd))
		die("close COPY destination");
	free(buffer);
	return hash;
}

static struct child_result exercise_async_copy(const char *source,
		const char *destination)
{
	struct child_result result = {};
	unsigned char *buffer = malloc(IO_BYTES);
	struct stat status;
	loff_t source_offset = 0;
	loff_t destination_offset = 0;
	ssize_t copied;
	int source_fd;
	int destination_fd;

	if (!buffer)
		die("malloc verify buffer");
	source_fd = open(source, O_RDONLY | O_CLOEXEC);
	if (source_fd < 0)
		die("open COPY source");
	destination_fd = open(destination, O_RDWR | O_CLOEXEC);
	if (destination_fd < 0)
		die("open COPY destination");
	do {
		copied = copy_file_range(source_fd, &source_offset, destination_fd,
			&destination_offset, COPY_BYTES, 0);
	} while (copied < 0 && errno == EINTR);
	if (copied != COPY_BYTES) {
		errno = copied < 0 ? errno : EIO;
		die("single async COPY");
	}
	if (fsync(destination_fd) || fstat(destination_fd, &status))
		die("sync/stat COPY destination");
	if (status.st_size != COPY_BYTES) {
		errno = EIO;
		die("COPY destination size");
	}
	result.content_hash = UINT64_C(1469598103934665603);
	for (size_t offset = 0; offset < COPY_BYTES; offset += IO_BYTES) {
		ssize_t received = pread(destination_fd, buffer, IO_BYTES,
					 (off_t)offset);

		if (received != IO_BYTES) {
			errno = received < 0 ? errno : EIO;
			die("read COPY destination");
		}
		result.content_hash = hash_bytes(result.content_hash, buffer,
			IO_BYTES);
	}
	if (close(destination_fd) || close(source_fd))
		die("close COPY files");
	free(buffer);
	result.operation_bytes = COPY_BYTES;
	return result;
}

static struct child_result exercise_deferred_lookup(const char *mount)
{
	struct child_result result = {};
	char path[512];
	char buffer[128];
	ssize_t received;
	int fd;

	if (snprintf(path, sizeof(path), "%s/shared/fixture", mount) >=
			(int)sizeof(path)) {
		errno = ENAMETOOLONG;
		die("format deferred lookup path");
	}
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open deferred fixture");
	do {
		received = read(fd, buffer, sizeof(buffer));
	} while (received < 0 && errno == EINTR);
	if (received <= 0)
		die("read deferred fixture");
	if (close(fd))
		die("close deferred fixture");
	result.operation_bytes = (uint64_t)received;
	result.content_hash = hash_bytes(UINT64_C(1469598103934665603),
		(const unsigned char *)buffer, (size_t)received);
	return result;
}

static void write_identity(const char *path, unsigned long owner,
		uint64_t generation)
{
	char buffer[128];
	char temporary[512];
	int length;
	int fd;

	length = snprintf(buffer, sizeof(buffer), "%lu %llu\n", owner,
		(unsigned long long)generation);
	if (length < 0 || (size_t)length >= sizeof(buffer) ||
	    snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
		     (long)getpid()) >= (int)sizeof(temporary)) {
		errno = EOVERFLOW;
		die("format identity");
	}
	fd = open(temporary, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0)
		die("create identity");
	write_all(fd, buffer, (size_t)length);
	if (close(fd) || rename(temporary, path))
		die("publish identity");
}

static struct child_result run_child(int owner_fd, uint64_t generation,
		const char *scenario, const char *mount, const char *source,
		const char *destination, bool pause_after_grant, bool async)
{
	struct child_result result;
	const char *pause_counter = async ?
		"async_pause_after_grant_entered" :
		"deferred_pause_after_grant_entered";
	const char *release_command = async ?
		"fault-release pause-async-after-grant\n" :
		"fault-release pause-deferred-after-grant\n";
	unsigned long long paused = 0;
	int result_pipe[2];
	int status;
	pid_t child;

	if (pause_after_grant)
		paused = stat_value(pause_counter);
	if (pipe2(result_pipe, O_CLOEXEC))
		die("pipe2 child result");
	child = fork();
	if (child < 0)
		die("fork workload child");
	if (!child) {
		struct kcov_session local;
		struct child_result child_result;

		close(result_pipe[0]);
		generation_bind(owner_fd, generation);
		local = kcov_local_start();
		if (!strncmp(scenario, "async-", 6))
			child_result = exercise_async_copy(source, destination);
		else
			child_result = exercise_deferred_lookup(mount);
		child_result.local_entries = kcov_stop(&local, false);
		write_all(result_pipe[1], &child_result, sizeof(child_result));
		_exit(EXIT_SUCCESS);
	}
	close(result_pipe[1]);
	if (pause_after_grant) {
		wait_stat_after(pause_counter, paused);
		generation_abort(owner_fd, generation);
		control_write(release_command);
	}
	read_all(result_pipe[0], &result, sizeof(result));
	if (close(result_pipe[0]))
		die("close child result");
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS) {
		errno = ECHILD;
		die("workload child failed");
	}
	return result;
}

int main(int argc, char **argv)
{
	struct kcov_session owner_session;
	struct child_result result;
	char source[512] = {};
	char destination[512] = {};
	const char *scenario;
	const char *close_mode;
	uint64_t expected_hash = 0;
	uint64_t generation;
	unsigned long remote_entries;
	unsigned long owner;
	bool async;
	bool abort_before;
	bool abort_after;

	if (argc != 4) {
		fprintf(stderr, "usage: %s SCENARIO MOUNT IDENTITY\n", argv[0]);
		return EXIT_FAILURE;
	}
	scenario = argv[1];
	async = !strncmp(scenario, "async-", 6);
	abort_before = strstr(scenario, "abort-before-grant") != NULL;
	abort_after = strstr(scenario, "abort-after-grant") != NULL;
	if ((strcmp(scenario, "async-normal") &&
	     strcmp(scenario, "async-abort-before-grant") &&
	     strcmp(scenario, "async-abort-after-grant") &&
	     strcmp(scenario, "deferred-normal") &&
	     strcmp(scenario, "deferred-abort-before-grant") &&
	     strcmp(scenario, "deferred-abort-after-grant")) ||
	    (abort_before && abort_after)) {
		errno = EINVAL;
		die("invalid scenario");
	}
	if (async) {
		if (snprintf(source, sizeof(source), "%s/shared/.phase8-src-%ld",
			     argv[2], (long)getpid()) >= (int)sizeof(source) ||
		    snprintf(destination, sizeof(destination),
			     "%s/shared/.phase8-dst-%ld", argv[2],
			     (long)getpid()) >= (int)sizeof(destination)) {
			errno = ENAMETOOLONG;
			die("format COPY paths");
		}
		expected_hash = prepare_copy(source, destination);
	}
	owner = (unsigned long)getpid();
	owner_session = kcov_owner_start(owner);
	generation = generation_begin(owner_session.fd);
	write_identity(argv[3], owner, generation);
	if (!strcmp(scenario, "async-abort-before-grant"))
		control_write("fault-arm abort-next-async\n");
	else if (!strcmp(scenario, "deferred-abort-before-grant"))
		control_write("abort-next-deferred\n");
	else if (!strcmp(scenario, "async-abort-after-grant"))
		control_write("fault-arm pause-next-async-after-grant\n");
	else if (!strcmp(scenario, "deferred-abort-after-grant"))
		control_write("fault-arm pause-next-deferred-after-grant\n");
	result = run_child(owner_session.fd, generation, scenario, argv[2],
		source, destination, abort_after, async);
	if (!abort_before && !abort_after) {
		generation_finish(owner_session.fd, generation);
		close_mode = "finish";
	} else if (abort_after) {
		close_mode = "abort-after-grant";
	} else {
		close_mode = "abort-before-grant";
	}
	remote_entries = __atomic_load_n(&owner_session.area[0],
		__ATOMIC_ACQUIRE);
	if (!result.local_entries || !result.operation_bytes ||
	    (async && (result.operation_bytes != COPY_BYTES ||
		result.content_hash != expected_hash)) ||
	    ((!abort_before && !abort_after) != (remote_entries > 0))) {
		fprintf(stderr,
			"Phase8 contract detail: local=%lu bytes=%llu "
			"hash=%llu expected=%llu remote=%lu normal=%u\n",
			result.local_entries,
			(unsigned long long)result.operation_bytes,
			(unsigned long long)result.content_hash,
			(unsigned long long)expected_hash, remote_entries,
			!abort_before && !abort_after);
		errno = EPROTO;
		die("Phase8 result contract");
	}
	kcov_stop(&owner_session, true);
	if (async && (unlink(source) || unlink(destination)))
		die("unlink COPY files");
	if (unlink(argv[3]) && errno != ENOENT)
		die("unlink identity");
	printf("{\"status\":\"pass\",\"scenario\":\"%s\","
	       "\"owner\":%lu,\"generation\":%llu,"
	       "\"close_mode\":\"%s\",\"operation_bytes\":%llu,"
	       "\"content_hash\":%llu,\"expected_hash\":%llu,"
	       "\"local_entries\":%lu,\"remote_entries\":%lu}\n",
	       scenario, owner, (unsigned long long)generation, close_mode,
	       (unsigned long long)result.operation_bytes,
	       (unsigned long long)result.content_hash,
	       (unsigned long long)expected_hash, result.local_entries,
	       remote_entries);
	return EXIT_SUCCESS;
}
