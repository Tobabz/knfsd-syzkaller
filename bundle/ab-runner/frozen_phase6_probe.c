// SPDX-License-Identifier: GPL-2.0
/* Frozen Baseline Phase 6 real-NFS scratch/aggregate publication probe. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/kcov.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
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
#define KCOV_CMP_WORDS 4U
#define DESTINATION_SEED ((unsigned long)UINT64_C(0x6b636f7650365eed))
#define PHASE5_CONTROL "/sys/kernel/debug/sunrpc_fuzz/phase5_control"
#define PHASE5_STATS "/sys/kernel/debug/sunrpc_fuzz/phase5_stats"
#define PHASE6_CONTROL "/sys/kernel/debug/sunrpc_fuzz/phase6_control"
#define PHASE6_STATS "/sys/kernel/debug/sunrpc_fuzz/phase6_stats"

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

struct worker {
	pid_t pid;
	int result_fd;
};

struct owner_exit_context {
	const char *mount;
	unsigned int iterations;
	unsigned long owner;
	uint64_t generation;
	struct kcov_session session;
	pthread_t finisher;
	atomic_int owner_ready_to_exit;
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

static struct kcov_session kcov_owner_start(unsigned long owner,
		unsigned int trace_mode)
{
	struct kcov_session session = {
		.fd = -1,
		.area = MAP_FAILED,
		.bytes = KCOV_ENTRIES * sizeof(unsigned long),
	};
	struct kcov_remote_arg remote = {
		.trace_mode = trace_mode,
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
	__atomic_store_n(&session.area[0], 0, __ATOMIC_RELEASE);
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

static void generation_abort_expect_busy(int fd, uint64_t generation)
{
	struct kcov_remote_generation request = { .generation = generation };

	errno = 0;
	if (ioctl(fd, KCOV_REMOTE_GENERATION_ABORT, &request) != -1 ||
	    errno != EBUSY) {
		errno = EPROTO;
		die("ABORT during PUBLISHING did not return EBUSY");
	}
}

static void generation_begin_expect_busy(int fd)
{
	struct kcov_remote_generation request = {};

	errno = 0;
	if (ioctl(fd, KCOV_REMOTE_GENERATION_BEGIN, &request) != -1 ||
	    errno != EBUSY) {
		errno = EPROTO;
		die("BEGIN during PUBLISHING did not return EBUSY");
	}
}

static void control_write(const char *path, const char *command)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		die(path);
	write_all(fd, command, strlen(command));
	if (close(fd))
		die("close control");
}

static unsigned long long stat_value(const char *path, const char *name)
{
	char line[256];
	FILE *stream = fopen(path, "re");
	unsigned long long value;

	if (!stream)
		die(path);
	while (fgets(line, sizeof(line), stream)) {
		char key[128];

		if (sscanf(line, "%127s %llu", key, &value) == 2 &&
		    !strcmp(key, name)) {
			fclose(stream);
			return value;
		}
	}
	fclose(stream);
	errno = ENOENT;
	die(name);
	return 0;
}

static void wait_stat_at_least(const char *path, const char *name,
		unsigned long long target)
{
	struct timespec delay = { .tv_nsec = 10000000 };

	for (unsigned int attempt = 0; attempt < 1000; attempt++) {
		if (stat_value(path, name) >= target)
			return;
		nanosleep(&delay, NULL);
	}
	errno = ETIMEDOUT;
	die(name);
}

static uint64_t remote_hash(const struct kcov_session *owner,
		unsigned long entries, unsigned int trace_mode,
		unsigned long *words_out)
{
	uint64_t hash = UINT64_C(1469598103934665603);
	unsigned long capacity;
	unsigned long words;

	capacity = trace_mode == KCOV_TRACE_CMP ?
		(KCOV_ENTRIES - 1) / KCOV_CMP_WORDS : KCOV_ENTRIES - 1;
	if (entries > capacity) {
		errno = EOVERFLOW;
		die("published KCOV entry count");
	}
	words = trace_mode == KCOV_TRACE_CMP ? entries * KCOV_CMP_WORDS : entries;
	*words_out = words;
	for (unsigned long i = 1; i <= words; i++) {
		hash ^= owner->area[i];
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

static void exercise_nfs(int rootfd, unsigned int iteration)
{
	char original[96];
	char renamed[96];
	char payload[128];
	char received[128] = {};
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 1,
	};
	ssize_t count;
	int fd;

	snprintf(original, sizeof(original), ".phase6-%ld-%u",
		 (long)getpid(), iteration);
	snprintf(renamed, sizeof(renamed), ".phase6-%ld-%u-renamed",
		 (long)getpid(), iteration);
	snprintf(payload, sizeof(payload), "phase6 pid=%ld iteration=%u\n",
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

static struct worker start_worker(int owner_fd, uint64_t generation,
		const char *mount, unsigned int iterations)
{
	struct worker worker;
	int result[2];

	if (pipe2(result, O_CLOEXEC))
		die("pipe2 worker result");
	worker.pid = fork();
	if (worker.pid < 0)
		die("fork NFS worker");
	if (!worker.pid) {
		struct kcov_session local;
		unsigned long entries;
		int rootfd;

		close(result[0]);
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
		write_all(result[1], &entries, sizeof(entries));
		_exit(EXIT_SUCCESS);
	}
	close(result[1]);
	worker.result_fd = result[0];
	return worker;
}

static unsigned long finish_worker(struct worker *worker)
{
	unsigned long entries;
	int status;

	if (read(worker->result_fd, &entries, sizeof(entries)) != sizeof(entries)) {
		errno = EIO;
		die("read NFS worker result");
	}
	close(worker->result_fd);
	if (waitpid(worker->pid, &status, 0) != worker->pid)
		die("waitpid NFS worker");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		errno = ECHILD;
		die("NFS worker failed");
	}
	return entries;
}

static unsigned int parse_count(const char *text, unsigned int maximum)
{
	char *end = NULL;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno || !end || *end || !value || value > maximum) {
		errno = EINVAL;
		die("invalid count");
	}
	return (unsigned int)value;
}

static void format_fault(char *buffer, size_t size, const char *name,
		unsigned long owner, uint64_t generation, unsigned int argument)
{
	int length;

	if (argument)
		length = snprintf(buffer, size, "fault-arm %s %lu %llu %u\n",
			name, owner, (unsigned long long)generation, argument);
	else
		length = snprintf(buffer, size, "fault-arm %s %lu %llu\n",
			name, owner, (unsigned long long)generation);
	if (length < 0 || (size_t)length >= size) {
		errno = EOVERFLOW;
		die("format fault");
	}
}

static void *owner_exit_finisher(void *argument)
{
	struct owner_exit_context *context = argument;

	generation_finish(context->session.fd, context->generation);
	return NULL;
}

static void *owner_exit_thread(void *argument)
{
	struct owner_exit_context *context = argument;
	char command[192];
	unsigned long long baseline;
	int rootfd;

	context->owner = (unsigned long)getpid();
	context->session = kcov_owner_start(context->owner, KCOV_TRACE_PC);
	context->generation = generation_begin(context->session.fd);
	rootfd = open(context->mount, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		die("open owner-exit NFS root");
	for (unsigned int i = 0; i < context->iterations; i++)
		exercise_nfs(rootfd, i);
	if (close(rootfd))
		die("close owner-exit NFS root");
	context->local_entries = 0;
	baseline = stat_value(PHASE6_STATS, "fault_pause_publish_entered");
	format_fault(command, sizeof(command), "pause-publish",
		context->owner, context->generation, 0);
	control_write(PHASE6_CONTROL, command);
	if (pthread_create(&context->finisher, NULL, owner_exit_finisher,
			   context)) {
		errno = EAGAIN;
		die("pthread_create owner-exit finisher");
	}
	wait_stat_at_least(PHASE6_STATS, "fault_pause_publish_entered",
		baseline + 1);
	atomic_store_explicit(&context->owner_ready_to_exit, 1,
		memory_order_release);
	/* Intentionally leave the remote KCOV fd/mmap to the surviving process. */
	return NULL;
}

static int run_owner_exit_publish(const char *mount, unsigned int iterations)
{
	struct owner_exit_context context = {
		.mount = mount,
		.iterations = iterations,
		.session = { .fd = -1, .area = MAP_FAILED },
	};
	struct timespec delay = { .tv_nsec = 10000000 };
	pthread_t owner_thread;
	unsigned long remote_entries;

	atomic_init(&context.owner_ready_to_exit, 0);
	if (pthread_create(&owner_thread, NULL, owner_exit_thread, &context)) {
		errno = EAGAIN;
		die("pthread_create owner thread");
	}
	while (!atomic_load_explicit(&context.owner_ready_to_exit,
					memory_order_acquire))
		nanosleep(&delay, NULL);
	if (pthread_join(owner_thread, NULL)) {
		errno = ECHILD;
		die("pthread_join owner thread");
	}
	control_write(PHASE6_CONTROL, "fault-release pause-publish\n");
	if (pthread_join(context.finisher, NULL)) {
		errno = ECHILD;
		die("pthread_join owner-exit finisher");
	}
	remote_entries = __atomic_load_n(&context.session.area[0],
		__ATOMIC_ACQUIRE);
	if (!context.iterations || remote_entries) {
		errno = EPROTO;
		die("owner-exit publication contract");
	}
	if (munmap(context.session.area, context.session.bytes) ||
	    close(context.session.fd))
		die("owner-exit KCOV cleanup");
	printf("{\"status\":\"pass\",\"scenario\":\"owner-exit-publish\","
	       "\"owner\":%lu,\"generation\":%llu,\"trace_mode\":\"PC\","
	       "\"local_entries\":0,\"workload_operations\":%u,"
	       "\"remote_entries\":0,"
	       "\"remote_words\":0,\"remote_hash\":0,"
	       "\"pre_publish_entries\":0,\"pre_finish_seed_entries\":0,"
	       "\"seed_overwritten\":false,\"publish_abort_busy\":false,"
	       "\"publish_begin_busy\":false,\"held_remote_refs\":0,"
	       "\"held_scratch\":0,\"held_publish_readers\":0}\n",
	       context.owner, (unsigned long long)context.generation,
	       context.iterations);
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	struct kcov_session owner_session;
	struct worker workers[8];
	char command[192];
	unsigned long long baseline;
	unsigned long local_entries = 0;
	unsigned long remote_entries;
	unsigned long remote_words = 0;
	unsigned long pre_publish_entries = 0;
	unsigned long pre_finish_seed_entries = 0;
	unsigned long long held_refs = 0;
	unsigned long long held_scratch = 0;
	unsigned long long held_readers = 0;
	unsigned long owner;
	unsigned int count;
	uint64_t generation;
	uint64_t hash;
	bool expect_publish;
	bool seed_overwritten = false;
	bool publish_abort_busy = false;
	bool publish_begin_busy = false;
	int status;
	unsigned int trace_mode;

	if (argc != 4 ||
	    (strcmp(argv[1], "normal") && strcmp(argv[1], "concurrent") &&
	     strcmp(argv[1], "cmp-normal") &&
	     strcmp(argv[1], "scratch-overflow") &&
	     strcmp(argv[1], "cmp-overflow") &&
	     strcmp(argv[1], "merge-truncate") &&
	     strcmp(argv[1], "cmp-truncate") &&
	     strcmp(argv[1], "abort") &&
	     strcmp(argv[1], "publish-lease") &&
	     strcmp(argv[1], "owner-exit-publish") &&
	     strcmp(argv[1], "nested-invalid"))) {
		fprintf(stderr, "usage: %s normal|concurrent|cmp-normal|"
			"scratch-overflow|cmp-overflow|merge-truncate|cmp-truncate|"
			"abort|publish-lease|owner-exit-publish|nested-invalid "
			"MOUNT COUNT\n", argv[0]);
		return EXIT_FAILURE;
	}
	count = parse_count(argv[3], !strcmp(argv[1], "concurrent") ? 8 : 100);
	if (!strcmp(argv[1], "owner-exit-publish"))
		return run_owner_exit_publish(argv[2], count);
	owner = (unsigned long)getpid();
	trace_mode = !strncmp(argv[1], "cmp-", 4) ?
		KCOV_TRACE_CMP : KCOV_TRACE_PC;
	owner_session = kcov_owner_start(owner, trace_mode);
	generation = generation_begin(owner_session.fd);
	expect_publish = !strcmp(argv[1], "normal") ||
			 !strcmp(argv[1], "cmp-normal") ||
			 !strcmp(argv[1], "concurrent") ||
			 !strcmp(argv[1], "publish-lease");

	if (!strcmp(argv[1], "scratch-overflow") ||
	    !strcmp(argv[1], "cmp-overflow")) {
		format_fault(command, sizeof(command), "scratch-limit", owner,
			generation, 8);
		control_write(PHASE6_CONTROL, command);
	} else if (!strcmp(argv[1], "merge-truncate") ||
		   !strcmp(argv[1], "cmp-truncate")) {
		format_fault(command, sizeof(command), "aggregate-limit", owner,
			generation, 8);
		control_write(PHASE6_CONTROL, command);
	} else if (!strcmp(argv[1], "nested-invalid")) {
		format_fault(command, sizeof(command), "nested-same", owner,
			generation, 0);
		control_write(PHASE5_CONTROL, command);
	}

	if (!strcmp(argv[1], "concurrent")) {
		unsigned int held = count < 2 ? count : 2;

		format_fault(command, sizeof(command), "hold-after-grant", owner,
			generation, held);
		control_write(PHASE6_CONTROL, command);
		baseline = stat_value(PHASE6_STATS, "fault_hold_after_grant_entered");
		for (unsigned int i = 0; i < count; i++)
			workers[i] = start_worker(owner_session.fd, generation,
				argv[2], 1);
		wait_stat_at_least(PHASE6_STATS, "fault_hold_after_grant_entered",
			baseline + held);
		held_refs = stat_value(PHASE6_STATS, "remote_refs");
		held_scratch = stat_value(PHASE6_STATS, "scratch_in_use");
		control_write(PHASE6_CONTROL, "fault-release hold-after-grant\n");
		for (unsigned int i = 0; i < count; i++)
			local_entries += finish_worker(&workers[i]);
	} else if (!strcmp(argv[1], "abort")) {
		baseline = stat_value(PHASE5_STATS,
			"fault_pause_after_grant_entered");
		format_fault(command, sizeof(command), "pause-after-grant", owner,
			generation, 0);
		control_write(PHASE5_CONTROL, command);
		workers[0] = start_worker(owner_session.fd, generation, argv[2], count);
		wait_stat_at_least(PHASE5_STATS, "fault_pause_after_grant_entered",
			baseline + 1);
		generation_abort(owner_session.fd, generation);
		control_write(PHASE5_CONTROL, "fault-release pause-after-grant\n");
		local_entries = finish_worker(&workers[0]);
	} else {
		workers[0] = start_worker(owner_session.fd, generation, argv[2], count);
		local_entries = finish_worker(&workers[0]);
	}

	if (!strcmp(argv[1], "normal")) {
		owner_session.area[1] = DESTINATION_SEED;
		__atomic_store_n(&owner_session.area[0], 1, __ATOMIC_RELEASE);
		pre_finish_seed_entries = 1;
	}

	if (!strcmp(argv[1], "publish-lease")) {
		pid_t child;

		baseline = stat_value(PHASE6_STATS, "fault_pause_publish_entered");
		format_fault(command, sizeof(command), "pause-publish", owner,
			generation, 0);
		control_write(PHASE6_CONTROL, command);
		child = fork();
		if (child < 0)
			die("fork finish publisher");
		if (!child) {
			generation_finish(owner_session.fd, generation);
			_exit(EXIT_SUCCESS);
		}
		wait_stat_at_least(PHASE6_STATS, "fault_pause_publish_entered",
			baseline + 1);
		pre_publish_entries = __atomic_load_n(&owner_session.area[0],
			__ATOMIC_ACQUIRE);
		held_readers = stat_value(PHASE6_STATS, "publish_readers");
		held_refs = stat_value(PHASE6_STATS, "remote_refs");
		generation_abort_expect_busy(owner_session.fd, generation);
		publish_abort_busy = true;
		generation_begin_expect_busy(owner_session.fd);
		publish_begin_busy = true;
		if (snprintf(command, sizeof(command), "probe-reuse %lu %llu\n",
			     owner, (unsigned long long)generation) >=
		    (int)sizeof(command)) {
			errno = EOVERFLOW;
			die("format reuse probe");
		}
		control_write(PHASE6_CONTROL, command);
		control_write(PHASE6_CONTROL, "fault-release pause-publish\n");
		if (waitpid(child, &status, 0) != child)
			die("waitpid publisher");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
			errno = ECHILD;
			die("publisher failed");
		}
	} else if (strcmp(argv[1], "abort")) {
		generation_finish(owner_session.fd, generation);
	}

	remote_entries = __atomic_load_n(&owner_session.area[0], __ATOMIC_ACQUIRE);
	hash = remote_hash(&owner_session, remote_entries, trace_mode,
		&remote_words);
	seed_overwritten = !strcmp(argv[1], "normal") &&
		!(remote_entries == 1 && owner_session.area[1] == DESTINATION_SEED);
	if (!local_entries || (expect_publish && (!remote_entries || !hash)) ||
	    (!expect_publish && remote_entries) ||
	    (!strcmp(argv[1], "normal") && !seed_overwritten)) {
		errno = EPROTO;
		die("remote publication contract");
	}
	kcov_stop(&owner_session, true);
	printf("{\"status\":\"pass\",\"scenario\":\"%s\","
	       "\"owner\":%lu,\"generation\":%llu,"
	       "\"trace_mode\":\"%s\",\"local_entries\":%lu,"
	       "\"remote_entries\":%lu,\"remote_words\":%lu,"
	       "\"remote_hash\":%llu,\"pre_publish_entries\":%lu,"
	       "\"pre_finish_seed_entries\":%lu,\"seed_overwritten\":%s,"
	       "\"publish_abort_busy\":%s,\"publish_begin_busy\":%s,"
	       "\"held_remote_refs\":%llu,\"held_scratch\":%llu,"
	       "\"held_publish_readers\":%llu}\n",
	       argv[1], owner, (unsigned long long)generation,
	       trace_mode == KCOV_TRACE_CMP ? "CMP" : "PC", local_entries,
	       remote_entries, remote_words, (unsigned long long)hash,
	       pre_publish_entries,
	       pre_finish_seed_entries,
	       seed_overwritten ? "true" : "false",
	       publish_abort_busy ? "true" : "false",
	       publish_begin_busy ? "true" : "false",
	       held_refs, held_scratch, held_readers);
	return EXIT_SUCCESS;
}
