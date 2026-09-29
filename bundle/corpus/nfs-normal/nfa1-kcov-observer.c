// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kcov.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KCOV_DEVICE "/sys/kernel/debug/kcov"
#define KCOV_ENTRIES (1U << 20)
#define NFSD_OBSERVE_HANDLE UINT64_C(0x0200000000000001)
#define HANDSHAKE_TIMEOUT_MS 10000

enum startup_stage {
	START_READY, START_SETSID, START_OPEN_KCOV, START_INIT_TRACE,
	START_MMAP, START_REMOTE_ENABLE, START_SOCKET, START_BIND, START_LISTEN,
};

struct startup_message {
	int stage;
	int error;
};

static const char *cleanup_socket_path;

static void cleanup_socket(void)
{
	if (cleanup_socket_path != NULL)
		(void)unlink(cleanup_socket_path);
}

static void signal_exit(int signal_number)
{
	if (cleanup_socket_path != NULL)
		(void)unlink(cleanup_socket_path);
	_exit(128 + signal_number);
}

static int install_cleanup_handlers(void)
{
	static const int signals[] = {
		SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGABRT, SIGPIPE,
	};
	struct sigaction action = {.sa_handler = signal_exit};
	size_t i;

	sigemptyset(&action.sa_mask);
	for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		if (sigaction(signals[i], &action, NULL) < 0)
			return -1;
	}
	return 0;
}

static const char *stage_name(int stage)
{
	switch (stage) {
	case START_SETSID: return "setsid";
	case START_OPEN_KCOV: return "open kcov";
	case START_INIT_TRACE: return "KCOV_INIT_TRACE";
	case START_MMAP: return "mmap kcov";
	case START_REMOTE_ENABLE: return "KCOV_REMOTE_ENABLE";
	case START_SOCKET: return "socket";
	case START_BIND: return "bind observer socket";
	case START_LISTEN: return "listen observer socket";
	default: return "unknown startup stage";
	}
}

static char *path_with_suffix(const char *prefix, const char *suffix)
{
	size_t prefix_length = strlen(prefix);
	size_t suffix_length = strlen(suffix);
	char *path;

	if (prefix_length > SIZE_MAX - suffix_length - 1) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	path = malloc(prefix_length + suffix_length + 1);
	if (path == NULL)
		return NULL;
	memcpy(path, prefix, prefix_length);
	memcpy(path + prefix_length, suffix, suffix_length + 1);
	return path;
}

static int64_t monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int wait_readable(int fd, int timeout_ms)
{
	struct pollfd descriptor = {.fd = fd, .events = POLLIN};
	int64_t deadline = monotonic_milliseconds();

	if (deadline < 0)
		return -1;
	deadline += timeout_ms;
	for (;;) {
		int64_t now = monotonic_milliseconds();
		int remaining;
		int result;

		if (now < 0)
			return -1;
		remaining = now >= deadline ? 0 : (int)(deadline - now);
		result = poll(&descriptor, 1, remaining);
		if (result > 0)
			return 0;
		if (result == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (errno != EINTR)
			return -1;
	}
}

static int write_all(int fd, const void *buffer, size_t length)
{
	const char *cursor = buffer;

	while (length != 0) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (written == 0) {
			errno = EIO;
			return -1;
		}
		cursor += written;
		length -= (size_t)written;
	}
	return 0;
}

static void report_startup(int fd, enum startup_stage stage, int error)
{
	struct startup_message message = {.stage = stage, .error = error};

	(void)write_all(fd, &message, sizeof(message));
}

static int make_listener(const char *path)
{
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	sigset_t blocked_signals;
	sigset_t old_mask;
	int saved_errno;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	memcpy(address.sun_path, path, strlen(path) + 1);
	sigfillset(&blocked_signals);
	if (sigprocmask(SIG_BLOCK, &blocked_signals, &old_mask) < 0) {
		saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		saved_errno = errno;
		(void)close(fd);
		(void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
		errno = saved_errno;
		return -2;
	}
	cleanup_socket_path = path;
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0) {
		saved_errno = errno;
		(void)close(fd);
		cleanup_socket();
		cleanup_socket_path = NULL;
		errno = saved_errno;
		return -1;
	}
	if (listen(fd, 1) < 0) {
		saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -3;
	}
	return fd;
}

static int flush_and_close(FILE *stream)
{
	int saved_errno = 0;

	if (fflush(stream) != 0)
		saved_errno = errno;
	else if (fsync(fileno(stream)) != 0)
		saved_errno = errno;
	if (fclose(stream) != 0 && saved_errno == 0)
		saved_errno = errno;
	if (saved_errno != 0) {
		errno = saved_errno;
		return -1;
	}
	return 0;
}

static int write_results(const char *prefix, const unsigned long *area)
{
	const size_t capacity = KCOV_ENTRIES - 1;
	unsigned long observed = __atomic_load_n(&area[0], __ATOMIC_ACQUIRE);
	size_t count = observed > capacity ? capacity : (size_t)observed;
	char *pcs_path = path_with_suffix(prefix, ".pcs");
	char *meta_path = path_with_suffix(prefix, ".meta");
	FILE *pcs = NULL;
	FILE *meta = NULL;
	size_t i;
	int result = -1;

	if (pcs_path == NULL || meta_path == NULL)
		goto out;
	pcs = fopen(pcs_path, "w");
	if (pcs == NULL)
		goto out;
	for (i = 0; i < count; i++) {
		if (fprintf(pcs, "0x%lx\n", area[i + 1]) < 0)
			goto out;
	}
	if (flush_and_close(pcs) < 0) {
		pcs = NULL;
		goto out;
	}
	pcs = NULL;
	meta = fopen(meta_path, "w");
	if (meta == NULL)
		goto out;
	if (fprintf(meta,
		    "handle=0x%016" PRIx64 "\n"
		    "capacity=%zu\ncount=%zu\nsaturated=%d\nstatus=stopped\n",
		    NFSD_OBSERVE_HANDLE, capacity, count,
		    observed >= capacity ? 1 : 0) < 0)
		goto out;
	if (flush_and_close(meta) < 0) {
		meta = NULL;
		goto out;
	}
	meta = NULL;
	result = 0;
out:
	if (pcs != NULL)
		(void)fclose(pcs);
	if (meta != NULL)
		(void)fclose(meta);
	free(pcs_path);
	free(meta_path);
	return result;
}

static int wait_for_stop(int listener)
{
	static const char expected[] = "STOP\n";
	char request[sizeof(expected) - 1];
	size_t received = 0;
	int connection;

	for (;;) {
		connection = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
		if (connection >= 0)
			break;
		if (errno != EINTR)
			return -1;
	}
	while (received < sizeof(request)) {
		ssize_t amount = read(connection, request + received,
				      sizeof(request) - received);
		if (amount < 0) {
			if (errno == EINTR)
				continue;
			(void)close(connection);
			return -1;
		}
		if (amount == 0) {
			(void)close(connection);
			errno = EPROTO;
			return -1;
		}
		received += (size_t)amount;
	}
	if (memcmp(request, expected, sizeof(request)) != 0) {
		(void)close(connection);
		errno = EPROTO;
		return -1;
	}
	return connection;
}

static void collector(const char *prefix, const char *socket_path, int ready_fd)
{
	struct kcov_remote_arg *remote;
	unsigned long *area = MAP_FAILED;
	size_t map_bytes = (size_t)KCOV_ENTRIES * sizeof(*area);
	int null_fd;
	int kcov_fd;
	int listener;
	int connection;
	int listener_result;
	int saved_errno;

	if (atexit(cleanup_socket) != 0 || install_cleanup_handlers() < 0) {
		report_startup(ready_fd, START_SOCKET, errno != 0 ? errno : EIO);
		_exit(EXIT_FAILURE);
	}
	if (setsid() < 0) {
		report_startup(ready_fd, START_SETSID, errno);
		exit(EXIT_FAILURE);
	}
	/* An SSH command must not wait for a detached child's inherited stdio. */
	null_fd = open("/dev/null", O_RDWR);
	if (null_fd < 0 ||
	    dup2(null_fd, STDIN_FILENO) < 0 ||
	    dup2(null_fd, STDOUT_FILENO) < 0 ||
	    dup2(null_fd, STDERR_FILENO) < 0) {
		report_startup(ready_fd, START_SETSID, errno);
		exit(EXIT_FAILURE);
	}
	if (null_fd > STDERR_FILENO)
		(void)close(null_fd);
	kcov_fd = open(KCOV_DEVICE, O_RDWR | O_CLOEXEC);
	if (kcov_fd < 0) {
		report_startup(ready_fd, START_OPEN_KCOV, errno);
		exit(EXIT_FAILURE);
	}
	if (ioctl(kcov_fd, KCOV_INIT_TRACE, KCOV_ENTRIES) < 0) {
		report_startup(ready_fd, START_INIT_TRACE, errno);
		exit(EXIT_FAILURE);
	}
	area = mmap(NULL, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
		    kcov_fd, 0);
	if (area == MAP_FAILED) {
		report_startup(ready_fd, START_MMAP, errno);
		exit(EXIT_FAILURE);
	}
	remote = calloc(1, sizeof(*remote) + sizeof(remote->handles[0]));
	if (remote == NULL) {
		report_startup(ready_fd, START_REMOTE_ENABLE, errno);
		exit(EXIT_FAILURE);
	}
	remote->trace_mode = KCOV_TRACE_PC;
	remote->area_size = KCOV_ENTRIES;
	remote->num_handles = 1;
	remote->common_handle = 0;
	remote->handles[0] = NFSD_OBSERVE_HANDLE;
	__atomic_store_n(&area[0], 0, __ATOMIC_RELEASE);
	if (ioctl(kcov_fd, KCOV_REMOTE_ENABLE, remote) < 0) {
		report_startup(ready_fd, START_REMOTE_ENABLE, errno);
		exit(EXIT_FAILURE);
	}
	listener_result = make_listener(socket_path);
	if (listener_result < 0) {
		saved_errno = errno;
		(void)ioctl(kcov_fd, KCOV_DISABLE, 0);
		report_startup(ready_fd,
			       listener_result == -1 ? START_SOCKET :
			       listener_result == -2 ? START_BIND : START_LISTEN,
			       saved_errno);
		exit(EXIT_FAILURE);
	}
	listener = listener_result;
	report_startup(ready_fd, START_READY, 0);
	(void)close(ready_fd);
	connection = wait_for_stop(listener);
	if (connection < 0)
		exit(EXIT_FAILURE);
	if (ioctl(kcov_fd, KCOV_DISABLE, 0) < 0)
		exit(EXIT_FAILURE);
	if (write_results(prefix, area) < 0)
		exit(EXIT_FAILURE);
	(void)close(listener);
	cleanup_socket();
	cleanup_socket_path = NULL;
	if (write_all(connection, "ACK\n", 4) < 0)
		exit(EXIT_FAILURE);
	(void)shutdown(connection, SHUT_RDWR);
	(void)close(connection);
	(void)munmap(area, map_bytes);
	(void)close(kcov_fd);
	free(remote);
	exit(EXIT_SUCCESS);
}

static int start_observer(const char *prefix)
{
	struct startup_message message;
	char *socket_path = path_with_suffix(prefix, ".sock");
	int pipe_fds[2];
	pid_t child;
	ssize_t amount;

	if (socket_path == NULL) {
		perror("observer: socket path");
		return EXIT_FAILURE;
	}
	if (strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
		fprintf(stderr, "observer: socket path is too long\n");
		free(socket_path);
		return EXIT_FAILURE;
	}
	if (pipe2(pipe_fds, O_CLOEXEC) < 0) {
		perror("observer: pipe2");
		free(socket_path);
		return EXIT_FAILURE;
	}
	child = fork();
	if (child < 0) {
		perror("observer: fork");
		(void)close(pipe_fds[0]);
		(void)close(pipe_fds[1]);
		free(socket_path);
		return EXIT_FAILURE;
	}
	if (child == 0) {
		(void)close(pipe_fds[0]);
		collector(prefix, socket_path, pipe_fds[1]);
	}
	(void)close(pipe_fds[1]);
	if (wait_readable(pipe_fds[0], HANDSHAKE_TIMEOUT_MS) < 0) {
		perror("observer: startup handshake");
		(void)kill(child, SIGTERM);
		(void)waitpid(child, NULL, 0);
		(void)close(pipe_fds[0]);
		free(socket_path);
		return EXIT_FAILURE;
	}
	amount = read(pipe_fds[0], &message, sizeof(message));
	(void)close(pipe_fds[0]);
	free(socket_path);
	if (amount != (ssize_t)sizeof(message)) {
		fprintf(stderr, "observer: incomplete startup handshake\n");
		(void)waitpid(child, NULL, 0);
		return EXIT_FAILURE;
	}
	if (message.stage != START_READY) {
		fprintf(stderr, "observer: %s: %s\n", stage_name(message.stage),
			strerror(message.error));
		(void)waitpid(child, NULL, 0);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int stop_observer(const char *prefix)
{
	static const char expected_ack[] = "ACK\n";
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	char ack[sizeof(expected_ack) - 1];
	char *socket_path = path_with_suffix(prefix, ".sock");
	int fd;
	size_t received = 0;

	if (socket_path == NULL) {
		perror("observer: socket path");
		return EXIT_FAILURE;
	}
	if (strlen(socket_path) >= sizeof(address.sun_path)) {
		fprintf(stderr, "observer: socket path is too long\n");
		free(socket_path);
		return EXIT_FAILURE;
	}
	memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
	free(socket_path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("observer: socket");
		return EXIT_FAILURE;
	}
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("observer: connect");
		(void)close(fd);
		return EXIT_FAILURE;
	}
	if (write_all(fd, "STOP\n", 5) < 0 || shutdown(fd, SHUT_WR) < 0) {
		perror("observer: send STOP");
		(void)close(fd);
		return EXIT_FAILURE;
	}
	while (received < sizeof(ack)) {
		ssize_t amount;

		if (wait_readable(fd, HANDSHAKE_TIMEOUT_MS) < 0) {
			perror("observer: stop handshake");
			(void)close(fd);
			return EXIT_FAILURE;
		}
		amount = read(fd, ack + received, sizeof(ack) - received);
		if (amount <= 0) {
			fprintf(stderr, "observer: incomplete stop acknowledgment\n");
			(void)close(fd);
			return EXIT_FAILURE;
		}
		received += (size_t)amount;
	}
	(void)close(fd);
	if (memcmp(ack, expected_ack, sizeof(ack)) != 0) {
		fprintf(stderr, "observer: invalid stop acknowledgment\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s {start|stop} <prefix>\n", program);
}

int main(int argc, char **argv)
{
	struct sigaction ignore_sigpipe = {.sa_handler = SIG_IGN};

	sigemptyset(&ignore_sigpipe.sa_mask);
	if (sigaction(SIGPIPE, &ignore_sigpipe, NULL) < 0) {
		perror("observer: sigaction SIGPIPE");
		return EXIT_FAILURE;
	}
	if (argc != 3 || argv[2][0] == '\0') {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	if (strcmp(argv[1], "start") == 0)
		return start_observer(argv[2]);
	if (strcmp(argv[1], "stop") == 0)
		return stop_observer(argv[2]);
	usage(argv[0]);
	return EXIT_FAILURE;
}
