// SPDX-License-Identifier: GPL-2.0
/* Frozen Baseline Phase 7 raw-RPC CMSG probe. */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kcov.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#define TCP_SUNRPC_FUZZ 47
#define SUNRPC_FUZZ_RECORD_VERSION 1U
#define SUNRPC_FUZZ_RECORD_NEW (1U << 0)
#define SUNRPC_FUZZ_RECORD_RETRY (1U << 1)
#define SUNRPC_FUZZ_RECORD_FINAL (1U << 2)
#define SUNRPC_FUZZ_RECORD_CANCEL (1U << 3)

#define KCOV_ENTRIES (256U << 10)
#define PHASE3_CONTROL "/sys/kernel/debug/sunrpc_fuzz/phase3_control"

struct scm_sunrpc_fuzz_record {
	uint32_t version;
	uint32_t flags;
	uint64_t user_tag;
};

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

struct kcov_session {
	int fd;
	unsigned long *area;
	size_t bytes;
};

struct scenario_result {
	uint64_t generation;
	unsigned long remote_entries;
	unsigned int sends;
	unsigned int replies;
	unsigned int expected_failures;
	unsigned int short_sends;
};

static void die(const char *operation)
{
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
}

static void fail(const char *message)
{
	errno = EPROTO;
	die(message);
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
		die("open KCOV");
	if (ioctl(session.fd, KCOV_INIT_TRACE, KCOV_ENTRIES))
		die("KCOV_INIT_TRACE");
	session.area = mmap(NULL, session.bytes, PROT_READ | PROT_WRITE,
			    MAP_SHARED, session.fd, 0);
	if (session.area == MAP_FAILED)
		die("mmap KCOV");
	if (ioctl(session.fd, KCOV_REMOTE_ENABLE, &remote))
		die("KCOV_REMOTE_ENABLE");
	__atomic_store_n(&session.area[0], 0, __ATOMIC_RELEASE);
	return session;
}

static uint64_t generation_begin(int fd)
{
	struct kcov_remote_generation request = {};

	if (ioctl(fd, KCOV_REMOTE_GENERATION_BEGIN, &request))
		die("KCOV_REMOTE_GENERATION_BEGIN");
	if (!request.generation)
		fail("zero generation");
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

static unsigned long kcov_owner_stop(struct kcov_session *session)
{
	unsigned long entries =
		__atomic_load_n(&session->area[0], __ATOMIC_ACQUIRE);

	if (ioctl(session->fd, KCOV_DISABLE, 0))
		die("KCOV_DISABLE");
	if (munmap(session->area, session->bytes))
		die("munmap KCOV");
	if (close(session->fd))
		die("close KCOV");
	return entries;
}

static void control(const char *command)
{
	int fd = open(PHASE3_CONTROL, O_WRONLY | O_CLOEXEC);
	size_t length = strlen(command);
	ssize_t written;

	if (fd < 0)
		die("open phase3_control");
	written = write(fd, command, length);
	if (written != (ssize_t)length)
		die("write phase3_control");
	if (close(fd))
		die("close phase3_control");
}

static int raw_socket(bool opt_in)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons(2049),
	};
	struct timeval timeout = { .tv_sec = 10 };
	int fd;
	int one = 1;

	if (inet_pton(AF_INET, "10.77.0.1", &address.sin_addr) != 1)
		fail("inet_pton");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (fd < 0)
		die("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
		die("setsockopt timeout");
	if (opt_in && setsockopt(fd, SOL_TCP, TCP_SUNRPC_FUZZ,
				 &one, sizeof(one)))
		die("setsockopt TCP_SUNRPC_FUZZ");
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)))
		die("connect NFS TCP");
	return fd;
}

static size_t make_null_call(unsigned char record[44], uint32_t xid)
{
	uint32_t words[11] = {
		htonl(0x80000028U), htonl(xid), htonl(0), htonl(2),
		htonl(100003), htonl(4), htonl(0), htonl(0),
		htonl(0), htonl(0), htonl(0),
	};

	memcpy(record, words, sizeof(words));
	return sizeof(words);
}

static ssize_t raw_send(int fd, uint32_t flags, uint64_t tag,
			uint32_t xid, bool payload)
{
	unsigned char record[44];
	unsigned char control_buffer[CMSG_SPACE(sizeof(struct scm_sunrpc_fuzz_record))];
	struct scm_sunrpc_fuzz_record metadata = {
		.version = SUNRPC_FUZZ_RECORD_VERSION,
		.flags = flags,
		.user_tag = tag,
	};
	struct iovec iov = {};
	struct msghdr message = {
		.msg_control = control_buffer,
		.msg_controllen = sizeof(control_buffer),
	};
	struct cmsghdr *cmsg;

	memset(control_buffer, 0, sizeof(control_buffer));
	if (payload) {
		iov.iov_base = record;
		iov.iov_len = make_null_call(record, xid);
		message.msg_iov = &iov;
		message.msg_iovlen = 1;
	}
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_TCP;
	cmsg->cmsg_type = TCP_SUNRPC_FUZZ;
	cmsg->cmsg_len = CMSG_LEN(sizeof(metadata));
	memcpy(CMSG_DATA(cmsg), &metadata, sizeof(metadata));
	return sendmsg(fd, &message, MSG_NOSIGNAL);
}

static void expect_failure(ssize_t result, const char *operation,
			   struct scenario_result *summary)
{
	if (result >= 0)
		fail(operation);
	summary->expected_failures++;
}

static void expect_full_send(ssize_t result, struct scenario_result *summary)
{
	if (result != 44)
		fail("raw full send");
	summary->sends++;
}

static void read_exact(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;

	while (length) {
		ssize_t received = recv(fd, cursor, length, 0);

		if (received < 0) {
			if (errno == EINTR)
				continue;
			die("recv RPC reply");
		}
		if (!received)
			fail("EOF in RPC reply");
		cursor += received;
		length -= (size_t)received;
	}
}

static void read_reply(int fd, uint32_t expected_xid,
		       struct scenario_result *summary)
{
	uint32_t marker;
	uint32_t header[2];
	unsigned char *payload;
	uint32_t length;

	read_exact(fd, &marker, sizeof(marker));
	marker = ntohl(marker);
	if (!(marker & 0x80000000U))
		fail("multi-fragment RPC reply");
	length = marker & 0x7fffffffU;
	if (length < sizeof(header) || length > 1024U * 1024U)
		fail("invalid RPC reply length");
	payload = malloc(length);
	if (!payload)
		die("malloc RPC reply");
	read_exact(fd, payload, length);
	memcpy(header, payload, sizeof(header));
	free(payload);
	if (ntohl(header[0]) != expected_xid || ntohl(header[1]) != 1)
		fail("RPC reply identity");
	summary->replies++;
}

static void do_normal_final(struct scenario_result *result)
{
	int fd = raw_socket(true);

	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW |
					 SUNRPC_FUZZ_RECORD_FINAL,
				 UINT64_C(0x7001), 0x71000001U, true), result);
	read_reply(fd, 0x71000001U, result);
	close(fd);
}

static void do_retry_final(struct scenario_result *result)
{
	int fd = raw_socket(true);
	uint64_t tag = UINT64_C(0x7002);

	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW, tag,
				 0x72000001U, true), result);
	read_reply(fd, 0x72000001U, result);
	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_RETRY, tag,
				 0x72000002U, true), result);
	read_reply(fd, 0x72000002U, result);
	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_RETRY |
					 SUNRPC_FUZZ_RECORD_FINAL,
				 tag, 0x72000003U, true), result);
	read_reply(fd, 0x72000003U, result);
	close(fd);
}

static void do_collision(struct scenario_result *result)
{
	int fd = raw_socket(true);
	uint64_t tag = UINT64_C(0x7003);

	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW, tag,
				 0x73000001U, true), result);
	read_reply(fd, 0x73000001U, result);
	expect_failure(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW, tag,
				0x73000002U, true), "duplicate tag accepted", result);
	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_RETRY |
					 SUNRPC_FUZZ_RECORD_FINAL,
				 tag, 0x73000003U, true), result);
	read_reply(fd, 0x73000003U, result);
	close(fd);
}

static void do_cross_socket(struct scenario_result *result)
{
	int first = raw_socket(true);
	int second;
	uint64_t tag = UINT64_C(0x7004);

	expect_full_send(raw_send(first, SUNRPC_FUZZ_RECORD_NEW, tag,
				 0x74000001U, true), result);
	read_reply(first, 0x74000001U, result);
	second = raw_socket(true);
	expect_failure(raw_send(second, SUNRPC_FUZZ_RECORD_RETRY, tag,
				0x74000002U, true), "cross-socket retry accepted", result);
	close(second);
	expect_full_send(raw_send(first, SUNRPC_FUZZ_RECORD_RETRY |
					 SUNRPC_FUZZ_RECORD_FINAL,
				 tag, 0x74000003U, true), result);
	read_reply(first, 0x74000003U, result);
	close(first);
}

static void do_cancel(struct scenario_result *result)
{
	int fd = raw_socket(true);
	uint64_t tag = UINT64_C(0x7005);

	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW, tag,
				 0x75000001U, true), result);
	read_reply(fd, 0x75000001U, result);
	if (raw_send(fd, SUNRPC_FUZZ_RECORD_CANCEL, tag, 0, false) != 0)
		fail("raw CANCEL");
	expect_failure(raw_send(fd, SUNRPC_FUZZ_RECORD_RETRY, tag,
				0x75000002U, true), "retry after cancel accepted", result);
	close(fd);
}

static void do_rollback(struct scenario_result *result, bool final)
{
	int fd = raw_socket(true);
	uint64_t tag = final ? UINT64_C(0x7007) : UINT64_C(0x7006);
	uint32_t flags = SUNRPC_FUZZ_RECORD_NEW |
		(final ? SUNRPC_FUZZ_RECORD_FINAL : 0);

	control("fault-arm precommit\n");
	expect_failure(raw_send(fd, flags, tag, 0x76000001U, true),
		       "precommit send unexpectedly succeeded", result);
	expect_full_send(raw_send(fd, flags, tag, 0x76000002U, true), result);
	read_reply(fd, 0x76000002U, result);
	if (!final && raw_send(fd, SUNRPC_FUZZ_RECORD_CANCEL, tag, 0, false) != 0)
		fail("cancel rollback NEW root");
	close(fd);
}

static void do_retry_final_rollback(struct scenario_result *result)
{
	int fd = raw_socket(true);
	uint64_t tag = UINT64_C(0x7008);

	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW, tag,
				 0x78000001U, true), result);
	read_reply(fd, 0x78000001U, result);
	control("fault-arm precommit\n");
	expect_failure(raw_send(fd, SUNRPC_FUZZ_RECORD_RETRY |
					 SUNRPC_FUZZ_RECORD_FINAL,
				 tag, 0x78000002U, true),
		       "precommit RETRY|FINAL unexpectedly succeeded", result);
	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_RETRY |
					 SUNRPC_FUZZ_RECORD_FINAL,
				 tag, 0x78000003U, true), result);
	read_reply(fd, 0x78000003U, result);
	close(fd);
}

static void do_partial(struct scenario_result *result)
{
	int fd = raw_socket(true);
	ssize_t sent;

	control("fault-arm postcommit\n");
	sent = raw_send(fd, SUNRPC_FUZZ_RECORD_NEW |
			    SUNRPC_FUZZ_RECORD_FINAL,
			UINT64_C(0x7009), 0x79000001U, true);
	if (sent <= 0 || sent >= 44)
		fail("postcommit send was not partial");
	result->short_sends++;
	close(fd);
}

static void do_socket_autoseal(struct scenario_result *result)
{
	int fd = raw_socket(true);

	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW,
				 UINT64_C(0x7010), 0x7a000001U, true), result);
	read_reply(fd, 0x7a000001U, result);
	close(fd);
}

static void do_closing_autoseal(struct scenario_result *result)
{
	int fd = raw_socket(true);

	expect_full_send(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW,
				 UINT64_C(0x7011), 0x7b000001U, true), result);
	read_reply(fd, 0x7b000001U, result);
	/* Deliberately leave both root and socket open until FINISH. */
	(void)fd;
}

static void do_non_opt_in(struct scenario_result *result)
{
	int fd = raw_socket(false);

	expect_failure(raw_send(fd, SUNRPC_FUZZ_RECORD_NEW |
					 SUNRPC_FUZZ_RECORD_FINAL,
				UINT64_C(0x7012), 0x7c000001U, true),
		       "non-opt-in CMSG accepted", result);
	close(fd);
}

static void do_unrelated_write(struct scenario_result *result)
{
	unsigned char record[44];
	int fd = raw_socket(true);

	make_null_call(record, 0x7d000001U);
	expect_failure(send(fd, record, sizeof(record), MSG_NOSIGNAL),
		       "unrelated raw writer accepted", result);
	close(fd);
}

int main(int argc, char **argv)
{
	struct scenario_result result = {};
	struct kcov_session session;
	unsigned long owner;

	if (argc != 2) {
		fprintf(stderr, "usage: %s SCENARIO\n", argv[0]);
		return EXIT_FAILURE;
	}
	owner = ((unsigned long)getpid() & 0x7fffffffUL) | 0x40000000UL;
	session = kcov_owner_start(owner);
	result.generation = generation_begin(session.fd);
	generation_bind(session.fd, result.generation);

	if (!strcmp(argv[1], "normal-final"))
		do_normal_final(&result);
	else if (!strcmp(argv[1], "retry-final"))
		do_retry_final(&result);
	else if (!strcmp(argv[1], "collision"))
		do_collision(&result);
	else if (!strcmp(argv[1], "cross-socket"))
		do_cross_socket(&result);
	else if (!strcmp(argv[1], "cancel"))
		do_cancel(&result);
	else if (!strcmp(argv[1], "rollback-new"))
		do_rollback(&result, false);
	else if (!strcmp(argv[1], "rollback-new-final"))
		do_rollback(&result, true);
	else if (!strcmp(argv[1], "rollback-retry-final"))
		do_retry_final_rollback(&result);
	else if (!strcmp(argv[1], "partial"))
		do_partial(&result);
	else if (!strcmp(argv[1], "socket-autoseal"))
		do_socket_autoseal(&result);
	else if (!strcmp(argv[1], "closing-autoseal"))
		do_closing_autoseal(&result);
	else if (!strcmp(argv[1], "non-opt-in"))
		do_non_opt_in(&result);
	else if (!strcmp(argv[1], "unrelated-write"))
		do_unrelated_write(&result);
	else
		fail("unknown scenario");

	generation_finish(session.fd, result.generation);
	result.remote_entries = kcov_owner_stop(&session);
	printf("{\"status\":\"pass\",\"scenario\":\"%s\","
	       "\"generation\":%llu,\"remote_entries\":%lu,"
	       "\"sends\":%u,\"replies\":%u,"
	       "\"expected_failures\":%u,\"short_sends\":%u}\n",
	       argv[1], (unsigned long long)result.generation,
	       result.remote_entries, result.sends, result.replies,
	       result.expected_failures, result.short_sends);
	return EXIT_SUCCESS;
}
