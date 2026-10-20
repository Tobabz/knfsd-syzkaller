#define _POSIX_C_SOURCE 200809L
#include "lifecycle.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

struct server_context {
	const char *socket_path;
	const char *clients_path;
	_Atomic int stop;
	int rc;
};

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get64(const uint8_t *p)
{
	return ((uint64_t)get32(p) << 32) | get32(p + 4);
}

static void put32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static int write_file(const char *path, const char *contents)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	size_t len = strlen(contents), used = 0;

	if (fd < 0)
		return -1;
	while (used < len) {
		ssize_t n = write(fd, contents + used, len - used);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			close(fd);
			return -1;
		}
		used += (size_t)n;
	}
	return close(fd);
}

static int make_client(const char *clients, const char *id, const char *name,
		       unsigned minor, const char *status, const char *slots)
{
	char directory[256], info_path[280], ctl_path[280], info[1024];

	if (snprintf(directory, sizeof(directory), "%s/%s", clients, id) >=
	    (int)sizeof(directory) ||
	    snprintf(info_path, sizeof(info_path), "%s/info", directory) >=
	    (int)sizeof(info_path) ||
	    snprintf(ctl_path, sizeof(ctl_path), "%s/ctl", directory) >=
	    (int)sizeof(ctl_path) ||
	    snprintf(info, sizeof(info),
		     "clientid: 0x123456789abcdef0\n"
		     "address: \"10.0.0.2:900\"\n"
		     "status: %s\nseconds from last renew: 0\n"
		     "name: \"%s\"\nminor version: %u\n"
		     "callback state: UP\ncallback address: \"10.0.0.2:0\"\n"
		     "admin-revoked states: 0\nsession slots:%s\n",
		     status, name, minor, slots) >= (int)sizeof(info))
		return -1;
	if (mkdir(directory, 0700) != 0 || write_file(info_path, info) != 0 ||
	    write_file(ctl_path, "") != 0)
		return -1;
	return 0;
}

static void *server_thread(void *arg)
{
	struct server_context *context = arg;

	context->rc = nfsp_lifecycle_serve(context->socket_path,
					   context->clients_path, 3, &context->stop);
	return NULL;
}

static int connect_server(const char *path)
{
	struct sockaddr_un address;
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int transact(const char *path, const char magic[8], uint32_t operation,
		    uint32_t client, uint8_t reply[NFSP_LIFECYCLE_REPLY_LEN])
{
	uint8_t request[NFSP_LIFECYCLE_REQUEST_LEN];
	int fd = connect_server(path);

	if (fd < 0)
		return -1;
	memcpy(request, magic, 8);
	put32(request + 8, operation);
	put32(request + 12, client);
	if (send(fd, request, sizeof(request), 0) != (ssize_t)sizeof(request) ||
	    recv(fd, reply, NFSP_LIFECYCLE_REPLY_LEN, 0) !=
		(ssize_t)NFSP_LIFECYCLE_REPLY_LEN) {
		close(fd);
		return -1;
	}
	return close(fd);
}

static int wait_socket(const char *path)
{
	struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};

	for (unsigned i = 0; i < 200u; i++) {
		struct stat st;

		if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode))
			return 0;
		(void)nanosleep(&delay, NULL);
	}
	return -1;
}

static void cleanup_client(const char *clients, const char *id)
{
	char path[280];

	(void)snprintf(path, sizeof(path), "%s/%s/info", clients, id);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s/ctl", clients, id);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s", clients, id);
	(void)rmdir(path);
}

int main(void)
{
	char temporary[] = "/tmp/nfsp-lifecycle-XXXXXX";
	char clients[256], socket_path[256], ctl_path[280], ctl[16] = {0};
	char hostname[256] = {0}, owner[512];
	struct server_context context = {0};
	uint8_t reply[NFSP_LIFECYCLE_REPLY_LEN];
	pthread_t thread;
	int fd;

	CHECK(mkdtemp(temporary) != NULL, "mkdtemp: %s", strerror(errno));
	CHECK(gethostname(hostname, sizeof(hostname) - 1u) == 0,
	      "gethostname: %s", strerror(errno));
	CHECK(snprintf(owner, sizeof(owner),
		       "Linux NFSv4.1 frozen-phase9-lane3-client0/%s", hostname) <
	      (int)sizeof(owner), "format deterministic client owner");
	if (snprintf(clients, sizeof(clients), "%s/clients", temporary) >=
	    (int)sizeof(clients) ||
	    snprintf(socket_path, sizeof(socket_path), "%s/lifecycle.sock", temporary) >=
	    (int)sizeof(socket_path))
		return 2;
	CHECK(mkdir(clients, 0700) == 0, "mkdir clients: %s", strerror(errno));
	CHECK(make_client(clients, "100", "frozen-phase9-lane3-client0", 1,
			  "confirmed", " 64") == 0,
	      "make identifier-only nonmatch: %s", strerror(errno));
	CHECK(make_client(clients, "101", owner, 1,
			  "confirmed", " 64 64") == 0,
	      "make matching client: %s", strerror(errno));
	CHECK(make_client(clients, "102", owner, 2,
			  "confirmed", " 64") == 0,
	      "make other-minor client: %s", strerror(errno));

	context.socket_path = socket_path;
	context.clients_path = clients;
	atomic_init(&context.stop, 0);
	CHECK(pthread_create(&thread, NULL, server_thread, &context) == 0,
	      "create server thread");
	CHECK(wait_socket(socket_path) == 0, "lifecycle socket became ready");

	CHECK(transact(socket_path, NFSP_LIFECYCLE_REQUEST_MAGIC,
		       NFSP_LIFECYCLE_OP_EXPIRE, 0, reply) == 0,
	      "valid transaction: %s", strerror(errno));
	CHECK(memcmp(reply, NFSP_LIFECYCLE_REPLY_MAGIC, 8) == 0,
	      "reply magic");
	CHECK(get32(reply + 8) == 0, "valid request status %u", get32(reply + 8));
	CHECK(get32(reply + 12) == 0 && get32(reply + 16) == 1,
	      "reply client/minor");
	CHECK(get32(reply + 20) == 2, "reply session count %u", get32(reply + 20));
	CHECK(get64(reply + 24) == UINT64_C(0x123456789abcdef0),
	      "reply clientid");
	(void)snprintf(ctl_path, sizeof(ctl_path), "%s/101/ctl", clients);
	fd = open(ctl_path, O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0 && read(fd, ctl, 7) == 7 && memcmp(ctl, "expire\n", 7) == 0,
	      "only the matching ctl received expire");
	if (fd >= 0)
		close(fd);
	(void)snprintf(ctl_path, sizeof(ctl_path), "%s/100/ctl", clients);
	fd = open(ctl_path, O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0 && read(fd, ctl, sizeof(ctl)) == 0,
	      "identifier-only owner was not selected");
	if (fd >= 0)
		close(fd);

	CHECK(transact(socket_path, "BADMAGIC", NFSP_LIFECYCLE_OP_EXPIRE, 0,
		       reply) == 0 && get32(reply + 8) == (uint32_t)EPROTO,
	      "bad magic is rejected");
	CHECK(transact(socket_path, NFSP_LIFECYCLE_REQUEST_MAGIC, 99, 0, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)EOPNOTSUPP,
	      "unknown operation is rejected");
	CHECK(transact(socket_path, NFSP_LIFECYCLE_REQUEST_MAGIC,
		       NFSP_LIFECYCLE_OP_EXPIRE, 1, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)ENOENT,
	      "unknown deterministic client is rejected");

	CHECK(make_client(clients, "103", owner, 1,
			  "confirmed", " 32") == 0,
	      "make duplicate client: %s", strerror(errno));
	CHECK(transact(socket_path, NFSP_LIFECYCLE_REQUEST_MAGIC,
		       NFSP_LIFECYCLE_OP_EXPIRE, 0, reply) == 0 &&
	      get32(reply + 8) == (uint32_t)EEXIST,
	      "ambiguous server records fail closed");

	atomic_store(&context.stop, 1);
	CHECK(pthread_join(thread, NULL) == 0 && context.rc == 0,
	      "server stopped cleanly");
	CHECK(access(socket_path, F_OK) != 0 && errno == ENOENT,
	      "server removed endpoint");

	cleanup_client(clients, "103");
	cleanup_client(clients, "102");
	cleanup_client(clients, "101");
	cleanup_client(clients, "100");
	(void)rmdir(clients);
	(void)rmdir(temporary);
	printf("lifecycle checks=%d failures=%d\n", checks, failures);
	return failures ? 1 : 0;
}
