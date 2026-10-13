/* Deterministic NFSv4.1 round-trip for the guest proxy's delta replay mode.
 * This probe provides the original RPC bytes; it never chooses mutations. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int exact(int fd, uint8_t *p, size_t len)
{
	while (len) {
		ssize_t n = recv(fd, p, len, 0);
		if (n <= 0) return -1;
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static void put32(uint8_t *p, uint32_t n)
{
	p[0] = (uint8_t)(n >> 24);
	p[1] = (uint8_t)(n >> 16);
	p[2] = (uint8_t)(n >> 8);
	p[3] = (uint8_t)n;
}

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int parse_u32(const char *text, uint32_t *out)
{
	char *end;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 0);
	if (errno != 0 || *text == '\0' || *end != '\0' || value > UINT32_MAX)
		return -1;
	*out = (uint32_t)value;
	return 0;
}

int main(int argc, char **argv)
{
	const uint32_t words[15] = {
		0, 0, 2, 100003, 4, 1, 0, 0, 0, 0, 0, 1, 1, 24, 0
	};
	struct sockaddr_in peer = {0};
	struct timeval timeout = {.tv_sec = 5};
	uint8_t req[4 + sizeof(words)], marker[4], data[4096];
	uint32_t request_xid, expected, reply_xid = 0;
	const char *target = "10.89.0.5";
	int fd, dir = -1;

	/* The one-argument form preserves the original NFSPDLT1 probe.  The
	 * explicit form also drives anchored NFSPDLT2 records without teaching
	 * this program anything about a mutation's contents. */
	if (argc == 2 && (!strcmp(argv[1], "0") || !strcmp(argv[1], "1") ||
	                  !strcmp(argv[1], "2"))) {
		dir = argv[1][0] - '0';
		request_xid = dir == 0 ? 0x22222222u :
		              dir == 1 ? 0x22222223u : 0x22222224u;
		expected = dir == 0 ? 0x22222223u :
		           dir == 1 ? 0x22222222u : 0x22222224u;
	} else if (argc == 4 && parse_u32(argv[2], &request_xid) == 0 &&
	           parse_u32(argv[3], &expected) == 0) {
		target = argv[1];
	} else {
		fprintf(stderr, "usage: %s 0|1|2 | TARGET REQUEST_XID EXPECTED_XID\n",
		        argv[0]);
		return 2;
	}
	for (unsigned i = 0; i < 15; i++)
		put32(req + 4u + 4u * i, i == 0 ? request_xid : words[i]);
	put32(req, 0x80000000u | (uint32_t)sizeof(words));
	peer.sin_family = AF_INET;
	peer.sin_port = htons(20549);
	if (inet_pton(AF_INET, target, &peer.sin_addr) != 1) return 1;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return 1;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    connect(fd, (struct sockaddr *)&peer, sizeof(peer)) ||
	    send(fd, req, sizeof(req), MSG_NOSIGNAL) != (ssize_t)sizeof(req)) {
		perror("replay request"); close(fd); return 1;
	}
	for (unsigned fragment = 0; fragment < 64; fragment++) {
		uint32_t n, last;
		if (exact(fd, marker, sizeof(marker))) break;
		n = get32(marker);
		last = n >> 31;
		n &= 0x7fffffffu;
		if (n > 65536u || (fragment == 0 && n < 4u)) break;
		if (fragment == 0) {
			if (exact(fd, marker, 4)) break;
			reply_xid = get32(marker);
			n -= 4;
		}
		while (n) {
			size_t chunk = n < sizeof(data) ? n : sizeof(data);
			if (exact(fd, data, chunk)) goto failed;
			n -= (uint32_t)chunk;
		}
		if (last) {
			close(fd);
			if (reply_xid != expected) {
				fprintf(stderr, "replay xid %#x != %#x\n", reply_xid, expected);
				return 1;
			}
			if (dir >= 0)
				printf("replay_direction=%d response_xid=%#x\n", dir, reply_xid);
			else
				printf("replay_target=%s request_xid=%#x response_xid=%#x\n",
				       target, request_xid, reply_xid);
			return 0;
		}
	}
failed:
	perror("replay reply missing or malformed");
	close(fd);
	return 1;
}
