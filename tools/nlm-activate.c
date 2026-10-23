/* NFSPACT1 diagnostic client for the minimal guest. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static void put32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

static uint32_t get32(const unsigned char *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
		(uint32_t)p[2] << 8 | p[3];
}

int main(int argc, char **argv)
{
	static const char digest[] = "b042b7e6a00843878631224539fbbce88a4ac0dfd90ee16198f4f7659a71e01c";
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct timeval timeout = { .tv_sec = 15 };
	unsigned char request[120] = {0}, answer[24];
	unsigned op;
	int fd, n;

	if (argc != 4 || strlen(argv[1]) >= sizeof(addr.sun_path) ||
	    strlen(argv[2]) != 64 ||
	    (strcmp(argv[3], "activate") && strcmp(argv[3], "deactivate"))) {
		fputs("usage: nlm-activate SOCKET RULE_SET_ID activate|deactivate\n", stderr);
		return 2;
	}
	op = strcmp(argv[3], "activate") == 0 ? 1u : 2u;
	memcpy(request, "NFSPACT1", 8);
	put32(request + 8, op);
	request[23] = 1;
	for (size_t i = 0; i < 32; i++) {
		unsigned byte;
		if (sscanf(digest + 2 * i, "%2x", &byte) != 1)
			return 2;
		request[24 + i] = (unsigned char)byte;
	}
	memcpy(request + 56, argv[2], 64);
	memcpy(addr.sun_path, argv[1], strlen(argv[1]) + 1);
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
				&timeout, sizeof(timeout)) < 0 ||
	    connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    send(fd, request, sizeof(request), 0) != sizeof(request)) {
		perror("activation request");
		return 1;
	}
	n = (int)recv(fd, answer, sizeof(answer), 0);
	close(fd);
	if (n != sizeof(answer) || memcmp(answer, "NFSPACK1", 8) ||
	    get32(answer + 8) != op || get32(answer + 16) != 0 ||
	    get32(answer + 20) != 1) {
		fprintf(stderr, "invalid activation ACK (length=%d)\n", n);
		return 1;
	}
	printf("op=%u status=%u generation=1\n", op, get32(answer + 12));
	return get32(answer + 12) == 0 ? 0 : 1;
}
