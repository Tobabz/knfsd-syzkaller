/* Bounded, diagnostic-only AF_PACKET capture for the disposable NLM VM. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static int capture_stats(int fd, FILE *out, uint64_t captured)
{
	struct tpacket_stats stats = { 0 };
	socklen_t length = sizeof(stats);
	if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &length) != 0 ||
	    length != sizeof(stats))
		return -1;
	if (fprintf(out, "captured=%" PRIu64 " packets=%u drops=%u\n",
		    captured, stats.tp_packets, stats.tp_drops) < 0)
		return -1;
	return 0;
}

static void stop(int signo)
{
	(void)signo;
	stopping = 1;
}

static int mark_complete(const char *path)
{
	FILE *complete = fopen(path, "wx");

	if (complete == NULL)
		return -1;
	return fclose(complete);
}

int main(int argc, char **argv)
{
	const size_t limit = 64u * 1024u * 1024u;
	uint8_t packet[65536];
	struct { uint32_t magic; uint16_t major, minor; int32_t zone;
		 uint32_t sigfigs, snaplen, linktype; } header = {
		0xa1b2c3d4u, 2, 4, 0, 0, sizeof(packet), 1
	};
	FILE *out;
	int fd;
	uint64_t captured = 0;
	size_t used = sizeof(header);
	struct sigaction action = { .sa_handler = stop };
	if (argc < 2 || argc > 6)
		return 2;
	out = fopen(argv[1], "wb");
	if (out == NULL)
		return 2;
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0 || fwrite(&header, sizeof(header), 1, out) != 1)
		return 2;
	if (sigaction(SIGTERM, &action, NULL) != 0 ||
	    sigaction(SIGINT, &action, NULL) != 0)
		return 2;
	if (argc >= 4) {
		FILE *ready;
		if (fflush(out) != 0)
			return 2;
		ready = fopen(argv[3], "wx");
		if (ready == NULL)
			return 2;
		if (fclose(ready) != 0)
			return 2;
	}
	while (!stopping) {
		struct timespec ts;
		struct { uint32_t seconds, micros, included, original; } ph;
		struct pollfd event = { .fd = fd, .events = POLLIN };
		ssize_t len;

		if (argc == 6) {
			if (access(argv[5], F_OK) == 0)
				break;
			if (errno != ENOENT)
				return 1;
		}
		int ready = poll(&event, 1, argc == 6 ? 100 : -1);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		if (ready == 0)
			continue;
		if (!(event.revents & POLLIN))
			return 1;
		len = recv(fd, packet, sizeof(packet), 0);
		if (len < 0) {
			if (stopping && errno == EINTR)
				break;
			return 1;
		}
		if (len < 54 || packet[12] != 0x08 || packet[13] != 0x00)
			continue;
		if ((packet[14] >> 4) != 4 || packet[23] != 6)
			continue;
		if (used + sizeof(ph) + (size_t)len > limit)
			return 3;
		if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
			return 1;
		ph.seconds = (uint32_t)ts.tv_sec;
		ph.micros = (uint32_t)(ts.tv_nsec / 1000);
		ph.included = ph.original = (uint32_t)len;
		if (fwrite(&ph, sizeof(ph), 1, out) != 1 ||
		    fwrite(packet, (size_t)len, 1, out) != 1)
			return 1;
		used += sizeof(ph) + (size_t)len;
		captured++;
	}
	if (fflush(out) != 0 || fclose(out) != 0)
		return 1;
	if (argc >= 3) {
		FILE *stats = fopen(argv[2], "w");
		if (stats == NULL)
			return 1;
		int ok = capture_stats(fd, stats, captured);
		if (fclose(stats) != 0 || ok != 0)
			return 1;
	}
	if (close(fd) != 0)
		return 1;
	/* Created last, so lifecycle cleanup can distinguish a clean exit. */
	if (argc >= 5 && mark_complete(argv[4]) != 0)
		return 1;
	return 0;
}
