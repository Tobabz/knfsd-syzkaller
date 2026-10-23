/* Ordered, diagnostic-only AF_PACKET capture for the disposable NLM VM. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define CAPTURE_LIMIT (64u * 1024u * 1024u)
#define EVENT_LIMIT (64u * 1024u * 1024u)

static volatile sig_atomic_t stopping;

struct capture_state {
	FILE *pcap;
	FILE *events;
	int packet_fd;
	uint64_t captured;
	uint64_t pcap_used;
	uint64_t event_used;
	uint64_t next_event;
	uint64_t last_event_ns;
	uint64_t last_packet_ns;
	uint64_t last_marker_ns;
	int ordering_ambiguous;
};

struct packet_stats {
	uint32_t packets;
	uint32_t drops;
};

static void stop(int signo)
{
	(void)signo;
	stopping = 1;
}

static int valid_atom(const char *value, size_t maximum)
{
	size_t length = strlen(value);

	if (length == 0 || length > maximum)
		return 0;
	for (size_t i = 0; i < length; i++)
		if (!(isalnum((unsigned char)value[i]) || value[i] == '_' ||
		      value[i] == '.' || value[i] == '-'))
			return 0;
	return 1;
}

static int valid_digest(const char *value)
{
	if (strlen(value) != 64)
		return 0;
	for (size_t i = 0; i < 64; i++)
		if (!(value[i] >= '0' && value[i] <= '9') &&
		    !(value[i] >= 'a' && value[i] <= 'f'))
			return 0;
	return 1;
}

static int realtime_ns(uint64_t *result)
{
	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0)
		return -1;
	*result = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
	return 0;
}

static int write_event(struct capture_state *state, const char *kind,
		       uint64_t packet_index, uint64_t timestamp_ns,
		       const char *phase, const char *nonce, uint64_t *assigned)
{
	char line[512];
	int length;
	uint64_t sequence = state->next_event;

	if (state->events == NULL)
		return 0;
	if (state->next_event != 0 && timestamp_ns < state->last_event_ns)
		state->ordering_ambiguous = 1;
	length = snprintf(line, sizeof(line),
			  "%" PRIu64 "\t%s\t%" PRIu64 "\t%" PRIu64
			  "\t%s\t%s\n", sequence, kind, packet_index,
			  timestamp_ns, phase, nonce);
	if (length < 0 || (size_t)length >= sizeof(line) ||
	    state->event_used + (size_t)length > EVENT_LIMIT ||
	    fwrite(line, (size_t)length, 1, state->events) != 1)
		return -1;
	state->event_used += (size_t)length;
	state->next_event++;
	state->last_event_ns = timestamp_ns;
	if (assigned != NULL)
		*assigned = sequence;
	return 0;
}

static int receive_timestamp(struct msghdr *message, uint64_t *timestamp_ns)
{
	for (struct cmsghdr *control = CMSG_FIRSTHDR(message); control != NULL;
	     control = CMSG_NXTHDR(message, control)) {
		if (control->cmsg_level == SOL_SOCKET &&
		    control->cmsg_type == SCM_TIMESTAMPNS &&
		    control->cmsg_len >= CMSG_LEN(sizeof(struct timespec))) {
			struct timespec timestamp;

			memcpy(&timestamp, CMSG_DATA(control), sizeof(timestamp));
			if (timestamp.tv_sec < 0 || timestamp.tv_nsec < 0 ||
			    timestamp.tv_nsec >= 1000000000L)
				return -1;
			*timestamp_ns = (uint64_t)timestamp.tv_sec * 1000000000u +
					(uint64_t)timestamp.tv_nsec;
			return 0;
		}
	}
	return -1;
}

static int attach_ipv4_tcp_filter(int fd, unsigned int loopback_ifindex)
{
	struct sock_filter instructions[] = {
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 7),
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (uint32_t)(SKF_AD_OFF + SKF_AD_PKTTYPE)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_OUTGOING, 0, 2),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (uint32_t)(SKF_AD_OFF + SKF_AD_IFINDEX)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, loopback_ifindex, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_fprog filter = {
		.len = sizeof(instructions) / sizeof(instructions[0]),
		.filter = instructions,
	};

	return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
}

static int receive_packet(struct capture_state *state)
{
	uint8_t packet[65536];
	char control[CMSG_SPACE(sizeof(struct timespec))];
	struct iovec vector = { .iov_base = packet, .iov_len = sizeof(packet) };
	struct msghdr message = {
		.msg_iov = &vector,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct {
		uint32_t seconds, micros, included, original;
	} packet_header;
	uint64_t timestamp_ns;
	ssize_t length = recvmsg(state->packet_fd, &message, MSG_DONTWAIT);

	if (length < 0)
		return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
	if (receive_timestamp(&message, &timestamp_ns) != 0)
		return -1;
	if (length < 54 || packet[12] != 0x08 || packet[13] != 0x00 ||
	    (packet[14] >> 4) != 4 || packet[23] != 6)
		return 1;
	if (state->pcap_used + sizeof(packet_header) + (size_t)length > CAPTURE_LIMIT)
		return -2;
	packet_header.seconds = (uint32_t)(timestamp_ns / 1000000000u);
	packet_header.micros = (uint32_t)((timestamp_ns % 1000000000u) / 1000u);
	packet_header.included = packet_header.original = (uint32_t)length;
	if (fwrite(&packet_header, sizeof(packet_header), 1, state->pcap) != 1 ||
	    fwrite(packet, (size_t)length, 1, state->pcap) != 1)
		return -1;
	state->pcap_used += sizeof(packet_header) + (size_t)length;
	state->captured++;
	if (state->last_marker_ns != 0 && timestamp_ns <= state->last_marker_ns)
		state->ordering_ambiguous = 1;
	state->last_packet_ns = timestamp_ns;
	if (write_event(state, "packet", state->captured, timestamp_ns, "-", "-",
			NULL) != 0)
		return -1;
	return 1;
}

static int drain_packets(struct capture_state *state)
{
	for (;;) {
		int result = receive_packet(state);

		if (result == 0)
			return 0;
		if (result < 0)
			return result;
	}
}

static int receive_marker(struct capture_state *state, int marker_fd)
{
	char input[256], output[256];
	char control[CMSG_SPACE(sizeof(struct timespec))];
	struct sockaddr_un peer;
	struct iovec vector = { .iov_base = input, .iov_len = sizeof(input) - 1 };
	struct msghdr message = {
		.msg_name = &peer,
		.msg_namelen = sizeof(peer),
		.msg_iov = &vector,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	char phase[65], nonce[65], extra;
	uint64_t timestamp_ns, sequence;
	ssize_t length;

	length = recvmsg(marker_fd, &message, MSG_DONTWAIT);
	if (length < 0)
		return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
	if (length == 0 || (size_t)length >= sizeof(input) ||
	    receive_timestamp(&message, &timestamp_ns) != 0)
		return -1;
	input[length] = '\0';
	if (sscanf(input, "MARK %64s %64s %c", phase, nonce, &extra) != 2 ||
	    !valid_atom(phase, 64) || !valid_digest(nonce))
		return -1;
	/* Both queues use kernel receive timestamps. Crossing timestamps mean
	 * poll scheduling could not establish a total order. */
	if ((state->last_packet_ns != 0 && state->last_packet_ns >= timestamp_ns) ||
	    (state->last_marker_ns != 0 && timestamp_ns <= state->last_marker_ns))
		state->ordering_ambiguous = 1;
	state->last_marker_ns = timestamp_ns;
	if (write_event(state, "marker", 0, timestamp_ns, phase, nonce,
			&sequence) != 0)
		return -1;
	if (fflush(state->events) != 0)
		return -1;
	length = snprintf(output, sizeof(output), "ACK %" PRIu64 " %s\n",
			  sequence, nonce);
	if (length < 0 || (size_t)length >= sizeof(output) ||
	    sendto(marker_fd, output, (size_t)length, 0,
		   (struct sockaddr *)&peer, message.msg_namelen) != length)
		return -1;
	return 1;
}

static int get_packet_stats(int fd, struct packet_stats *result)
{
	struct tpacket_stats stats = { 0 };
	socklen_t length = sizeof(stats);

	if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &length) != 0 ||
	    length != sizeof(stats))
		return -1;
	result->packets = stats.tp_packets;
	result->drops = stats.tp_drops;
	return 0;
}

static int freeze_packet_socket(int fd)
{
	struct sock_filter instructions[] = {
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_fprog filter = {
		.len = sizeof(instructions) / sizeof(instructions[0]),
		.filter = instructions,
	};
	struct sockaddr_ll address = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
	};

	/* A zero protocol preserves po->num in packet_do_bind(), so it cannot
	 * detach an ETH_P_ALL socket. Reject new traffic first, then force a
	 * protocol rehook. The old hook's synchronize_net() completes before bind
	 * returns; the replacement hook cannot queue or account packets. */
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) != 0)
		return -1;
	return bind(fd, (struct sockaddr *)&address, sizeof(address));
}

static int write_stats(const char *path, const struct capture_state *state,
		       const struct packet_stats *stats, int ordered)
{
	FILE *output = fopen(path, ordered ? "wx" : "w");
	int failed;

	if (output == NULL)
		return -1;
	if (ordered)
		failed = fprintf(output,
				 "schema=nlm-capture-stats.v2 captured=%" PRIu64
				 " packets=%u drops=%u events=%" PRIu64
				 " ordering_ambiguous=%d\n", state->captured,
				 stats->packets, stats->drops, state->next_event + 1,
				 state->ordering_ambiguous) < 0;
	else
		failed = fprintf(output,
				 "captured=%" PRIu64 " packets=%u drops=%u\n",
				 state->captured, stats->packets, stats->drops) < 0;
	return fclose(output) != 0 || failed ? -1 : 0;
}

static int write_complete(const char *path, const struct capture_state *state,
			  int ordered)
{
	FILE *output = fopen(path, "wx");
	int failed;

	if (output == NULL)
		return -1;
	failed = ordered && fprintf(output,
				    "schema=nlm-capture-complete.v1 captured=%" PRIu64
				    " events=%" PRIu64 " ordering_ambiguous=%d\n",
				    state->captured, state->next_event,
				    state->ordering_ambiguous) < 0;
	return fclose(output) != 0 || failed ? -1 : 0;
}

static int mark_client(const char *socket_path, const char *phase,
		       const char *nonce)
{
	struct sockaddr_un local = { .sun_family = AF_UNIX };
	struct sockaddr_un remote = { .sun_family = AF_UNIX };
	char local_path[sizeof(local.sun_path)], request[256], response[256];
	struct pollfd event;
	char ack_nonce[65], extra;
	uint64_t sequence;
	ssize_t received;
	int fd, length, ready, result = 1, bound = 0;

	if (strlen(socket_path) >= sizeof(remote.sun_path) ||
	    !valid_atom(phase, 64) || !valid_digest(nonce))
		return 2;
	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 1;
	length = snprintf(local_path, sizeof(local_path), "/tmp/nlm-pcap-mark.%ld",
			  (long)getpid());
	if (length < 0 || (size_t)length >= sizeof(local_path))
		goto out;
	memcpy(local.sun_path, local_path, (size_t)length + 1);
	memcpy(remote.sun_path, socket_path, strlen(socket_path) + 1);
	unlink(local.sun_path);
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0)
		goto out;
	bound = 1;
	length = snprintf(request, sizeof(request), "MARK %s %s\n", phase, nonce);
	if (length < 0 || (size_t)length >= sizeof(request) ||
	    sendto(fd, request, (size_t)length, 0, (struct sockaddr *)&remote,
		   sizeof(remote)) != length)
		goto out;
	event.fd = fd;
	event.events = POLLIN;
	ready = poll(&event, 1, 5000);
	if (ready != 1 || !(event.revents & POLLIN))
		goto out;
	received = recv(fd, response, sizeof(response) - 1, 0);
	if (received <= 0)
		goto out;
	response[received] = '\0';
	if (sscanf(response, "ACK %" SCNu64 " %64s %c", &sequence,
		   ack_nonce, &extra) != 2 || strcmp(ack_nonce, nonce) != 0)
		goto out;
	result = 0;
out:
	close(fd);
	if (bound)
		unlink(local.sun_path);
	return result;
}

int main(int argc, char **argv)
{
	int timestamping = 1;
	unsigned int loopback_ifindex = 0;
	struct {
		uint32_t magic;
		uint16_t major, minor;
		int32_t zone;
		uint32_t sigfigs, snaplen, linktype;
	} header = { 0xa1b2c3d4u, 2, 4, 0, 0, 65536, 1 };
	struct capture_state state = { .packet_fd = -1 };
	struct packet_stats stats;
	struct sigaction action = { .sa_handler = stop };
	struct sockaddr_un marker_address = { .sun_family = AF_UNIX };
	const char *stats_path, *ready_path = NULL, *complete_path = NULL;
	const char *stop_path = NULL, *event_path = NULL, *marker_path = NULL;
	const char *vm_instance_id = NULL;
	int marker_fd = -1, ordered = 0, result = 1;
	uint64_t timestamp_ns;

	if (argc == 5 && strcmp(argv[1], "--mark") == 0)
		return mark_client(argv[2], argv[3], argv[4]);
	if (argc < 2 || argc > 9 || (argc > 6 && argc != 9))
		return 2;
	stats_path = argc >= 3 ? argv[2] : NULL;
	ready_path = argc >= 4 ? argv[3] : NULL;
	complete_path = argc >= 5 ? argv[4] : NULL;
	stop_path = argc >= 6 ? argv[5] : NULL;
	if (argc == 9) {
		event_path = argv[6];
		marker_path = argv[7];
		vm_instance_id = argv[8];
		if (!valid_atom(vm_instance_id, 128) ||
		    strlen(marker_path) >= sizeof(marker_address.sun_path))
			return 2;
		ordered = 1;
	}
	state.pcap = fopen(argv[1], ordered ? "wbx" : "wb");
	if (state.pcap == NULL)
		return 2;
	state.packet_fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK,
				 htons(ETH_P_ALL));
	if (ordered)
		loopback_ifindex = if_nametoindex("lo");
	if (state.packet_fd < 0 ||
	    (ordered && (loopback_ifindex == 0 ||
			 attach_ipv4_tcp_filter(state.packet_fd,
					loopback_ifindex) != 0)) ||
	    setsockopt(state.packet_fd, SOL_SOCKET, SO_TIMESTAMPNS,
		       &timestamping, sizeof(timestamping)) != 0 ||
	    fwrite(&header, sizeof(header), 1, state.pcap) != 1)
		goto out;
	state.pcap_used = sizeof(header);
	if (ordered) {
		state.events = fopen(event_path, "wx");
		if (state.events == NULL)
			goto out;
		state.event_used = (uint64_t)fprintf(state.events,
				"NLM_CAPTURE_EVENTS_V1\t%s\n", vm_instance_id);
		if ((int64_t)state.event_used <= 0 || realtime_ns(&timestamp_ns) != 0 ||
		    write_event(&state, "capture_start", 0, timestamp_ns, "-", "-",
				NULL) != 0)
			goto out;
		marker_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (marker_fd < 0 || setsockopt(marker_fd, SOL_SOCKET, SO_TIMESTAMPNS,
					  &timestamping, sizeof(timestamping)) != 0)
			goto out;
		memcpy(marker_address.sun_path, marker_path, strlen(marker_path) + 1);
		unlink(marker_path);
		if (bind(marker_fd, (struct sockaddr *)&marker_address,
			 sizeof(marker_address)) != 0 || chmod(marker_path, 0600) != 0)
			goto out;
	}
	if (sigaction(SIGTERM, &action, NULL) != 0 ||
	    sigaction(SIGINT, &action, NULL) != 0)
		goto out;
	if (fflush(state.pcap) != 0 ||
	    (state.events != NULL && fflush(state.events) != 0))
		goto out;
	if (ready_path != NULL) {
		FILE *ready = fopen(ready_path, "wx");

		if (ready == NULL || fclose(ready) != 0)
			goto out;
	}
	while (!stopping) {
		struct pollfd events[2] = {
			{ .fd = state.packet_fd, .events = POLLIN },
			{ .fd = marker_fd, .events = POLLIN },
		};
		int ready;

		if (stop_path != NULL) {
			if (access(stop_path, F_OK) == 0)
				break;
			if (errno != ENOENT)
				goto out;
		}
		ready = poll(events, ordered ? 2 : 1, stop_path != NULL ? 100 : -1);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (ready == 0)
			continue;
		if (events[0].revents & POLLIN) {
			int drained = drain_packets(&state);
			if (drained == -2) {
				result = 3;
				goto out;
			}
			if (drained != 0)
				goto out;
		} else if (events[0].revents)
			goto out;
		if (ordered && (events[1].revents & POLLIN)) {
			int drained = drain_packets(&state);
			if (drained != 0 || receive_marker(&state, marker_fd) <= 0)
				goto out;
		} else if (ordered && events[1].revents)
			goto out;
	}
	if (freeze_packet_socket(state.packet_fd) != 0 ||
	    drain_packets(&state) != 0 || realtime_ns(&timestamp_ns) != 0 ||
	    write_event(&state, "capture_stop", 0, timestamp_ns, "-", "-", NULL) != 0 ||
	    get_packet_stats(state.packet_fd, &stats) != 0)
		goto out;
	if (stats_path != NULL &&
	    write_stats(stats_path, &state, &stats, ordered) != 0)
		goto out;
	if (realtime_ns(&timestamp_ns) != 0 ||
	    write_event(&state, "capture_complete", 0, timestamp_ns, "-", "-",
			NULL) != 0 || fflush(state.pcap) != 0 ||
	    (state.events != NULL && fflush(state.events) != 0))
		goto out;
	if (fclose(state.pcap) != 0)
		goto out_closed;
	state.pcap = NULL;
	if (state.events != NULL && fclose(state.events) != 0)
		goto out_closed;
	state.events = NULL;
	if (close(state.packet_fd) != 0)
		goto out_closed;
	state.packet_fd = -1;
	if (marker_fd >= 0 && close(marker_fd) != 0)
		goto out_closed;
	marker_fd = -1;
	if (marker_path != NULL && unlink(marker_path) != 0)
		goto out_closed;
	if (complete_path != NULL &&
	    write_complete(complete_path, &state, ordered) != 0)
		goto out_closed;
	return 0;

out:
	if (state.pcap != NULL)
		fclose(state.pcap);
	if (state.events != NULL)
		fclose(state.events);
	if (state.packet_fd >= 0)
		close(state.packet_fd);
	if (marker_fd >= 0)
		close(marker_fd);
out_closed:
	if (marker_path != NULL)
		unlink(marker_path);
	return result;
}
