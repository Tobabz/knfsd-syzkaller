#define _POSIX_C_SOURCE 200809L
#include "control.h"
#include "walk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

static void w32(uint8_t *b, unsigned off, uint32_t v)
{
	b[off] = (uint8_t)(v >> 24);
	b[off + 1u] = (uint8_t)(v >> 16);
	b[off + 2u] = (uint8_t)(v >> 8);
	b[off + 3u] = (uint8_t)v;
}

static void reply(uint8_t b[44])
{
	memset(b, 0, 44);
	w32(b, 0, 0x80000028u);
	w32(b, 4, 0x12345678u);
	w32(b, 8, NFSP_MSGTYPE_REPLY);
	w32(b, 12, NFSP_MSGP_ACCEPTED);
	w32(b, 24, NFSP_MSGS_ACCEPTED);
	w32(b, 28, 0); /* NFS status; this is the typed slot to patch */
	w32(b, 36, 1); /* opcount */
	w32(b, 40, 9); /* GETATTR */
}

int main(void)
{
	char dir[] = "/tmp/nfsp-ctl-XXXXXX";
	char socket_path[64], delta_dir[64], delta_path[96];
	struct nfsp_control *live = NULL, *replay = NULL;
	struct nfsp_delta_reader *reader = NULL;
	struct nfsp_rule rule;
	struct sockaddr_un sa = {0};
	uint8_t packet[NFSP_ARM_WIRE_LEN] = {0}, record[44], ack = 255;
	int fd = -1;

	printf("control FD lifetime, four scopes, durable delta, same replay apply\n");
	CHECK(mkdtemp(dir) != NULL, "mkdtemp");
	if (failures) return 1;
	(void)snprintf(socket_path, sizeof(socket_path), "%s/arm.sock", dir);
	(void)snprintf(delta_dir, sizeof(delta_dir), "%s/deltas", dir);
	(void)snprintf(delta_path, sizeof(delta_path), "%s/arm-0.delta", delta_dir);
	CHECK(mkdir(delta_dir, 0700) == 0, "mkdir deltas");
	CHECK(nfsp_control_open(&live, socket_path, delta_dir, NULL) == 0, "control open");
	if (live == NULL) return 1;
	sa.sun_family = AF_UNIX;
	(void)snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", socket_path);
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	CHECK(fd >= 0, "socket");
	if (fd < 0) return 1;
	CHECK(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0, "connect");
	memcpy(packet, NFSP_ARM_MAGIC, 8);
	w32(packet, 8, NFSP_DELTA_S2C);
	w32(packet, 12, NFSP_DELTA_BACKEND_GANESHA);
	w32(packet, 16, 1);  /* client 1 only */
	w32(packet, 20, NFSP_DELTA_OPCODE_ANY);
	w32(packet, 32, 28); /* NFS status, not the record marker */
	w32(packet, 36, 4);
	packet[8u + 4u * NFSP_ARM_WORDS + NFSP_DELTA_ANCHOR_MAX +
		NFSP_DELTA_PATCH_MAX + 2u] = 0x27;
	packet[8u + 4u * NFSP_ARM_WORDS + NFSP_DELTA_ANCHOR_MAX +
		NFSP_DELTA_PATCH_MAX + 3u] = 0x16;
	CHECK(send(fd, packet, sizeof(packet), 0) == (ssize_t)sizeof(packet), "send arm");
	nfsp_control_tick(live);
	CHECK(recv(fd, &ack, 1, MSG_DONTWAIT) == 1 && ack == 0,
	      "arm ACK requires registration before execution");
	for (unsigned client = 0; client < 2; client++) {
		for (unsigned backend = 0; backend < 2; backend++) {
			reply(record);
			CHECK(nfsp_control_record(client, backend, 1, record,
						  sizeof(record), live) == 0, "record hook");
			CHECK(record[30] == (client == 1 && backend == 1 ? 0x27 : 0),
				      "tuple (%u,%u) changed when it should not", client, backend);
		}
	}
	reply(record);
	CHECK(nfsp_control_record(1, 1, 0, record, sizeof(record), live) == 0,
	      "C2S scope");
	CHECK(record[30] == 0, "C2S must be untouched");
	CHECK(nfsp_delta_read_open(&reader, delta_path) == 0, "durable file before close");
	CHECK(nfsp_delta_read_rule(reader, &rule) == 1 && rule.applied_count == 1,
	      "on-disk count after first application");
	nfsp_delta_read_close(reader);
	reader = NULL;
	reply(record);
	CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record), live) == 0,
	      "all-content second application");
	CHECK(nfsp_delta_read_open(&reader, delta_path) == 0, "read updated count");
	CHECK(nfsp_delta_read_rule(reader, &rule) == 1 && rule.applied_count == 2,
	      "durable all-match count");
	nfsp_delta_read_close(reader);
	close(fd);
	nfsp_control_tick(live);
	reply(record);
	CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record), live) == 0,
	      "after-close hook");
	CHECK(record[30] == 0, "closed owner rule leaked to subsequent program");
	CHECK(nfsp_control_close(live) == 0, "live close");
	CHECK(nfsp_control_open(&replay, NULL, NULL, delta_path) == 0, "replay open");
	if (replay != NULL) {
		for (unsigned i = 0; i < 2; i++) {
			reply(record);
			CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record), replay) == 0,
			      "replay application");
			CHECK(record[30] == 0x27 && record[31] == 0x16,
			      "replay used different bytes");
		}
		CHECK(nfsp_control_close(replay) == 0, "matched replay count");
	}
	CHECK(nfsp_control_open(&replay, NULL, NULL, delta_path) == 0,
	      "mismatch replay open");
	if (replay != NULL) {
		reply(record);
		record[28] = 1;
		CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record), replay) == 0,
		      "mismatch is a refused record, not a malformed connection");
		CHECK(record[28] == 1, "refused orig mismatch changed the record");
		CHECK(nfsp_control_close(replay) == -1,
		      "count mismatch/original mismatch must fail replay");
	}
	CHECK(unlink(delta_path) == 0, "remove delta");
	CHECK(rmdir(delta_dir) == 0 && rmdir(dir) == 0,
	      "control socket removed on close");
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
