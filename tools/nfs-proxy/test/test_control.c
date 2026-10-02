#define _POSIX_C_SOURCE 200809L
#include "control.h"
#include "walk.h"

#include <errno.h>
#include <limits.h>
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

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
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

/* A COMPOUND4args CALL: 2 ops, each one word, after the fixed header. */
static size_t build_call(uint8_t b[64])
{
	memset(b, 0, 64);
	w32(b, 0, 0x80000000u | 60u);	/* body: everything after the marker */
	w32(b, 4, 0x22334455u);		/* xid */
	w32(b, 8, NFSP_MSGTYPE_CALL);
	w32(b, 12, NFSP_RPCVERS);
	w32(b, 16, NFSP_PROG_NFS);
	w32(b, 20, NFSP_NFS_V4);
	w32(b, 24, NFSP_PROC4_COMPOUND);
	w32(b, 28, 0); /* cred flavour */
	w32(b, 32, 0); /* cred len */
	w32(b, 36, 0); /* verf flavour */
	w32(b, 40, 0); /* verf len */
	w32(b, 44, 0); /* tag len */
	w32(b, 48, 1); /* minorversion */
	w32(b, 52, 2); /* opcount */
	w32(b, 56, 9); /* op[0] = GETATTR */
	w32(b, 60, 10); /* op[1] = GETFH */
	return 64u;	/* marker(4) + 15 header/op words(60) */
}

static int connect_arm(const char *socket_path)
{
	struct sockaddr_un sa = {0};
	int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0) return -1;
	sa.sun_family = AF_UNIX;
	(void)snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", socket_path);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
	return fd;
}

static int wait_ack(int fd, uint8_t *ack)
{
	*ack = 255;
	return recv(fd, ack, 1, MSG_DONTWAIT) == 1 ? 0 : -1;
}

/* ---- v1 scenario (same as before the on_record signature changed) -------- */

static void test_v1_lifecycle(struct nfsp_control *live, const char *socket_path,
			      const char *delta_path)
{
	uint8_t packet[NFSP_ARM_WIRE_LEN] = {0}, record[44], ack;
	struct nfsp_delta_reader *reader = NULL;
	struct nfsp_rule rule;
	const uint8_t *out;
	size_t outlen;
	int fd;

	fd = connect_arm(socket_path);
	CHECK(fd >= 0, "v1: connect");
	if (fd < 0) return;
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
	CHECK(send(fd, packet, sizeof(packet), 0) == (ssize_t)sizeof(packet), "v1: send arm");
	nfsp_control_tick(live);
	CHECK(wait_ack(fd, &ack) == 0 && ack == 0,
	      "v1: arm ACK requires registration before execution");

	for (unsigned client = 0; client < 2; client++) {
		for (unsigned backend = 0; backend < 2; backend++) {
			reply(record);
			out = record; outlen = sizeof(record);
			CHECK(nfsp_control_record(client, backend, 1, record, sizeof(record),
						  &out, &outlen, live) == 0, "v1: record hook");
			CHECK(out != NULL && outlen == sizeof(record), "v1: output shape");
			CHECK(out[30] == (client == 1 && backend == 1 ? 0x27 : 0),
			      "v1: tuple (%u,%u) changed when it should not", client, backend);
			/* the caller's own buffer must never be touched */
			CHECK(record[30] == 0, "v1: read-only record was mutated");
		}
	}
	reply(record);
	out = record; outlen = sizeof(record);
	CHECK(nfsp_control_record(1, 1, 0, record, sizeof(record), &out, &outlen, live) == 0,
	      "v1: C2S scope");
	CHECK(out[30] == 0, "v1: C2S must be untouched");

	CHECK(nfsp_delta_read_open(&reader, delta_path) == 0, "v1: durable file before close");
	CHECK(nfsp_delta_read_rule(reader, &rule) == 1 && rule.applied_count == 1,
	      "v1: on-disk count after first application");
	nfsp_delta_read_close(reader);
	reader = NULL;

	reply(record);
	out = record; outlen = sizeof(record);
	CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record), &out, &outlen, live) == 0,
	      "v1: all-content second application");
	CHECK(nfsp_delta_read_open(&reader, delta_path) == 0, "v1: read updated count");
	CHECK(nfsp_delta_read_rule(reader, &rule) == 1 && rule.applied_count == 2,
	      "v1: durable all-match count");
	nfsp_delta_read_close(reader);

	close(fd);
	nfsp_control_tick(live);
	reply(record);
	out = record; outlen = sizeof(record);
	CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record), &out, &outlen, live) == 0,
	      "v1: after-close hook");
	CHECK(out[30] == 0, "v1: closed owner rule leaked to subsequent program");
}

static void test_v1_replay(const char *delta_path)
{
	struct nfsp_control *replay = NULL;
	uint8_t record[44];
	const uint8_t *out;
	size_t outlen;

	CHECK(nfsp_control_open(&replay, NULL, NULL, delta_path) == 0, "v1 replay: open");
	if (replay != NULL) {
		for (unsigned i = 0; i < 2; i++) {
			reply(record);
			out = record; outlen = sizeof(record);
			CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record),
						  &out, &outlen, replay) == 0,
			      "v1 replay: application");
			CHECK(out[30] == 0x27 && out[31] == 0x16,
			      "v1 replay: used different bytes");
		}
		CHECK(nfsp_control_close(replay) == 0, "v1 replay: matched count");
	}

	CHECK(nfsp_control_open(&replay, NULL, NULL, delta_path) == 0,
	      "v1 replay: mismatch open");
	if (replay != NULL) {
		reply(record);
		record[28] = 1;
		out = record; outlen = sizeof(record);
		CHECK(nfsp_control_record(1, 1, 1, record, sizeof(record),
					  &out, &outlen, replay) == 0,
		      "v1 replay: mismatch is a refused record, not a malformed connection");
		CHECK(out[28] == 1, "v1 replay: refused orig mismatch changed the record");
		CHECK(nfsp_control_close(replay) == -1,
		      "v1 replay: count mismatch/original mismatch must fail replay");
	}
}

/* ---- v2 (variable-length edit) arm packet builder ------------------------ */

struct v2builder {
	uint8_t buf[NFSP_EDIT_ARM_MAX_LEN];
	size_t len;
};

static void v2_begin(struct v2builder *b, uint32_t dir, uint32_t backend,
		     uint32_t client, uint32_t mode)
{
	memset(b->buf, 0, sizeof(b->buf));
	memcpy(b->buf, NFSP_EDIT_ARM_MAGIC, 8);
	w32(b->buf, 8, dir);
	w32(b->buf, 12, backend);
	w32(b->buf, 16, client);
	w32(b->buf, 20, 0xffffffffu);	/* first_opcode: any */
	w32(b->buf, 24, 0);		/* anchor_off */
	w32(b->buf, 28, 0);		/* anchor_len */
	w32(b->buf, 32, mode);
	w32(b->buf, 36, 0);		/* nedits, filled by v2_add_edit */
	w32(b->buf, 40, 0);		/* reserved */
	b->len = NFSP_EDIT_ARM_HDR_LEN;
}

static void v2_add_edit(struct v2builder *b, uint32_t kind, uint32_t offset,
			const uint8_t *orig, uint32_t orig_len,
			const uint8_t *data, uint32_t data_len)
{
	uint32_t n = get32(b->buf + 36) + 1u;
	unsigned off = (unsigned)b->len;
	w32(b->buf, off, kind); w32(b->buf, off + 4u, offset);
	w32(b->buf, off + 8u, orig_len); w32(b->buf, off + 12u, data_len);
	off += NFSP_EDIT_ARM_FIELD_HDR_LEN;
	if (orig_len) memcpy(b->buf + off, orig, orig_len);
	off += orig_len;
	if (data_len) memcpy(b->buf + off, data, data_len);
	off += data_len;
	b->len = off;
	w32(b->buf, 36, n);
}

static int send_v2(const char *socket_path, const struct v2builder *b)
{
	int fd = connect_arm(socket_path);
	if (fd < 0) return -1;
	if (send(fd, b->buf, b->len, 0) != (ssize_t)b->len) { close(fd); return -1; }
	return fd;
}

/* ---- v2 scenario: OP_APPEND grows a COMPOUND, replay reproduces it ------- */

static void test_v2_lifecycle_and_replay(const char *socket_path, const char *delta_dir)
{
	struct nfsp_control *live = NULL;
	struct v2builder b;
	uint8_t call[64], ack;
	const uint8_t *out;
	size_t calllen, outlen;
	char delta_path[128];
	int fd;

	CHECK(nfsp_control_open(&live, socket_path, delta_dir, NULL) == 0, "v2: control open");
	if (live == NULL) return;

	calllen = build_call(call);
	v2_begin(&b, NFSP_DELTA_C2S, NFSP_DELTA_BACKEND_KNFSD, 0, NFSP_EDIT_MODE_STRUCT);
	{
		uint8_t appended[4] = {0xde, 0xad, 0xbe, 0xef};
		v2_add_edit(&b, NFSP_EDIT_OP_APPEND, 0, NULL, 0, appended, sizeof(appended));
	}
	fd = send_v2(socket_path, &b);
	CHECK(fd >= 0, "v2: connect+send arm");
	if (fd < 0) { nfsp_control_close(live); return; }
	nfsp_control_tick(live);
	CHECK(wait_ack(fd, &ack) == 0 && ack == 0, "v2: arm ACK");

	out = call; outlen = calllen;
	CHECK(nfsp_control_record(0, NFSP_DELTA_BACKEND_KNFSD, NFSP_DELTA_C2S,
				  call, calllen, &out, &outlen, live) == 0,
	      "v2: record hook");
	CHECK(outlen == calllen + 4u, "v2: grew by 4, got %zu want %zu",
	      outlen, calllen + 4u);
	CHECK(out != NULL && get32(out + calllen) == 0xdeadbeefu,
	      "v2: appended op missing");
	CHECK(get32(out + 52) == 3u, "v2: opcount not bumped, got %u", get32(out + 52));
	CHECK(call[52] == 0 && get32(call + 52) == 2u,
	      "v2: read-only input record was mutated");

	/* a tuple this arm does not cover is pure relay: *out / *out_len untouched */
	{
		const uint8_t *out2 = (const uint8_t *)0x1;
		size_t outlen2 = 999;
		CHECK(nfsp_control_record(1, NFSP_DELTA_BACKEND_KNFSD, NFSP_DELTA_C2S,
					  call, calllen, &out2, &outlen2, live) == 0,
		      "v2: non-matching tuple hook");
		CHECK(out2 == (const uint8_t *)0x1 && outlen2 == 999,
		      "v2: non-matching tuple must leave out/out_len untouched");
	}

	close(fd);
	nfsp_control_tick(live);
	CHECK(nfsp_control_close(live) == 0, "v2: live close");

	/* exactly one delta file should exist; replay it */
	(void)snprintf(delta_path, sizeof(delta_path), "%s/arm-0.delta", delta_dir);
	{
		struct nfsp_control *replay = NULL;
		CHECK(nfsp_control_open(&replay, NULL, NULL, delta_path) == 0,
		      "v2 replay: open");
		if (replay != NULL) {
			out = call; outlen = calllen;
			CHECK(nfsp_control_record(0, NFSP_DELTA_BACKEND_KNFSD, NFSP_DELTA_C2S,
						  call, calllen, &out, &outlen, replay) == 0,
			      "v2 replay: application");
			CHECK(outlen == calllen + 4u && get32(out + calllen) == 0xdeadbeefu,
			      "v2 replay: did not rebuild the same record");
			CHECK(nfsp_control_close(replay) == 0, "v2 replay: matched count");
		}
	}
	CHECK(unlink(delta_path) == 0, "v2: remove delta");
}

/* ---- v1 and v2 arms chained on the SAME record --------------------------- */

static void test_v1_then_v2_chain(const char *socket_path, const char *delta_dir)
{
	struct nfsp_control *live = NULL;
	uint8_t v1packet[NFSP_ARM_WIRE_LEN] = {0};
	struct v2builder b;
	uint8_t call[64], ack;
	const uint8_t *out;
	size_t calllen, outlen;
	int fd1, fd2;
	char path0[128], path1[128];

	CHECK(nfsp_control_open(&live, socket_path, delta_dir, NULL) == 0, "chain: open");
	if (live == NULL) return;

	/* v1 arm: overwrite op[0] (GETATTR, word at offset 56) with a 4-byte
	 * same-width patch, verified against its real value. */
	memcpy(v1packet, NFSP_ARM_MAGIC, 8);
	w32(v1packet, 8, NFSP_DELTA_C2S);
	w32(v1packet, 12, NFSP_DELTA_BACKEND_KNFSD);
	w32(v1packet, 16, 0);
	w32(v1packet, 20, 0xffffffffu);
	w32(v1packet, 32, 56); /* patch_off: op[0] */
	w32(v1packet, 36, 4);
	v1packet[8u + 4u * NFSP_ARM_WORDS + NFSP_DELTA_ANCHOR_MAX + 3u] = 9; /* orig = GETATTR */
	v1packet[8u + 4u * NFSP_ARM_WORDS + NFSP_DELTA_ANCHOR_MAX + NFSP_DELTA_PATCH_MAX + 3u] = 3; /* repl = ACCESS */
	fd1 = connect_arm(socket_path);
	CHECK(fd1 >= 0, "chain: v1 connect");
	CHECK(send(fd1, v1packet, sizeof(v1packet), 0) == (ssize_t)sizeof(v1packet),
	      "chain: v1 send");

	v2_begin(&b, NFSP_DELTA_C2S, NFSP_DELTA_BACKEND_KNFSD, 0, NFSP_EDIT_MODE_RAW);
	{
		uint8_t appended[4] = {0, 0, 0, 77};
		v2_add_edit(&b, NFSP_EDIT_OP_APPEND, 0, NULL, 0, appended, sizeof(appended));
	}
	fd2 = send_v2(socket_path, &b);
	CHECK(fd2 >= 0, "chain: v2 connect+send");

	nfsp_control_tick(live);
	CHECK(wait_ack(fd1, &ack) == 0 && ack == 0, "chain: v1 ack");
	CHECK(wait_ack(fd2, &ack) == 0 && ack == 0, "chain: v2 ack");

	calllen = build_call(call);
	out = call; outlen = calllen;
	CHECK(nfsp_control_record(0, NFSP_DELTA_BACKEND_KNFSD, NFSP_DELTA_C2S,
				  call, calllen, &out, &outlen, live) == 0,
	      "chain: record hook");
	CHECK(outlen == calllen + 4u, "chain: length after append");
	CHECK(get32(out + 56) == 3u, "chain: v1 patch not visible (op[0]=%u)",
	      get32(out + 56));
	CHECK(get32(out + calllen) == 77u, "chain: v2 append not applied");
	/* raw mode: opcount must NOT be bumped by the append */
	CHECK(get32(out + 52) == 2u, "chain: raw append bumped opcount to %u",
	      get32(out + 52));

	close(fd1); close(fd2);
	nfsp_control_tick(live);
	CHECK(nfsp_control_close(live) == 0, "chain: close");
	(void)snprintf(path0, sizeof(path0), "%s/arm-0.delta", delta_dir);
	(void)snprintf(path1, sizeof(path1), "%s/arm-1.delta", delta_dir);
	CHECK(unlink(path0) == 0 && unlink(path1) == 0, "chain: remove deltas");
}

int main(void)
{
	char dir[] = "/tmp/nfsp-ctl-XXXXXX";
	char socket_path[64], delta_dir[64], delta_path[96];
	struct nfsp_control *live = NULL;

	printf("control FD lifetime, four scopes, durable delta, same replay apply\n");
	CHECK(mkdtemp(dir) != NULL, "mkdtemp");
	if (failures) return 1;
	(void)snprintf(socket_path, sizeof(socket_path), "%s/arm.sock", dir);
	(void)snprintf(delta_dir, sizeof(delta_dir), "%s/deltas", dir);
	(void)snprintf(delta_path, sizeof(delta_path), "%s/arm-0.delta", delta_dir);
	CHECK(mkdir(delta_dir, 0700) == 0, "mkdir deltas");

	CHECK(nfsp_control_open(&live, socket_path, delta_dir, NULL) == 0, "control open");
	if (live != NULL) {
		test_v1_lifecycle(live, socket_path, delta_path);
		CHECK(nfsp_control_close(live) == 0, "live close");
		test_v1_replay(delta_path);
		CHECK(unlink(delta_path) == 0, "remove delta");
	}

	printf("v2 (variable-length edit) arm lifecycle and replay\n");
	test_v2_lifecycle_and_replay(socket_path, delta_dir);

	printf("v1 and v2 arms chained on one record\n");
	test_v1_then_v2_chain(socket_path, delta_dir);

	CHECK(rmdir(delta_dir) == 0 && rmdir(dir) == 0,
	      "control socket removed on close");
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
