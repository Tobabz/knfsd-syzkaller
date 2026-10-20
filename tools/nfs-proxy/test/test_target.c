/* Focused target generation-retirement integration test.
 *
 * This is deliberately a white-box test: target.c owns the ordering between
 * the journal callback, its tgen storage, and activation.c's bounded slots.
 * Including it lets the test prove that merely queueing GENERATION_COMPLETE
 * does not retire either object; only the host durability ACK may do so.
 */
#define _POSIX_C_SOURCE 200809L
#include "../src/target.c"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

extern const struct nfsp_schema_family nfsp_schema_family_nfs4;

static unsigned checks, failures;
#define CHECK(x, ...) do { checks++; if (!(x)) { failures++; \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

#define TEST_SESSION "target-retirement"
#define ZERO64 "0000000000000000000000000000000000000000000000000000000000000000"

struct host_event {
	int fd;
	uint64_t seq;
	char type[32];
	char request_sha[65];
};

struct answer_log {
	unsigned count;
	uint32_t op;
	uint32_t status;
	uint64_t generation;
};

static void put32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static size_t put_string(uint8_t *p, size_t off, const char *value)
{
	size_t len = strlen(value);
	size_t padded = (len + 3u) & ~(size_t)3u;

	put32(p + off, (uint32_t)len);
	off += 4u;
	memcpy(p + off, value, len);
	memset(p + off + len, 0, padded - len);
	return off + padded;
}

static size_t zero_rule_set(uint8_t out[512], const char *schema_id)
{
	size_t off = 0;

	memset(out, 0, 512);
	memcpy(out, NFSP_RULESET_MAGIC, 8);
	off = 8;
	put32(out + off, NFSP_SEMANTIC_RUNTIME_VERSION);
	off += 4;
	off = put_string(out, off, schema_id);
	off = put_string(out, off, "retirement-candidate");
	put32(out + off, 0); /* rules<> */
	return off + 4u;
}

static int wait_readable(int fd)
{
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	return poll(&pfd, 1, 2000) == 1 && (pfd.revents & POLLIN) != 0;
}

static int read_full(int fd, uint8_t *p, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t got = recv(fd, p + off, len - off, 0);

		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0)
			return -1;
		off += (size_t)got;
	}
	return 0;
}

static int write_full(int fd, const uint8_t *p, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t sent = send(fd, p + off, len - off, MSG_NOSIGNAL);

		if (sent < 0 && errno == EINTR)
			continue;
		if (sent <= 0)
			return -1;
		off += (size_t)sent;
	}
	return 0;
}

static int host_read_event(struct host_event *host)
{
	uint8_t header[NFSP_JOURNAL_HEADER_LEN];
	uint8_t *payload = NULL;
	struct nfsp_jval root, value;
	uint8_t digest[NFSP_SHA256_LEN];
	uint32_t len;
	int result = -1;

	if (!wait_readable(host->fd) || read_full(host->fd, header,
						     sizeof(header)) != 0)
		return -1;
	len = (uint32_t)header[12] << 24 | (uint32_t)header[13] << 16 |
	      (uint32_t)header[14] << 8 | header[15];
	if (len == 0 || len > NFSP_JOURNAL_MAX_REQUEST)
		return -1;
	payload = malloc(len);
	if (payload == NULL || read_full(host->fd, payload, len) != 0)
		goto out;
	root.p = (const char *)payload;
	root.len = len;
	if (nfsp_json_member(root, "event_seq", &value) != 0 ||
	    nfsp_json_u64(value, &host->seq) != 0 ||
	    nfsp_json_member(root, "event_type", &value) != 0 ||
	    nfsp_json_str(value, host->type, sizeof(host->type)) != 0)
		goto out;
	nfsp_sha256(payload, len, digest);
	nfsp_sha256_hex(digest, host->request_sha);
	result = 0;
out:
	free(payload);
	return result;
}

static int host_send_json(struct host_event *host, uint16_t kind,
			  const char *json)
{
	uint8_t *frame;
	size_t len;
	int result;

	frame = nfsp_journal_frame(kind, (const uint8_t *)json, strlen(json),
				   &len);
	if (frame == NULL)
		return -1;
	result = write_full(host->fd, frame, len);
	free(frame);
	return result;
}

static int host_ack(struct host_event *host, const char *rule_set_id)
{
	char json[1024];

	(void)snprintf(json, sizeof(json),
		"{\"committed_end_offset\":%llu,\"event_seq\":%llu,"
		"\"journal_id\":\"lane0.0001\",\"record_sha256\":\"" ZERO64 "\","
		"\"request_sha256\":\"%s\",\"schema_version\":"
		"\"nfs-proxy-journal-ack.v1\",\"session_binding\":{"
		"\"channel_id\":\"c\",\"proxy_session_id\":\"" TEST_SESSION "\","
		"\"rule_set_id\":\"%s\",\"vm_instance_id\":\"vm\"}}",
		(unsigned long long)(1000u + host->seq),
		(unsigned long long)host->seq, host->request_sha, rule_set_id);
	return host_send_json(host, 3, json);
}

static int host_reject(struct host_event *host, const char *reason)
{
	char json[512];

	(void)snprintf(json, sizeof(json),
		"{\"event_seq\":%llu,\"journal_id\":\"lane0.0001\","
		"\"reason\":\"%s\",\"request_sha256\":\"%s\","
		"\"schema_version\":\"nfs-proxy-journal-reject.v1\"}",
		(unsigned long long)host->seq, reason, host->request_sha);
	return host_send_json(host, 2, json);
}

static void answer(void *arg, uint32_t op, uint64_t generation,
		   uint32_t status)
{
	struct answer_log *log = arg;

	log->count++;
	log->op = op;
	log->generation = generation;
	log->status = status;
}

static void expect_event(struct nfsp_target *target, struct host_event *host,
			 const char *type)
{
	nfsp_target_tick(target);
	CHECK(host_read_event(host) == 0, "read %s", type);
	CHECK(strcmp(host->type, type) == 0, "event %s, want %s", host->type,
	      type);
}

static void ack_event(struct nfsp_target *target, struct host_event *host,
		      const char *rule_set_id)
{
	CHECK(host_ack(host, rule_set_id) == 0, "ACK %s", host->type);
	nfsp_target_tick(target);
}

static void test_complete_ack_is_retirement_point(void)
{
	const struct nfsp_schema_family *families[] = {
		&nfsp_schema_family_nfs4,
	};
	const char *schema_id = nfsp_schema_family_nfs4.schemas[0]->schema_id;
	struct nfsp_target_cfg cfg;
	struct nfsp_target *target = NULL;
	struct host_event host;
	struct answer_log log;
	uint8_t rules[512], digest[NFSP_SHA256_LEN];
	char rule_set_id[65], err[256];
	size_t rules_len;
	int sv[2];
	uint32_t status;

	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "journal socketpair");
	if (checks == failures)
		return;
	rules_len = zero_rule_set(rules, schema_id);
	nfsp_sha256(rules, rules_len, digest);
	nfsp_sha256_hex(digest, rule_set_id);
	memset(&cfg, 0, sizeof(cfg));
	cfg.families = families;
	cfg.nfamilies = 1;
	cfg.rule_set = rules;
	cfg.rule_set_len = rules_len;
	cfg.journal_fd = sv[0];
	cfg.proxy_session_id = TEST_SESSION;
	cfg.lane_id = 0;
	cfg.retransmit_ms = 100;
	memset(err, 0, sizeof(err));
	CHECK(nfsp_target_open(&target, &cfg, err, sizeof(err)) == 0,
	      "target open: %s", err);
	if (target == NULL) {
		close(sv[1]);
		return;
	}
	memset(&host, 0, sizeof(host));
	host.fd = sv[1];
	expect_event(target, &host, "RULESET");
	ack_event(target, &host, rule_set_id);
	CHECK(target->stats.ruleset_state == 1, "RULESET durable");

	for (uint64_t generation = 1; generation <= 300; generation++) {
		memset(digest, (int)(generation & 0xffu), sizeof(digest));
		memset(&log, 0, sizeof(log));
		status = UINT32_MAX;
		CHECK(nfsp_target_request(target, NFSP_TARGET_OP_ACTIVATE,
					  generation, digest, rule_set_id,
					  &status, answer, &log) == 1,
		      "G%llu activation waits for OPEN durability",
		      (unsigned long long)generation);
		expect_event(target, &host, "GENERATION_OPEN");
		ack_event(target, &host, rule_set_id);
		CHECK(log.count == 1 && log.op == NFSP_TARGET_OP_ACTIVATE &&
		      log.generation == generation && log.status == 0,
		      "G%llu activation ACK", (unsigned long long)generation);

		memset(&log, 0, sizeof(log));
		status = UINT32_MAX;
		CHECK(nfsp_target_request(target, NFSP_TARGET_OP_DEACTIVATE,
					  generation, digest, rule_set_id,
					  &status, answer, &log) == 1,
		      "G%llu deactivation waits for DRAINING durability",
		      (unsigned long long)generation);
		expect_event(target, &host, "GENERATION_DRAINING");
		ack_event(target, &host, rule_set_id);
		CHECK(log.count == 1 && log.op == NFSP_TARGET_OP_DEACTIVATE &&
		      log.generation == generation && log.status == 0,
		      "G%llu deactivation ACK", (unsigned long long)generation);

		/* The DRAINING ACK closes a zero-call generation and lifecycle()
		 * queues its summary in the same tick.  Its state must remain until
		 * the host answers that summary. */
		CHECK(host_read_event(&host) == 0 &&
		      strcmp(host.type, "GENERATION_COMPLETE") == 0,
		      "G%llu COMPLETE queued", (unsigned long long)generation);
		CHECK(target->act.generation_count == 1 && target->ngens == 1,
		      "G%llu is not retired before COMPLETE ACK",
		      (unsigned long long)generation);
		ack_event(target, &host, rule_set_id);
		CHECK(target->act.generation_count == 0 && target->ngens == 0 &&
		      target->stats.generations_complete == generation,
		      "G%llu retires exactly at COMPLETE ACK",
		      (unsigned long long)generation);
	}
	CHECK(target->generations_started == 300 &&
	      target->stats.generations_complete == 300 &&
	      !target->stats.evidence_path_degraded,
	      "300 generations pass the former 256-slot lifetime bound");

	status = UINT32_MAX;
	CHECK(nfsp_target_request(target, NFSP_TARGET_OP_ACTIVATE, 1, digest,
				  rule_set_id, &status, NULL, NULL) == 0 &&
	      status == NFSP_ACTIVATION_GENERATION_REUSED,
	      "retired G1 cannot be activated again");
	CHECK(nfsp_target_request(target, NFSP_TARGET_OP_DEACTIVATE, 1, digest,
				  rule_set_id, &status, NULL, NULL) == 0 &&
	      status == 0 &&
	      nfsp_target_request(target, NFSP_TARGET_OP_ABORT, 1, digest,
				  rule_set_id, &status, NULL, NULL) == 0 &&
	      status == 0,
	      "late release of retired G1 is idempotent");

	/* A host refusal is terminal for the journal event but is not the
	 * durability point.  Keep both local objects for diagnostics/fail-closed
	 * shutdown instead of freeing them on any callback. */
	memset(&log, 0, sizeof(log));
	status = UINT32_MAX;
	CHECK(nfsp_target_request(target, NFSP_TARGET_OP_ACTIVATE, 301, digest,
				  rule_set_id, &status, answer, &log) == 1,
	      "G301 activate");
	expect_event(target, &host, "GENERATION_OPEN");
	ack_event(target, &host, rule_set_id);
	memset(&log, 0, sizeof(log));
	CHECK(nfsp_target_request(target, NFSP_TARGET_OP_DEACTIVATE, 301, digest,
				  rule_set_id, &status, answer, &log) == 1,
	      "G301 deactivate");
	expect_event(target, &host, "GENERATION_DRAINING");
	ack_event(target, &host, rule_set_id);
	CHECK(host_read_event(&host) == 0 &&
	      strcmp(host.type, "GENERATION_COMPLETE") == 0,
	      "G301 COMPLETE queued");
	CHECK(host_reject(&host, "summary_mismatch") == 0,
	      "reject G301 COMPLETE");
	nfsp_target_tick(target);
	CHECK(target->act.generation_count == 1 && target->ngens == 1 &&
	      target->stats.evidence_path_degraded,
	      "rejected COMPLETE is retained and fails closed");

	nfsp_target_close(target);
	close(host.fd);
}

int main(void)
{
	test_complete_ack_is_retirement_point();
	printf("%u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
