#include "nfs_decode.h"
#include "rpc_decode.h"
#include "schema.h"

#include <stdio.h>
#include <string.h>

extern const struct nfsp_schema_family nfsp_schema_family_nlm4;

#define PROG 100021u
#define VERS 4u
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
	printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static int checks, failures;

struct msg { uint8_t bytes[256]; size_t len; };

static void word(struct msg *m, uint32_t n)
{
	m->bytes[m->len++] = (uint8_t)(n >> 24);
	m->bytes[m->len++] = (uint8_t)(n >> 16);
	m->bytes[m->len++] = (uint8_t)(n >> 8);
	m->bytes[m->len++] = (uint8_t)n;
}

static void blob(struct msg *m, const char *s)
{
	size_t n = strlen(s);

	word(m, (uint32_t)n);
	memcpy(m->bytes + m->len, s, n);
	m->len += n;
	while (m->len % 4u)
		m->bytes[m->len++] = 0;
}

static void call(struct msg *m, uint32_t proc)
{
	m->len = 0;
	word(m, 0x12345678u);
	word(m, 0);
	word(m, 2);
	word(m, PROG);
	word(m, VERS);
	word(m, proc);
	word(m, 0);
	word(m, 0);
	word(m, 0);
	word(m, 0);
}

static void reply(struct msg *m)
{
	m->len = 0;
	word(m, 0x12345678u);
	word(m, 1);
	word(m, 0);
	word(m, 0);
	word(m, 0);
	word(m, 0);
}

static enum nfsp_decode_status decode(struct msg *m, uint32_t proc,
				      struct nfsp_decoded_msg *out)
{
	const struct nfsp_schema_family *const fams[] = {
		&nfsp_schema_family_nlm4,
	};
	struct nfsp_rpc_envelope env;
	struct nfsp_reply_dispatch dispatch = {
		PROG, VERS, proc, 0, 0, NFSP_DISPATCH_TEST_FIXTURE,
		NFSP_RPC_AUTH_NONE,
	};
	struct nfsp_decode_input in = {0};

	nfsp_rpc_decode(m->bytes, m->len, &env);
	in.payload = m->bytes;
	in.len = m->len;
	in.rpc = &env;
	in.reply_dispatch = env.msg_type == NFSP_RPC_REPLY ? &dispatch : NULL;
	in.allow_test_fixture = 1;
	return nfsp_nfs_decode(fams, 1, &in, out);
}

static void lock(struct msg *m)
{
	blob(m, "host");
	blob(m, "fh");
	blob(m, "owner");
	word(m, 7);
	word(m, 0);
	word(m, 0x1000);
	word(m, 0);
	word(m, 0x20);
}

static void test_lock(void)
{
	struct msg m;
	struct nfsp_decoded_msg out = {0};
	uint32_t index;

	call(&m, 2);
	blob(&m, "cookie");
	word(&m, 1);
	word(&m, 1);
	lock(&m);
	word(&m, 0);
	word(&m, 42);
	CHECK(decode(&m, 2, &out) == NFSP_DECODE_DECODED);
	index = nfsp_field_find(&out, "nlm4.request.LOCK.args.alock.l_offset", 0);
	CHECK(index != NFSP_FIELD_NONE);
	if (index != NFSP_FIELD_NONE)
		CHECK(out.fields[index].value == 0x1000u);
	index = nfsp_field_find(&out, "nlm4.request.LOCK.args.alock.fh", 0);
	CHECK(index != NFSP_FIELD_NONE);
	if (index != NFSP_FIELD_NONE)
		CHECK(out.fields[index].wire.length.len == 4u);
	nfsp_decoded_msg_free(&out);
}

static void test_reply_and_async(void)
{
	struct msg m;
	struct nfsp_decoded_msg out = {0};
	uint32_t index;

	reply(&m);
	blob(&m, "cookie");
	word(&m, 1);
	word(&m, 1);
	word(&m, 9);
	blob(&m, "owner");
	word(&m, 0);
	word(&m, 8);
	word(&m, 0);
	word(&m, 16);
	CHECK(decode(&m, 1, &out) == NFSP_DECODE_DECODED);
	index = nfsp_field_find(&out,
		"nlm4.response.TEST.result.stat.denied.l_offset", 0);
	CHECK(index != NFSP_FIELD_NONE);
	if (index != NFSP_FIELD_NONE)
		CHECK(out.fields[index].value == 8);
	CHECK(decode(&m, 2, &out) == NFSP_DECODE_MALFORMED);
	nfsp_decoded_msg_free(&out);
	{
		const struct nfsp_schema_family *const fams[] = {
			&nfsp_schema_family_nlm4,
		};
		struct nfsp_rpc_envelope env;
		struct nfsp_decode_input in = {0};

		nfsp_rpc_decode(m.bytes, m.len, &env);
		in.payload = m.bytes;
		in.len = m.len;
		in.rpc = &env;
		CHECK(nfsp_nfs_decode(fams, 1, &in, &out) ==
		      NFSP_DECODE_TRANSACTION_CONTEXT_MISSING);
		CHECK(out.nfields == 0);
		nfsp_decoded_msg_free(&out);
	}

	call(&m, 12);
	blob(&m, "cookie");
	word(&m, 0);
	CHECK(decode(&m, 12, &out) == NFSP_DECODE_DECODED);
	index = nfsp_field_find(&out, "nlm4.request.LOCK_RES.args.stat.stat", 0);
	CHECK(index != NFSP_FIELD_NONE);
	nfsp_decoded_msg_free(&out);

	reply(&m);
	CHECK(decode(&m, 12, &out) == NFSP_DECODE_DECODED);
	CHECK(out.nfields == 0);
	nfsp_decoded_msg_free(&out);
}

static void test_bounds(void)
{
	struct msg m;
	struct nfsp_decoded_msg out = {0};
	size_t full;

	call(&m, 1);
	word(&m, 1025);
	CHECK(decode(&m, 1, &out) == NFSP_DECODE_MALFORMED);
	CHECK(out.nfields == 0);
	nfsp_decoded_msg_free(&out);

	call(&m, 16);
	blob(&m, "host");
	word(&m, 1);
	for (unsigned i = 0; i < 4; i++)
		word(&m, 0);
	full = m.len;
	CHECK(decode(&m, 16, &out) == NFSP_DECODE_DECODED);
	nfsp_decoded_msg_free(&out);
	for (size_t n = 0; n < full; n++) {
		struct nfsp_rpc_envelope env;
		struct nfsp_decode_input in = {0};
		const struct nfsp_schema_family *const fams[] = {
			&nfsp_schema_family_nlm4,
		};

		nfsp_rpc_decode(m.bytes, n, &env);
		if (env.status != NFSP_RPC_OK)
			continue;
		in.payload = m.bytes;
		in.len = n;
		in.rpc = &env;
		if (nfsp_nfs_decode(fams, 1, &in, &out) !=
		    (n >= 44 && n < 48 ? NFSP_DECODE_MALFORMED :
		     NFSP_DECODE_TRUNCATED)) {
			failures++;
			printf("FAIL prefix %zu: %s\n", n,
			       nfsp_decode_strstatus(out.status));
		}
		checks++;
		CHECK(out.nfields == 0);
		nfsp_decoded_msg_free(&out);
	}
}

int main(void)
{
	const struct nfsp_protocol_schema *schema =
		nfsp_schema_family_nlm4.schemas[0];

	CHECK(schema->program == PROG && schema->version == VERS);
	CHECK(schema->nprocs == 21);
	CHECK(nfsp_schema_proc(schema, 16) != NULL);
	CHECK(nfsp_schema_proc(schema, 17) == NULL);
	test_lock();
	test_reply_and_async();
	test_bounds();
	printf("test_nlm4_decode: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
