/* NFSv4.0/4.1/4.2 decoding over the schema generated from the RFC XDR.
 *
 * src/schema_nfs4.c comes from schema/nfs4/ (RFC 7531, RFC 5662, RFC 7863,
 * pinned by schema/nfs4/SOURCES).  test_nfs_decode.c proves the interpreter
 * on synthetic schemas; this file proves the real tables: every golden
 * vector below has its offsets written out word by word, and every span the
 * decoder reports is checked against them.
 *
 * CROSS-CHECK REFERENCES
 *
 *   The vectors were checked by hand against how two implementations read
 *   and write the same operations, so they are shaped like real traffic and
 *   not only like the XDR.  No code was copied from either (tools/ is MIT;
 *   the kernel is GPL-2.0 and Ganesha mostly LGPL-3.0).
 *
 *     Linux v7.3-rc5 client  fs/nfs/nfs4xdr.c   nfs4_xdr_enc_open (SEQUENCE,
 *                            PUTFH, OPEN, GETFH, ...), encode_openhdr (the
 *                            28-byte "open id:" owner), encode_readdir
 *     Linux v7.3-rc5 knfsd   fs/nfsd/nfs4xdr.c  nfsd4_decode_sequence,
 *                            nfsd4_decode_open, nfsd4_decode_readdir,
 *                            nfsd4_encode_sequence, nfsd4_encode_open,
 *                            nfsd4_encode_open_none_delegation4,
 *                            nfsd4_encode_dirlist4
 *     NFS-Ganesha V15.6      src/include/nfsv41.h xdr_bitmap4
 *
 *   Where the servers differ from the XDR, the decoder follows the XDR and
 *   test_cross_check() pins the difference (design 03-nfs-proxy/02 §2: wire
 *   truth is the XDR source set, not one server's policy).
 *
 * Oracles: golden spans, every-prefix truncation, located malformed
 * refusals, minor-version selection, reply dispatch, mutation address,
 * random edits under the sanitizer.  The helpers mirror test_nfs_decode.c.
 */
#include "nfs_decode.h"
#include "rpc_decode.h"
#include "schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct nfsp_schema_family nfsp_schema_family_nfs4;

static const struct nfsp_schema_family *const fams[] = {
	&nfsp_schema_family_nfs4,
};
#define NFAMS (sizeof(fams) / sizeof(fams[0]))

#define NFS4_PROG	100003u
#define NFS_V4		4u

/* nfs_opnum4 */
#define OP_GETFH	10u
#define OP_OPEN		18u
#define OP_PUTFH	22u
#define OP_READDIR	26u
#define OP_SEQUENCE	53u
#define OP_SEEK		69u	/* NFSv4.2 */
#define OP_GETXATTR	72u	/* RFC 8276, an NFSv4.2 extension */
#define OP_LAYOUTGET	50u

#define SESSIONID	"sess-0123456789a"	/* sessionid4[16] */
#define DIRFH		"dir-fh-00001"		/* nfs_fh4, 12 bytes */
#define FILEFH		"file-fh-0002"
#define OTHER		"stateid-o-12"		/* stateid4.other[12] */

static int failures;
static int checks;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			printf("  FAIL %s:%d: ", __FILE__, __LINE__);          \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
		}                                                              \
	} while (0)

struct msg {
	uint8_t b[1024];
	size_t n;
};

static void w32(struct msg *m, uint32_t v)
{
	m->b[m->n++] = (uint8_t)(v >> 24);
	m->b[m->n++] = (uint8_t)(v >> 16);
	m->b[m->n++] = (uint8_t)(v >> 8);
	m->b[m->n++] = (uint8_t)v;
}

static void w64(struct msg *m, uint64_t v)
{
	w32(m, (uint32_t)(v >> 32));
	w32(m, (uint32_t)v);
}

/* `len` bytes of s, then XDR padding. */
static void wraw(struct msg *m, const char *s, size_t len)
{
	memcpy(m->b + m->n, s, len);
	m->n += len;
	while (m->n % 4u)
		m->b[m->n++] = 0;
}

static void wopaque(struct msg *m, const char *s)
{
	w32(m, (uint32_t)strlen(s));
	wraw(m, s, strlen(s));
}

static void put32(struct msg *m, size_t at, uint32_t v)
{
	m->b[at] = (uint8_t)(v >> 24);
	m->b[at + 1] = (uint8_t)(v >> 16);
	m->b[at + 2] = (uint8_t)(v >> 8);
	m->b[at + 3] = (uint8_t)v;
}

/* CALL with an AUTH_SYS credential, as the Linux client sends it, so the
 * body does not start at a convenient offset. */
static void call_header(struct msg *m, uint32_t proc)
{
	m->n = 0;
	w32(m, 0x5eed0001);	/*  0 xid */
	w32(m, 0);		/*  4 CALL */
	w32(m, 2);		/*  8 rpcvers */
	w32(m, NFS4_PROG);	/* 12 */
	w32(m, NFS_V4);		/* 16 */
	w32(m, proc);		/* 20 */
	w32(m, 1);		/* 24 cred AUTH_SYS */
	w32(m, 24);		/* 28 cred length */
	w32(m, 0x5f000001);	/* 32 stamp */
	wopaque(m, "kvm");	/* 36 machinename: len, 40..42, pad 43 */
	w32(m, 0);		/* 44 uid */
	w32(m, 0);		/* 48 gid */
	w32(m, 0);		/* 52 gids count */
	w32(m, 0);		/* 56 verf AUTH_NONE */
	w32(m, 0);		/* 60 */
}				/* 64 body */

static void reply_header(struct msg *m)
{
	m->n = 0;
	w32(m, 0x5eed0001);	/*  0 xid */
	w32(m, 1);		/*  4 REPLY */
	w32(m, 0);		/*  8 MSG_ACCEPTED */
	w32(m, 0);		/* 12 verf AUTH_NONE */
	w32(m, 0);		/* 16 */
	w32(m, 0);		/* 20 SUCCESS */
}				/* 24 body */

static void sequence_args(struct msg *m, uint32_t seqid, uint32_t cachethis)
{
	w32(m, OP_SEQUENCE);	/* +0 */
	wraw(m, SESSIONID, 16);	/* +4 sa_sessionid */
	w32(m, seqid);		/* +20 sa_sequenceid */
	w32(m, 0);		/* +24 sa_slotid */
	w32(m, 0);		/* +28 sa_highest_slotid */
	w32(m, cachethis);	/* +32 sa_cachethis */
}				/* +36 */

static void sequence_res(struct msg *m, uint32_t seqid)
{
	w32(m, OP_SEQUENCE);	/* +0 */
	w32(m, 0);		/* +4 sr_status NFS4_OK */
	wraw(m, SESSIONID, 16);	/* +8 sr_sessionid */
	w32(m, seqid);		/* +24 sr_sequenceid */
	w32(m, 0);		/* +28 sr_slotid */
	w32(m, 63);		/* +32 sr_highest_slotid */
	w32(m, 63);		/* +36 sr_target_highest_slotid */
	w32(m, 0);		/* +40 sr_status_flags */
}				/* +44 */

/* NFSv4.1 OPEN with create, the head of the Linux client's
 * nfs4_xdr_enc_open compound.  236 bytes. */
static void build_open_call(struct msg *m)
{
	call_header(m, 1);
	w32(m, 0);			/*  64 tag: empty */
	w32(m, 1);			/*  68 minorversion */
	w32(m, 4);			/*  72 argarray count */
	sequence_args(m, 0x11, 1);	/*  76 SEQUENCE, 80..111 */
	w32(m, OP_PUTFH);		/* 112 */
	wopaque(m, DIRFH);		/* 116 object: len, 120..131 */
	w32(m, OP_OPEN);		/* 132 */
	w32(m, 0);			/* 136 seqid */
	w32(m, 3);			/* 140 share_access BOTH */
	w32(m, 0);			/* 144 share_deny NONE */
	w64(m, 0x5f00000100000002ull);	/* 148 owner.clientid */
	w32(m, 28);			/* 156 owner.owner: len, 160..187 */
	wraw(m, "open id:", 8);		/* 160 */
	w32(m, 0x21);			/* 168 s_dev */
	w64(m, 7);			/* 172 uniquifier */
	w64(m, 0x18f0a2b3c4d5e6f7ull);	/* 180 create_time */
	w32(m, 1);			/* 188 openhow.opentype OPEN4_CREATE */
	w32(m, 0);			/* 192 how.mode UNCHECKED4 */
	w32(m, 2);			/* 196 createattrs.attrmask count */
	w32(m, 0);			/* 200 attrmask[0] */
	w32(m, 2);			/* 204 attrmask[1]: FATTR4_MODE (33) */
	w32(m, 4);			/* 208 attr_vals: len, 212..215 */
	w32(m, 0644);			/* 212 mode */
	w32(m, 0);			/* 216 claim CLAIM_NULL */
	wopaque(m, "newfile");		/* 220 file: len, 224..230, pad 231 */
	w32(m, OP_GETFH);		/* 232 */
}					/* 236 */

/* knfsd's reply to it.  184 bytes. */
static void build_open_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0);			/*  24 status NFS4_OK */
	w32(m, 0);			/*  28 tag: empty */
	w32(m, 4);			/*  32 resarray count */
	sequence_res(m, 0x11);		/*  36 SEQUENCE, 40..79 */
	w32(m, OP_PUTFH);		/*  80 */
	w32(m, 0);			/*  84 status */
	w32(m, OP_OPEN);		/*  88 */
	w32(m, 0);			/*  92 status */
	w32(m, 1);			/*  96 stateid.seqid */
	wraw(m, OTHER, 12);		/* 100 stateid.other */
	w32(m, 1);			/* 112 cinfo.atomic */
	w64(m, 0x000000000000a001ull);	/* 116 cinfo.before */
	w64(m, 0x000000000000a002ull);	/* 124 cinfo.after */
	w32(m, 4);			/* 132 rflags LOCKTYPE_POSIX */
	w32(m, 2);			/* 136 attrset count */
	w32(m, 0);			/* 140 attrset[0] */
	w32(m, 2);			/* 144 attrset[1] */
	w32(m, 3);			/* 148 delegation_type NONE_EXT */
	w32(m, 1);			/* 152 ond_why WND4_CONTENTION */
	w32(m, 0);			/* 156 ond_server_will_push_deleg */
	w32(m, OP_GETFH);		/* 160 */
	w32(m, 0);			/* 164 status */
	wopaque(m, FILEFH);		/* 168 object: len, 172..183 */
}					/* 184 */

/* NFSv4.1 READDIR, attr_request as encode_readdir() builds it without
 * READDIR_PLUS: TYPE|RDATTR_ERROR, MOUNTED_ON_FILEID.  172 bytes. */
static void build_readdir_call(struct msg *m)
{
	call_header(m, 1);
	w32(m, 0);			/*  64 tag */
	w32(m, 1);			/*  68 minorversion */
	w32(m, 3);			/*  72 argarray count */
	sequence_args(m, 0x12, 0);	/*  76 SEQUENCE, 80..111 */
	w32(m, OP_PUTFH);		/* 112 */
	wopaque(m, DIRFH);		/* 116 object: len, 120..131 */
	w32(m, OP_READDIR);		/* 132 */
	w64(m, 0);			/* 136 cookie */
	wraw(m, "\0\0\0\0\0\0\0\0", 8);	/* 144 cookieverf */
	w32(m, 0x8000);			/* 152 dircount */
	w32(m, 0x8000);			/* 156 maxcount */
	w32(m, 2);			/* 160 attr_request count */
	w32(m, 0x00000802);		/* 164 [0] TYPE | RDATTR_ERROR */
	w32(m, 0x00800000);		/* 168 [1] MOUNTED_ON_FILEID */
}					/* 172 */

/* Two entries and eof, entry4 as an XDR linked list (knfsd writes it with
 * nfsd4_encode_entry4/nfsd4_encode_dirlist4).  attr_vals is opaque to the
 * schema.  220 bytes. */
static void build_readdir_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0);			/*  24 status */
	w32(m, 0);			/*  28 tag */
	w32(m, 3);			/*  32 resarray count */
	sequence_res(m, 0x12);		/*  36 SEQUENCE, 40..79 */
	w32(m, OP_PUTFH);		/*  80 */
	w32(m, 0);			/*  84 status */
	w32(m, OP_READDIR);		/*  88 */
	w32(m, 0);			/*  92 status */
	wraw(m, "cookieVF", 8);		/*  96 cookieverf */
	w32(m, 1);			/* 104 entries: present */
	w64(m, 0x1c2d3e4f5a6b7c8dull);	/* 108 entry[0].cookie */
	wopaque(m, "alpha");		/* 116 name: len, 120..124, pad ..127 */
	w32(m, 2);			/* 128 attrs.attrmask count */
	w32(m, 0x00000802);		/* 132 */
	w32(m, 0x00800000);		/* 136 */
	w32(m, 16);			/* 140 attrs.attr_vals: len, 144..159 */
	w32(m, 1);			/* 144 type NF4REG */
	w32(m, 0);			/* 148 rdattr_error */
	w64(m, 0x1001);			/* 152 mounted_on_fileid */
	w32(m, 1);			/* 160 entry[0] link: next present */
	w64(m, 0x7fffffffffffffffull);	/* 164 entry[1].cookie */
	wopaque(m, "beta");		/* 172 name: len, 176..179 */
	w32(m, 2);			/* 180 attrs.attrmask count */
	w32(m, 0x00000802);		/* 184 */
	w32(m, 0x00800000);		/* 188 */
	w32(m, 16);			/* 192 attrs.attr_vals: len, 196..211 */
	w32(m, 2);			/* 196 type NF4DIR */
	w32(m, 0);			/* 200 rdattr_error */
	w64(m, 0x1002);			/* 204 mounted_on_fileid */
	w32(m, 0);			/* 212 entry[1] link: end */
	w32(m, 1);			/* 216 eof */
}					/* 220 */

/* NFSv4.0: no SEQUENCE, a tag that needs padding.  136 bytes. */
static void build_v40_call(struct msg *m)
{
	call_header(m, 1);
	wopaque(m, "ls");		/*  64 tag: len, 68..69, pad 70..71 */
	w32(m, 0);			/*  72 minorversion */
	w32(m, 2);			/*  76 argarray count */
	w32(m, OP_PUTFH);		/*  80 */
	wopaque(m, DIRFH);		/*  84 object: len, 88..99 */
	w32(m, OP_READDIR);		/* 100 */
	w64(m, 0);			/* 104 cookie */
	wraw(m, "\0\0\0\0\0\0\0\0", 8);	/* 112 cookieverf */
	w32(m, 0x2000);			/* 120 dircount */
	w32(m, 0x8000);			/* 124 maxcount */
	w32(m, 1);			/* 128 attr_request count */
	w32(m, 0x00100000);		/* 132 [0] FATTR4_FILEID (20) */
}					/* 136 */

/* The compound stops at the first failing operation.  48 bytes. */
static void build_v40_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 70);			/*  24 status NFS4ERR_STALE */
	wopaque(m, "ls");		/*  28 tag: len, 32..33, pad 34..35 */
	w32(m, 1);			/*  36 resarray count */
	w32(m, OP_PUTFH);		/*  40 */
	w32(m, 70);			/*  44 status NFS4ERR_STALE */
}					/*  48 */

/* NFSv4.2 SEEK, an operation RFC 7863 adds.  164 bytes. */
static void build_seek_call(struct msg *m, uint32_t minor, uint32_t opcode)
{
	call_header(m, 1);
	w32(m, 0);			/*  64 tag */
	w32(m, minor);			/*  68 minorversion */
	w32(m, 3);			/*  72 argarray count */
	sequence_args(m, 0x13, 0);	/*  76 SEQUENCE, 80..111 */
	w32(m, OP_PUTFH);		/* 112 */
	wopaque(m, FILEFH);		/* 116 object: len, 120..131 */
	w32(m, opcode);			/* 132 OP_SEEK */
	w32(m, 1);			/* 136 sa_stateid.seqid */
	wraw(m, OTHER, 12);		/* 140 sa_stateid.other */
	w64(m, 0x1000);			/* 152 sa_offset */
	w32(m, 1);			/* 160 sa_what NFS4_CONTENT_HOLE */
}					/* 164 */

/* RFC 8276 GETXATTR as the Linux client's nfs4_xdr_enc_getxattr sends it:
 * SEQUENCE, PUTFH, GETXATTR.  152 bytes. */
static void build_getxattr_call(struct msg *m)
{
	call_header(m, 1);
	w32(m, 0);			/*  64 tag */
	w32(m, 2);			/*  68 minorversion */
	w32(m, 3);			/*  72 argarray count */
	sequence_args(m, 0x14, 0);	/*  76 SEQUENCE, 80..111 */
	w32(m, OP_PUTFH);		/* 112 */
	wopaque(m, FILEFH);		/* 116 object: len, 120..131 */
	w32(m, OP_GETXATTR);		/* 132 */
	wopaque(m, "user.test");	/* 136 gxa_name: len, 140..148, pad */
}					/* 152 */

/* NFSv4.1 LAYOUTGET for a flex files layout (RFC 8435), as the Linux
 * client's nfs4_xdr_enc_layoutget sends it.  192 bytes. */
static void build_layoutget_call(struct msg *m)
{
	call_header(m, 1);
	w32(m, 0);			/*  64 tag */
	w32(m, 1);			/*  68 minorversion */
	w32(m, 3);			/*  72 argarray count */
	sequence_args(m, 0x15, 0);	/*  76 SEQUENCE, 80..111 */
	w32(m, OP_PUTFH);		/* 112 */
	wopaque(m, FILEFH);		/* 116 object: len, 120..131 */
	w32(m, OP_LAYOUTGET);		/* 132 */
	w32(m, 0);			/* 136 loga_signal_layout_avail */
	w32(m, 4);			/* 140 loga_layout_type FLEX_FILES */
	w32(m, 1);			/* 144 loga_iomode LAYOUTIOMODE4_READ */
	w64(m, 0);			/* 148 loga_offset */
	w64(m, ~0ull);			/* 156 loga_length */
	w64(m, 0);			/* 164 loga_minlength */
	w32(m, 1);			/* 172 loga_stateid.seqid */
	wraw(m, OTHER, 12);		/* 176 loga_stateid.other */
	w32(m, 4096);			/* 188 loga_maxcount */
}					/* 192 */

/* knfsd's reply for a SCSI layout (RFC 8154), body abridged.  152 bytes. */
static void build_layoutget_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0);			/*  24 status */
	w32(m, 0);			/*  28 tag */
	w32(m, 3);			/*  32 resarray count */
	sequence_res(m, 0x15);		/*  36 SEQUENCE, 40..79 */
	w32(m, OP_PUTFH);		/*  80 */
	w32(m, 0);			/*  84 status */
	w32(m, OP_LAYOUTGET);		/*  88 */
	w32(m, 0);			/*  92 logr_status */
	w32(m, 1);			/*  96 logr_return_on_close */
	w32(m, 2);			/* 100 logr_stateid.seqid */
	wraw(m, OTHER, 12);		/* 104 logr_stateid.other */
	w32(m, 1);			/* 116 logr_layout count */
	w64(m, 0);			/* 120 lo_offset */
	w64(m, ~0ull);			/* 128 lo_length */
	w32(m, 1);			/* 136 lo_iomode */
	w32(m, 5);			/* 140 loc_type SCSI */
	wopaque(m, "abcd");		/* 144 loc_body: len, 148..151 */
}					/* 152 */

/* knfsd's reply: the value "abc".  104 bytes. */
static void build_getxattr_reply(struct msg *m)
{
	reply_header(m);
	w32(m, 0);			/*  24 status NFS4_OK */
	w32(m, 0);			/*  28 tag */
	w32(m, 3);			/*  32 resarray count */
	sequence_res(m, 0x14);		/*  36 SEQUENCE, 40..79 */
	w32(m, OP_PUTFH);		/*  80 */
	w32(m, 0);			/*  84 status */
	w32(m, OP_GETXATTR);		/*  88 */
	w32(m, 0);			/*  92 gxr_status NFS4_OK */
	wopaque(m, "abc");		/*  96 gxr_value: len, 100..102, pad */
}					/* 104 */

/* build_open_reply with an RFC 9754 read attribute delegation, which knfsd
 * encodes with the open_read_delegation4 arm.  224 bytes. */
static void build_open_reply_rdeleg(struct msg *m)
{
	build_open_reply(m);
	m->n = 148;
	w32(m, 4);			/* 148 OPEN_DELEGATE_READ_ATTRS_DELEG */
	w32(m, 2);			/* 152 stateid.seqid */
	wraw(m, OTHER, 12);		/* 156 stateid.other */
	w32(m, 0);			/* 168 recall */
	w32(m, 0);			/* 172 permissions.type ALLOWED */
	w32(m, 0);			/* 176 permissions.flag */
	w32(m, 1);			/* 180 permissions.access_mask */
	wopaque(m, "EVERYONE@");	/* 184 who: len, 188..196, pad */
	w32(m, OP_GETFH);		/* 200 */
	w32(m, 0);			/* 204 status */
	wopaque(m, FILEFH);		/* 208 object: len, 212..223 */
}					/* 224 */

/* The write attribute delegation: the open_write_delegation4 arm, with a
 * size limit.  236 bytes. */
static void build_open_reply_wdeleg(struct msg *m)
{
	build_open_reply(m);
	m->n = 148;
	w32(m, 5);			/* 148 OPEN_DELEGATE_WRITE_ATTRS_DELEG */
	w32(m, 2);			/* 152 stateid.seqid */
	wraw(m, OTHER, 12);		/* 156 stateid.other */
	w32(m, 0);			/* 168 recall */
	w32(m, 1);			/* 172 space_limit NFS_LIMIT_SIZE */
	w64(m, 0x100000);		/* 176 filesize */
	w32(m, 0);			/* 184 permissions.type */
	w32(m, 0);			/* 188 permissions.flag */
	w32(m, 1);			/* 192 permissions.access_mask */
	wopaque(m, "EVERYONE@");	/* 196 who: len, 200..208, pad */
	w32(m, OP_GETFH);		/* 212 */
	w32(m, 0);			/* 216 status */
	wopaque(m, FILEFH);		/* 220 object: len, 224..235 */
}					/* 236 */

static struct nfsp_reply_dispatch dispatch(uint32_t minor)
{
	/* The CALLs here carry AUTH_SYS, as the Linux client sends them. */
	return (struct nfsp_reply_dispatch){ NFS4_PROG, NFS_V4, 1, 1, minor,
					     NFSP_DISPATCH_TEST_FIXTURE,
					     NFSP_RPC_AUTH_SYS };
}

static enum nfsp_decode_status
run(const struct msg *v, size_t n, const struct nfsp_reply_dispatch *rd,
    struct nfsp_decoded_msg *out)
{
	struct nfsp_rpc_envelope env;
	struct nfsp_decode_input in;

	memset(&in, 0, sizeof(in));
	in.payload = v->b;
	in.len = n;
	in.rpc = &env;
	in.reply_dispatch = rd;
	in.allow_test_fixture = 1;
	nfsp_rpc_decode(v->b, n, &env);
	return nfsp_nfs_decode(fams, NFAMS, &in, out);
}

static const struct nfsp_semantic_field *
field(const struct nfsp_decoded_msg *m, const char *path, unsigned nth)
{
	uint32_t i = 0;

	for (;;) {
		i = nfsp_field_find(m, path, i);
		if (i == NFSP_FIELD_NONE)
			return NULL;
		if (!nth--)
			return &m->fields[i];
		i++;
	}
}

#define SPAN(s, o, l) ((s).off == (o) && (s).len == (l))

static void expect(const struct nfsp_decoded_msg *m, const char *path,
		   unsigned nth, uint32_t eoff, uint32_t elen, uint32_t voff,
		   uint32_t vlen, uint64_t value, int line)
{
	const struct nfsp_semantic_field *f = field(m, path, nth);

	checks++;
	if (!f) {
		failures++;
		printf("  FAIL line %d: no field %s #%u\n", line, path, nth);
		return;
	}
	CHECK(SPAN(f->wire.encoded, eoff, elen) &&
	      SPAN(f->wire.value, voff, vlen),
	      "line %d %s: encoded %u+%u value %u+%u, want %u+%u %u+%u",
	      line, path, f->wire.encoded.off, f->wire.encoded.len,
	      f->wire.value.off, f->wire.value.len, eoff, elen, voff, vlen);
	CHECK(f->value == value, "line %d %s: value %llx, want %llx", line,
	      path, (unsigned long long)f->value, (unsigned long long)value);
}

#define EXPECT(m, path, nth, eo, el, vo, vl, v) \
	expect(m, path, nth, eo, el, vo, vl, v, __LINE__)

/* A metadata span of the field at `path`. */
static void expect_meta(const struct nfsp_decoded_msg *m, const char *path,
			unsigned nth, uint32_t role, uint32_t off,
			uint32_t len, int line)
{
	const struct nfsp_semantic_field *f = field(m, path, nth);
	const struct nfsp_span *s;

	checks++;
	if (!f) {
		failures++;
		printf("  FAIL line %d: no field %s #%u\n", line, path, nth);
		return;
	}
	s = role == NFSP_META_LENGTH ? &f->wire.length :
	    role == NFSP_META_COUNT ? &f->wire.count :
	    role == NFSP_META_DISCRIMINANT ? &f->wire.discriminant :
	    &f->wire.padding;
	CHECK((f->wire.meta & role) && SPAN(*s, off, len),
	      "line %d %s: meta %#x %u+%u, want %#x %u+%u", line, path,
	      f->wire.meta, s->off, s->len, role, off, len);
}

#define META(m, path, nth, role, o, l) \
	expect_meta(m, path, nth, role, o, l, __LINE__)

static void check_invariants(const struct nfsp_decoded_msg *m, size_t len,
			     const char *what);

/* A partial CALL: fields and ops end where the failed operation starts,
 * and the ops are exactly the operations before it. */
static void check_partial(const struct nfsp_decoded_msg *m, size_t len,
			  const char *what)
{
	const struct nfsp_decode_failure *f = &m->failure;

	CHECK(m->status == NFSP_DECODE_PARTIAL && m->msg_type == 0 &&
	      (uint64_t)f->op_offset + 4 <= len && f->offset >= f->op_offset &&
	      m->nops == f->op_index && m->nfields > 0,
	      "%s: partial op %u at %u, %u ops, failure at %u", what,
	      f->op_index, f->op_offset, m->nops, f->offset);
	check_invariants(m, f->op_offset, what);
	for (uint32_t i = 0; i < m->nops; i++)
		CHECK(m->ops[i].sequence_index == i &&
		      m->ops[i].field < m->nfields, "%s: op %u", what, i);
}

/* run() is partial at operation op_index starting at op_offset. */
static void expect_partial_at(const struct msg *v, uint32_t op_index,
			      uint32_t op_offset, uint32_t opcode,
			      const char *what)
{
	struct nfsp_decoded_msg m = {0};

	CHECK(run(v, v->n, NULL, &m) == NFSP_DECODE_PARTIAL &&
	      m.failure.op_index == op_index &&
	      m.failure.op_offset == op_offset && m.failure.opcode == opcode,
	      "%s: %s, op %u at %u opcode %u; want partial op %u at %u",
	      what, nfsp_decode_strstatus(m.status), m.failure.op_index,
	      m.failure.op_offset, m.failure.opcode, op_index, op_offset);
	if (m.status == NFSP_DECODE_PARTIAL)
		check_partial(&m, v->n, what);
	nfsp_decoded_msg_free(&m);
}

static void check_invariants(const struct nfsp_decoded_msg *m, size_t len,
			     const char *what)
{
	char buf[1024];
	struct nfsp_schema_node node;
	enum nfsp_schema_resolve res;
	size_t n;

	for (uint32_t i = 0; i < m->nfields; i++) {
		const struct nfsp_semantic_field *f = &m->fields[i];
		const struct nfsp_wire_ref *w = &f->wire;
		uint64_t eend = (uint64_t)w->encoded.off + w->encoded.len;
		const struct nfsp_span *meta[4] = {
			&w->length, &w->count, &w->discriminant, &w->padding
		};

		CHECK(eend <= len, "%s field %u: encoded beyond payload", what,
		      i);
		CHECK(w->value.off >= w->encoded.off &&
		      (uint64_t)w->value.off + w->value.len <= eend,
		      "%s field %u: value outside encoded", what, i);
		for (unsigned r = 0; r < 4; r++) {
			if (!(w->meta & (1u << r)))
				continue;
			CHECK(meta[r]->off >= w->encoded.off &&
			      (uint64_t)meta[r]->off + meta[r]->len <= eend,
			      "%s field %u: metadata %u outside encoded", what,
			      i, r);
		}
		if (f->parent != NFSP_FIELD_NONE) {
			const struct nfsp_span *p =
				&m->fields[f->parent].wire.encoded;

			CHECK(f->parent < i, "%s field %u: parent after child",
			      what, i);
			CHECK(w->encoded.off >= p->off &&
			      eend <= (uint64_t)p->off + p->len,
			      "%s field %u: outside parent", what, i);
		}
		n = nfsp_field_path(m, i, buf, sizeof(buf));
		CHECK(n > 0 && n < sizeof(buf), "%s field %u: path length %zu",
		      what, i, n);
		/* A rule names this field by the same path before any
		 * message exists (schema.h): it must resolve to this node. */
		res = nfsp_schema_resolve(m->schema,
					  m->msg_type == NFSP_RPC_REPLY, buf,
					  &node);
		CHECK(res == NFSP_SCHEMA_FOUND && node.type == f->type &&
		      !(node.flags & NFSP_SN_OPERATION) ==
		      (f->op == NFSP_FIELD_NONE),
		      "%s field %u: %s resolves %d, type %u flags %#x; want "
		      "type %u", what, i, buf, res, res ? 0u : node.type,
		      res ? 0u : node.flags, f->type);
	}
}

static int decoded(const struct msg *v, const struct nfsp_reply_dispatch *rd,
		   struct nfsp_decoded_msg *m, const char *what)
{
	CHECK(run(v, v->n, rd, m) == NFSP_DECODE_DECODED, "%s: %s at %u: %s",
	      what, nfsp_decode_strstatus(m->status), m->failure.offset,
	      m->failure.reason ? m->failure.reason : "");
	if (m->status != NFSP_DECODE_DECODED)
		return 0;
	check_invariants(m, v->n, what);
	return 1;
}

static int schema_is(const struct nfsp_decoded_msg *m, uint32_t minor)
{
	char want[16];

	snprintf(want, sizeof(want), "nfs4.%u/sha256:", minor);
	return m->schema && m->has_minor && m->minor_version == minor &&
	       m->schema == nfsp_schema_family_nfs4.schemas[minor] &&
	       !strncmp(m->schema->schema_id, want, strlen(want));
}

static void expect_ops(const struct nfsp_decoded_msg *m, unsigned n,
		       const char *const *names, int response,
		       const uint32_t *status)
{
	CHECK(m->nops == n, "nops %u, want %u", m->nops, n);
	for (unsigned i = 0; i < n && i < m->nops; i++) {
		CHECK(!strcmp(m->ops[i].name, names[i]) &&
		      m->ops[i].sequence_index == i,
		      "op %u: %s #%u, want %s", i, m->ops[i].name,
		      m->ops[i].sequence_index, names[i]);
		CHECK(m->ops[i].has_status == response &&
		      (!response || m->ops[i].status == status[i]),
		      "op %u status %d/%u", i, m->ops[i].has_status,
		      m->ops[i].status);
	}
}

static void test_open_call(void)
{
	static const char *const ops[] = { "SEQUENCE", "PUTFH", "OPEN",
					   "GETFH" };
	struct nfsp_decoded_msg m = {0};
	struct msg c;

	printf("CALL 4.1: SEQUENCE PUTFH OPEN GETFH, exact WireRefs\n");
	build_open_call(&c);
	CHECK(c.n == 236, "vector length %zu", c.n);
	if (!decoded(&c, NULL, &m, "open call"))
		return;
	CHECK(schema_is(&m, 1), "schema is not nfs4.1");
	CHECK(m.procedure == 1 && !strcmp(m.procedure_name, "COMPOUND"),
	      "procedure");
	expect_ops(&m, 4, ops, 0, NULL);

	EXPECT(&m, "nfs4.request.COMPOUND.args", 0, 64, 172, 64, 172, 0);
	EXPECT(&m, "nfs4.request.COMPOUND.args.tag", 0, 64, 4, 68, 0, 0);
	EXPECT(&m, "nfs4.request.COMPOUND.args.minorversion", 0, 68, 4, 68, 4,
	       1);
	EXPECT(&m, "nfs4.request.COMPOUND.args.argarray", 0, 72, 164, 76, 160,
	       0);
	META(&m, "nfs4.request.COMPOUND.args.argarray", 0, NFSP_META_COUNT,
	     72, 4);

	EXPECT(&m, "nfs4.request.SEQUENCE", 0, 76, 36, 80, 32, 0);
	META(&m, "nfs4.request.SEQUENCE", 0, NFSP_META_DISCRIMINANT, 76, 4);
	EXPECT(&m, "nfs4.request.SEQUENCE.argop", 0, 76, 4, 76, 4,
	       OP_SEQUENCE);
	EXPECT(&m, "nfs4.request.SEQUENCE.args", 0, 80, 32, 80, 32, 0);
	EXPECT(&m, "nfs4.request.SEQUENCE.args.sa_sessionid", 0, 80, 16, 80,
	       16, 0);
	EXPECT(&m, "nfs4.request.SEQUENCE.args.sa_sequenceid", 0, 96, 4, 96,
	       4, 0x11);
	EXPECT(&m, "nfs4.request.SEQUENCE.args.sa_slotid", 0, 100, 4, 100, 4,
	       0);
	EXPECT(&m, "nfs4.request.SEQUENCE.args.sa_highest_slotid", 0, 104, 4,
	       104, 4, 0);
	EXPECT(&m, "nfs4.request.SEQUENCE.args.sa_cachethis", 0, 108, 4, 108,
	       4, 1);

	EXPECT(&m, "nfs4.request.PUTFH", 0, 112, 20, 116, 16, 0);
	EXPECT(&m, "nfs4.request.PUTFH.args.object", 0, 116, 16, 120, 12, 0);
	META(&m, "nfs4.request.PUTFH.args.object", 0, NFSP_META_LENGTH, 116,
	     4);

	EXPECT(&m, "nfs4.request.OPEN", 0, 132, 100, 136, 96, 0);
	EXPECT(&m, "nfs4.request.OPEN.args", 0, 136, 96, 136, 96, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.seqid", 0, 136, 4, 136, 4, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.share_access", 0, 140, 4, 140, 4,
	       3);
	EXPECT(&m, "nfs4.request.OPEN.args.share_deny", 0, 144, 4, 144, 4, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.owner", 0, 148, 40, 148, 40, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.owner.clientid", 0, 148, 8, 148, 8,
	       0x5f00000100000002ull);
	EXPECT(&m, "nfs4.request.OPEN.args.owner.owner", 0, 156, 32, 160, 28,
	       0);
	/* union openflag4 -> union createhow4 -> struct fattr4 */
	EXPECT(&m, "nfs4.request.OPEN.args.openhow", 0, 188, 28, 192, 24, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.openhow.opentype", 0, 188, 4, 188,
	       4, 1);
	EXPECT(&m, "nfs4.request.OPEN.args.openhow.open4_create.how", 0, 192,
	       24, 196, 20, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.openhow.open4_create.how.mode", 0,
	       192, 4, 192, 4, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.openhow.open4_create.how.unchecked4",
	       0, 196, 20, 196, 20, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.openhow.open4_create.how.unchecked4"
	       ".attrmask", 0, 196, 12, 200, 8, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.openhow.open4_create.how.unchecked4"
	       ".attrmask[]", 1, 204, 4, 204, 4, 2);
	EXPECT(&m, "nfs4.request.OPEN.args.openhow.open4_create.how.unchecked4"
	       ".attr_vals", 0, 208, 8, 212, 4, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.claim", 0, 216, 16, 220, 12, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.claim.claim", 0, 216, 4, 216, 4, 0);
	EXPECT(&m, "nfs4.request.OPEN.args.claim.claim_null.file", 0, 220, 12,
	       224, 7, 0);
	META(&m, "nfs4.request.OPEN.args.claim.claim_null.file", 0,
	     NFSP_META_PADDING, 231, 1);

	EXPECT(&m, "nfs4.request.GETFH", 0, 232, 4, 236, 0, 0);
	EXPECT(&m, "nfs4.request.GETFH.argop", 0, 232, 4, 232, 4, OP_GETFH);
	CHECK(!field(&m, "nfs4.request.GETFH.args", 0),
	      "GETFH takes no arguments");
	nfsp_decoded_msg_free(&m);
}

static void test_open_reply(void)
{
	static const char *const ops[] = { "SEQUENCE", "PUTFH", "OPEN",
					   "GETFH" };
	static const uint32_t ok[] = { 0, 0, 0, 0 };
	struct nfsp_reply_dispatch rd = dispatch(1);
	struct nfsp_decoded_msg m = {0};
	struct msg r;
	const char *const dlg =
		"nfs4.response.OPEN.result.ok.delegation."
		"open_delegate_none_ext.od_whynone";
	char path[160];

	printf("REPLY 4.1: SEQUENCE PUTFH OPEN GETFH from reply_dispatch\n");
	build_open_reply(&r);
	CHECK(r.n == 184, "vector length %zu", r.n);
	if (!decoded(&r, &rd, &m, "open reply"))
		return;
	CHECK(schema_is(&m, 1), "schema is not nfs4.1");
	expect_ops(&m, 4, ops, 1, ok);

	EXPECT(&m, "nfs4.response.COMPOUND.result", 0, 24, 160, 24, 160, 0);
	EXPECT(&m, "nfs4.response.COMPOUND.result.status", 0, 24, 4, 24, 4, 0);
	EXPECT(&m, "nfs4.response.COMPOUND.result.tag", 0, 28, 4, 32, 0, 0);
	EXPECT(&m, "nfs4.response.COMPOUND.result.resarray", 0, 32, 152, 36,
	       148, 0);

	EXPECT(&m, "nfs4.response.SEQUENCE", 0, 36, 44, 40, 40, 0);
	EXPECT(&m, "nfs4.response.SEQUENCE.resop", 0, 36, 4, 36, 4,
	       OP_SEQUENCE);
	EXPECT(&m, "nfs4.response.SEQUENCE.result", 0, 40, 40, 44, 36, 0);
	EXPECT(&m, "nfs4.response.SEQUENCE.result.sr_status", 0, 40, 4, 40, 4,
	       0);
	/* The NFS4_OK arm is a struct: spliced as `ok`, not `ok.sr_resok4`. */
	EXPECT(&m, "nfs4.response.SEQUENCE.result.ok", 0, 44, 36, 44, 36, 0);
	EXPECT(&m, "nfs4.response.SEQUENCE.result.ok.sr_sessionid", 0, 44, 16,
	       44, 16, 0);
	EXPECT(&m, "nfs4.response.SEQUENCE.result.ok.sr_sequenceid", 0, 60, 4,
	       60, 4, 0x11);
	EXPECT(&m, "nfs4.response.SEQUENCE.result.ok.sr_slotid", 0, 64, 4, 64,
	       4, 0);
	EXPECT(&m, "nfs4.response.SEQUENCE.result.ok.sr_highest_slotid", 0, 68,
	       4, 68, 4, 63);
	EXPECT(&m, "nfs4.response.SEQUENCE.result.ok.sr_target_highest_slotid",
	       0, 72, 4, 72, 4, 63);
	EXPECT(&m, "nfs4.response.SEQUENCE.result.ok.sr_status_flags", 0, 76,
	       4, 76, 4, 0);

	EXPECT(&m, "nfs4.response.PUTFH", 0, 80, 8, 84, 4, 0);
	EXPECT(&m, "nfs4.response.PUTFH.result", 0, 84, 4, 84, 4, 0);
	EXPECT(&m, "nfs4.response.PUTFH.result.status", 0, 84, 4, 84, 4, 0);

	EXPECT(&m, "nfs4.response.OPEN", 0, 88, 72, 92, 68, 0);
	EXPECT(&m, "nfs4.response.OPEN.result", 0, 92, 68, 96, 64, 0);
	EXPECT(&m, "nfs4.response.OPEN.result.status", 0, 92, 4, 92, 4, 0);
	EXPECT(&m, "nfs4.response.OPEN.result.ok", 0, 96, 64, 96, 64, 0);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.stateid", 0, 96, 16, 96, 16,
	       0);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.stateid.seqid", 0, 96, 4, 96,
	       4, 1);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.stateid.other", 0, 100, 12,
	       100, 12, 0);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.cinfo", 0, 112, 20, 112, 20,
	       0);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.cinfo.atomic", 0, 112, 4, 112,
	       4, 1);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.cinfo.before", 0, 116, 8, 116,
	       8, 0xa001);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.cinfo.after", 0, 124, 8, 124,
	       8, 0xa002);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.rflags", 0, 132, 4, 132, 4,
	       4);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.attrset", 0, 136, 12, 140, 8,
	       0);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation", 0, 148, 12, 152,
	       8, 0);
	EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation.delegation_type",
	       0, 148, 4, 148, 4, 3);
	EXPECT(&m, dlg, 0, 152, 8, 156, 4, 0);
	snprintf(path, sizeof(path), "%s.ond_why", dlg);
	EXPECT(&m, path, 0, 152, 4, 152, 4, 1);
	snprintf(path, sizeof(path), "%s.wnd4_contention."
		 "ond_server_will_push_deleg", dlg);
	EXPECT(&m, path, 0, 156, 4, 156, 4, 0);

	EXPECT(&m, "nfs4.response.GETFH", 0, 160, 24, 164, 20, 0);
	EXPECT(&m, "nfs4.response.GETFH.result", 0, 164, 20, 168, 16, 0);
	EXPECT(&m, "nfs4.response.GETFH.result.status", 0, 164, 4, 164, 4, 0);
	EXPECT(&m, "nfs4.response.GETFH.result.ok.object", 0, 168, 16, 172, 12,
	       0);
	nfsp_decoded_msg_free(&m);
}

static void test_readdir_call(void)
{
	static const char *const ops[] = { "SEQUENCE", "PUTFH", "READDIR" };
	struct nfsp_decoded_msg m = {0};
	struct msg c;

	printf("CALL 4.1: SEQUENCE PUTFH READDIR\n");
	build_readdir_call(&c);
	CHECK(c.n == 172, "vector length %zu", c.n);
	if (!decoded(&c, NULL, &m, "readdir call"))
		return;
	CHECK(schema_is(&m, 1), "schema is not nfs4.1");
	expect_ops(&m, 3, ops, 0, NULL);
	EXPECT(&m, "nfs4.request.COMPOUND.args.argarray", 0, 72, 100, 76, 96,
	       0);
	EXPECT(&m, "nfs4.request.SEQUENCE.args.sa_cachethis", 0, 108, 4, 108,
	       4, 0);
	EXPECT(&m, "nfs4.request.READDIR", 0, 132, 40, 136, 36, 0);
	EXPECT(&m, "nfs4.request.READDIR.args", 0, 136, 36, 136, 36, 0);
	EXPECT(&m, "nfs4.request.READDIR.args.cookie", 0, 136, 8, 136, 8, 0);
	EXPECT(&m, "nfs4.request.READDIR.args.cookieverf", 0, 144, 8, 144, 8,
	       0);
	EXPECT(&m, "nfs4.request.READDIR.args.dircount", 0, 152, 4, 152, 4,
	       0x8000);
	EXPECT(&m, "nfs4.request.READDIR.args.maxcount", 0, 156, 4, 156, 4,
	       0x8000);
	EXPECT(&m, "nfs4.request.READDIR.args.attr_request", 0, 160, 12, 164,
	       8, 0);
	META(&m, "nfs4.request.READDIR.args.attr_request", 0, NFSP_META_COUNT,
	     160, 4);
	EXPECT(&m, "nfs4.request.READDIR.args.attr_request[]", 0, 164, 4, 164,
	       4, 0x802);
	EXPECT(&m, "nfs4.request.READDIR.args.attr_request[]", 1, 168, 4, 168,
	       4, 0x800000);
	CHECK(!field(&m, "nfs4.request.READDIR.args.attr_request[]", 2),
	      "two bitmap words");
	nfsp_decoded_msg_free(&m);
}

static void test_readdir_reply(void)
{
	static const char *const ops[] = { "SEQUENCE", "PUTFH", "READDIR" };
	static const uint32_t ok[] = { 0, 0, 0 };
	struct nfsp_reply_dispatch rd = dispatch(1);
	struct nfsp_decoded_msg m = {0};
	const struct nfsp_semantic_field *f;
	struct msg r;
	const char *const ent = "nfs4.response.READDIR.result.ok.reply."
				"entries[]";
	char path[160];

	printf("REPLY 4.1: READDIR entry4 list, two entries, eof\n");
	build_readdir_reply(&r);
	CHECK(r.n == 220, "vector length %zu", r.n);
	if (!decoded(&r, &rd, &m, "readdir reply"))
		return;
	CHECK(schema_is(&m, 1), "schema is not nfs4.1");
	expect_ops(&m, 3, ops, 1, ok);

	EXPECT(&m, "nfs4.response.READDIR", 0, 88, 132, 92, 128, 0);
	EXPECT(&m, "nfs4.response.READDIR.result", 0, 92, 128, 96, 124, 0);
	EXPECT(&m, "nfs4.response.READDIR.result.status", 0, 92, 4, 92, 4, 0);
	EXPECT(&m, "nfs4.response.READDIR.result.ok", 0, 96, 124, 96, 124, 0);
	EXPECT(&m, "nfs4.response.READDIR.result.ok.cookieverf", 0, 96, 8, 96,
	       8, 0);
	EXPECT(&m, "nfs4.response.READDIR.result.ok.reply", 0, 104, 116, 104,
	       116, 0);
	EXPECT(&m, "nfs4.response.READDIR.result.ok.reply.entries", 0, 104,
	       112, 108, 108, 0);
	META(&m, "nfs4.response.READDIR.result.ok.reply.entries", 0,
	     NFSP_META_DISCRIMINANT, 104, 4);

	/* Each element owns the link word after it. */
	EXPECT(&m, ent, 0, 108, 56, 108, 52, 0);
	META(&m, ent, 0, NFSP_META_DISCRIMINANT, 160, 4);
	EXPECT(&m, ent, 1, 164, 52, 164, 48, 0);
	META(&m, ent, 1, NFSP_META_DISCRIMINANT, 212, 4);
	f = field(&m, ent, 1);
	CHECK(f && f->index == 1, "entry index is metadata");
	snprintf(path, sizeof(path), "%s.cookie", ent);
	EXPECT(&m, path, 0, 108, 8, 108, 8, 0x1c2d3e4f5a6b7c8dull);
	EXPECT(&m, path, 1, 164, 8, 164, 8, 0x7fffffffffffffffull);
	snprintf(path, sizeof(path), "%s.name", ent);
	EXPECT(&m, path, 0, 116, 12, 120, 5, 0);
	META(&m, path, 0, NFSP_META_PADDING, 125, 3);
	EXPECT(&m, path, 1, 172, 8, 176, 4, 0);
	snprintf(path, sizeof(path), "%s.attrs", ent);
	EXPECT(&m, path, 0, 128, 32, 128, 32, 0);
	snprintf(path, sizeof(path), "%s.attrs.attrmask[]", ent);
	EXPECT(&m, path, 1, 136, 4, 136, 4, 0x800000);
	EXPECT(&m, path, 2, 184, 4, 184, 4, 0x802);
	snprintf(path, sizeof(path), "%s.attrs.attr_vals", ent);
	EXPECT(&m, path, 0, 140, 20, 144, 16, 0);
	EXPECT(&m, path, 1, 192, 20, 196, 16, 0);
	snprintf(path, sizeof(path), "%s.nextentry", ent);
	CHECK(!field(&m, path, 0), "the list link is not a member");
	EXPECT(&m, "nfs4.response.READDIR.result.ok.reply.eof", 0, 216, 4,
	       216, 4, 1);
	nfsp_decoded_msg_free(&m);
}

static void test_minor0(void)
{
	static const char *const ops[] = { "PUTFH", "READDIR" };
	static const uint32_t stale[] = { 70 };
	struct nfsp_reply_dispatch rd = dispatch(0);
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	printf("NFSv4.0: CALL PUTFH READDIR, REPLY stops at NFS4ERR_STALE\n");
	build_v40_call(&v);
	CHECK(v.n == 136, "vector length %zu", v.n);
	if (decoded(&v, NULL, &m, "4.0 call")) {
		CHECK(schema_is(&m, 0), "schema is not nfs4.0");
		expect_ops(&m, 2, ops, 0, NULL);
		EXPECT(&m, "nfs4.request.COMPOUND.args", 0, 64, 72, 64, 72, 0);
		EXPECT(&m, "nfs4.request.COMPOUND.args.tag", 0, 64, 8, 68, 2,
		       0);
		META(&m, "nfs4.request.COMPOUND.args.tag", 0,
		     NFSP_META_PADDING, 70, 2);
		EXPECT(&m, "nfs4.request.COMPOUND.args.minorversion", 0, 72, 4,
		       72, 4, 0);
		EXPECT(&m, "nfs4.request.PUTFH.args.object", 0, 84, 16, 88, 12,
		       0);
		EXPECT(&m, "nfs4.request.READDIR", 0, 100, 36, 104, 32, 0);
		EXPECT(&m, "nfs4.request.READDIR.args.dircount", 0, 120, 4,
		       120, 4, 0x2000);
		EXPECT(&m, "nfs4.request.READDIR.args.attr_request[]", 0, 132,
		       4, 132, 4, 0x100000);
	}

	build_v40_reply(&v);
	CHECK(v.n == 48, "vector length %zu", v.n);
	if (decoded(&v, &rd, &m, "4.0 reply")) {
		CHECK(schema_is(&m, 0), "schema is not nfs4.0");
		expect_ops(&m, 1, ops, 1, stale);
		EXPECT(&m, "nfs4.response.COMPOUND.result.status", 0, 24, 4,
		       24, 4, 70);
		EXPECT(&m, "nfs4.response.COMPOUND.result.tag", 0, 28, 8, 32,
		       2, 0);
		EXPECT(&m, "nfs4.response.COMPOUND.result.resarray", 0, 36, 12,
		       40, 8, 0);
		EXPECT(&m, "nfs4.response.PUTFH.result.status", 0, 44, 4, 44,
		       4, 70);
	}
	nfsp_decoded_msg_free(&m);
}

/* The minor version in the CALL picks the schema; an operation another
 * minor version added is undeclared, so the message is malformed. */
static void test_minor_selection(void)
{
	struct nfsp_reply_dispatch rd;
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	printf("minor versions: CALL selects, REPLY needs the dispatch\n");
	CHECK(nfsp_schema_family_nfs4.nschemas == 3 &&
	      nfsp_schema_family_nfs4.has_minor, "three minor versions");
	CHECK(strcmp(nfsp_schema_family_nfs4.schemas[0]->schema_id,
		     nfsp_schema_family_nfs4.schemas[1]->schema_id) &&
	      strcmp(nfsp_schema_family_nfs4.schemas[1]->schema_id,
		     nfsp_schema_family_nfs4.schemas[2]->schema_id),
	      "minor versions share a schema_id");

	build_seek_call(&v, 2, OP_SEEK);
	CHECK(v.n == 164, "vector length %zu", v.n);
	if (decoded(&v, NULL, &m, "4.2 SEEK")) {
		CHECK(schema_is(&m, 2), "schema is not nfs4.2");
		EXPECT(&m, "nfs4.request.SEEK", 0, 132, 32, 136, 28, 0);
		EXPECT(&m, "nfs4.request.SEEK.args.sa_stateid.seqid", 0, 136,
		       4, 136, 4, 1);
		EXPECT(&m, "nfs4.request.SEEK.args.sa_stateid.other", 0, 140,
		       12, 140, 12, 0);
		EXPECT(&m, "nfs4.request.SEEK.args.sa_offset", 0, 152, 8, 152,
		       8, 0x1000);
		EXPECT(&m, "nfs4.request.SEEK.args.sa_what", 0, 160, 4, 160, 4,
		       1);
	}

	/* An operation of another minor is where knfsd stops (OP_ILLEGAL):
	 * the operations before it stay. */
	build_seek_call(&v, 1, OP_SEEK);
	expect_partial_at(&v, 2, 132, OP_SEEK, "SEEK in 4.1");

	build_open_call(&v);
	put32(&v, 68, 0);
	expect_partial_at(&v, 0, 76, OP_SEQUENCE, "SEQUENCE in 4.0");
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_PARTIAL &&
	      m.failure.offset == 76 && m.failure.reason &&
	      !strcmp(m.failure.reason, "enum value not declared"),
	      "SEQUENCE in 4.0: %s at %u", nfsp_decode_strstatus(m.status),
	      m.failure.offset);
	put32(&v, 68, 3);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_UNSUPPORTED_SCHEMA &&
	      m.has_minor && m.minor_version == 3 && !m.schema,
	      "minor 3: %s", nfsp_decode_strstatus(m.status));

	call_header(&v, 0);	/* NULL: no COMPOUND, so no minor version */
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_UNSUPPORTED_SCHEMA,
	      "NULL: %s", nfsp_decode_strstatus(m.status));

	/* A REPLY carries no minor version: only the dispatch can say. */
	build_open_reply(&v);
	rd = dispatch(1);
	rd.has_minor = 0;
	CHECK(run(&v, v.n, &rd, &m) == NFSP_DECODE_DISPATCH_INCOMPLETE &&
	      m.nfields == 0, "no minor: %s",
	      nfsp_decode_strstatus(m.status));
	rd = dispatch(0);
	CHECK(run(&v, v.n, &rd, &m) == NFSP_DECODE_MALFORMED &&
	      m.failure.offset == 36,
	      "4.1 reply under a 4.0 dispatch: %s at %u",
	      nfsp_decode_strstatus(m.status), m.failure.offset);
	rd = dispatch(2);
	CHECK(run(&v, v.n, &rd, &m) == NFSP_DECODE_DECODED && schema_is(&m, 2),
	      "4.1 reply bytes under a 4.2 dispatch: %s",
	      nfsp_decode_strstatus(m.status));
	CHECK(run(&v, v.n, NULL, &m) ==
	      NFSP_DECODE_TRANSACTION_CONTEXT_MISSING && m.nfields == 0,
	      "no dispatch: %s", nfsp_decode_strstatus(m.status));
	nfsp_decoded_msg_free(&m);
}

/* Where knfsd or Ganesha and the pinned XDR part ways. */
static void test_cross_check(void)
{
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	printf("cross-check: XDR, not one server's policy\n");

	/* bitmap4 is uint32_t<>: no bound.  knfsd's nfsd4_decode_readdir
	 * reads attr_request into rd_bmval[3] and answers NFS4ERR_BADXDR for
	 * a fourth word; Ganesha's xdr_bitmap4 reads every word and keeps
	 * BITMAP4_MAPLEN (3).  The decoder must decode all four. */
	build_readdir_call(&v);
	put32(&v, 160, 4);
	w32(&v, 0);			/* 172 [2] */
	w32(&v, 0x00000001);		/* 176 [3] */
	if (decoded(&v, NULL, &m, "4-word bitmap")) {
		EXPECT(&m, "nfs4.request.READDIR.args.attr_request", 0, 160,
		       20, 164, 16, 0);
		EXPECT(&m, "nfs4.request.READDIR.args.attr_request[]", 3, 176,
		       4, 176, 4, 1);
	}

	nfsp_decoded_msg_free(&m);
}

/* The NFSv4.2 extensions knfsd v7.3-rc5 speaks: RFC 8276 xattr operations
 * and the RFC 9754 attribute delegation types.  They exist only in minor
 * 2; in 4.1 the same bytes stay malformed, never decoded with a guessed
 * layout. */
static void test_extensions(void)
{
	struct nfsp_reply_dispatch rd = dispatch(2), rd41 = dispatch(1);
	struct nfsp_decoded_msg m = {0};
	static const char *const xnames[] = { "SEQUENCE", "PUTFH",
					      "GETXATTR" };
	static const uint32_t ok3[] = { 0, 0, 0 };
	static const uint32_t noxattr[] = { 0, 0, 10095 };
	struct msg v;

	printf("NFSv4.2 extensions: RFC 8276 xattr, RFC 9754 delegations\n");
	build_getxattr_call(&v);
	CHECK(v.n == 152, "getxattr call length %zu", v.n);
	if (decoded(&v, NULL, &m, "GETXATTR call")) {
		CHECK(schema_is(&m, 2), "schema is not nfs4.2");
		expect_ops(&m, 3, xnames, 0, NULL);
		EXPECT(&m, "nfs4.request.GETXATTR.args.gxa_name", 0, 136, 16,
		       140, 9, 0);
		META(&m, "nfs4.request.GETXATTR.args.gxa_name", 0,
		     NFSP_META_PADDING, 149, 3);
	}
	put32(&v, 68, 1);
	expect_partial_at(&v, 2, 132, OP_GETXATTR, "GETXATTR in 4.1");

	build_getxattr_reply(&v);
	CHECK(v.n == 104, "getxattr reply length %zu", v.n);
	if (decoded(&v, &rd, &m, "GETXATTR reply")) {
		expect_ops(&m, 3, xnames, 1, ok3);
		EXPECT(&m, "nfs4.response.GETXATTR.result.gxr_status", 0, 92,
		       4, 92, 4, 0);
		EXPECT(&m, "nfs4.response.GETXATTR.result.ok.gxr_value", 0, 96,
		       8, 100, 3, 0);
	}
	put32(&v, 92, 10095);		/* NFS4ERR_NOXATTR, RFC 8276 */
	v.n = 96;
	if (decoded(&v, &rd, &m, "GETXATTR NOXATTR"))
		expect_ops(&m, 3, xnames, 1, noxattr);
	CHECK(run(&v, v.n, &rd41, &m) == NFSP_DECODE_MALFORMED,
	      "GETXATTR reply in 4.1: %s", nfsp_decode_strstatus(m.status));

	build_open_reply_rdeleg(&v);
	CHECK(v.n == 224, "rdeleg reply length %zu", v.n);
	if (decoded(&v, &rd, &m, "READ_ATTRS_DELEG reply")) {
		EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation."
		       "delegation_type", 0, 148, 4, 148, 4, 4);
		EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation."
		       "open_delegate_read_attrs_deleg.stateid.seqid", 0, 152,
		       4, 152, 4, 2);
		EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation."
		       "open_delegate_read_attrs_deleg.recall", 0, 168, 4,
		       168, 4, 0);
		EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation."
		       "open_delegate_read_attrs_deleg.permissions.who", 0,
		       184, 16, 188, 9, 0);
		EXPECT(&m, "nfs4.response.GETFH.result.ok.object", 0, 208, 16,
		       212, 12, 0);
	}
	CHECK(run(&v, v.n, &rd41, &m) == NFSP_DECODE_MALFORMED &&
	      m.failure.offset == 148, "READ_ATTRS_DELEG in 4.1: %s at %u",
	      nfsp_decode_strstatus(m.status), m.failure.offset);

	build_open_reply_wdeleg(&v);
	CHECK(v.n == 236, "wdeleg reply length %zu", v.n);
	if (decoded(&v, &rd, &m, "WRITE_ATTRS_DELEG reply")) {
		EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation."
		       "delegation_type", 0, 148, 4, 148, 4, 5);
		EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation."
		       "open_delegate_write_attrs_deleg.space_limit."
		       "nfs_limit_size.filesize", 0, 176, 8, 176, 8, 0x100000);
		EXPECT(&m, "nfs4.response.OPEN.result.ok.delegation."
		       "open_delegate_write_attrs_deleg.permissions.who", 0,
		       196, 16, 200, 9, 0);
	}
	put32(&v, 148, 6);		/* no type 6 anywhere */
	CHECK(run(&v, v.n, &rd, &m) == NFSP_DECODE_MALFORMED &&
	      m.failure.offset == 148, "delegation type 6: %s at %u",
	      nfsp_decode_strstatus(m.status), m.failure.offset);
	nfsp_decoded_msg_free(&m);
}

/* RFC 8435 flex files (4) and RFC 8154 SCSI (5) layout types, which knfsd
 * implements, in 4.1 and 4.2.  The layout body stays opaque. */
static void test_layout_types(void)
{
	struct nfsp_reply_dispatch rd = dispatch(1), rd42 = dispatch(2);
	struct nfsp_decoded_msg m = {0};
	static const char *const names[] = { "SEQUENCE", "PUTFH",
					     "LAYOUTGET" };
	static const uint32_t ok3[] = { 0, 0, 0 };
	struct msg v;

	printf("pNFS layout types: RFC 8435 flex files, RFC 8154 SCSI\n");
	build_layoutget_call(&v);
	CHECK(v.n == 192, "layoutget call length %zu", v.n);
	if (decoded(&v, NULL, &m, "LAYOUTGET flex files call")) {
		expect_ops(&m, 3, names, 0, NULL);
		EXPECT(&m, "nfs4.request.LAYOUTGET.args.loga_layout_type", 0,
		       140, 4, 140, 4, 4);
		EXPECT(&m, "nfs4.request.LAYOUTGET.args.loga_maxcount", 0,
		       188, 4, 188, 4, 4096);
	}
	put32(&v, 140, 5);
	if (decoded(&v, NULL, &m, "LAYOUTGET SCSI call"))
		EXPECT(&m, "nfs4.request.LAYOUTGET.args.loga_layout_type", 0,
		       140, 4, 140, 4, 5);
	put32(&v, 68, 2);
	if (decoded(&v, NULL, &m, "LAYOUTGET SCSI call in 4.2"))
		EXPECT(&m, "nfs4.request.LAYOUTGET.args.loga_layout_type", 0,
		       140, 4, 140, 4, 5);

	build_layoutget_reply(&v);
	CHECK(v.n == 152, "layoutget reply length %zu", v.n);
	if (decoded(&v, &rd, &m, "LAYOUTGET SCSI reply")) {
		expect_ops(&m, 3, names, 1, ok3);
		EXPECT(&m, "nfs4.response.LAYOUTGET.result.ok.logr_layout[]."
		       "lo_content.loc_type", 0, 140, 4, 140, 4, 5);
		EXPECT(&m, "nfs4.response.LAYOUTGET.result.ok.logr_layout[]."
		       "lo_content.loc_body", 0, 144, 8, 148, 4, 0);
	}
	put32(&v, 140, 4);
	if (decoded(&v, &rd42, &m, "LAYOUTGET flex files reply in 4.2"))
		EXPECT(&m, "nfs4.response.LAYOUTGET.result.ok.logr_layout[]."
		       "lo_content.loc_type", 0, 140, 4, 140, 4, 4);
	nfsp_decoded_msg_free(&m);
}

typedef void (*builder)(struct msg *);

struct golden {
	const char *what;
	builder build;
	int reply;
	uint32_t minor;
	unsigned leaves;	/* mutable leaves, for the address oracle */
};

static void build_seek42(struct msg *m)
{
	build_seek_call(m, 2, OP_SEEK);
}

static const struct golden goldens[] = {
	{ "open call", build_open_call, 0, 1, 14 },
	{ "open reply", build_open_reply, 1, 1, 14 },
	{ "readdir call", build_readdir_call, 0, 1, 11 },
	{ "readdir reply", build_readdir_reply, 1, 1, 17 },
	{ "4.0 call", build_v40_call, 0, 0, 7 },
	{ "4.0 reply", build_v40_reply, 1, 0, 1 },
	{ "4.2 seek", build_seek42, 0, 2, 8 },
	{ "4.2 getxattr call", build_getxattr_call, 0, 2, 6 },
	{ "4.2 getxattr reply", build_getxattr_reply, 1, 2, 7 },
	{ "4.2 read attrs deleg", build_open_reply_rdeleg, 1, 2, 20 },
	{ "4.2 write attrs deleg", build_open_reply_wdeleg, 1, 2, 21 },
	{ "4.1 layoutget call", build_layoutget_call, 0, 1, 11 },
	{ "4.1 layoutget reply", build_layoutget_reply, 1, 1, 11 },
};
#define NGOLDEN (sizeof(goldens) / sizeof(goldens[0]))

/* Every proper prefix fails.  It leaves nothing behind, except a CALL cut
 * inside an operation whose opcode word is present: partial. */
static void test_truncation(void)
{
	struct nfsp_decoded_msg m = {0};

	printf("truncation: every prefix of every golden message\n");
	for (size_t g = 0; g < NGOLDEN; g++) {
		struct nfsp_reply_dispatch rd = dispatch(goldens[g].minor);
		struct msg v;
		unsigned bad = 0;

		goldens[g].build(&v);
		for (size_t n = goldens[g].reply ? 24 : 64; n < v.n; n++) {
			enum nfsp_decode_status st =
				run(&v, n, goldens[g].reply ? &rd : NULL, &m);

			if (st == NFSP_DECODE_PARTIAL && !goldens[g].reply) {
				check_partial(&m, n, goldens[g].what);
				continue;
			}
			if (st == NFSP_DECODE_DECODED || m.nfields || m.nops)
				bad++;
		}
		CHECK(bad == 0, "%s: %u prefixes decoded or kept fields",
		      goldens[g].what, bad);
	}
	nfsp_decoded_msg_free(&m);
}

static void refused(builder build, const struct nfsp_reply_dispatch *rd,
		    size_t at, uint32_t word, enum nfsp_decode_status st,
		    uint32_t fail_off, const char *reason, int line)
{
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	build(&v);
	put32(&v, at, word);
	CHECK(run(&v, v.n, rd, &m) == st && m.nfields == 0 && m.nops == 0 &&
	      m.failure.offset == fail_off && m.failure.reason &&
	      !strcmp(m.failure.reason, reason),
	      "line %d: word %zu = %#x: %s at %u (%s), want %s at %u (%s)",
	      line, at, word, nfsp_decode_strstatus(m.status),
	      m.failure.offset, m.failure.reason ? m.failure.reason : "",
	      nfsp_decode_strstatus(st), fail_off, reason);
	nfsp_decoded_msg_free(&m);
}

#define REFUSED(b, rd, at, w, st, off, why) \
	refused(b, rd, at, w, st, off, why, __LINE__)

/* Word `at` of the OPEN call set to w fails operation op_index. */
static void partial_open(size_t at, uint32_t w, uint32_t fail_off,
			 const char *reason, uint32_t op_index,
			 uint32_t op_offset, int line)
{
	struct nfsp_decoded_msg m = {0};
	struct msg v;
	char what[48];

	snprintf(what, sizeof(what), "line %d", line);
	build_open_call(&v);
	put32(&v, at, w);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_PARTIAL &&
	      m.failure.offset == fail_off && m.failure.reason &&
	      !strcmp(m.failure.reason, reason) &&
	      m.failure.op_index == op_index &&
	      m.failure.op_offset == op_offset,
	      "%s: word %zu = %#x: %s at %u (%s) op %u at %u", what, at, w,
	      nfsp_decode_strstatus(m.status), m.failure.offset,
	      m.failure.reason ? m.failure.reason : "", m.failure.op_index,
	      m.failure.op_offset);
	if (m.status == NFSP_DECODE_PARTIAL)
		check_partial(&m, v.n, what);
	nfsp_decoded_msg_free(&m);
}

#define PARTIAL(at, w, off, why, idx, opoff) \
	partial_open(at, w, off, why, idx, opoff, __LINE__)

static void test_malformed(void)
{
	struct nfsp_reply_dispatch rd = dispatch(1);
	const enum nfsp_decode_status bad = NFSP_DECODE_MALFORMED;

	printf("malformed: located refusals on the NFSv4 bounds\n");
	/* Inside an operation of a CALL: partial at that operation (PUTFH
	 * at 112, OPEN at 132), the operations before it kept. */
	PARTIAL(116, 129, 116, "length exceeds bound", 1, 112);
	PARTIAL(156, 1025, 156, "length exceeds bound", 2, 132);
	PARTIAL(156, 200, 156, "length exceeds remaining record", 2, 132);
	PARTIAL(192, 4, 192, "enum value not declared", 2, 132);
	PARTIAL(216, 7, 216, "enum value not declared", 2, 132);
	PARTIAL(196, 1000, 196, "count exceeds remaining record", 2, 132);
	/* No opcode word for the fifth operation: knfsd refuses the whole
	 * request (its opcode read fails), so this is no partial. */
	REFUSED(build_open_call, NULL, 72, 5, NFSP_DECODE_TRUNCATED, 236,
		"record ends here");			/* count 5, four ops */
	/* The operation count is not checked as a whole: the four operations
	 * decode and the fifth opcode word is missing. */
	REFUSED(build_open_call, NULL, 72, 1000, NFSP_DECODE_TRUNCATED, 236,
		"record ends here");
	REFUSED(build_readdir_reply, &rd, 160, 2, bad, 160,
		"list link is not 0 or 1");
	REFUSED(build_readdir_reply, &rd, 216, 2, bad, 216,
		"bool is not 0 or 1");
	REFUSED(build_readdir_reply, &rd, 92, 99999, bad, 92,
		"enum value not declared");		/* nfsstat4 */
}

/* A short COMPOUND: AUTH_SYS header, empty tag, minor 0, then `n` words
 * from `ops`.  knfsd reads operations until one fails and never looks at
 * the count of those after it (nfsd4_decode_compound). */
static void short_compound(struct msg *m, uint32_t count,
			   const uint32_t *ops, size_t n)
{
	call_header(m, 1);
	w32(m, 0);			/* 64 tag */
	w32(m, 0);			/* 68 minorversion */
	w32(m, count);			/* 72 argarray count */
	for (size_t i = 0; i < n; i++)
		w32(m, ops[i]);		/* 76, 80, ... */
}

static void test_short_compound(void)
{
	static const uint32_t putroot_read[] = { 24, 25 };
	static const uint32_t putroot_bad[] = { 24, 99999 };
	static const uint32_t putroot2[] = { 24, 24 };
	struct nfsp_decoded_msg m = {0};
	struct msg v;

	printf("short COMPOUND: partial where knfsd stops\n");
	/* PUTROOTFH, then READ with no arguments: knfsd stops at READ. */
	short_compound(&v, 3, putroot_read, 2);
	expect_partial_at(&v, 1, 80, 25, "count 3, READ without args");
	short_compound(&v, 2, putroot_read, 2);
	expect_partial_at(&v, 1, 80, 25, "count 2, READ without args");
	short_compound(&v, 3, putroot_bad, 2);
	expect_partial_at(&v, 1, 80, 99999, "count 3, opcode 99999");
	/* The third opcode word is missing: knfsd refuses the request. */
	short_compound(&v, 3, putroot2, 2);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_TRUNCATED &&
	      m.failure.offset == 84 && m.nfields == 0 && m.nops == 0,
	      "missing third opcode: %s at %u",
	      nfsp_decode_strstatus(m.status), m.failure.offset);
	short_compound(&v, 0xffffffffu, putroot2, 2);
	CHECK(run(&v, v.n, NULL, &m) == NFSP_DECODE_TRUNCATED &&
	      m.failure.offset == 84 && m.nfields == 0,
	      "huge count: %s at %u", nfsp_decode_strstatus(m.status),
	      m.failure.offset);
	nfsp_decoded_msg_free(&m);
}

/* In a CALL, knfsd reads sa_cachethis as a plain word and skips padding
 * unread (nfsd4_decode_sequence, __xdr_inline_decode), so these decode and
 * are flagged; the same oddities in a REPLY stay malformed. */
static void test_lenient_call(void)
{
	struct nfsp_reply_dispatch rd = dispatch(1);
	struct nfsp_decoded_msg m = {0};
	const struct nfsp_semantic_field *f;
	struct msg v;

	printf("lenient CALL, strict REPLY\n");
	build_open_call(&v);
	put32(&v, 108, 2);			/* sa_cachethis */
	put32(&v, 228, 0x696c6501u);		/* "ile" + pad */
	if (decoded(&v, NULL, &m, "odd cachethis and padding")) {
		f = field(&m, "nfs4.request.SEQUENCE.args.sa_cachethis", 0);
		CHECK(f && f->flags == NFSP_FF_UNDECLARED && f->value == 2,
		      "sa_cachethis not flagged");
		f = field(&m, "nfs4.request.OPEN.args.claim.claim_null.file", 0);
		CHECK(f && f->flags == NFSP_FF_PAD_NONZERO &&
		      f->wire.value.off == 224 && f->wire.value.len == 7,
		      "claim.file padding not flagged");
		CHECK(m.nops == 4, "%u ops", m.nops);
	}
	REFUSED(build_readdir_reply, &rd, 216, 2, NFSP_DECODE_MALFORMED, 216,
		"bool is not 0 or 1");
	nfsp_decoded_msg_free(&m);
}

static int is_mutable_leaf(const struct nfsp_decoded_msg *m, uint32_t i)
{
	const struct nfsp_semantic_field *f = &m->fields[i];
	char buf[256];

	switch (f->kind) {
	case NFSP_XK_INT:
	case NFSP_XK_UINT:
	case NFSP_XK_HYPER:
	case NFSP_XK_UHYPER:
	case NFSP_XK_OPAQUE_FIXED:
	case NFSP_XK_OPAQUE_VAR:
	case NFSP_XK_STRING:
		break;
	default:
		return 0;	/* enum/bool/discriminant: validity changes */
	}
	if (!f->wire.value.len)
		return 0;
	nfsp_field_path(m, i, buf, sizeof(buf));
	return !strstr(buf, ".minorversion");
}

/* Change one field's value bytes; nothing else may move. */
static void test_address_oracle(void)
{
	struct nfsp_decoded_msg a = {0}, b = {0};

	printf("mutation-address oracle: one field changes, nothing moves\n");
	for (size_t g = 0; g < NGOLDEN; g++) {
		struct nfsp_reply_dispatch rd = dispatch(goldens[g].minor);
		const struct nfsp_reply_dispatch *rdp =
			goldens[g].reply ? &rd : NULL;
		struct msg base;
		unsigned tried = 0;

		goldens[g].build(&base);
		if (run(&base, base.n, rdp, &a) != NFSP_DECODE_DECODED) {
			CHECK(0, "%s: base does not decode", goldens[g].what);
			continue;
		}
		for (uint32_t i = 0; i < a.nfields; i++) {
			struct msg mut = base;
			const struct nfsp_span *v = &a.fields[i].wire.value;
			int same = 1;

			if (!is_mutable_leaf(&a, i))
				continue;
			tried++;
			for (uint32_t k = 0; k < v->len; k++)
				mut.b[v->off + k] ^= 0x5a;
			if (run(&mut, mut.n, rdp, &b) != NFSP_DECODE_DECODED ||
			    b.nfields != a.nfields) {
				CHECK(0, "%s field %u: mutated message %s",
				      goldens[g].what, i,
				      nfsp_decode_strstatus(b.status));
				continue;
			}
			for (uint32_t j = 0; j < a.nfields; j++) {
				const struct nfsp_semantic_field *x =
					&a.fields[j];
				const struct nfsp_semantic_field *y =
					&b.fields[j];

				if (memcmp(&x->wire, &y->wire,
					   sizeof(x->wire)) ||
				    x->parent != y->parent ||
				    x->type != y->type ||
				    x->component != y->component ||
				    x->root != y->root ||
				    x->index != y->index ||
				    (j != i && x->value != y->value))
					same = 0;
			}
			CHECK(same, "%s field %u: mutation moved another field",
			      goldens[g].what, i);
		}
		CHECK(tried == goldens[g].leaves,
		      "%s: %u leaves tried, want %u", goldens[g].what, tried,
		      goldens[g].leaves);
	}
	nfsp_decoded_msg_free(&a);
	nfsp_decoded_msg_free(&b);
}

/* Random byte edits of the goldens under the sanitizer build: nothing may
 * read out of bounds, and whatever still decodes keeps the invariants. */
static void test_random_edits(void)
{
	struct nfsp_decoded_msg m = {0};
	uint64_t x = 0x243f6a8885a308d3ull;
	unsigned ok = 0, partial_n = 0, refused_n = 0;
	enum nfsp_decode_status st;

	printf("random edits: 20000 mutated messages, invariants hold\n");
	for (unsigned it = 0; it < 20000; it++) {
		const struct golden *g = &goldens[it % NGOLDEN];
		struct nfsp_reply_dispatch rd = dispatch(g->minor);
		size_t hdr = g->reply ? 24 : 64;
		struct msg v;
		unsigned edits;

		g->build(&v);
		x ^= x << 13, x ^= x >> 7, x ^= x << 17;
		edits = 1 + (unsigned)(x % 4);
		for (unsigned e = 0; e < edits; e++) {
			x ^= x << 13, x ^= x >> 7, x ^= x << 17;
			v.b[hdr + (size_t)(x % (v.n - hdr))] =
				(uint8_t)(x >> 32);
		}
		st = run(&v, v.n, g->reply ? &rd : NULL, &m);
		if (st == NFSP_DECODE_DECODED) {
			ok++;
			check_invariants(&m, v.n, "random edit");
		} else if (st == NFSP_DECODE_PARTIAL) {
			partial_n++;
			CHECK(!g->reply, "partial REPLY");
			check_partial(&m, v.n, "random edit");
		} else {
			refused_n++;
			CHECK(m.nfields == 0 && m.nops == 0,
			      "refused message kept fields");
		}
	}
	printf("  %u decoded, %u partial, %u refused\n", ok, partial_n,
	       refused_n);
	CHECK(ok > 0 && refused_n > 0, "edits did not exercise both paths");
	nfsp_decoded_msg_free(&m);
}

int main(void)
{
	test_open_call();
	test_open_reply();
	test_readdir_call();
	test_readdir_reply();
	test_minor0();
	test_minor_selection();
	test_cross_check();
	test_extensions();
	test_layout_types();
	test_truncation();
	test_malformed();
	test_lenient_call();
	test_short_compound();
	test_address_oracle();
	test_random_edits();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
