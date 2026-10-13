/*
 * tproto: a synthetic COMPOUND protocol for the decoder's host tests.
 *
 * It is not NFS.  It exists so that every XDR construct the normalizer
 * accepts is exercised by a vector whose offsets are written out in
 * test/test_nfs_decode.c, independently of any RFC.  Minor version 0.
 */
%/* rpcgen pass-through lines are ignored by the normalizer */

const TP_MAXNAME = 16;
const TP_IDSIZE = 12;
const TP_MASKS = 4;

typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned hyper uint64_t;
typedef hyper int64_t;

typedef opaque tp_name<TP_MAXNAME>;
typedef string tp_text<>;
typedef uint32_t tp_count;

enum tp_status {
	TP_OK         = 0,
	TP_ERR_IO     = 5,
	TP_ERR_DENIED = 13
};

enum tp_opnum {
	OP_PING    = 1,
	OP_WRITE   = 2,
	OP_LOOKUP  = 3,
	OP_ILLEGAL = 0x271c
};

enum tp_kind {
	TK_FILE = 1,
	TK_LINK = 2,
	TK_DIR  = 3
};

struct tp_id {
	uint32_t	seq;
	opaque		other[TP_IDSIZE];
};

union tp_target switch (tp_kind kind) {
case TK_FILE:
	tp_id		file;
case TK_LINK:
	tp_text		link;
case TK_DIR:
	void;
};

struct WRITE_args {
	tp_id		id;
	uint64_t	offset;
	int32_t		delta;
	int64_t		when;
	bool		sync;
	opaque		data<>;
	uint32_t	mask<TP_MASKS>;
	tp_id		pair[2];
	tp_target	target;
};

struct WRITE_resok {
	tp_count	count;
	tp_id		id;
};

union WRITE_res switch (tp_status status) {
case TP_OK:
	WRITE_resok	resok;
case TP_ERR_DENIED:
	tp_name		owner;
default:
	void;
};

struct LOOKUP_args {
	tp_name		name;
};

struct entry {
	uint64_t	cookie;
	tp_name		name;
	entry		*next;
};

struct LOOKUP_resok {
	entry		*entries;
	bool		eof;
};

union LOOKUP_res switch (tp_status status) {
case TP_OK:
	LOOKUP_resok	resok;
default:
	void;
};

struct PING_res {
	tp_status	status;
};

struct ILLEGAL_res {
	tp_status	status;
};

union tp_argop switch (tp_opnum argop) {
case OP_PING:		void;
case OP_WRITE:		WRITE_args opwrite;
case OP_LOOKUP:		LOOKUP_args oplookup;
case OP_ILLEGAL:	void;
};

union tp_resop switch (tp_opnum resop) {
case OP_PING:		PING_res opping;
case OP_WRITE:		WRITE_res opwrite;
case OP_LOOKUP:		LOOKUP_res oplookup;
case OP_ILLEGAL:	ILLEGAL_res opillegal;
};

struct COMPOUND_args {
	tp_text		tag;
	uint32_t	minorversion;
	tp_argop	argarray<>;
};

struct COMPOUND_res {
	tp_status	status;
	tp_text		tag;
	tp_resop	resarray<>;
};

/* A declaration nothing reachable uses: it must not appear in the tables. */
struct UNUSED_args {
	float_is_not_here_either	x;
};

program TPROTO_PROGRAM {
	version TPROTO_V1 {
		void		TPPROC_NULL(void) = 0;
		COMPOUND_res	TPPROC_COMPOUND(COMPOUND_args) = 1;
	} = 1;
} = 0x20000099;
