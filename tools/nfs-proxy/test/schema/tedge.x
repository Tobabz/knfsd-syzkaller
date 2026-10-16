/*
 * tedge: a synthetic protocol whose operation unions are not elements of an
 * operation array: one is a procedure's whole argument (DIRECT), the other
 * a struct member (EMBEDDED).  The decoder emits each operation as a root of
 * its own, so neither container path names it; the static path resolver
 * (schema.h) must agree (PR #33 review).  It is not NFS.
 */
typedef unsigned int uint32_t;

enum te_opnum {
	OP_PING = 1,
	OP_ECHO = 2
};

enum te_status {
	TE_OK  = 0,
	TE_ERR = 1
};

struct ECHO_args {
	uint32_t	value;
};

struct ECHO_res {
	te_status	status;
	uint32_t	value;
};

struct PING_res {
	te_status	status;
};

union te_argop switch (te_opnum argop) {
case OP_PING:	void;
case OP_ECHO:	ECHO_args opecho;
};

union te_resop switch (te_opnum resop) {
case OP_PING:	PING_res opping;
case OP_ECHO:	ECHO_res opecho;
};

struct EMBEDDED_args {
	uint32_t	tag;
	te_argop	operation;
};

struct EMBEDDED_res {
	uint32_t	tag;
	te_resop	operation;
};

program TEDGE_PROGRAM {
	version TEDGE_V1 {
		void		TEPROC_NULL(void) = 0;
		te_resop	TEPROC_DIRECT(te_argop) = 1;
		EMBEDDED_res	TEPROC_EMBEDDED(EMBEDDED_args) = 2;
	} = 1;
} = 0x2000009b;
