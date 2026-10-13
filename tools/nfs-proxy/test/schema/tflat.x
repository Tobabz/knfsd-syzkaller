/*
 * tflat: a synthetic procedure-dispatched protocol (the NFSv3 shape) for the
 * decoder's host tests.  A REPLY carries no procedure, so its result type is
 * known only from reply_dispatch.
 */
typedef unsigned int uint32_t;
typedef opaque tf_handle<8>;

enum tf_status {
	TF_OK    = 0,
	TF_NOENT = 2
};

struct READ_args {
	tf_handle	fh;
	uint32_t	count;
};

struct READ_resok {
	bool		eof;
	opaque		data<>;
};

union READ_res switch (tf_status status) {
case TF_OK:
	READ_resok	resok;
default:
	void;
};

struct GETSIZE_res {
	tf_status	status;
	unsigned hyper	size;
};

program TFLAT_PROGRAM {
	version TFLAT_V2 {
		void		TFPROC_NULL(void) = 0;
		READ_res	TFPROC_READ(READ_args) = 6;
		GETSIZE_res	TFPROC_GETSIZE(tf_handle) = 7;
	} = 2;
} = 0x2000009a;
