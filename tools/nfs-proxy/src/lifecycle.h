#ifndef NFSP_LIFECYCLE_H
#define NFSP_LIFECYCLE_H

#include <stdatomic.h>
#include <stdint.h>

#include "cld.h"

/* A deliberately small fixture-admin ABI.  The executor can select one of
 * the two deterministic lane clients and request one operation: expire its
 * confirmed NFSv4.1 server record.  It cannot supply a path, client owner,
 * minor version, clientid, or arbitrary ctl payload. */
#define NFSP_LIFECYCLE_REQUEST_MAGIC "NFSLIFE1"
#define NFSP_LIFECYCLE_REPLY_MAGIC "NFSLIFR1"
#define NFSP_LIFECYCLE_REQUEST_LEN 16u
#define NFSP_LIFECYCLE_REPLY_LEN 32u
#define NFSP_LIFECYCLE_OP_EXPIRE 1u

struct nfsp_lifecycle_result {
	uint32_t client;
	uint32_t minor_version;
	uint32_t session_count;
	uint64_t clientid;
};

/* Scan clients_dir on every call, require exactly one confirmed NFSv4.1
 * record whose quoted owner is the Linux client format
 * "Linux NFSv4.1 frozen-phase9-laneN-clientM/<UTS hostname>", and write the
 * kernel's sole accepted command ("expire\n") to that record's ctl file. */
int nfsp_lifecycle_expire(const char *clients_dir, uint32_t lane,
			  uint32_t client, struct nfsp_lifecycle_result *result);

/* Serve the fixed request ABI on a mode-0600 SOCK_SEQPACKET endpoint until
 * stop becomes nonzero.  Each response records the pre-expiry clientid,
 * minor version and number of session slots for audit correlation. */
int nfsp_lifecycle_serve(const char *socket_path, const char *clients_dir,
			 uint32_t lane, const _Atomic int *stop);

/* The same endpoint with bounded nfsdcld control (cld.h).  With cld NULL it
 * is exactly nfsp_lifecycle_serve().  With cld set, the CLD operations are
 * accepted and every operation, client expiry included, is refused with
 * EBUSY while a CLD transaction is pending: expiry upcalls nfsdcld from this
 * process, so it must not run while the daemon is held or down.  CLD replies
 * carry status, operation, transaction sequence, daemon PID and start time.
 * On stop a pending transaction is completed before the endpoint closes. */
int nfsp_lifecycle_serve_cld(const char *socket_path, const char *clients_dir,
			     uint32_t lane, struct nfsp_cld *cld,
			     const _Atomic int *stop);

#endif
