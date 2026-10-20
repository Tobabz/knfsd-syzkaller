#ifndef NFSP_CLD_H
#define NFSP_CLD_H

#include <stdint.h>
#include <sys/types.h>

/* Bounded nfsdcld control for one lane's server namespaces.
 *
 * The lifecycle broker owns this state machine.  A request names only a
 * fixed operation; the daemon executable, the CLD pipe, the namespaces and
 * every timeout are broker configuration fixed by lane.sh.  Each operation
 * first proves the live daemon's identity:
 *
 *   - exactly one process named nfsdcld shares the broker's network and
 *     mount namespaces;
 *   - its executable is the configured daemon and its argv is exactly
 *     "nfsdcld";
 *   - it holds an open descriptor on the CLD pipe inode the broker resolves
 *     (on rpc_pipefs in production), so a stale pathname cannot pass;
 *   - a pidfd opened on it names the same start time, so a reused PID
 *     cannot receive a signal.
 *
 * RECONNECT stops the daemon with SIGSTOP and returns.  While it is stopped
 * the CLD pipe keeps its reader, so an upcall issued in that window stays
 * queued.  After the fixed hold the broker kills the stopped daemon, which
 * closes the pipe and makes the kernel complete queued upcalls with -EAGAIN
 * (cld_pipe_upcall then requeues them), and starts one replacement daemon.
 *
 * DOWN stops the daemon with SIGTERM, waits for it to exit and returns.
 * After the fixed down window, longer than the kernel's 30 s upcall timeout,
 * the broker starts one replacement daemon.
 *
 * Either way the transaction ends idle with a validated replacement, or
 * FAILED.  Nothing else is accepted while a transaction is pending. */

#define NFSP_LIFECYCLE_OP_CLD_RECONNECT 2u
#define NFSP_LIFECYCLE_OP_CLD_DOWN 3u

#define NFSP_CLD_COMM "nfsdcld"
#define NFSP_CLD_PIPE_PATH "/var/lib/nfs/rpc_pipefs/nfsd/cld"
#define NFSP_CLD_HOLD_MS 2000u
#define NFSP_CLD_DOWN_MS 35000u
#define NFSP_CLD_STOP_TIMEOUT_MS 5000u
#define NFSP_CLD_START_TIMEOUT_MS 10000u

enum nfsp_cld_state {
	NFSP_CLD_IDLE = 0,
	NFSP_CLD_HELD,
	NFSP_CLD_DOWN,
	NFSP_CLD_FAILED,
};

struct nfsp_cld_config {
	const char *proc_root;
	const char *pipe_path;
	const char *daemon_path;
	/* Replaced atomically after every transition.  NULL disables it. */
	const char *state_path;
	/* Require the pipe to live on rpc_pipefs (production). */
	int require_pipefs;
	unsigned hold_ms;
	unsigned down_ms;
	unsigned stop_timeout_ms;
	unsigned start_timeout_ms;
};

struct nfsp_cld_identity {
	pid_t pid;
	uint64_t starttime;
	uint64_t pipe_dev;
	uint64_t pipe_ino;
};

/* Typed counters.  Each is owned by exactly one transition; see
 * docs/design/02-llm-agent/04-harness-capability-spec.md (HCAP-12). */
struct nfsp_cld_counters {
	uint64_t reconnect_attempts;
	uint64_t reconnect_ok;
	uint64_t reconnect_fail;
	uint64_t down_attempts;
	uint64_t down_ok;
	uint64_t down_fail;
	uint64_t daemon_stop_ok;
	uint64_t daemon_stop_fail;
	uint64_t daemon_start_ok;
	uint64_t daemon_start_fail;
	uint64_t refused_busy;
	uint64_t refused_identity;
	uint64_t restore_ok;
	uint64_t restore_fail;
};

struct nfsp_cld {
	struct nfsp_cld_config config;
	enum nfsp_cld_state state;
	uint32_t op;
	uint64_t seq;
	uint64_t deadline_ms;
	int pidfd;
	struct nfsp_cld_identity current;
	struct nfsp_cld_counters counters;
	int last_errno;
};

/* Validate the initial daemon and record it.  Returns 0 or -1/errno. */
int nfsp_cld_init(struct nfsp_cld *cld, const struct nfsp_cld_config *config);

/* Find and validate the one live daemon without changing state. */
int nfsp_cld_find(const struct nfsp_cld *cld, int allow_stopped,
		  struct nfsp_cld_identity *identity);

/* Start one operation.  Returns 0 (transaction armed) or an errno:
 * EBUSY while a transaction is pending, EIO after a failed one,
 * EOPNOTSUPP for another operation, or the identity/stop error. */
uint32_t nfsp_cld_begin(struct nfsp_cld *cld, uint32_t op,
			struct nfsp_cld_identity *identity);

/* Milliseconds until the pending transaction is due (0 = now), or -1. */
int nfsp_cld_due_in_ms(const struct nfsp_cld *cld);

/* Complete the pending transaction if its deadline passed (or force). */
void nfsp_cld_tick(struct nfsp_cld *cld, int force);

int nfsp_cld_pending(const struct nfsp_cld *cld);
const char *nfsp_cld_state_name(enum nfsp_cld_state state);
void nfsp_cld_close(struct nfsp_cld *cld);

#endif
