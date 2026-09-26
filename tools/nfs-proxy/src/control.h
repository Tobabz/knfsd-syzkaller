#ifndef NFSP_CONTROL_H
#define NFSP_CONTROL_H

#include "delta.h"
#include <stddef.h>
#include <stdint.h>

#define NFSP_ARM_MAGIC "NFSPARM1"
#define NFSP_ARM_WORDS 9u
#define NFSP_ARM_WIRE_LEN (8u + 4u * NFSP_ARM_WORDS + \
		NFSP_DELTA_ANCHOR_MAX + 2u * NFSP_DELTA_PATCH_MAX)

struct nfsp_control;

/* The Unix SOCK_SEQPACKET endpoint lives in the proc-specific sandbox source.
 * The registered rule exists only while its owner holds the returned FD.
 * Every applied mutation updates a durable per-arm delta file.  Replay loads
 * one such file, needs no control endpoint, and calls the same apply path. */
int nfsp_control_open(struct nfsp_control **out, const char *socket_path,
		      const char *delta_dir, const char *replay_path);
void nfsp_control_tick(void *state);
int nfsp_control_record(unsigned client, unsigned backend, int dir,
			uint8_t *record, size_t len, void *state);
void nfsp_control_report(const struct nfsp_control *state);
int nfsp_control_close(struct nfsp_control *state);

#endif
