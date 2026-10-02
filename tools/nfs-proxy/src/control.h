#ifndef NFSP_CONTROL_H
#define NFSP_CONTROL_H

#include "delta.h"
#include "edit.h"
#include <stddef.h>
#include <stdint.h>

#define NFSP_ARM_MAGIC "NFSPARM1"
#define NFSP_ARM_WORDS 9u
#define NFSP_ARM_WIRE_LEN (8u + 4u * NFSP_ARM_WORDS + \
		NFSP_DELTA_ANCHOR_MAX + 2u * NFSP_DELTA_PATCH_MAX)

/* Variable-length arm (Phase 1): operation insertion and resizing edits.  A
 * distinct magic on the same control socket means the two formats need no
 * flag day: an executor built against the old syzlang still sends NFSPARM1,
 * one built against patch 0019 sends NFSPARM2, and a proxy accepts either on
 * every connection.  Unlike NFSPARM1 the wire size is not fixed: it is
 * self-describing (the header carries `nedits`, each edit carries its own
 * `orig_len`/`data_len`), and decoding verifies the declared sizes consume
 * the packet exactly, with no trailing bytes. */
#define NFSP_EDIT_ARM_MAGIC "NFSPARM2"
/* dir, backend, client, first_opcode, anchor_off, anchor_len, mode, nedits,
 * reserved(0). */
#define NFSP_EDIT_ARM_HDR_WORDS 9u
#define NFSP_EDIT_ARM_HDR_LEN (8u + 4u * NFSP_EDIT_ARM_HDR_WORDS)
/* kind, offset, orig_len, data_len, per edit. */
#define NFSP_EDIT_ARM_FIELD_HDR_LEN (4u * 4u)
/* Upper bound on one v2 packet: header + anchor + one field header per edit +
 * the total edit-byte cap (NFSP_EDIT_TOTAL_MAX bounds the SUM of orig_len and
 * data_len over all edits in the rule, which is why this is far smaller than
 * NFSP_EDIT_MAX times the per-edit byte arrays in struct nfsp_edit_rule). */
#define NFSP_EDIT_ARM_MAX_LEN (NFSP_EDIT_ARM_HDR_LEN + NFSP_DELTA_ANCHOR_MAX + \
		NFSP_EDIT_MAX * NFSP_EDIT_ARM_FIELD_HDR_LEN + NFSP_EDIT_TOTAL_MAX)

struct nfsp_control;

/* The Unix SOCK_SEQPACKET endpoint lives in the proc-specific sandbox source.
 * The registered rule exists only while its owner holds the returned FD.
 * Every applied mutation updates a durable per-arm delta file.  Replay loads
 * one such file, needs no control endpoint, and calls the same apply path. */
int nfsp_control_open(struct nfsp_control **out, const char *socket_path,
		      const char *delta_dir, const char *replay_path);
void nfsp_control_tick(void *state);
/* Matches the nfsp_proxy_cfg.on_record contract (proxy.h): `record` is
 * read-only.  Leaving *out / *out_len untouched means "forward unchanged",
 * which is what happens when no armed rule's predicate matches this tuple.
 * When something applies, *out points at a buffer this nfsp_control instance
 * owns and keeps valid until the next call to nfsp_control_record or
 * nfsp_control_tick on it. */
int nfsp_control_record(unsigned client, unsigned backend, int dir,
			const uint8_t *record, size_t len,
			const uint8_t **out, size_t *out_len, void *state);
void nfsp_control_report(const struct nfsp_control *state);
int nfsp_control_close(struct nfsp_control *state);

#endif
