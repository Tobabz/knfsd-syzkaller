/* Selector-free, original-coordinate byte rebuild contract.
 *
 * This header is separate from edit.h because the legacy delta ABI and the
 * semantic rule ABI both historically use the tag `struct nfsp_rule`.  The
 * concrete boundary depends on neither and can therefore be shared safely.
 */
#ifndef NFSP_CONCRETE_EDIT_H
#define NFSP_CONCRETE_EDIT_H

#include <stddef.h>
#include <stdint.h>

/* M4c currently lowers one resolved mutation to at most two edits. */
#define NFSP_CONCRETE_EDIT_MAX	128u

/* Every edit replaces [offset, offset + remove_len) with data[0..data_len).
 * `original` is the immutable precondition for the removed bytes.  Inserts
 * have remove_len zero and original NULL. */
struct nfsp_concrete_edit {
	uint32_t offset;
	uint32_t remove_len;
	const uint8_t *original;
	uint32_t data_len;
	const uint8_t *data;
};

struct nfsp_concrete_edit_batch {
	const struct nfsp_concrete_edit *edits;
	size_t nedits;
};

enum nfsp_concrete_status {
	NFSP_CONCRETE_OK = 0,
	NFSP_CONCRETE_INVALID,
	NFSP_CONCRETE_BOUNDS,
	NFSP_CONCRETE_CONFLICT,
	NFSP_CONCRETE_ORIGINAL_MISMATCH,
	NFSP_CONCRETE_TOO_LARGE
};

/* Validate every edit, span, conflict, original precondition and final size
 * without writing output.  Independent edits at one offset are conflicts. */
enum nfsp_concrete_status
nfsp_concrete_preflight(const struct nfsp_concrete_edit_batch *batch,
			const uint8_t *in, size_t in_len, size_t max_output,
			size_t *final_len);

/* Run the same complete preflight, then rebuild exactly once.  On refusal the
 * bytes in out are untouched and *out_len is zero.  `in` and `out` must not
 * overlap. */
enum nfsp_concrete_status
nfsp_apply_concrete_batch(const struct nfsp_concrete_edit_batch *batch,
			  const uint8_t *in, size_t in_len,
			  uint8_t *out, size_t out_cap, size_t *out_len);

const char *nfsp_concrete_strstatus(enum nfsp_concrete_status status);

#endif /* NFSP_CONCRETE_EDIT_H */
