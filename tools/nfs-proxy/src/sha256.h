/* SHA-256 (FIPS 180-4) for journal frame integrity and request digests.
 *
 * The NFSPJNL1 frame (05-mutation-delta-replay.md §45) hashes its header and
 * payload with SHA-256, and the host ACK names the request by its SHA-256.
 * The guest build links libc only, so the proxy carries its own digest.
 */
#ifndef NFSP_SHA256_H
#define NFSP_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define NFSP_SHA256_LEN	32u

struct nfsp_sha256 {
	uint32_t h[8];
	uint64_t bytes;
	uint8_t block[64];
	size_t fill;
};

void nfsp_sha256_init(struct nfsp_sha256 *c);
void nfsp_sha256_update(struct nfsp_sha256 *c, const void *data, size_t len);
void nfsp_sha256_final(struct nfsp_sha256 *c, uint8_t out[NFSP_SHA256_LEN]);
void nfsp_sha256(const void *data, size_t len, uint8_t out[NFSP_SHA256_LEN]);
/* Lowercase hex, NUL-terminated: out must hold 65 bytes. */
void nfsp_sha256_hex(const uint8_t digest[NFSP_SHA256_LEN], char out[65]);

#endif /* NFSP_SHA256_H */
