/* Canonical JSON for journal requests, and a strict reader for host replies.
 *
 * The host sink accepts a request only in the repository's canonical form
 * (agent_pipeline/data.py canonical_json: sorted keys, no whitespace, UTF-8
 * unescaped).  Every string the proxy writes is visible ASCII, so the only
 * escapes are \" and \; callers write keys in sorted order themselves.
 *
 * The reader only finds values in a host reply.  It validates the whole
 * document's syntax first, so a value is never taken from a prefix of
 * something that is not JSON.
 */
#ifndef NFSP_JSONW_H
#define NFSP_JSONW_H

#include <stddef.h>
#include <stdint.h>

struct nfsp_jbuf {
	char *p;
	size_t len, cap, limit;
	int failed;	/* sticky: no memory, limit, or an unwritable string */
};

void nfsp_jb_init(struct nfsp_jbuf *b, size_t limit);
void nfsp_jb_free(struct nfsp_jbuf *b);
void nfsp_jb_raw(struct nfsp_jbuf *b, const char *s);
void nfsp_jb_rawn(struct nfsp_jbuf *b, const char *s, size_t n);
/* "s": refuses (sets failed) anything outside 0x20-0x7e. */
void nfsp_jb_str(struct nfsp_jbuf *b, const char *s);
void nfsp_jb_u64(struct nfsp_jbuf *b, uint64_t v);
/* "hex" of bytes, lowercase. */
void nfsp_jb_hex(struct nfsp_jbuf *b, const uint8_t *p, size_t n);
/* "key": (with the quotes and colon), preceded by a comma unless first. */
void nfsp_jb_key(struct nfsp_jbuf *b, const char *key, int first);

/* A value span inside a document. */
struct nfsp_jval {
	const char *p;
	size_t len;
};

/* 0 when doc[0..len) is exactly one JSON value (object at top level). */
int nfsp_json_valid(const char *doc, size_t len);
/* Find a member of the object `obj`; 0 found, -1 not found or not an object. */
int nfsp_json_member(struct nfsp_jval obj, const char *key,
		     struct nfsp_jval *out);
/* Unescaped-string equality for a value with no escapes; -1 otherwise. */
int nfsp_json_str_eq(struct nfsp_jval v, const char *s);
/* Copy a plain (escape-free) string value; -1 if not one or too long. */
int nfsp_json_str(struct nfsp_jval v, char *out, size_t cap);
int nfsp_json_u64(struct nfsp_jval v, uint64_t *out);
int nfsp_json_is_null(struct nfsp_jval v);

#endif /* NFSP_JSONW_H */
