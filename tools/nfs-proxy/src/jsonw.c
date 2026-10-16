/* Canonical JSON writer and strict reader.  See jsonw.h. */
#include "jsonw.h"

#include <stdlib.h>
#include <string.h>

void nfsp_jb_init(struct nfsp_jbuf *b, size_t limit)
{
	memset(b, 0, sizeof(*b));
	b->limit = limit;
}

void nfsp_jb_free(struct nfsp_jbuf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

void nfsp_jb_rawn(struct nfsp_jbuf *b, const char *s, size_t n)
{
	if (b->failed)
		return;
	if (n > b->limit || b->len > b->limit - n) {
		b->failed = 1;
		return;
	}
	if (b->len + n + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 256u;
		char *grown;

		while (cap < b->len + n + 1)
			cap *= 2u;
		grown = realloc(b->p, cap);
		if (grown == NULL) {
			b->failed = 1;
			return;
		}
		b->p = grown;
		b->cap = cap;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

void nfsp_jb_raw(struct nfsp_jbuf *b, const char *s)
{
	nfsp_jb_rawn(b, s, strlen(s));
}

void nfsp_jb_str(struct nfsp_jbuf *b, const char *s)
{
	nfsp_jb_raw(b, "\"");
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c < 0x20 || c > 0x7e) {
			b->failed = 1;
			return;
		}
		if (c == '"' || c == '\\')
			nfsp_jb_raw(b, "\\");
		nfsp_jb_rawn(b, s, 1);
	}
	nfsp_jb_raw(b, "\"");
}

void nfsp_jb_u64(struct nfsp_jbuf *b, uint64_t v)
{
	char tmp[24];
	size_t i = sizeof(tmp);

	do {
		tmp[--i] = (char)('0' + v % 10u);
		v /= 10u;
	} while (v != 0);
	nfsp_jb_rawn(b, tmp + i, sizeof(tmp) - i);
}

void nfsp_jb_hex(struct nfsp_jbuf *b, const uint8_t *p, size_t n)
{
	static const char hex[] = "0123456789abcdef";
	char pair[2];

	nfsp_jb_raw(b, "\"");
	for (size_t i = 0; i < n && !b->failed; i++) {
		pair[0] = hex[p[i] >> 4];
		pair[1] = hex[p[i] & 15u];
		nfsp_jb_rawn(b, pair, 2);
	}
	nfsp_jb_raw(b, "\"");
}

void nfsp_jb_key(struct nfsp_jbuf *b, const char *key, int first)
{
	if (!first)
		nfsp_jb_raw(b, ",");
	nfsp_jb_str(b, key);
	nfsp_jb_raw(b, ":");
}

/* --- reader -------------------------------------------------------------- */

#define JSON_MAX_DEPTH 32

static size_t skip_ws(const char *p, size_t len, size_t i)
{
	while (i < len && (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' ||
			   p[i] == '\r'))
		i++;
	return i;
}

static int is_hex(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

/* Returns the index after the value at i, or 0 on a syntax error (a value
 * can never end at index 0). */
static size_t value_end(const char *p, size_t len, size_t i, unsigned depth)
{
	if (depth > JSON_MAX_DEPTH || i >= len)
		return 0;
	if (p[i] == '"') {
		for (i++; i < len; i++) {
			unsigned char c = (unsigned char)p[i];

			if (c == '"')
				return i + 1;
			if (c < 0x20)
				return 0;
			if (c == '\\') {
				if (++i >= len)
					return 0;
				if (p[i] == 'u') {
					if (i + 4 >= len || !is_hex(p[i + 1]) ||
					    !is_hex(p[i + 2]) ||
					    !is_hex(p[i + 3]) || !is_hex(p[i + 4]))
						return 0;
					i += 4;
				} else if (!strchr("\"\\/bfnrt", p[i])) {
					return 0;
				}
			}
		}
		return 0;
	}
	if (p[i] == '{' || p[i] == '[') {
		char close = p[i] == '{' ? '}' : ']';
		int object = p[i] == '{';

		i = skip_ws(p, len, i + 1);
		if (i < len && p[i] == close)
			return i + 1;
		for (;;) {
			if (object) {
				if (i >= len || p[i] != '"')
					return 0;
				i = value_end(p, len, i, depth + 1);
				if (i == 0)
					return 0;
				i = skip_ws(p, len, i);
				if (i >= len || p[i] != ':')
					return 0;
				i = skip_ws(p, len, i + 1);
			}
			i = value_end(p, len, i, depth + 1);
			if (i == 0)
				return 0;
			i = skip_ws(p, len, i);
			if (i < len && p[i] == ',') {
				i = skip_ws(p, len, i + 1);
				continue;
			}
			if (i < len && p[i] == close)
				return i + 1;
			return 0;
		}
	}
	if (p[i] == '-' || (p[i] >= '0' && p[i] <= '9')) {
		size_t start = i;

		if (p[i] == '-')
			i++;
		if (i >= len || p[i] < '0' || p[i] > '9')
			return 0;
		if (p[i] == '0')
			i++;
		else
			while (i < len && p[i] >= '0' && p[i] <= '9')
				i++;
		if (i < len && p[i] == '.') {
			i++;
			if (i >= len || p[i] < '0' || p[i] > '9')
				return 0;
			while (i < len && p[i] >= '0' && p[i] <= '9')
				i++;
		}
		if (i < len && (p[i] == 'e' || p[i] == 'E')) {
			i++;
			if (i < len && (p[i] == '+' || p[i] == '-'))
				i++;
			if (i >= len || p[i] < '0' || p[i] > '9')
				return 0;
			while (i < len && p[i] >= '0' && p[i] <= '9')
				i++;
		}
		return i > start ? i : 0;
	}
	if (len - i >= 4 && !memcmp(p + i, "true", 4))
		return i + 4;
	if (len - i >= 5 && !memcmp(p + i, "false", 5))
		return i + 5;
	if (len - i >= 4 && !memcmp(p + i, "null", 4))
		return i + 4;
	return 0;
}

int nfsp_json_valid(const char *doc, size_t len)
{
	size_t i = skip_ws(doc, len, 0), end;

	if (i >= len || doc[i] != '{')
		return -1;
	end = value_end(doc, len, i, 0);
	if (end == 0)
		return -1;
	return skip_ws(doc, len, end) == len ? 0 : -1;
}

int nfsp_json_member(struct nfsp_jval obj, const char *key,
		     struct nfsp_jval *out)
{
	const char *p = obj.p;
	size_t len = obj.len, i, klen = strlen(key);
	int found = 0;

	i = skip_ws(p, len, 0);
	if (i >= len || p[i] != '{')
		return -1;
	i = skip_ws(p, len, i + 1);
	if (i < len && p[i] == '}')
		return -1;
	for (;;) {
		size_t kstart = i, kend, vstart, vend;

		kend = value_end(p, len, i, 1);
		if (kend == 0)
			return -1;
		i = skip_ws(p, len, kend);
		if (i >= len || p[i] != ':')
			return -1;
		vstart = skip_ws(p, len, i + 1);
		vend = value_end(p, len, vstart, 1);
		if (vend == 0)
			return -1;
		if (kend - kstart == klen + 2 &&
		    !memcmp(p + kstart + 1, key, klen)) {
			/* A duplicate key makes the document ambiguous. */
			if (found)
				return -1;
			found = 1;
			out->p = p + vstart;
			out->len = vend - vstart;
		}
		i = skip_ws(p, len, vend);
		if (i < len && p[i] == ',') {
			i = skip_ws(p, len, i + 1);
			continue;
		}
		if (i < len && p[i] == '}')
			return found ? 0 : -1;
		return -1;
	}
}

int nfsp_json_str(struct nfsp_jval v, char *out, size_t cap)
{
	if (v.len < 2 || v.p[0] != '"' || v.p[v.len - 1] != '"' ||
	    v.len - 2 >= cap || memchr(v.p, '\\', v.len) != NULL)
		return -1;
	memcpy(out, v.p + 1, v.len - 2);
	out[v.len - 2] = '\0';
	return 0;
}

int nfsp_json_str_eq(struct nfsp_jval v, const char *s)
{
	size_t n = strlen(s);

	if (v.len != n + 2 || v.p[0] != '"' || v.p[v.len - 1] != '"' ||
	    memchr(v.p, '\\', v.len) != NULL)
		return -1;
	return memcmp(v.p + 1, s, n) == 0 ? 0 : -1;
}

int nfsp_json_u64(struct nfsp_jval v, uint64_t *out)
{
	uint64_t n = 0;

	if (v.len == 0 || v.len > 20 || (v.p[0] == '0' && v.len > 1))
		return -1;
	for (size_t i = 0; i < v.len; i++) {
		unsigned d;

		if (v.p[i] < '0' || v.p[i] > '9')
			return -1;
		d = (unsigned)(v.p[i] - '0');
		if (n > (UINT64_MAX - d) / 10u)
			return -1;
		n = n * 10u + d;
	}
	*out = n;
	return 0;
}

int nfsp_json_is_null(struct nfsp_jval v)
{
	return v.len == 4 && !memcmp(v.p, "null", 4);
}
