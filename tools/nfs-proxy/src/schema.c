/* ProtocolSchema lookups.  The tables themselves are generated; see schema.h. */
#include "schema.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

const struct nfsp_schema_proc *
nfsp_schema_proc(const struct nfsp_protocol_schema *s, uint32_t number)
{
	for (uint32_t i = 0; i < s->nprocs; i++)
		if (s->procs[i].number == number)
			return &s->procs[i];
	return NULL;
}

const struct nfsp_protocol_schema *
nfsp_schema_minor(const struct nfsp_schema_family *f, uint32_t minor)
{
	for (uint32_t i = 0; i < f->nschemas; i++)
		if (f->schemas[i]->has_minor && f->schemas[i]->minor == minor)
			return f->schemas[i];
	return NULL;
}

const char *nfsp_schema_enum_name(const struct nfsp_protocol_schema *s,
				  uint16_t type, uint32_t value)
{
	const struct nfsp_schema_type *t;

	if (type >= s->ntypes)
		return NULL;
	t = &s->types[type];
	if (t->kind != NFSP_XK_ENUM)
		return NULL;
	for (uint32_t i = 0; i < t->count; i++)
		if (s->enums[t->first + i].value == value)
			return s->enums[t->first + i].name;
	return NULL;
}

int nfsp_schema_enum_has(const struct nfsp_protocol_schema *s, uint16_t type,
			 uint32_t value)
{
	const struct nfsp_schema_type *t;

	if (type >= s->ntypes || s->types[type].kind != NFSP_XK_ENUM)
		return 0;
	t = &s->types[type];
	for (uint32_t i = 0; i < t->count; i++)
		if (s->enums[t->first + i].value == value)
			return 1;
	return 0;
}

/* A walk consumes at least one path byte per step, so the path bounds it;
 * this bounds it again whatever the table says. */
#define WALK_MAX	(2u * 64u + 4u)

struct walk {
	const struct nfsp_protocol_schema *s;
	uint8_t mine;		/* NFSP_STF_OPS_* of this direction */
	struct nfsp_schema_node found;
	unsigned nfound;
	int ambiguous;
};

static int is_ops_union(const struct nfsp_schema_type *ty)
{
	return ty->kind == NFSP_XK_UNION &&
	       (ty->flags & (NFSP_STF_OPS_REQUEST | NFSP_STF_OPS_RESPONSE));
}

/* Does p start with component c, as nfsp_field_path() writes it (".c", or
 * "[]" for an element), ending where the next component may start?  Arm
 * components may hold a dot ("claim_null.file"), so the end is checked, not
 * assumed. */
static int component_at(const char *p, const char *c, const char **rest)
{
	size_t n;

	if (!c)
		return 0;
	if (!strcmp(c, "[]")) {
		if (p[0] != '[' || p[1] != ']')
			return 0;
		*rest = p + 2;
		return 1;
	}
	n = strlen(c);
	if (p[0] != '.' || strncmp(p + 1, c, n))
		return 0;
	p += 1 + n;
	if (*p && *p != '.' && *p != '[')
		return 0;
	*rest = p;
	return 1;
}

static void hit(struct walk *w, const struct nfsp_schema_node *n)
{
	if (w->nfound && (w->found.type != n->type ||
			  w->found.flags != n->flags ||
			  w->found.root_type != n->root_type ||
			  w->found.proc != n->proc ||
			  strcmp(w->found.root, n->root)))
		w->ambiguous = 1;
	if (!w->nfound)
		w->found = *n;
	w->nfound++;
}

static void walk(struct walk *w, const struct nfsp_schema_node *at,
		 const char *p, unsigned depth)
{
	const struct nfsp_protocol_schema *s = w->s;
	const struct nfsp_schema_type *ty;
	struct nfsp_schema_node child = *at;
	uint8_t inherit = at->flags & (NFSP_SN_OPERATION | NFSP_SN_REPEATED);
	const char *rest;

	if (at->type >= s->ntypes || depth > WALK_MAX)
		return;
	ty = &s->types[at->type];
	if (!*p) {
		child.flags = at->flags;
		if ((ty->kind == NFSP_XK_ARRAY_FIXED ||
		     ty->kind == NFSP_XK_ARRAY_VAR) && ty->sub < s->ntypes &&
		    is_ops_union(&s->types[ty->sub]) &&
		    (s->types[ty->sub].flags & w->mine))
			child.flags |= NFSP_SN_OPS_ARRAY;
		hit(w, &child);
		return;
	}
	switch (ty->kind) {
	case NFSP_XK_STRUCT:
		for (uint32_t k = 0; k < ty->count; k++) {
			const struct nfsp_schema_field *f =
				&s->fields[ty->first + k];

			if (!component_at(p, f->name, &rest))
				continue;
			child.type = f->type;
			child.flags = inherit;
			walk(w, &child, rest, depth + 1);
		}
		break;
	case NFSP_XK_UNION:
		/* An operation is reached only as a root; an operation union
		 * of the other direction is never decoded. */
		if (is_ops_union(ty))
			break;
		if (component_at(p, ty->disc_name, &rest)) {
			child.type = ty->sub;
			child.flags = inherit | NFSP_SN_DISCRIMINANT;
			walk(w, &child, rest, depth + 1);
		}
		for (uint32_t k = 0; k < ty->count; k++) {
			const struct nfsp_schema_arm *a = &s->arms[ty->first + k];

			if (a->type == NFSP_SCHEMA_NONE ||
			    !component_at(p, a->component, &rest))
				continue;
			child.type = a->type;
			child.flags = inherit;
			walk(w, &child, rest, depth + 1);
		}
		break;
	case NFSP_XK_ARRAY_FIXED:
	case NFSP_XK_ARRAY_VAR:
		if (ty->sub >= s->ntypes || is_ops_union(&s->types[ty->sub]) ||
		    !component_at(p, "[]", &rest))
			break;
		child.type = ty->sub;
		child.flags = inherit | NFSP_SN_REPEATED;
		walk(w, &child, rest, depth + 1);
		break;
	case NFSP_XK_LIST:
		if (!component_at(p, "[]", &rest))
			break;
		child.type = ty->sub;
		child.flags = inherit | NFSP_SN_REPEATED | NFSP_SN_LIST_ELEMENT;
		walk(w, &child, rest, depth + 1);
		break;
	default:
		break;
	}
}

enum nfsp_schema_resolve
nfsp_schema_resolve(const struct nfsp_protocol_schema *s, int response,
		    const char *path, struct nfsp_schema_node *out)
{
	const char *dir = response ? ".response." : ".request.";
	const char *leaf = response ? s->response_leaf : s->request_leaf;
	struct walk w;
	const char *p, *rest;
	size_t n;

	memset(&w, 0, sizeof(w));
	w.s = s;
	w.mine = response ? NFSP_STF_OPS_RESPONSE : NFSP_STF_OPS_REQUEST;
	if (!path || !s->family)
		return NFSP_SCHEMA_NOT_FOUND;
	n = strlen(s->family);
	if (strncmp(path, s->family, n) ||
	    strncmp(path + n, dir, strlen(dir)))
		return NFSP_SCHEMA_NOT_FOUND;
	p = path + n + strlen(dir);

	/* <PROC>.<leaf>...: the procedure's argument or result. */
	for (uint32_t i = 0; i < s->nprocs; i++) {
		const struct nfsp_schema_proc *pr = &s->procs[i];
		uint16_t rt = response ? pr->res : pr->arg;
		struct nfsp_schema_node at;

		n = strlen(pr->name);
		if (rt == NFSP_SCHEMA_NONE || strncmp(p, pr->name, n) ||
		    !component_at(p + n, leaf, &rest))
			continue;
		memset(&at, 0, sizeof(at));
		at.type = rt;
		at.flags = NFSP_SN_ROOT;
		at.root = pr->name;
		at.root_type = rt;
		at.proc = pr;
		walk(&w, &at, rest, 0);
	}

	/* <OP>...: an operation of this direction, its opcode and its arm. */
	for (uint32_t t = 0; t < s->ntypes; t++) {
		const struct nfsp_schema_type *ty = &s->types[t];

		if (!is_ops_union(ty) || !(ty->flags & w.mine))
			continue;
		for (uint32_t k = 0; k < ty->count; k++) {
			const struct nfsp_schema_arm *a = &s->arms[ty->first + k];
			struct nfsp_schema_node at;
			const char *q;

			n = a->branch ? strlen(a->branch) : 0;
			if (!n || strncmp(p, a->branch, n))
				continue;
			q = p + n;
			memset(&at, 0, sizeof(at));
			at.root = a->branch;
			at.root_type = (uint16_t)t;
			if (!*q) {
				at.type = (uint16_t)t;
				at.flags = NFSP_SN_ROOT | NFSP_SN_OPERATION;
				hit(&w, &at);
				continue;
			}
			if (component_at(q, ty->disc_name, &rest)) {
				at.type = ty->sub;
				at.flags = NFSP_SN_OPERATION |
					   NFSP_SN_DISCRIMINANT;
				walk(&w, &at, rest, 0);
			}
			if (a->type != NFSP_SCHEMA_NONE &&
			    component_at(q, a->component, &rest)) {
				at.type = a->type;
				at.flags = NFSP_SN_OPERATION;
				walk(&w, &at, rest, 0);
			}
		}
	}

	if (w.ambiguous)
		return NFSP_SCHEMA_AMBIGUOUS;
	if (!w.nfound)
		return NFSP_SCHEMA_NOT_FOUND;
	*out = w.found;
	return NFSP_SCHEMA_FOUND;
}

int nfsp_schema_reaches(const struct nfsp_protocol_schema *s, uint16_t from,
			uint16_t to)
{
	uint16_t *stack;
	uint8_t *seen;
	uint32_t top = 0;
	int found = 0;

	if (from >= s->ntypes || to >= s->ntypes)
		return 0;
	stack = malloc((size_t)s->ntypes * sizeof(*stack));
	seen = calloc(s->ntypes, 1);
	if (!stack || !seen) {
		free(stack);
		free(seen);
		return -1;
	}
	stack[top++] = from;
	seen[from] = 1;
	while (top && !found) {
		const struct nfsp_schema_type *ty = &s->types[stack[--top]];
		uint16_t next[2] = { NFSP_SCHEMA_NONE, NFSP_SCHEMA_NONE };
		uint32_t nn = 0;

		/* Every edge the decoder follows: members, discriminant and
		 * arms, element. */
		for (uint32_t k = 0; ty->kind == NFSP_XK_STRUCT && k < ty->count;
		     k++) {
			uint16_t c = s->fields[ty->first + k].type;

			if (c < s->ntypes && !seen[c]) {
				seen[c] = 1;
				stack[top++] = c;
			}
		}
		for (uint32_t k = 0; ty->kind == NFSP_XK_UNION && k < ty->count;
		     k++) {
			uint16_t c = s->arms[ty->first + k].type;

			if (c < s->ntypes && !seen[c]) {
				seen[c] = 1;
				stack[top++] = c;
			}
		}
		if (ty->kind == NFSP_XK_UNION || ty->kind == NFSP_XK_ARRAY_FIXED ||
		    ty->kind == NFSP_XK_ARRAY_VAR || ty->kind == NFSP_XK_LIST)
			next[nn++] = ty->sub;
		for (uint32_t k = 0; k < nn; k++)
			if (next[k] < s->ntypes && !seen[next[k]]) {
				seen[next[k]] = 1;
				stack[top++] = next[k];
			}
		found = seen[to];
	}
	free(stack);
	free(seen);
	return found;
}
