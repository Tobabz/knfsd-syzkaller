/* ProtocolSchema lookups.  The tables themselves are generated; see schema.h. */
#include "schema.h"

#include <stddef.h>

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
