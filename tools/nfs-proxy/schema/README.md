# ProtocolSchema normalizer

`normalize.py` turns pinned XDR source plus a small annotation file into the
constant C tables that the proxy's NFS Semantic Decoder (`../src/nfs_decode.c`)
interprets. It runs at build/development time only. The proxy never parses XDR.
Design: [02-semantic-decoder.md](../../../docs/design/03-nfs-proxy/02-semantic-decoder.md) §2–§4.

```sh
schema/normalize.py ANN --out FILE.c     # write the tables
schema/normalize.py ANN --check FILE.c   # fail if FILE.c is stale (build.sh does this)
schema/normalize.py ANN --json           # print the normalized schemas
python3 schema/test_normalize.py         # normalizer tests (build.sh runs them)
```

The generated `.c` files are committed, so the C build and the guest build
container need no Python. `build.sh` regenerates every table listed in its
`SCHEMAS` variable and fails if a committed table differs.

## What comes from where

| Fact | Owner |
|---|---|
| field order, widths, union arms, bounds, padding | XDR source only |
| family name, program/version to expose, procedure-name prefix | annotation |
| which unions are COMPOUND operation boundaries | annotation |
| short branch names for union case labels | annotation |
| every other path component | XDR identifiers |

The annotation file never repeats a field, an offset or a width.

## Annotation grammar

One directive per line, `#` starts a comment.

| Directive | Meaning |
|---|---|
| `family NAME` | path prefix, `[a-z][a-z0-9]*` (`nfs4`, `nfs3`) |
| `program PROG VERS` | XDR `program` and `version` identifiers to expose |
| `procedure-prefix P` | stripped from procedure names (`NFSPROC4_COMPOUND` → `COMPOUND`) |
| `leaf REQ RES` | path word after a procedure name; default `args result` |
| `operation DIR UNION LEAF PREFIX` | `UNION` is the COMPOUND op for `DIR` (`request`/`response`); its arms become path roots `<family>.<DIR>.<OP>`, the arm value `.LEAF`, `PREFIX` is stripped from case labels |
| `status-type ENUM` | the enum whose value at the start of a response operation is its status |
| `source FILE` | the single XDR file, for a family without minor versions |
| `minor N FILE` | one XDR file per minor version |
| `minor-field STRUCT FIELD` | the CALL argument member that carries the minor version |
| `branch LABEL NAME` | path branch for every union case labelled `LABEL` |

## Path rules

| XDR node | Path |
|---|---|
| struct member | `<parent>.<member>` |
| union discriminant | `<union>.<discriminant>` |
| union arm whose type is a struct | `<union>.<branch>` (members spliced in) |
| any other union arm | `<union>.<branch>.<arm name>` |
| array or linked-list element | `<array>[]`, element index is metadata |
| procedure argument / result | `<family>.request.<PROC>.args` / `<family>.response.<PROC>.result` |
| COMPOUND operation | `<family>.<direction>.<OP>`, its arm `.args` / `.result` |

A branch is the annotation's name for the case label, otherwise the lowercased
label (`TK_LINK` → `tk_link`); a `default:` arm is `default`.

## What the normalizer refuses

Each of these is a build error, because the runtime could only handle it by
guessing: `float`/`double`/`quadruple`; type cycles other than the XDR linked
list `struct T { ...; T *next; }`; optional-data (`T *x`) that is not such a
list, `opaque *x` and `string *x` included; arrays of zero-size elements;
union case values outside the discriminant's type; duplicate case values; more
union arms than a 16-bit arm index holds; a smallest encoding longer than
32 bits; nesting deeper than `NFSP_DECODE_MAX_DEPTH`; minor versions that
disagree on the layout before the minor-version field; a `branch` annotation
that names nothing reachable.

A semantic path names one position in the schema (array and list elements
and repeated operations repeat it), so these are build errors too:
duplicate struct member names or procedure names; a union arm whose branch
repeats the discriminant's name; two different arms of one union with the same
branch; one union named as the operation of both directions; an operation
leaf that repeats the operation discriminant's name; an operation or procedure
whose name is only its prefix, or an operation named like a procedure; a
leaf, in `leaf` or `operation`, that is not an identifier.

The parser reads every declaration in a source file, so a syntax error,
`float`/`double`/`quadruple`, a multi-argument procedure, or a duplicate
member or procedure name fails the build wherever it appears. The other
checks only see declarations an exposed procedure reaches; everything else is
dropped and does not change the tables.

## schema_id

`<family>[.<minor>]/sha256:<hex>`, the SHA-256 of the canonical JSON of one
normalized schema (types, procedures, path names, selector). It changes when
decode behaviour or a semantic path can change. It does not change for an XDR
comment. The source file's own SHA-256 is recorded separately in the
generated file's header.

## Schemas in this repository

| Annotation | Table | Status |
|---|---|---|
| `../test/schema/tproto.ann` | `../test/schema_tproto.c` | synthetic, host tests only |
| `../test/schema/tflat.ann` | `../test/schema_tflat.c` | synthetic, host tests only |

The NFSv4.0/4.1/4.2 schemas come from the XDR in RFC 7531, RFC 5662 and
RFC 7863 and will be added with those pinned sources. NFSv3 follows. Until then
an NFS message is `unsupported_schema`.
