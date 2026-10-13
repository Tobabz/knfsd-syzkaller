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
| names the XDR uses but takes from rpcgen's C environment | prelude, built from pinned RFC text |
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
| `prelude FILE` | XDR read before every source file, into the same namespace; a name defined in both is an error |
| `notice TEXT` | one line copied into the generated file's header, for a license notice the sources require |
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
list; arrays of zero-size elements; union case values outside the
discriminant's type; duplicate case values; nesting deeper than
`NFSP_DECODE_MAX_DEPTH`; minor versions that disagree on the layout before the
minor-version field; a `branch` annotation that names nothing reachable.

Declarations that no exposed procedure reaches are dropped, so they neither
need to be supported nor change the tables.

## schema_id

`<family>[.<minor>]/sha256:<hex>`, the SHA-256 of the canonical JSON of one
normalized schema (types, procedures, path names, selector). It changes when
decode behaviour or a semantic path can change. It does not change for an XDR
comment. The source file's own SHA-256 is recorded separately in the
generated file's header.

## Pinned RFC sources

No XDR file here is written by hand. `rfc_xdr.py` builds every file listed in
a `SOURCES` manifest from RFC plain text whose SHA-256 the manifest pins:

```sh
schema/rfc_xdr.py schema/nfs4/SOURCES --check    # files match their pins (build.sh)
schema/rfc_xdr.py schema/nfs4/SOURCES --verify   # fetch the RFCs, rebuild, compare
python3 schema/test_rfc_xdr.py                   # its tests (build.sh runs them)
```

- `extract`: the file is the output of the RFC's own `///` extraction script,
  run with `sh` under `LC_ALL=C` on the RFC text. The script string must be a
  line of that RFC, so it cannot drift from what the RFC prints.
- `prelude`: what the XDR uses without declaring it, because rpcgen takes it
  from the C environment. `typedefs` copies the basic typedefs every NFSv4
  file states only in a comment (the files must agree); `copy` copies one
  `KEYWORD NAME { ... };` definition from an RFC, which must occur once and not
  cross a page break. For NFSv4 that is RFC 5531's `auth_flavor` (the
  `AUTH_NONE`, `AUTH_SYS`, `RPCSEC_GSS` case labels) and `authsys_parms`.
- No errata are applied. `SOURCES` records which errata existed when the pins
  were taken and why none was applied.

`--verify` and `--write` need the network (or `--rfc-dir` with the RFC texts).
The RFC texts are not committed; their pins are enough to fetch and check them.

## Schemas in this repository

| Annotation | Table | Source | Status |
|---|---|---|---|
| `nfs4/nfs4.ann` | `../src/schema_nfs4.c` | RFC 7531 (4.0), RFC 5662 (4.1), RFC 7863 (4.2) | NFSv4 COMPOUND, CALL and REPLY |
| `../test/schema/tproto.ann` | `../test/schema_tproto.c` | written for the tests | synthetic, host tests only |
| `../test/schema/tflat.ann` | `../test/schema_tflat.c` | written for the tests | synthetic, host tests only |

NFSv3 has no schema yet (RFC 1813 has no extractable XDR file), so an NFSv3
message is `unsupported_schema`. NFSv4.2 is RFC 7863 as published: later
extensions such as the RFC 8276 xattr operations or the RFC 9754 delegation
types are undeclared there, so a message that uses them is `malformed`.
