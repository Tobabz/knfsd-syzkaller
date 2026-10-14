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
| `extension N FILE` | an NFSv4 extension (RFC 8178) applied after minor `N`'s source: new definitions join the namespace, an enum restated with more values widens it (every value the source declared must stay; several restatements add up, whatever their order, and one value with two names is an error), and the RFC's own `/* Following lines are to be added to [enum\|union] NAME */` blocks add their lines to `NAME`; nothing else may change an existing definition |
| `alias-arm UNION LABEL LIKE` | a case value the XDR declares with no arm in `UNION` is decoded with `LIKE`'s arm. The only layout fact an annotation may state; each use names the implementation it follows. A `LABEL` that already has an arm, a `LIKE` with none, or an alias used in no minor version is an error |
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
list, `opaque *x` and `string *x` included; arrays of zero-size elements;
union case values outside the discriminant's type; duplicate case values; more
union arms than a 16-bit arm index holds; a smallest encoding longer than
32 bits; nesting deeper than `NFSP_DECODE_MAX_DEPTH`; minor versions that
disagree on the layout before the minor-version field (compared by wire layout
only: member names, and whether two members share one type or use two equal
ones, do not count); a `branch` annotation
that names nothing reachable.

A semantic path names one position in the schema (array and list elements
and repeated operations repeat it), so these are build errors too:
duplicate struct member names or procedure names; a union arm whose branch
repeats the discriminant's name; two different arms of one union with the same
branch; one union named as the operation of both directions; an operation
union reached in the other direction's message (a response operation inside
a CALL argument, or the reverse); an operation
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
- `fragment`: a file of `copy` lines, for a definition an RFC states in its
  prose but not in its `///` XDR. RFC 8435 (flex files) and RFC 8154 (SCSI)
  restate `layouttype4` that way, each with its own new value; each fragment
  is an `extension` of minors 1 and 2.
- No errata are applied. `SOURCES` records which errata existed when the pins
  were taken and why none was applied.

`--verify` and `--write` need the network (or `--rfc-dir` with the RFC texts).
The RFC texts are not committed; their pins are enough to fetch and check them.

## Schemas in this repository

| Annotation | Table | Source | Status |
|---|---|---|---|
| `nfs4/nfs4.ann` | `../src/schema_nfs4.c` | RFC 7531 (4.0), RFC 5662 + RFC 8435 + RFC 8154 (4.1), RFC 7863 + RFC 8276 + RFC 9754 + RFC 8435 + RFC 8154 (4.2) | NFSv4 COMPOUND, CALL and REPLY |
| `../test/schema/tproto.ann` | `../test/schema_tproto.c` | written for the tests | synthetic, host tests only |
| `../test/schema/tflat.ann` | `../test/schema_tflat.c` | written for the tests | synthetic, host tests only |
| `../test/schema/tedge.ann` | `../test/schema_tedge.c` | written for the tests | synthetic, host tests only: operation unions outside an operation array |

NFSv3 has no schema yet (RFC 1813 has no extractable XDR file), so an NFSv3
message is `unsupported_schema`. NFSv4.2 is RFC 7863 plus the extensions knfsd
implements: the RFC 8276 xattr operations and the RFC 9754 attribute
delegation types. RFC 9754 declares delegation types 4 and 5 but no
`open_delegation4` arm for them; `nfs4.ann` aliases them to the READ and WRITE
arms, as knfsd encodes them (`nfsd4_encode_open_delegation4`). NFSv4.1 and
NFSv4.2 also have the pNFS layout types knfsd implements beyond RFC 5662:
flex files (4, RFC 8435) and SCSI (5, RFC 8154); the layout bodies stay
opaque. Any other extension is undeclared.

Errata: an erratum is applied only when it is Verified and changes the XDR;
`SOURCES` records the errata of every pinned RFC and the decision.
