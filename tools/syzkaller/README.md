# Pinned syzkaller parser and call-table exporter

This is a host parser adapter for `agent_pipeline.materializer.PinnedSyzParser`.
It uses the real `prog.GetTarget("linux", "amd64")` generated target and
`target.Deserialize(data, prog.Strict)` from the exact repository pin and patch
series. It never executes a program or infers calls from source text. No new
syzkaller patch is needed: the public `prog` API exposes the required data.

## Build and test

Use Python with this repository's Pydantic dependency and Go **1.26.0** (the
version in the pinned syzkaller `go.mod`). Supply a local Git repository that
contains the `syzkaller_commit` in `bundle/patches/BASE`:

```sh
python tools/syzkaller/build.py \
  --source /path/to/syzkaller-git \
  --output /tmp/new-syz-parser-build \
  --go /path/to/go1.26.0/bin/go

KNFSD_SYZ_BUNDLE=/tmp/new-syz-parser-build/bundle \
  python -m pytest -q tests/agent_pipeline/syzkaller
```

The builder creates a fresh checkout, checks out BASE, reapplies **all** patches
in the checked-in `series` and filename order, and regenerates descriptions with
`sys/syz-sysgen`. It builds and tests the bridge inside that module, so its
dependencies are the pinned `go.mod`/`go.sum`. The source repository is read-only;
the checkout and Go compilation cache are under the new output directory.
The normal Go module cache is used for dependency downloads. Network access is
needed only for dependencies missing from that cache. Existing output directories
are refused, including partial builds; choose a new output to retry.

The builder runs the real Go integration tests and a Python export/parse smoke
test. Python integration tests skip when `KNFSD_SYZ_BUNDLE` is absent; setting it
to a broken bundle fails the tests. The tests cover actual disabled and unknown
calls, malformed programs, changed identity axes and build bytes, sealed binary
replacement, stream/time limits, large allocations, and conservative NFS facts.

## Authority and artifact identity

The output `bundle/` contains:

| Artifact | Meaning |
|---|---|
| `bridge` | Static Linux amd64 ELF linked to the regenerated target |
| `target.gob.flate` | Copy of the generated linux/amd64 description embedded in the bridge |
| `go.mod`, `go.sum`, `provenance.json` | Dependency pin, upstream/applied commit, tree, toolchain and bridge source digests |
| `build-manifest.json` | Existing `SyzkallerBuildManifest` over the files above |
| `call-table.json` | Existing `SyzkallerCallTable`, exported from **every actual** `Target.Syscalls` entry, sorted uniquely |
| `patch-series.bin` | Exact filename + NUL + patch bytes + NUL inventory in apply order |
| `identity.json` | Existing `SyzkallerTargetIdentity`, for host review/approval |

`patch-series.bin` hashes to the existing bootstrap `series_fingerprint` value.
It is the `patch_series` input to `inspect_pinned_syzkaller`, **not** the textual
filename-only `series` file. The identity's `syzkaller_commit` is the **applied
HEAD**, which the existing admission generator checks against the clean checkout.
`provenance.json` separately records upstream BASE. The builder fixes committer
name/email and uses patch author dates to make the applied HEAD reproducible.
Generated files are Git-ignored by upstream; the inspector still requires a clean
checkout. The bridge source and generated table are bound through artifact hashes.

This manifest identifies a **parser bundle**. It does not contain `syz-executor`,
an execution engine, VM images, kernel or an `ExecutionHarnessApproval`. A host
must separately approve an `ExecutionHarnessDescriptor` with the matching
syzkaller source/patch/target and actual execution artifacts. Parser provenance
does not prove that an unrelated executor build matches or that a guest supports
the calls. The present build output must not be advertised as a complete
production NFS harness. Promotion and runtime capability validation remain
separate gates.

Use a **host-trusted expected identity**; an adjacent `identity.json` does not
authorize itself. Given that identity, the adapter verifies the manifest, all
listed artifact digests, compiled source/patch/target metadata, and the exported
call table. Table presence means name resolution, not admission or availability:
disabled calls occur in the export, but strict parsing rejects them. Kernel/VM
availability remains the responsibility of the approved HCAP/admission profile.

## Python API

```python
from pathlib import Path
from agent_pipeline.syzkaller import BridgeLimits, PinnedSyzParser

# trusted_identity comes from the host-approved execution authority.
with PinnedSyzParser(Path("/tmp/new-syz-parser-build/bundle"),
                     identity=trusted_identity,
                     limits=BridgeLimits()) as parser:
    table = parser.export_call_table()  # SyzkallerCallTable
    result = parser.parse(program_bytes, identity=trusted_identity)  # ParsedProgram
    # The same parser can be passed to the existing Materializer constructor.
```

Close the parser when done. A constructed instance executes its sealed `memfd`
snapshot using `/proc/self/fd`, so replacing the path after verification cannot
replace the running parser. A new instance detects changed bytes. Only regular
files are read; symlink components within bundle file paths are refused. The
adapter bounds file sizes (128 MiB each, 256 MiB total), metadata, program input
(256 KiB), stdout (16 MiB), stderr (64 KiB), and wall time (10 seconds). Optional
`BridgeLimits` can lower byte limits or set wall time up to 60 seconds. Both pipes
are drained and limited while the helper runs; failures kill and reap its process
group. The helper receives a minimal environment, caps address space at **2 GiB**
and CPU at 20 seconds, and sets a 256 MiB Go GC memory target. The hard address
limit protects against short programs requesting many large DataArgs. Linux
memfd/sealing support is required; there is no unsealed fallback.

## Supported facts and conservative refusals

Facts come from parsed `prog.Arg` values; program comments, labels, annotations,
and call-name suffixes alone confer no origin. The original program byte digest
is retained. `prog.Strict` validates and sanitizes without non-strict repairs;
its explicit valid `AUTO` syntax remains part of the pinned parser semantics.

* **Integers:** direct input Const/Int/Flags/Len arguments, native format, no
  bitfield, and values representable identically by signed and unsigned types of
  that width. Signedness-ambiguous, truncated, checksum, per-process and resource
  operands have no integer fact.
* **Byte lengths:** actual `DataArg.Size()` for a direct pointer-to-buffer operand,
  including output buffers. This is the declared concrete buffer extent, not a
  neighboring count argument, arbitrary aggregate allocation or runtime write
  length. Struct/union/array pointers and null pointers have no byte-length fact.
* **Resource usage:** original byte length and parsed call count; `resource_count`
  counts every ResultArg (including returned resources, references and constants),
  PointerArg and DataArg node. This deliberately conservative **syntax budget**
  includes buffers/pointers and repeated references; it is not a live-FD estimate.
  The bridge also enforces 4,096 calls and 65,536 such resource nodes.
* **NFS acquisitions:** only the ten explicit
  `syz_open_nfs_lane_profile$client{0,1}_{knfsd_v3,knfsd_v40,knfsd_v41,knfsd_v42,ganesha_v41}`
  variants. The actual `ConstArg` values, generated `ConstType` values, full
  variant name and `fd_nfs_dir` return type must agree. Both profile and client
  are retained in origin labels, e.g. `nfs-profile:knfsd-v41:client0`. These
  labels must be explicitly admitted by the host's authority mapping; synthetic
  test labels such as `lane-root` are not aliases. Duplicate acquisition facts
  are deduplicated and sorted; different profiles are all reported so Materializer
  can reject mixed runtime selections. Recognizing experimental profile calls
  is static extraction, **not validation or HCAP promotion**.
* **FD origins:** only an untransformed direct reference to a verified acquisition
  result, with a generated FD resource type. `r0+N` / `r0/N`, literals, nested
  memory resources, dup/fcntl-derived FDs, and `openat` return values have no
  origin. An explicit close invalidates that root; unknown FD effects invalidate
  all roots. A small allowlist of ordinary IO/metadata calls (listed in
  `preservesRoots` in `facts.go`) preserves existing roots. Opening a filename
  does not prove it stays on NFS: symlink/mount traversal is runtime state.
* **Unsupported:** path/socket/buffer origins; legacy lane/pair and raw NFS socket
  acquisitions whose protocol profile cannot be proved; asynchronous, rerun and
  fault-injected call properties. Unverified NFS acquisitions reject the entire
  program, so they cannot be hidden alongside one valid acquisition. Other
  unavailable facts are omitted; existing admission constraints then fail closed.

This first slice supports acquisition plus direct-root FD plans. It intentionally
does not establish descendant-file provenance for the full normal-flow corpus.
Generic parsable programs can have empty `nfs_acquisitions`; Materializer refuses
them when it requires an NFS profile acquisition.

## Typed refusals

Three refusals name the offending call so Planning repair can see what to
change. The bridge exits with status 3 and writes one JSON object
`{"reason", "call_index", "call"}` to stderr; the adapter raises
`SyzParseFailure` with those fields, and Materializer maps them:

| Bridge reason | Materializer reason | Detail |
|---|---|---|
| `call_unresolved` (not in the pinned target) | `call_unresolved` | `scenario:<index>:<call>` |
| `call_disabled` (in the target, disabled) | `disallowed_or_unavailable_call` | `scenario:<index>:<call>:disabled` |
| `nfs_acquisition_unverified` | `profile_fixture_route_mismatch` | `scenario:<index>:<call>:nfs_acquisition_unverified` |

(`neutral:` replaces `scenario:` for the neutral control.) The index counts
call lines, skipping blank and comment lines. The adapter checks the reason, a
bounded call name, and that only an unresolved call is absent from the call
table; anything else stays an untyped `parse_failure`, as do all other strict
parse errors.
