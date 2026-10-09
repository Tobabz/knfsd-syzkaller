# knfsd-syzkaller

A tool that builds **customized syzkaller fuzzing environments for fuzzing the NFS subsystem of the Linux kernel (knfsd)**.
It reflects a **remote KCOV coverage model** — collecting NFS server-side coverage remotely — on a kernel instrumented with KCOV and either KASAN (memory safety) or KCSAN (data races),
and automates the whole pipeline from base image to a bootable fuzz VM (instrumented kernels + syzkaller binaries +
one baked protocol image).

The checked-in [kernel](bundle/patches/kernel/series) and [syzkaller](bundle/patches/syzkaller/series) patch series are applied by
`tools/fport-apply.sh` during bootstrap. By default, bootstrap boots each selected kernel variant with the baked image and checks that the NFS lane fixture
comes up and that the kernel carries the expected sanitizer. `--skip-verify` omits this final verification.

## Design highlights

| Aspect | Description |
|---|---|
| Instrumentation | KCOV + KASAN/KCSAN boot kernels, built **out of tree** from one patched source tree |
| Mutation Engine | A [Mutation Engine specialized for NFS](tools/nfs-proxy/README.md), implemented as a proxy between clients and servers. It applies mutation rules supplied by syzkaller programs to NFS RPC/XDR traffic |
| Coverage model | **Remote KCOV** — instrumented knfsd and SUNRPC paths feed `experimental.remote_cover`. Request ownership is lane-scoped (kernel 0002); asynchronous COPY carries that ownership (0003), and server callbacks retain the originating program's ownership (0004). See the [callback attribution contract and limits](docs/design/decisions/2026-10-05-callback-attribution.md) |
| Fuzz lanes | One NFS lane per executor proc (knfsd and Ganesha backends plus two client mount namespaces, `/nfs-lane`); the boot fixture provides 4 lanes, so run syz-manager with `procs` equal to the lane count and top-level `snapshot` off. Lanes exist for parallel fuzzing inside one VM |
| NFS version | `koov.nfs_version=3\|4.0\|4.1\|4.2` in `vm.cmdline` selects one mount version for both backends at boot |
| Boot model | One version-neutral image serves both sanitizer kernels; the lane script is copied from a read-only host 9P share at each VM boot |
| Seeds | [Normal-flow corpus](bundle/corpus/nfs-normal/README.md) — TCP programs and a manifest recording their versions, backends and execution status; use the patched syzkaller binaries built by bootstrap |

The image uses `bundle/lane/lane.sh` for all four NFS versions. Its default `SERVER_IMPL=both`
routes both clients through the Mutation Engine; `nfs-lane/client0` and `client1` select the same knfsd
export. Explicit `client{0,1}-ganesha` paths select the separate Ganesha export.
Both backends use the selected version. The lane exports a bounded ext4
loop image through [Ganesha V15.6](https://github.com/nfs-ganesha/nfs-ganesha/releases/tag/V15.6)
FSAL_VFS; knfsd keeps its tmpfs.
NFSv3 uses pinned TCP MOUNT ports
and `nolock`; cross-client NLM locking is not part of this fixture. Build and
guest-check commands are in
[tools/README.md](tools/README.md).

The reusable image is `env/images/bookworm-kcov-fresh.qcow2`. Prepare each manager config
with the helper in step 3 to supply the required host lane script.
Use separate manager configs, workdirs and corpora for each backend, running one backend
at a time. Seed selection is described in the [corpus guide](bundle/corpus/nfs-normal/README.md).

The corpus covers normal NFS scenarios. [tools/flow-trace/](tools/flow-trace/README.md)
provides kernel event collection and thread-transition analysis.
Lane setup enables NFSD trace events in the guest so their generated callbacks can
contribute to existing remote KCOV sections. Keep `experimental.remote_cover=true`
for knfsd campaigns.

## Host requirements

Prepare the host using [tools/tool-requirements.txt](tools/tool-requirements.txt).
Python requirements are declared in [pyproject.toml](pyproject.toml), with the default interpreter
selected by [.python-version](.python-version) and dependencies resolved in [uv.lock](uv.lock).
From the repository root, prepare the Python environment:

```sh
uv sync --locked
```

Run the Python tools with `uv run python ...`. Shell wrappers that invoke Python can also run
under `uv run`, so their child processes use the project environment.

## Usage — commands, inputs, outputs

### 1. Create the base image (once per site)

```sh
sudo bash tools/make-base-image.sh --out artifacts
```

- **Input**: host root (sudo) + debootstrap + network (runs `create-image.sh -d bookworm` from the pinned syzkaller tree)
- **Output**: `artifacts/bookworm-base.img` (2 GiB raw ext4, kernel not included) and `artifacts/bookworm.id_rsa[.pub]` (SSH keypair, `.id_rsa` mode 0600; handed back to the invoking user when run through `sudo`, because bootstrap must be able to read the key)

### 1b. Build the lane deps (Ganesha + Mutation Engine)

The lane fixture starts knfsd, NFS-Ganesha and the NFS-specific Mutation Engine (`nfs-proxy`) in every lane.
The engine operates as a proxy between each client and server. The deps tarball therefore carries all three. Needs Docker and
network access; the outputs are local (`bundle/src/*` is gitignored except `guest-deps.tar.gz`).

```sh
uv run tools/build-ganesha-v15.sh              # pinned upstream V15.6
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-lane
uv run python tools/assemble-guest-deps.py \
  --ganesha-deps bundle/src/guest-deps-ganesha-v15.6.tar.gz \
  --proxy bundle/src/nfs-proxy-lane --out bundle/src/guest-deps-lane.tar.gz
```

### 2. Provision the fuzzing environment (build + bake)

```sh
uv run python tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps-lane.tar.gz \
  --version 4.2
```

| Input | Description |
|---|---|
| `--base-image`, `--ssh-key`, `--deps-tar` (required) | Stage-1 outputs + guest dependencies |
| `--version 3\|4.0\|4.1\|4.2` (required) | Version for verification boots; legacy `--minor 1\|2` remains an alias for v4.1/v4.2 |
| kernel/syzkaller sources (default) | Cloned at the refs in [bundle/patches/BASE](bundle/patches/BASE) |
| `--kernel-repo` / `--syz-repo` (optional) | Override clone URLs |
| `--kernel-ref TAG\|latest` (optional) | Kernel release or rc tag to build; `latest` is the newest tag, rc included. Default: the tag in `bundle/patches/BASE` |
| `--variant kasan\|kcsan` (optional, repeatable) | Sanitizer kernels to build and verify; default: both |
| `--jobs N` (optional) | Parallel build jobs |

- **Behavior**: clone upstream (kernel at `--kernel-ref`, syzkaller at the commit in `bundle/patches/BASE`) → apply the checked-in patch series → build one `bzImage`/`vmlinux` per variant out of tree (`make O=`) plus the syzkaller binaries → bake the version-neutral VM image once (`bookworm-kcov-fresh.qcow2`) → boot every variant with the host lane script and verify its hash and lane status
- **Output**: `env/` — `env/images/<variant>/bzImage` and `env/images/<variant>/vmlinux` and `.config` (`<variant>` = `kasan` or `kcsan`), `env/images/bookworm-kcov-fresh.qcow2`, `env/syzkaller/bin/...`, and **`env/manifest.json`** (records the kernel ref and resolved commit, pins, per-variant kernel hashes and verification). `env/linux/` is the clean patched source tree and `env/build/<variant>/` the disposable build tree; delete `env/build/` once `env/images/` is populated.

### 3. Using the result with syz-manager

Start campaigns directly with the syz-manager built in step 2 and a config pointing at its outputs.

| syz-manager setting | Value |
|---|---|
| `vm.kernel` / `kernel_obj` | `env/images/<variant>/bzImage` / `env/images/<variant>/` (holding `vmlinux`) |
| `kernel_src` / `syzkaller` | `env/linux/` / `env/syzkaller/` |
| `image`, `sshkey` | `env/images/bookworm-kcov-fresh.qcow2`, `artifacts/bookworm.id_rsa` |
| `procs` | the fixture's lane count (4) |
| `snapshot` (top level) | `false` (or absent). Program snapshot mode runs one program at a time with one proc, so only lane 0 is used |
| `vm.snapshot` | `true` (default). QEMU's temporary disk writes preserve the baked image; this setting does not select program snapshot mode |
| `workdir`, `http` | distinct for knfsd and Ganesha; each workdir owns its own `corpus.db` |
| `experimental.remote_cover` | `true` for knfsd; `false` for Ganesha, whose current feedback is local client-kernel coverage |
| `vm.cmdline` | must include `nfs.localio_enabled=N`; the helper below adds `koov.nfs_version` and the expected lane-script SHA-256. `sunrpc.lane_attribution=0` disables lane attribution; it does not restore request-level attribution |

Create one base config per backend with distinct `workdir` and `http` values.
Initialize each new workdir's DB from only that backend's seed: knfsd uses
`basic-v41-tcp.prog`, Ganesha uses `basic-v41-ganesha-tcp.prog`.
Do not pack the whole seed directory into both DBs, merge the DBs, or share a
corpus hub between these campaigns. Keep existing DBs when resuming.

For the reusable image, freeze the host script and add the read-only 9P device
to each config separately; the helper preserves its backend-specific workdir
and coverage settings:

```sh
uv run python tools/prepare-live-lane-config.py manager-knfsd-base.cfg manager-knfsd-v41.cfg --version 4.1
uv run python tools/prepare-live-lane-config.py manager-ganesha-base.cfg manager-ganesha-v41.cfg --version 4.1
```

Run one backend at a time. Start knfsd with:

```sh
env/syzkaller/bin/syz-manager -config manager-knfsd-v41.cfg -mode fuzzing
```

After stopping it and waiting for shutdown, run Ganesha:

```sh
env/syzkaller/bin/syz-manager -config manager-ganesha-v41.cfg -mode fuzzing
```

Corpus separation prevents splicing
between backend corpora; it does not preserve seed paths or disable minimization.
The fixture still exposes both backends, so this is not a strict execution filter.

Use `--version 3`, `4.0`, `4.1` or `4.2` for a campaign. The helper leaves the input config alone,
copies `bundle/lane/lane.sh` to a hash-named `workdir_template`, and pins that
hash in the guest boot arguments. Each VM copies the script once into `/run`;
setup, status and cleanup use that same copy. Changing `lane.sh` requires a new
prepared config, **not** a new image. The host share is read-only and is unmounted
after the copy. A missing share or wrong hash fails the fixture at boot.
The checked-in corpus includes inputs for NFSv3, v4.0, v4.1 and v4.2. Their targets and
functional contracts are listed in the [corpus guide](bundle/corpus/nfs-normal/README.md).

For version comparisons, mount only the selected version in each VM. Extra
NFSv4 mounts establish client/server state and can issue lease-renewal traffic
even when no seed opens their paths; concurrent mounts can also change cache
behavior. A run with all versions mounted is a valid, separate topology if it
is held constant across repeats, but it is not equivalent to a single-version
run. This matters especially here because remote coverage is lane-scoped.
See [NFSv4.1 lease renewal](https://www.rfc-editor.org/rfc/rfc8881.html#section-8.3)
and [Linux NFS mount caching](https://man7.org/linux/man-pages/man5/nfs.5.html).

### 4. Moving to a newer kernel

```sh
uv run python tools/bump-kernel.py latest          # or a tag, e.g. v7.4-rc1
uv run python tools/bootstrap-kcov-env.py env ... --update
```

`bump-kernel.py` applies the kernel series to a shallow clone of the tag. If it applies, `bundle/patches/BASE` moves to that tag and the patch files stay as they are. If it conflicts, the clone is left in the middle of `git am`: resolve it with git (edit, `git add`, `git am --continue`), then run `uv run python tools/bump-kernel.py --export <clone>` to write the rebased series back and update `BASE`. Resolutions are remembered (git rerere) in `cache/rr-cache-kernel` and replayed on the next release.

Re-running bootstrap with `--update` rebuilds the selected kernels (both by default) and syzkaller
into the same `env/`, so only the latest kernel images are kept. `--skip-build` reuses existing build
outputs. The VM image is reused when its bytes and the base image, baker, boot wrapper, service and
guest dependencies still match the image metadata; the kernel, lane script and selected version do
not require a re-bake. By default, every selected variant is booted and checked again.

A failure inside the build/bake/verify stages preserves the previous `manifest.json` and writes
`manifest.failed.json`. It does **not** roll back the whole environment: kernel images are replaced
after export and the VM image after baking, before final verification. Source trees and syzkaller
binaries may also have changed. An older passing manifest alone therefore does not validate the
files left by a failed update. With `--skip-verify`, `status: "pass"` is written with `verify: "skipped"`;
check the per-variant verification results before claiming a verified boot.

`manifest.json` also records stage durations (`timing_seconds`) and the change axis (`changes.axis`:
`kernel-release`, `scenario`, `both`, `none`, `first-run` or `unknown`);
`tools/README.md` explains when syzkaller must be rebuilt.

## Command summary

| Stage | Command | Input → Output |
|---|---|---|
| Base image | `sudo bash tools/make-base-image.sh --out artifacts` | sudo + debootstrap → `artifacts/bookworm-base.img` + keypair |
| Bootstrap | `uv run python tools/bootstrap-kcov-env.py env --base-image ... --ssh-key ... --deps-tar ... --version 4.2` | base · key · deps + upstream → `env/` (per-variant kernel images, binaries, shared image, manifest); `--version` selects the verification boot only |
| New kernel | `uv run python tools/bump-kernel.py latest` then bootstrap with `--update` | newest release/rc tag → `bundle/patches/BASE` + rebuilt kernel images |

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Bootstrap · base-image generation · patch apply · kernel base bump · Ganesha and Mutation Engine builds · flow tracing (usage: `tools/README.md`) |
| `bundle/` | Inputs — patch series · guest deps · kernel configs · lane fixture · image baker · seed corpus (`bundle/README-HANDOFF.md`) |
| `docs/` | Design overview, attribution decisions and implementation handoff records |
| `report/` | Normal-flow scope, measurements and [validation history](report/validation-history.md) |
| `pyproject.toml` · `.python-version` · `uv.lock` | Python tool environment and dependency metadata |
| `LICENSE` · `THIRD-PARTY-LICENSES.md` | MIT + vendor component attribution |

## License

MIT (`LICENSE`) — the kernel series is GPL-2.0 (derivative work); the syzkaller series is Apache-2.0; other vendor
attributions are listed in `THIRD-PARTY-LICENSES.md`.
