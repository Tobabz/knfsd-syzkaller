# knfsd-syzkaller

A tool that builds **customized syzkaller fuzzing environments for fuzzing the NFS subsystem of the Linux kernel (knfsd)**.
It reflects a **remote KCOV coverage model** — collecting NFS server-side coverage remotely — on a KCOV + memory-sanitizer (KASAN or KCSAN) instrumented
kernel, and automates the whole pipeline from base image to a bootable fuzz VM (instrumented kernels + syzkaller binaries +
one baked protocol image).

The checked-in customization series — **4 kernel patches + 19 syzkaller patches** (`bundle/patches/`) — is applied by
`tools/fport-apply.sh` during bootstrap. Every bootstrap run boots each kernel variant with the baked image and checks that the NFS lane fixture
comes up and that the kernel carries the expected memory sanitizer.

## Design highlights

| Aspect | Description |
|---|---|
| Instrumentation | KCOV + KASAN/KCSAN boot kernels, built **out of tree** from one patched source tree |
| Coverage model | **Remote KCOV** — knfsd server-side coverage collected remotely (`remote_cover`, `cover_edges`); fs/nfsd and net/sunrpc PCs are attributed through this path. Ownership is lane-scoped (kernel 0002): every request that reaches lane N's server counts for the program proc N is running, so attribution survives the NFS wire relay |
| Fuzz lanes | One NFS lane per executor proc (a server plus two client mount namespaces, `/nfs-lane`); the boot fixture provides 4 lanes, so run syz-manager with `procs` equal to the lane count and `vm.snapshot` off. Lanes exist for parallel fuzzing inside one VM |
| NFS version | `koov.nfs_version=3\|4.0\|4.1\|4.2` in `vm.cmdline` selects one mount version for both backends at boot |
| Boot model | One version-neutral image serves both sanitizer kernels; the lane script is copied from a read-only host 9P share at each VM boot |
| Seeds | `bundle/corpus/nfs-normal/` — normal-flow syzkaller programs plus a manifest; run them with a stock syz-manager (remote coverage is the `experimental.remote_cover` setting) |

The image uses `bundle/lane/lane.sh` for all four NFS versions. Its default `SERVER_IMPL=both`
routes both clients through the relay; `nfs-lane/client0` and `client1` select the same knfsd
export. Explicit `client{0,1}-ganesha` paths select the separate Ganesha export.
Both backends use the selected version. The lane exports a bounded ext4
loop image through [Ganesha V15.6](https://github.com/nfs-ganesha/nfs-ganesha/releases/tag/V15.6)
FSAL_VFS; knfsd keeps its tmpfs.
The reusable image passed four-mount cross-client reads, writes, backend isolation
and cleanup with NFSv3, v4.0, v4.1 and v4.2. NFSv3 uses pinned TCP MOUNT ports
and `nolock`; cross-client NLM locking is not part of this fixture. Build and
guest-check commands are in
[tools/README.md](tools/README.md).

The reusable image is `env/images/bookworm-kcov-fresh.qcow2`. The earlier
V15.6 v4.1/v4.2 image names in historical evidence refer to the baked-script
configuration used for those runs.
An earlier KASAN snapshot run of the 11-call COPY seed returned 32 MiB and collected a
nonempty remote `.extra`; the v4.1 knfsd and Ganesha seeds each passed 34 calls
in separate KASAN snapshots. Current fuzzing uses a separate syz-manager,
workdir and `corpus.db` for each backend, running one backend at a time. Each
manager starts from its own basic seed; the former combined DBs have been removed.
The separate managers completed `corpus-triage` with 100 knfsd and 109 Ganesha
programs, with no opposite-backend path literals found in either saved corpus.
See the [corpus execution guide](bundle/corpus/nfs-normal/README.md#execution-scope-2026-10-02)
for resume commands, evidence and limits.

New configs use the reusable image. The validated separate v4.1 cache configs
still pin `bookworm-kcov-v41-ganesha-v15.6.qcow2`, which contains its lane script.
To use the reusable image instead, prepare each config with the helper in step 3;
changing only the image filename does not supply the required host lane script.

The corpus objective is to cover thread-execution flows reachable through normal NFS scenarios; see
[scope and completion criteria](report/normal-flow-corpus.md).

## Host requirements

Build prerequisites are exactly those of the upstream components — this repo adds nothing to them:

- **Linux kernel**: toolchain and libraries per `Documentation/process/changes.rst` in the kernel tree
  (mirror: <https://www.kernel.org/doc/html/latest/process/changes.html>).
- **syzkaller**: Go, gcc, and VM prerequisites per [docs/linux/setup.md](https://github.com/google/syzkaller/blob/master/docs/linux/setup.md).

On top of that, this repo needs network access to `git.kernel.org` and `github.com` for the pinned source clones, and ~30 GiB of working space.

## Usage — commands, inputs, outputs

### 1. Create the base image (once per site)

```sh
sudo bash tools/make-base-image.sh --out artifacts
```

- **Input**: host root (sudo) + debootstrap + network (runs `create-image.sh -d bookworm` from the pinned syzkaller tree)
- **Output**: `artifacts/bookworm-base.img` (2 GiB raw ext4, kernel not included) and `artifacts/bookworm.id_rsa[.pub]` (SSH keypair, `.id_rsa` mode 0600; handed back to the invoking user when run through `sudo`, because bootstrap must be able to read the key)

### 1b. Build the lane deps (Ganesha + relay)

The lane fixture starts knfsd, NFS-Ganesha and the wire relay (`nfs-proxy`) in every lane, and every
client reaches the servers through the relay. The deps tarball therefore carries all three. Needs Docker and
network access; the outputs are local (`bundle/src/*` is gitignored except `guest-deps.tar.gz`).

```sh
tools/build-ganesha-v15.sh              # pinned upstream V15.6
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-lane
python3 tools/assemble-guest-deps.py \
  --ganesha-deps bundle/src/guest-deps-ganesha-v15.6.tar.gz \
  --proxy bundle/src/nfs-proxy-lane --out bundle/src/guest-deps-lane.tar.gz
```

### 2. Provision the fuzzing environment (build + bake)

```sh
python3 tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps-lane.tar.gz \
  --version 4.2
```

| Input | Description |
|---|---|
| `--base-image`, `--ssh-key`, `--deps-tar` (required) | Stage-1 outputs + guest dependencies |
| `--version 3\|4.0\|4.1\|4.2` (required) | Version for verification boots; legacy `--minor 1\|2` remains an alias for v4.1/v4.2 |
| kernel/syzkaller sources (default) | Cloned at pinned refs — kernel `v7.3-rc5` (git.kernel.org), syzkaller `801f09666` (github.com/google/syzkaller) |
| `--kernel-repo` / `--syz-repo` (optional) | Override clone URLs |
| `--kernel-ref TAG\|latest` (optional) | Kernel release or rc tag to build; `latest` is the newest tag, rc included. Default: the tag in `bundle/patches/BASE` |
| `--variant kasan\|kcsan` (optional, repeatable) | Sanitizer kernels to build and verify; default: both |
| `--jobs N` (optional) | Parallel build jobs |

- **Behavior**: clone upstream (kernel at `--kernel-ref`, syzkaller at the commit in `bundle/patches/BASE`) → apply the series (4+19) → build one `bzImage`/`vmlinux` per variant out of tree (`make O=`) plus the syzkaller binaries → bake the version-neutral VM image once (`bookworm-kcov-fresh.qcow2`) → boot every variant with the host lane script and verify its hash and lane status
- **Output**: `env/` — `env/images/<variant>/bzImage` and `env/images/<variant>/vmlinux` and `.config` (`<variant>` = `kasan` or `kcsan`), `env/images/bookworm-kcov-fresh.qcow2`, `env/syzkaller/bin/...`, and **`env/manifest.json`** (records the kernel ref and resolved commit, pins, per-variant kernel hashes and verification). `env/linux/` is the clean patched source tree and `env/build/<variant>/` the disposable build tree; delete `env/build/` once `env/images/` is populated.

### 3. Using the result with syz-manager

No runner is provided: point a syz-manager config at the outputs of step 2.

| syz-manager setting | Value |
|---|---|
| `kernel` / `kernel_obj` | `env/images/<variant>/bzImage` / the directory holding `vmlinux` |
| `image`, `sshkey` | `env/images/bookworm-kcov-fresh.qcow2`, `artifacts/bookworm.id_rsa` |
| `procs` | the fixture's lane count (4) |
| `vm.snapshot` | `false` (or absent). Snapshot mode runs one program at a time with one proc, so only lane 0 is used |
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
python3 tools/prepare-live-lane-config.py manager-knfsd-base.cfg manager-knfsd-v41.cfg --version 4.1
python3 tools/prepare-live-lane-config.py manager-ganesha-base.cfg manager-ganesha-v41.cfg --version 4.1
```

Run one backend at a time. Start knfsd with:

```sh
env/syzkaller/bin/syz-manager -config manager-knfsd-v41.cfg -mode fuzzing
```

After stopping it and waiting for shutdown, run Ganesha:

```sh
env/syzkaller/bin/syz-manager -config manager-ganesha-v41.cfg -mode fuzzing
```

The [existing local campaign commands](bundle/corpus/nfs-normal/README.md#execution-scope-2026-10-02)
use the already validated separate configs. Those configs set `vm.snapshot: true`, so they ran
one proc (lane 0) only; turn snapshot mode off for the parallel lane operation this fixture is
designed for. Parallel four-lane manager runs with the current topology are not yet validated. Corpus separation prevents splicing
between backend corpora; it does not preserve seed paths or disable minimization.
The fixture still exposes both backends, so this is not a strict execution filter.

Use `--version 3`, `4.0`, `4.1` or `4.2` for a campaign. The helper leaves the input config alone,
copies `bundle/lane/lane.sh` to a hash-named `workdir_template`, and pins that
hash in the guest boot arguments. Each VM copies the script once into `/run`;
setup, status and cleanup use that same copy. Changing `lane.sh` requires a new
prepared config, **not** a new image. The host share is read-only and is unmounted
after the copy. A missing share or wrong hash fails the fixture at boot.
The checked-in normal corpus has v4.1/v4.2 inputs; version-specific v3/v4.0
seeds and their oracles still need to be prepared before fuzzing those versions.

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
python3 tools/bump-kernel.py latest          # or a tag, e.g. v7.4-rc1
python3 tools/bootstrap-kcov-env.py env ... --update
```

`bump-kernel.py` applies the kernel series to a shallow clone of the tag. If it applies, `bundle/patches/BASE` moves to that tag and the patch files stay as they are. If it conflicts, the clone is left in the middle of `git am`: resolve it with git (edit, `git add`, `git am --continue`), then run `python3 tools/bump-kernel.py --export <clone>` to write the rebased series back and update `BASE`. Resolutions are remembered (git rerere) in `cache/rr-cache-kernel` and replayed on the next release.

Re-running bootstrap with `--update` rebuilds both kernels and syzkaller into the same `env/`, so only the latest kernel images are kept. The VM image does not depend on the kernel, lane script or selected version; it is reused when the base image, baker, boot wrapper, service and guest dependencies are unchanged. Every variant is booted with the current host script and checked again. A failed run keeps the previous images and `manifest.json` and records the failure in `manifest.failed.json`. `manifest.json` also records the seconds each stage took (`timing_seconds`) and which axis the run moved (`changes.axis`: `kernel-release`, `scenario`, `both`, `none`, `first-run` or `unknown`); `tools/README.md` explains when syzkaller must be rebuilt.

## Command summary

| Stage | Command | Input → Output |
|---|---|---|
| Base image | `sudo bash tools/make-base-image.sh --out artifacts` | sudo + debootstrap → `artifacts/bookworm-base.img` + keypair |
| Bootstrap | `python3 tools/bootstrap-kcov-env.py env --base-image ... --ssh-key ... --deps-tar ... --version 4.2` | base · key · deps + upstream → `env/` (per-variant kernel images, binaries, shared image, manifest); `--version` selects the verification boot only |
| New kernel | `python3 tools/bump-kernel.py latest` then bootstrap with `--update` | newest release/rc tag → `bundle/patches/BASE` + rebuilt kernel images |

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Bootstrap · base-image generation · patch apply · kernel base bump · Ganesha and NFS-proxy builds (usage: `tools/README.md`) |
| `bundle/` | Inputs — patch series · guest deps · kernel configs · lane fixture · image baker · seed corpus (`bundle/README-HANDOFF.md`) |
| `report/` | Design notes and the normal-flow corpus audit |
| `LICENSE` · `THIRD-PARTY-LICENSES.md` | MIT + vendor component attribution |

## License

MIT (`LICENSE`) — the kernel series is GPL-2.0 (derivative work); the syzkaller series is Apache-2.0; other vendor
attributions are listed in `THIRD-PARTY-LICENSES.md`.
