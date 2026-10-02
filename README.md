# knfsd-syzkaller

A tool that builds **customized syzkaller fuzzing environments for fuzzing the NFS subsystem of the Linux kernel (knfsd)**.
It reflects a **remote KCOV coverage model** — collecting NFS server-side coverage remotely — on a KCOV + memory-sanitizer (KASAN or KCSAN) instrumented
kernel, and automates the whole pipeline from base image to a bootable fuzz VM (instrumented kernels + syzkaller binaries +
one baked protocol image).

The checked-in customization series — **3 kernel patches + 18 syzkaller patches** (`bundle/patches/`) — is applied by
`tools/fport-apply.sh` during bootstrap. Every bootstrap run boots each kernel variant with the baked image and checks that the NFS lane fixture
comes up and that the kernel carries the expected memory sanitizer.

## Design highlights

| Aspect | Description |
|---|---|
| Instrumentation | KCOV + KASAN/KCSAN boot kernels, built **out of tree** from one patched source tree |
| Coverage model | **Remote KCOV** — knfsd server-side coverage collected remotely (`remote_cover`, `cover_edges`); fs/nfsd and net/sunrpc PCs are attributed through this path. Ownership is lane-scoped (kernel 0002): every request that reaches lane N's server counts for the program proc N is running, so attribution survives the NFS wire relay |
| Fuzz lanes | One NFS lane per executor proc (a server plus two client mount namespaces, `/nfs-lane`); the baked fixture provides 4 lanes, so run syz-manager with `procs` equal to the lane count |
| NFS version | `--minor 1\|2` selects the knfsd mount version baked into the image (recorded in the manifest); Ganesha mounts use v4.1 |
| Boot model | Kernel is injected **outside the image** (`-kernel`), so one baked image serves both sanitizer kernels |
| Seeds | `bundle/corpus/nfs-normal/` — normal-flow syzkaller programs plus a manifest; run them with a stock syz-manager (remote coverage is the `experimental.remote_cover` setting) |

The image uses `bundle/lane/lane.sh` for both NFS minor versions. Its default `SERVER_IMPL=both`
routes both clients through the relay; `nfs-lane/client0` and `client1` select the same knfsd
export. Explicit `client{0,1}-ganesha` paths select the separate Ganesha export.
In a `--minor 2` image, knfsd mounts use v4.2 and Ganesha mounts remain v4.1. The
current Ganesha v4.2 mount negotiates successfully, but reads of existing files
and files written by another client return zero-filled data both directly and through the relay.
The client issues `READ_PLUS`; Debian Ganesha 4.3-2 omits the `read_arg->info` pointer,
so FSAL_VFS treats it as a normal read while the `READ_PLUS` reply uses empty metadata.
Keep Ganesha on v4.1 until a corrected build passes guest validation.

The current `env/manifest.json` records the v4.1 image and both KASAN/KCSAN boot checks.
A separate v4.2 image, `env/images/bookworm-kcov-fresh-v2.qcow2`, was baked from
the same lane input and records its hashes in the adjacent `.json` file. One
KASAN snapshot run of the 11-call COPY seed returned 32 MiB and collected a
nonempty remote `.extra`; the v4.1 knfsd and Ganesha seeds each passed 34 calls
in separate KASAN snapshots. The two basic seeds also passed syz-manager
`corpus-triage` admission and a bounded single-manager fuzzing smoke with both
backend paths retained in the corpus. See `bundle/corpus/nfs-normal/README.md` for limits
and evidence paths.

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
tools/build-ganesha-deps.sh                                   # bundle/src/guest-deps-ganesha.tar.gz
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-lane
python3 tools/assemble-guest-deps.py \
  --ganesha-deps bundle/src/guest-deps-ganesha.tar.gz \
  --proxy bundle/src/nfs-proxy-lane --out bundle/src/guest-deps-lane.tar.gz
```

### 2. Provision the fuzzing environment (build + bake)

```sh
python3 tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps-lane.tar.gz \
  --minor 1
```

| Input | Description |
|---|---|
| `--base-image`, `--ssh-key`, `--deps-tar` (required) | Stage-1 outputs + guest dependencies |
| `--minor 1\|2` (required) | NFS minor version |
| kernel/syzkaller sources (default) | Cloned at pinned refs — kernel `v7.3-rc4` (git.kernel.org), syzkaller `801f09666` (github.com/google/syzkaller) |
| `--kernel-repo` / `--syz-repo` (optional) | Override clone URLs |
| `--kernel-ref TAG\|latest` (optional) | Kernel release or rc tag to build; `latest` is the newest tag, rc included. Default: the tag in `bundle/patches/BASE` |
| `--variant kasan\|kcsan` (optional, repeatable) | Sanitizer kernels to build and verify; default: both |
| `--jobs N` (optional) | Parallel build jobs |

- **Behavior**: clone upstream (kernel at `--kernel-ref`, syzkaller at the commit in `bundle/patches/BASE`) → apply the series (3+18) → build one `bzImage`/`vmlinux` per variant out of tree (`make O=`) plus the syzkaller binaries → bake the bootable VM image once (`bookworm-kcov-fresh-v1.qcow2`, shared by all variants) → boot every variant and verify lane status
- **Output**: `env/` — `env/images/<variant>/bzImage` and `env/images/<variant>/vmlinux` (`<variant>` = `kasan` or `kcsan`), `env/images/bookworm-kcov-fresh-v1.qcow2`, `env/syzkaller/bin/...`, and **`env/manifest.json`** (records the kernel ref and resolved commit, pins, per-variant kernel hashes and verification). `env/linux/` is the clean patched source tree and `env/build/<variant>/` the disposable build tree; delete `env/build/` once `env/images/` is populated.

### 3. Using the result with syz-manager

No runner is provided: point a syz-manager config at the outputs of step 2.

| syz-manager setting | Value |
|---|---|
| `kernel` / `kernel_obj` | `env/images/<variant>/bzImage` / the directory holding `vmlinux` |
| `image`, `sshkey` | `env/images/bookworm-kcov-fresh-v1.qcow2`, `artifacts/bookworm.id_rsa` |
| `procs` | the fixture's lane count (4) |
| `experimental.remote_cover` | on/off switch for remote coverage |
| `vm.cmdline` | must include `nfs.localio_enabled=N` (the baked lane fixture refuses to start otherwise, so no lane exists and fuzzing never reaches NFS); bootstrap and the baker pass it the same way. `sunrpc.lane_attribution=0` switches to request-level attribution for comparison runs |

### 4. Moving to a newer kernel

```sh
python3 tools/bump-kernel.py latest          # or a tag, e.g. v7.4-rc1
python3 tools/bootstrap-kcov-env.py env ... --update
```

`bump-kernel.py` applies the kernel series to a shallow clone of the tag. If it applies, `bundle/patches/BASE` moves to that tag and the patch files stay as they are. If it conflicts, the clone is left in the middle of `git am`: resolve it with git (edit, `git add`, `git am --continue`), then run `python3 tools/bump-kernel.py --export <clone>` to write the rebased series back and update `BASE`. Resolutions are remembered (git rerere) in `cache/rr-cache-kernel` and replayed on the next release.

Re-running bootstrap with `--update` rebuilds both kernels and syzkaller into the same `env/`, so only the latest kernel images are kept. The baked VM image does not depend on the kernel (it is booted with `-kernel`); it is reused when the base image, lane fixture, service, deps and NFS minor are unchanged, and re-baked otherwise. Every variant is booted and verified again against the new kernel. A failed run keeps the previous images and `manifest.json` and records the failure in `manifest.failed.json`. `manifest.json` also records the seconds each stage took (`timing_seconds`) and which axis the run moved (`changes.axis`: `kernel-release`, `scenario`, `both`, `none`, `first-run` or `unknown`); `tools/README.md` explains when syzkaller must be rebuilt.

## Command summary

| Stage | Command | Input → Output |
|---|---|---|
| Base image | `sudo bash tools/make-base-image.sh --out artifacts` | sudo + debootstrap → `artifacts/bookworm-base.img` + keypair |
| Bootstrap | `python3 tools/bootstrap-kcov-env.py env --base-image ... --ssh-key ... --deps-tar ... --minor 1` | base · key · deps + upstream → `env/` (per-variant kernel images, binaries, image, manifest) |
| New kernel | `python3 tools/bump-kernel.py latest` then bootstrap with `--update` | newest release/rc tag → `bundle/patches/BASE` + rebuilt kernel images |

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Bootstrap · base-image generation · patch apply · kernel base bump · Ganesha and NFS-proxy builds (usage: `tools/README.md`) |
| `bundle/` | Inputs — patch series · guest deps · kernel configs · lane fixture · image baker · seed corpus (`bundle/README-HANDOFF.md`) |
| `report/` | Design notes and the normal-flow corpus audit |
| `LICENSE` · `THIRD-PARTY-LICENSES.md` | MIT + vendor component attribution |

The earlier A/B harness, NF-A1/B06 observers, attribution scenario matrix, design gate and forward-port pipeline were removed in commit `7833ed3`.

## License

MIT (`LICENSE`) — the kernel series is GPL-2.0 (derivative work); the syzkaller series is Apache-2.0; other vendor
attributions are listed in `THIRD-PARTY-LICENSES.md`.
