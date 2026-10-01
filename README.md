# knfsd-syzkaller

A tool that builds **customized syzkaller fuzzing environments for fuzzing the NFS subsystem of the Linux kernel (knfsd)**.
It reflects a **remote KCOV coverage model** — collecting NFS server-side coverage remotely — on a KCOV + memory-sanitizer (KASAN or KCSAN) instrumented
kernel, and automates the whole pipeline from base image to a bootable fuzz VM (instrumented kernels + syzkaller binaries +
one baked protocol image).

The checked-in customization series — **13 kernel patches + 17 syzkaller patches** (`bundle/patches/`) — is applied by
`tools/fport-apply.sh` during bootstrap. Every bootstrap run boots each kernel variant with the baked image and checks that the NFS lane fixture
comes up and that the kernel carries the expected memory sanitizer.

## Design highlights

| Aspect | Description |
|---|---|
| Instrumentation | KCOV + KASAN/KCSAN boot kernels, built **out of tree** from one patched source tree |
| Coverage model | **Remote KCOV** — knfsd server-side coverage collected remotely (`remote_cover`, `cover_edges`); fs/nfsd and net/sunrpc PCs are attributed through this path |
| Fuzz lanes | One NFS lane per executor proc (a server plus two client mount namespaces, `/nfs-lane`); the baked fixture provides 4 lanes, so run syz-manager with `procs` equal to the lane count |
| NFS version | `--minor 1\|2` selects the NFS minor version baked into the image (recorded in the manifest) |
| Boot model | Kernel is injected **outside the image** (`-kernel`), so one baked image serves both sanitizer kernels |
| Seeds | `bundle/corpus/nfs-normal/` — normal-flow syzkaller programs plus a manifest; run them with a stock syz-manager (remote coverage is the `experimental.remote_cover` setting) |

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

### 2. Provision the fuzzing environment (build + bake)

```sh
python3 tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps.tar.gz \
  --minor 1
```

| Input | Description |
|---|---|
| `--base-image`, `--ssh-key`, `--deps-tar` (required) | Stage-1 outputs + guest dependencies |
| `--minor 1\|2` (required) | NFS minor version |
| kernel/syzkaller sources (default) | Cloned at pinned refs — kernel `v7.3-rc4` (git.kernel.org), syzkaller `801f09666` (github.com/google/syzkaller) |
| `--kernel-repo` / `--syz-repo` (optional) | Override clone URLs |
| `--kernel-tarball` / `--syz-tarball` (optional) | Offline source archives instead of clones |
| `--variant kasan\|kcsan` (optional, repeatable) | Sanitizer kernels to build and verify; default: both |
| `--jobs N` (optional) | Parallel build jobs |

- **Behavior**: clone upstream → apply the series (13+17) → build one `bzImage`/`vmlinux` per variant out of tree (`make O=`) plus the syzkaller binaries → bake the bootable VM image once (`bookworm-kcov-fresh-v1.qcow2`, shared by all variants) → boot every variant and verify lane status
- **Output**: `env/` — `env/images/<variant>/bzImage` and `env/images/<variant>/vmlinux` (`<variant>` = `kasan` or `kcsan`), `env/images/bookworm-kcov-fresh-v1.qcow2`, `env/syzkaller/bin/...`, and **`env/manifest.json`** (records all sources, pins, per-variant kernel hashes and verification). `env/linux/` is the clean patched source tree and `env/build/<variant>/` the disposable build tree; delete `env/build/` once `env/images/` is populated.

### 3. Using the result with syz-manager

No runner is provided: point a syz-manager config at the outputs of step 2.

| syz-manager setting | Value |
|---|---|
| `kernel` / `kernel_obj` | `env/images/<variant>/bzImage` / the directory holding `vmlinux` |
| `image`, `sshkey` | `env/images/bookworm-kcov-fresh-v1.qcow2`, `artifacts/bookworm.id_rsa` |
| `procs` | the fixture's lane count (4) |
| `experimental.remote_cover` | on/off switch for remote coverage |

## Command summary

| Stage | Command | Input → Output |
|---|---|---|
| Base image | `sudo bash tools/make-base-image.sh --out artifacts` | sudo + debootstrap → `artifacts/bookworm-base.img` + keypair |
| Bootstrap | `python3 tools/bootstrap-kcov-env.py env --base-image ... --ssh-key ... --deps-tar ... --minor 1` | base · key · deps + upstream → `env/` (per-variant kernel images, binaries, image, manifest) |

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Bootstrap · base-image generation · patch apply · Ganesha and NFS-proxy builds (usage: `tools/README.md`) |
| `bundle/` | Inputs — patch series · guest deps · kernel configs · lane fixture · image baker · seed corpus (`bundle/README-HANDOFF.md`) |
| `report/` | Design notes and the normal-flow corpus audit |
| `LICENSE` · `THIRD-PARTY-LICENSES.md` | MIT + vendor component attribution |

The earlier A/B harness, NF-A1/B06 observers, attribution scenario matrix, design gate and forward-port pipeline were removed in commit `7833ed3`.

## License

MIT (`LICENSE`) — the kernel series is GPL-2.0 (derivative work); the syzkaller series is Apache-2.0; other vendor
attributions are listed in `THIRD-PARTY-LICENSES.md`.
