# Handoff bundle — reproduction of the knfsd KCOV environment

Upstream Linux and syzkaller sources are
**cloned by the bootstrap at the refs recorded in [patches/BASE](patches/BASE)** (the kernel tag can be overridden with `--kernel-ref`, `latest` included), so a first fresh
environment build requires network access to `git.kernel.org` and
`github.com`. Patches, fixtures and the base nfs-utils deps ship in
this repository; Ganesha and [NFS-specific Mutation Engine](../tools/nfs-proxy/README.md) deps are built locally.
The Mutation Engine (`nfs-proxy`) operates as a proxy between NFS clients and servers.
The **base image and keypair are generated per site**
(`tools/make-base-image.sh`). No release assets are distributed.

## Contents

| Path | Description | Size |
|---|---:|---:|
| upstream kernel | cloned by bootstrap at the kernel ref in `patches/BASE`; `--kernel-ref` overrides | — |
| upstream syzkaller | cloned by bootstrap at the syzkaller commit in `patches/BASE` | — |
| base image (site-generated) | `tools/make-base-image.sh` → `artifacts/bookworm-base.img` (2 GiB raw, `create-image.sh -d bookworm`) | 2 GiB |
| `src/guest-deps.tar.gz` | Debian nfs-utils extraction for guests (committed) | ~6 MB |
| guest keypair (site-generated) | same run: `artifacts/bookworm.id_rsa[.pub]` (pairs with your base) | — |
| `patches/kernel/` | kernel patches, listed in [series](patches/kernel/series) | — |
| `patches/syzkaller/` | syzkaller patches, listed in [series](patches/syzkaller/series) | — |
| `patches/BASE` | last base the series applies to (kernel tag + commit, syzkaller commit); updated by `tools/bump-kernel.py` | — |
| `patches/kernel.config` | kernel build config used by bootstrap | — |
| `patches/kernel-kcsan.config` | KCSAN variant config (KASAN off, `CONFIG_KCSAN=y`); built by `bootstrap-kcov-env.py --variant kcsan` | — |
| `lane/` | `lane.sh` is supplied from a read-only host share at boot; `boot-fixture.sh` and `fixture.service` are baked into the image | — |
| `baker/` | protocol image baking (`bake_nfs_protocol_image.py`) | — |
| `corpus/` | TCP seed programs and [manifest](corpus/nfs-normal/manifest.json) with versions, backends and validation status | — |



`patches/*/series` lists the patches in apply order. The apply script uses filename order;
bootstrap records a combined filename/content hash per series in `env/manifest.json`.

## Base image provenance

The base image is **not shipped**; every site generates its own with
the turnkey wrapper **`tools/make-base-image.sh`**, which runs syzkaller's
official image builder, `tools/create-image.sh` (in the syzkaller tree pinned by
`patches/BASE`, referenced by `docs/linux/setup.md`;
Apache-2.0 per its header):

```sh
sudo bash tools/make-base-image.sh --out artifacts   # arch amd64, default SEEK=2047
```

The chain:

1. `debootstrap` creates a Bookworm amd64 root filesystem using the package list in the pinned `tools/create-image.sh`.
2. Guest defaults: passwordless root, `ttyS0` getty, `eth0` dhcp, fstab /
   debugfs / securityfs / configfs / binfmt_misc entries, hostname
   `syzkaller`; `ssh-keygen -f bookworm.id_rsa` with the pubkey installed to
   `/root/.ssh/authorized_keys` inside the image.
3. `dd if=/dev/zero of=bookworm.img bs=1M seek=2047 count=1` -> 2 GiB raw;
   `mkfs.ext4 -F`; loop-mount and copy the chroot in.

The result is a plain ext4 image with **no partition table**. It is never booted RW
after creation — the baked protocol image is produced by the bootstrap
(from the raw) on a copy.

**Regeneration is not byte-reproducible**: `debootstrap` pulls current
mirrors and `ssh-keygen` output is random, so a fresh run yields a
functionally equivalent but hash-different image. There is no shipped
base bytes — each site's generated base (and its hash) is its own
artifact. The builder embeds its own pubkey, so the generated
keypair stays paired with the generated base and any re-bake must use
the same `--ssh-key`.

## Licenses and the guest key

- `tools/`, `bundle/` (`lane/`, `baker/`, `corpus/`), and the `report/`
  documents are new work,
  distributed under the **MIT License** (see `LICENSE` at the repository
  root; provenance in `THIRD-PARTY-LICENSES.md`).
- `patches/kernel/` derive from the Linux kernel (**GPL-2.0**),
  `patches/syzkaller/` derive from syzkaller (**Apache-2.0**); upstream
  sources are cloned by bootstrap and carry their upstream licenses
  (`COPYING` / `LICENSE`).
- The site-generated `bookworm.id_rsa[.pub]` is a **disposable guest
  keypair** in the style of syzkaller's `create-image.sh`: it grants root
  SSH access only to QEMU guests built from your generated base on your
  private network, and is not a credential for any other service.
  Regenerate the pair and re-bake the image before any non-sandboxed
  deployment.

## Reproduce (teammate side)

Prepare the host using [tools/tool-requirements.txt](../tools/tool-requirements.txt),
then run `uv sync --locked` from the repository root. Python requirements and the default
interpreter are declared in [pyproject.toml](../pyproject.toml) and [.python-version](../.python-version).

Generate the site base + keypair and assemble the complete lane deps (Docker is needed for both Ganesha and Mutation Engine builds):

```sh
sudo bash tools/make-base-image.sh --out artifacts
uv run tools/build-ganesha-v15.sh
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-lane
uv run python tools/assemble-guest-deps.py \
  --ganesha-deps bundle/src/guest-deps-ganesha-v15.6.tar.gz \
  --proxy bundle/src/nfs-proxy-lane --out bundle/src/guest-deps-lane.tar.gz
```

```sh
# working root containing tools/ + bundle/ + env/
# upstream refs (bundle/patches/BASE) are cloned; override the URLs with
# --kernel-repo/--syz-repo and the kernel tag with --kernel-ref.
uv run python tools/bootstrap-kcov-env.py /work/env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps-lane.tar.gz \
  --version 4.2
```

The run clones the upstream refs in `patches/BASE`, then patches
(`tools/fport-apply.sh`, series = `bundle/patches/{kernel,syzkaller}`),
builds (one out-of-tree `bzImage`/`vmlinux` per `--variant`, default `kasan` and
`kcsan`, plus all syzkaller binaries), bakes one manager-ready image shared by all
variants, and verifies every variant (lane status). Kernel images land in
`<target>/images/<variant>/`; `<target>/build/` is disposable. Only the target
directory is written;
`manifest.json` records every pin (git refs for upstream sources).

Later updates arrive as a new bundle (or repo pull where available):
re-run the same command with `--update` — both kernels and syzkaller are rebuilt
(only the latest kernel images are kept), and the baked image is reused when its
inputs are unchanged. To follow a new kernel release first run
`uv run python tools/bump-kernel.py latest`.

## Fuzzing after bootstrap

Use the syz-manager built by bootstrap: `vm.kernel` = `<target>/images/<variant>/bzImage`,
`kernel_obj` = the directory holding `vmlinux`, `image` = `<target>/images/bookworm-kcov-fresh.qcow2`,
`sshkey` = the generated `artifacts/bookworm.id_rsa`, `procs` = the fixture's lane count (4),
`kernel_src` = `<target>/linux`, `syzkaller` = `<target>/syzkaller`, and
`experimental.remote_cover` to switch remote coverage. Use top-level `snapshot=false` for parallel
program execution; keep `vm.snapshot=true` (the default) for temporary disk writes.
Before starting the manager, run `tools/prepare-live-lane-config.py`
on its base config to add the hash-pinned host lane script share and select
`--version 3|4.0|4.1|4.2`.

Use separate manager configs, workdirs and `corpus.db` files for knfsd and
Ganesha, running one manager at a time. Initialize each DB from only its backend's
seed and keep the corpora separate on resume. Set `experimental.remote_cover=true`
for knfsd and `false` for Ganesha (local client-kernel feedback only).
Seed selection and DB operation are described in the
[corpus guide](corpus/nfs-normal/README.md#campaign-setup).
