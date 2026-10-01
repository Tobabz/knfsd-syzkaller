# Handoff bundle — reproduction of the knfsd KCOV environment

Upstream sources (Linux kernel `v7.3-rc4`, syzkaller `801f09666`) are
**cloned by the bootstrap at the refs recorded in `bundle/patches/BASE`** (the kernel tag can be overridden with `--kernel-ref`, `latest` included), so a first fresh
environment build requires network access to `git.kernel.org` and
`github.com`. Everything else (patches, fixtures, guest deps) ships in
this repository; the **base image and keypair are generated per site**
(`tools/make-base-image.sh`) — no release assets are distributed
(2026-09-26 asset-free model). The bundle is **independent**: it no
longer mirrors the handoff repo's internal layout (`repo/` tree removed
2026-09-25).

## Contents

| Path | Description | Size |
|---|---:|---:|
| upstream kernel | cloned by bootstrap at the `BASE` tag (currently `v7.3-rc4`, commit `93f51579…`, git.kernel.org); `--kernel-ref` overrides | — |
| upstream syzkaller | cloned by bootstrap at commit `801f09666…` (github.com/google/syzkaller) | — |
| base image (site-generated) | `tools/make-base-image.sh` → `artifacts/bookworm-base.img` (2 GiB raw, `create-image.sh -d bookworm`) | 2 GiB |
| `src/guest-deps.tar.gz` | Debian nfs-utils extraction for guests (committed) | ~6 MB |
| guest keypair (site-generated) | same run: `artifacts/bookworm.id_rsa[.pub]` (pairs with your base) | — |
| `patches/kernel/` | kernel series: 13 patches + `series` | — |
| `patches/syzkaller/` | syzkaller series: 17 patches + `series` | — |
| `patches/BASE` | last base the series applies to (kernel tag + commit, syzkaller commit); updated by `tools/bump-kernel.py` | — |
| `patches/kernel.config` | kernel build config used by bootstrap | — |
| `patches/kernel-kcsan.config` | KCSAN variant config (KASAN off, `CONFIG_KCSAN=y`); built by `bootstrap-kcov-env.py --variant kcsan` | — |
| `ab-runner/` | Lane fixture inputs baked into the image (`frozen_phase9_lane.sh`, `frozen_phase9_boot_fixture.sh`, `frozen-phase9-fixture.service`) | — |
| `baker/` | protocol image baking (`bake_nfs_protocol_image.py`) | — |
| `corpus/` | seed corpus (`nfs-normal/`: `.prog` seeds, manifest, lane fixtures for NFS v3 and v4.2) | — |



## Provenance

- The original handoff repo tarball `knfsd-fuzz-HEAD.tar.gz`
  (sha256 `42f2789ce0dd8c2591239da100b5c08b7ae369fccb1e4e544ce65a284b438c0d`)
  was **deleted 2026-09-25** during the bundle independence restructure; its
  hash is kept here for audit. Its useful contents survived as the flat
  `patches/` + `ab-runner/` (+`baker/`, `corpus/`) above.
- `patches/*/series` records apply order; no SHA256 verification is performed
  re-verifies them on every pipeline run.

## Base image provenance

The base image is **not shipped**; every site generates its own with
the turnkey wrapper **`tools/make-base-image.sh`**, which runs syzkaller's
official image builder, `tools/create-image.sh` (in the syzkaller tree at
pinned commit `801f09666…`, referenced by `docs/linux/setup.md`;
Apache-2.0 per its header):

```sh
sudo bash tools/make-base-image.sh --out artifacts   # arch amd64, default SEEK=2047
```

The chain:

1. `debootstrap --arch=amd64 --include=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros,debian-ports-archive-keyring --components=main,contrib,non-free,non-free-firmware bookworm <dir>`
2. Guest defaults: passwordless root, `ttyS0` getty, `eth0` dhcp, fstab /
   debugfs / securityfs / configfs / binfmt_misc entries, hostname
   `syzkaller`; `ssh-keygen -f bookworm.id_rsa` with the pubkey installed to
   `/root/.ssh/authorized_keys` inside the image.
3. `dd if=/dev/zero of=bookworm.img bs=1M seek=2047 count=1` -> 2 GiB raw;
   `mkfs.ext4 -F`; loop-mount and copy the chroot in.

The result is a plain ext4 image with **no partition table** (verified:
`file` -> ext4 filesystem data, `fdisk -l` -> no partitions,
`qemu-img info` -> raw 2 GiB / 2147483648 bytes). It is never booted RW
after creation — the baked protocol image is produced by the bootstrap
(from the raw) on a copy.

**Regeneration is not byte-reproducible**: `debootstrap` pulls current
mirrors and `ssh-keygen` output is random, so a fresh run yields a
functionally equivalent but hash-different image. There is no shipped
base bytes — each site's generated base (and its hash) is its own
validated artifact. The builder embeds its own pubkey, so the generated
keypair stays paired with the generated base and any re-bake must use
the same `--ssh-key`.

## Licenses and the guest key

- `tools/`, `bundle/` (`ab-runner/`, `baker/`, `corpus/`), and the `report/`
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

Prerequisites on the new host: KVM (`/dev/kvm`), QEMU, Go ≥1.23,
gcc, kernel build deps (`flex bison libssl-dev libelf-dev`), ~30 GB
free, Python 3, **passwordless sudo** (needed once for base generation;
the rest of the flow runs unprivileged).

Generate the site base + keypair, then verify the committed manifest:

```sh
sudo bash tools/make-base-image.sh --out artifacts
```

```sh
# working root containing tools/ + bundle/ + env/
# upstream refs are cloned by default (kernel v7.3-rc4, syzkaller 801f09666);
# override with --kernel-repo/--syz-repo, or supply your own archives via
# --kernel-tarball/--syz-tarball (pre-fetched) instead of cloning.
python3 tools/bootstrap-kcov-env.py /work/env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps.tar.gz \
  --minor 1
```

The run clones the pinned upstream refs (git.kernel.org `v7.3-rc4` /
github.com `801f09666…`), then patches
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
`python3 tools/bump-kernel.py latest`.

## Fuzzing after bootstrap

Point a stock syz-manager at the outputs: `kernel` = `<target>/images/<variant>/bzImage`,
`kernel_obj` = the directory holding `vmlinux`, `image` = `<target>/images/bookworm-kcov-fresh-v1.qcow2`,
`sshkey` = the generated `artifacts/bookworm.id_rsa`, `procs` = the fixture's lane count (4), and
`experimental.remote_cover` to switch remote coverage. The earlier A/B harness was removed in
commit `7833ed3`.
