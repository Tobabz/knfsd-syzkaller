# Handoff bundle — offline reproduction of the knfsd KCOV environment

No git remote access is required. Everything below expands from this
directory. The bundle is **independent**: it no longer mirrors the
handoff repo's internal layout (`repo/` tree removed 2026-09-25).

## Contents

| Path | Description | Size |
|---|---:|---:|
| `src/linux-v7.3-rc4.tar.xz` | pristine kernel source at `v7.3-rc4` | ~160 MB |
| `src/syzkaller-801f09666.tar.gz` | pristine syzkaller source at `801f09666` | ~24 MB |
| `src/bookworm-base.img[.gz]` | clean raw base image (never opened RW) | 2.0 GB / ~360 MB |
| `src/guest-deps.tar.gz` | Debian nfs-utils extraction for guests | ~6 MB |
| `src/bookworm.id_rsa[.pub]` | guest SSH keypair (fuzzing-only) | — |
| `patches/kernel/` | kernel series: 11 patches + `series` + `SHA256SUMS` | — |
| `patches/syzkaller/` | syzkaller series: 15 patches + `series` + `SHA256SUMS` | — |
| `patches/kernel.config` | kernel build config used by bootstrap | — |
| `ab-runner/` | AB experiment lane drivers (`run_frozen_phase*_vm.py`, lane/probe/bootstrap files, `monitor_knfsd.py`, workload prog) | — |
| `baker/` | protocol image baking (`bake_nfs_protocol_image.py`) | — |
| `corpus/` | fuzz corpus / candidate preparation (`audit_*`, `build_*`) | — |
| `SHA256SUMS` | checksums of all source/VM/config assets | — |

Verify first: `sha256sum -c SHA256SUMS`.

## Provenance

- The original handoff repo tarball `knfsd-fuzz-HEAD.tar.gz`
  (sha256 `42f2789ce0dd8c2591239da100b5c08b7ae369fccb1e4e544ce65a284b438c0d`)
  was **deleted 2026-09-25** during the bundle independence restructure; its
  hash is kept here for audit. Its useful contents survived as the flat
  `patches/` + `ab-runner/` (+`baker/`, `corpus/`) above.
- `patches/*/SHA256SUMS` pin the series bytes; forward-port gate R6
  re-verifies them on every pipeline run.

## Licenses and the guest key

- `tools/`, `bundle/` (`ab-runner/`, `baker/`, `corpus/`), and the `report/`
  documents are new work,
  distributed under the **MIT License** (see `LICENSE` at the repository
  root; provenance in `THIRD-PARTY-LICENSES.md`).
- `patches/kernel/` derive from the Linux kernel (**GPL-2.0**),
  `patches/syzkaller/` derive from syzkaller (**MIT**); the source archives
  in `src/` carry their upstream licenses (`COPYING` / `LICENSE`).
- `src/bookworm.id_rsa[.pub]` is a **disposable guest keypair** in the style
  of syzkaller's `create-image.sh`: it grants root SSH access only to QEMU
  guests built from the bundled image on your private network, and is not a
  credential for any other service. Regenerate the pair and re-bake the
  image before any non-sandboxed deployment.

## Reproduce (teammate side)

Prerequisites on the new host: KVM (`/dev/kvm`), QEMU, Go ≥1.23,
gcc, kernel build deps (`flex bison libssl-dev libelf-dev`), ~30 GB
free, Python 3. Root or sudo for `create-image`-style steps is not
needed for the flow below.

The distribution archive ships the base image **compressed** only
(`bundle/src/bookworm-base.img.gz`); the bootstrap requires the raw
twin. Restore it first, then verify against the pinned manifest:

```sh
[ -f bundle/src/bookworm-base.img ] || \
  zcat bundle/src/bookworm-base.img.gz > bundle/src/bookworm-base.img
cd bundle && sha256sum -c SHA256SUMS
```

```sh
# working root containing tools/ + bundle/ + env/
python3 tools/bootstrap-kcov-env.py /work/env \
  --kernel-tarball bundle/src/linux-v7.3-rc4.tar.xz \
  --syz-tarball bundle/src/syzkaller-801f09666.tar.gz \
  --base-image bundle/src/bookworm-base.img \
  --ssh-key bundle/src/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps.tar.gz \
  --minor 1
```

The run clones nothing: tarballs are extracted, committed locally,
patched (`tools/fport-apply.sh`, series = `bundle/patches/{kernel,syzkaller}`),
built (`bzImage`, all syzkaller binaries), baked into a manager-ready
image, and verified (lane status). Only the target directory is written;
`manifest.json` records every pin.

Later updates arrive as a new bundle (or repo pull where available):
re-run the same command with `--update` — only stages whose content
pins changed are rebuilt.

## Fuzzing after bootstrap

Point a syz-manager at the baked image with the generic
`tools/portable-env` helper of your choice; the AB harness entry points
are `tools/run-ab.sh` / `tools/analyze-ab.sh` (evidence lands in
`evidence/`).