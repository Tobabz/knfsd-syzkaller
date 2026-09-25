# Third-party licenses & notices

This repository distributes the following components with their own licensing:

| Component | Origin | License |
|---|---|---|
| `bundle/patches/kernel/` (11 patches) | Linux kernel (series targets `v7.3-rc4`) | **GPL-2.0** (derivative) |
| `bundle/patches/syzkaller/` (15 patches) | syzkaller @ `801f09666` | **MIT** (derivative; upstream license by Google LLC) |
| `bundle/src/linux-v7.3-rc4.tar.xz` | kernel.org | GPL-2.0 (full text inside archive: `COPYING`) |
| `bundle/src/syzkaller-801f09666.tar.gz` | syzkaller repo | MIT (full text inside archive: `LICENSE`) |
| `bundle/src/bookworm-base.img[.gz]` | Debian bookworm (cloud/base image) | DFSG-free; individual package licenses live inside the image |
| `bundle/src/guest-deps.tar.gz` | Debian nfs-utils + deps extraction | DFSG-free package licenses |
| `bundle/src/bookworm.id_rsa[.pub]` | generated guest keypair | see note below |
| `tools/`, `bundle/` (`ab-runner/`·`baker/`·`corpus/`), `report/` docs, `LICENSE`, this file | new work | **MIT** (`LICENSE`) |

## Notes

- **Guest SSH keypair** (`bookworm.id_rsa`, fingerprint
  `SHA256:hp4uezultsFtRDrHSnagtgclnK3E9QI144ZlpPuS+wg`): a disposable
  syzkaller-`create-image.sh`-style credential. It grants passwordless root
  SSH **only** to QEMU guests built from the bundled base image on your
  private network. It is not a credential for any other service. The pair was
  rotated 2026-09-26 for public release (comment `syzkaller-guest`); the old
  pair is not shipped. Treat it as throwaway: regenerate the pair and
  re-bake the image before any non-sandboxed deployment.
- Binaries built from the bundled sources (kernel `bzImage`, syzkaller
  binaries) inherit the licenses of their sources as above.
- The kernel and syzkaller patch series must be distributed under their
  upstream licenses; do not relicense them.
