#!/usr/bin/env bash
# tools/make-base-image.sh — generate a site-local pristine base image +
# keypair from the pinned syzkaller tree (create-image.sh -d bookworm).
#
# Asset-free model (2026-09-26): the base image and guest keypair are no
# longer shipped. create-image.sh output is NOT byte-reproducible
# (debootstrap mirrors + ssh-keygen randomness), so every site generates
# its own raw 2 GiB base + SSH keypair and treats it as its own validated
# artifact. The generated keypair must stay paired with the generated base:
# create-image.sh embeds the pubkey in /root/.ssh/authorized_keys inside
# the image (the bake/harness log in with the private key).
#
# Host requirements: passwordless sudo for this user, network access to
# github.com (unless --syz-tree is given), host package `debootstrap`,
# ~6 GiB free disk, ~5-15 min.
#
# Usage:
#   sudo bash tools/make-base-image.sh [--out DIR] [--syz-tree PATH]
#     --out       output dir for bookworm-base.img + bookworm.id_rsa[.pub]
#                 (default: $WORK_ROOT/artifacts; KOOV_ARTIFACTS_DIR env)
#     --syz-tree  existing syzkaller checkout; default: clone the pinned
#                 commit 801f09666 into $WORK_ROOT/cache/syzkaller-src
set -eu

TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
OUT="${KOOV_ARTIFACTS_DIR:-$WORK_ROOT/artifacts}"
SYZ_TREE=""
SYZ_COMMIT="801f0966669a37e048adabf9e5f38ce52825ea82"
SYZ_REPO="https://github.com/google/syzkaller.git"

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT=$2; shift 2 ;;
        --syz-tree) SYZ_TREE=$2; shift 2 ;;
        *) echo "usage: $0 [--out DIR] [--syz-tree PATH]" >&2; exit 2 ;;
    esac
done
OUT="$(realpath -m "$OUT")"
mkdir -p "$OUT" "$WORK_ROOT/cache"

# 1) resolve the pinned syzkaller tree
if [ -z "$SYZ_TREE" ]; then
    SYZ_TREE="$WORK_ROOT/cache/syzkaller-src"
    if [ ! -d "$SYZ_TREE/.git" ]; then
        echo "cloning syzkaller at $SYZ_COMMIT ..."
        git clone "$SYZ_REPO" "$SYZ_TREE"
    fi
    git -C "$SYZ_TREE" checkout "$SYZ_COMMIT" >/dev/null 2>&1
    if git -C "$SYZ_TREE" status --porcelain | grep -q .; then
        echo "ERROR: syzkaller tree is dirty; run with a clean checkout" >&2
        exit 1
    fi
fi
[ -f "$SYZ_TREE/tools/create-image.sh" ] || {
    echo "ERROR: no tools/create-image.sh in $SYZ_TREE" >&2; exit 1; }

# 2) prerequisites
sudo -n true 2>/dev/null || {
    echo "ERROR: passwordless sudo required for create-image.sh" >&2; exit 1; }
command -v debootstrap >/dev/null || {
    echo "ERROR: host package 'debootstrap' is required" >&2; exit 1; }

# 3) run the official builder (chroot -> 2 GiB plain-ext4 image + keypair)
SCRATCH="$(mktemp -d)"
trap 'sudo rm -rf "$SCRATCH" 2>/dev/null || rm -rf "$SCRATCH"' EXIT
( cd "$SCRATCH" && bash "$SYZ_TREE/tools/create-image.sh" -d bookworm )

# 4) collect outputs
[ -f "$SCRATCH/bookworm.img" ]   || { echo "ERROR: no bookworm.img produced" >&2;   exit 1; }
[ -f "$SCRATCH/bookworm.id_rsa" ] || { echo "ERROR: no bookworm.id_rsa produced" >&2; exit 1; }
cp "$SCRATCH/bookworm.img" "$OUT/bookworm-base.img"
cp "$SCRATCH/bookworm.id_rsa" "$OUT/bookworm.id_rsa"
cp "$SCRATCH/bookworm.id_rsa.pub" "$OUT/bookworm.id_rsa.pub"
chmod 600 "$OUT/bookworm.id_rsa"
# `sudo bash` leaves these root-owned; the user who runs bootstrap must be able to
# read the private key. Only the files are handed back, never the directory.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    chown "$SUDO_USER:$(id -gn "$SUDO_USER")" "$OUT/bookworm-base.img" \
        "$OUT/bookworm.id_rsa" "$OUT/bookworm.id_rsa.pub"
fi

echo
echo "site-local base + keypair generated:"
sha256sum "$OUT/bookworm-base.img" "$OUT/bookworm.id_rsa"
echo
cat <<EOF
  base      $OUT/bookworm-base.img    (2 GiB raw, plain ext4, never booted RW)
  key       $OUT/bookworm.id_rsa      (private)
  public    $OUT/bookworm.id_rsa.pub

Site-specific bytes (not reproducible) — record them and continue:

  python3 tools/bootstrap-kcov-env.py <TARGET> \\
    --base-image $OUT/bookworm-base.img \\
    --ssh-key $OUT/bookworm.id_rsa \\
    --deps-tar bundle/src/guest-deps.tar.gz \\
    --minor 1

syz-manager must use the same key (the sshkey setting of its config).
EOF