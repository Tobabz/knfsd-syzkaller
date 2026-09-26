#!/usr/bin/env bash
# Rebuild the guest's Debian bookworm NFS-Ganesha 4.3 with AddressSanitizer.
# The input Ganesha deps tarball is immutable; the output is a separate,
# site-generated tarball selected with KOOV_GANESHA_DEPS.
set -euo pipefail

tools=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$tools")
base=${KOOV_GANESHA_DEPS_BASE:-$repo/bundle/src/guest-deps-ganesha.tar.gz}
out=${KOOV_GANESHA_ASAN_OUT:-$repo/bundle/src/guest-deps-ganesha-asan.tar.gz}
work=${KOOV_GANESHA_ASAN_WORK:-${TMPDIR:-/tmp}/ganesha-asan-build}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --base) base=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --help)
            echo "Usage: $0 [--base BASE_TAR] [--out ASAN_TAR] [--work DIR]"
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for cmd in docker curl sha256sum tar realpath; do
    command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[ -s "$base" ] || { echo "missing baseline Ganesha deps: $base" >&2; exit 2; }
mkdir -p "$work"
work=$(cd "$work" && pwd)
base=$(realpath "$base")
out=$(realpath -m "$out")
[ "$out" != "$base" ] || { echo "refusing to overwrite the input" >&2; exit 2; }
[ ! -e "$out" ] || { echo "output already exists (remove intentionally): $out" >&2; exit 2; }

mirror=https://deb.debian.org/debian/pool/main/n/nfs-ganesha
source_name=nfs-ganesha_4.3.orig.tar.gz
patch_name=nfs-ganesha_4.3-2.debian.tar.xz
source_sha=d4efd020edf4dfe65abfd0f0f66eb4390613360f99dce4354467ab297e0e1c0f
patch_sha=45421606d92d9e33a25ec55e18bd8bcc8dcbe9472beba344ef60b7b2cdc635ee
for spec in "$source_name:$source_sha" "$patch_name:$patch_sha"; do
    file=${spec%%:*}
    expected=${spec#*:}
    if [ ! -s "$work/$file" ]; then
        curl -fLsS --retry 3 --output "$work/$file.tmp" "$mirror/$file"
        mv "$work/$file.tmp" "$work/$file"
    fi
    echo "$expected  $work/$file" | sha256sum -c -
done

echo "baseline $(sha256sum "$base")"
echo "Compiling in Debian bookworm (GCC/libasan from the guest's distribution)."
docker run --rm --init \
    --mount "type=bind,src=$work,dst=/work" \
    --mount "type=bind,src=$base,dst=/inputs/baseline.tar.gz,readonly" \
    --mount "type=bind,src=$tools/ganesha-asan-container.sh,dst=/scripts/build.sh,readonly" \
    debian:bookworm bash /scripts/build.sh "$(id -u)" "$(id -g)"

[ -s "$work/guest-deps-ganesha-asan.tar.gz" ] || { echo 'missing generated tarball' >&2; exit 1; }
mkdir -p "$(dirname "$out")"
mv "$work/guest-deps-ganesha-asan.tar.gz" "$out"
echo "ASan deps: $out"
sha256sum "$out" "$base"
echo "Build details: $work/provenance.txt"
