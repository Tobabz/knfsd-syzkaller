#!/usr/bin/env bash
# Build the pinned upstream NFS-Ganesha V15.6 for the Bookworm guest.
set -euo pipefail

tools=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$tools")
base=
out=$repo/bundle/src/guest-deps-ganesha-v15.6.tar.gz
work=${TMPDIR:-/tmp}/ganesha-v156-build
while [ "$#" -gt 0 ]; do
    case "$1" in
        --base) base=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --help) echo "Usage: $0 [--base DEPENDENCY_TAR] [--out NEW_TAR] [--work DIR]"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
for cmd in docker git sha256sum tar realpath; do
    command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 2; }
mkdir -p "$work"
work=$(realpath "$work")
if [ -z "$base" ]; then
    base=$work/bookworm-baseline.tar.gz
    trap 'rm -f "$base"' EXIT
    [ -s "$base" ] || bash "$tools/build-ganesha-deps.sh" --out "$base"
fi
[ -s "$base" ] || { echo "missing baseline: $base" >&2; exit 2; }
source=$work/upstream
commit=98eb4beb642674d4188361008495bb6d585d393d
ntirpc_commit=848ab93b63174338ad72875bddd5680113f64b39
if [ ! -e "$source" ]; then
    git clone --depth 1 --branch V15.6 --recurse-submodules \
        https://github.com/nfs-ganesha/nfs-ganesha.git "$source"
fi
[ "$(git -C "$source" rev-parse HEAD)" = "$commit" ] || {
    echo "unexpected Ganesha source revision" >&2; exit 1;
}
[ "$(git -C "$source/src/libntirpc" rev-parse HEAD)" = "$ntirpc_commit" ] || {
    echo "unexpected libntirpc source revision" >&2; exit 1;
}
[ -z "$(git -C "$source" status --porcelain --ignore-submodules=none)" ] || {
    echo "source tree contains local modifications" >&2; exit 1;
}
docker run --rm --init \
    --mount "type=bind,src=$source,dst=/src,readonly" \
    --mount "type=bind,src=$work,dst=/work" \
    --mount "type=bind,src=$tools/ganesha-v15-container.sh,dst=/scripts/build.sh,readonly" \
    debian:bookworm bash /scripts/build.sh
bash "$tools/package-ganesha-v15.sh" "$base" "$work" "$out"
