#!/usr/bin/env bash
# Build the host-gated relay against the guest's Debian bookworm glibc.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${KOOV_NFS_PROXY_GUEST:-$repo/bundle/src/nfs-proxy-guest}
work=${KOOV_NFS_PROXY_GUEST_WORK:-${TMPDIR:-/tmp}/nfs-proxy-guest-build}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --out) out=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --help) echo "Usage: $0 [--out FILE] [--work DIR]"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
command -v docker >/dev/null
command -v realpath >/dev/null
out=$(realpath -m "$out")
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 2; }
"$here/build.sh"
mkdir -p "$work"
work=$(cd "$work" && pwd)
docker run --rm --init \
    --mount "type=bind,src=$here/src,dst=/src,readonly" \
    --mount "type=bind,src=$work,dst=/work" \
    --mount "type=bind,src=$here/guest-build.sh,dst=/scripts/build.sh,readonly" \
    debian:bookworm bash /scripts/build.sh "$(id -u)" "$(id -g)"
[ -s "$work/nfs-proxy" ] && [ -s "$work/provenance.txt" ]
mkdir -p "$(dirname "$out")"
mv "$work/nfs-proxy" "$out"
cp "$work/provenance.txt" "$out.provenance"
sha256sum "$out"
echo "bookworm relay: $out"
