#!/usr/bin/env bash
# Build the host-gated relay against the guest's Debian bookworm glibc.
#
# The guest is x86_64: run-verify.sh boots arch/x86's bzImage, which bootstrap
# runs under qemu-system-x86_64.  So the relay is built for linux/amd64 whatever
# the host is.  On an arm64 host Docker runs the amd64 image under emulation;
# where it cannot, docker run fails rather than build for the wrong machine.
# guest-build.sh then checks the container and the binary's ELF header itself.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${KOOV_NFS_PROXY_GUEST:-$repo/bundle/src/nfs-proxy-control-guest}
work=${KOOV_NFS_PROXY_GUEST_WORK:-${TMPDIR:-/tmp}/nfs-proxy-guest-build}
platform=linux/amd64
image=debian:bookworm
while [ "$#" -gt 0 ]; do
    case "$1" in
        --out) out=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --help) echo "Usage: $0 [--out FILE] [--work DIR]"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
command -v docker >/dev/null
case "$out" in
    /*) ;;
    *) out="$PWD/$out" ;;
esac
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 2; }
"$here/build.sh"
mkdir -p "$work"
work=$(cd "$work" && pwd)
docker run --rm --init --platform "$platform" \
    --mount "type=bind,src=$here/src,dst=/src,readonly" \
    --mount "type=bind,src=$work,dst=/work" \
    --mount "type=bind,src=$here/guest-build.sh,dst=/scripts/build.sh,readonly" \
    "$image" bash /scripts/build.sh "$(id -u)" "$(id -g)"
[ -s "$work/nfs-proxy" ] && [ -s "$work/provenance.txt" ]
# Identify the image as the local image store reports it.  The architecture
# that counts is the one guest-build.sh verified inside the container.
{
    echo "docker run --platform $platform $image"
    docker image inspect --format \
        'image: {{.Id}} {{.Os}}/{{.Architecture}} {{join .RepoDigests " "}}' \
        "$image" || echo "image: docker image inspect failed"
} >> "$work/provenance.txt"
mkdir -p "$(dirname "$out")"
mv "$work/nfs-proxy" "$out"
cp "$work/provenance.txt" "$out.provenance"
sha256sum "$out"
echo "bookworm relay: $out"
