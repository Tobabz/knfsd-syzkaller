#!/usr/bin/env bash
# Overlay the V15.6 source build on the existing Bookworm NFS dependency set.
set -euo pipefail

base=${1:?usage: package-ganesha-v15.sh BASE_TAR WORK_DIR OUT_TAR}
work=${2:?usage: package-ganesha-v15.sh BASE_TAR WORK_DIR OUT_TAR}
out=${3:?usage: package-ganesha-v15.sh BASE_TAR WORK_DIR OUT_TAR}
[ -s "$base" ] || { echo "missing baseline: $base" >&2; exit 2; }
[ ! -e "$out" ] || { echo "output already exists: $out" >&2; exit 2; }
build=$work/build
daemon=$build/ganesha.nfsd
core=$build/MainNFSD/libganesha_nfsd.so.15.6
plugin=$build/FSAL/FSAL_VFS/vfs/libfsalvfs.so
ntirpc=$build/libntirpc/src/libntirpc.so.15.5
for file in "$daemon" "$core" "$plugin" "$ntirpc"; do
    [ -s "$file" ] || { echo "missing build output: $file" >&2; exit 2; }
    if readelf --version-info "$file" | grep -E 'Name: GLIBC_2\.(3[7-9]|[4-9][0-9])'; then
        echo "guest-incompatible glibc requirement: $file" >&2
        exit 1
    fi
done

stage=$work/stage
rm -rf "$stage"
mkdir -p "$stage"
tar -xzf "$base" -C "$stage"
lib=$stage/usr/lib/x86_64-linux-gnu
rm -f "$lib/libganesha_nfsd.so" "$lib/libganesha_nfsd.so.4.3" \
    "$lib/libntirpc.so.4.3"
install -m 0755 "$daemon" "$stage/usr/sbin/ganesha.nfsd"
install -m 0644 "$core" "$lib/libganesha_nfsd.so.15.6"
ln -s libganesha_nfsd.so.15.6 "$lib/libganesha_nfsd.so"
install -m 0644 "$ntirpc" "$lib/libntirpc.so.15.5"
install -m 0644 "$plugin" "$stage/usr/lib/ganesha/libfsalvfs.so"
install -m 0644 "$plugin" "$lib/ganesha/libfsalvfs.so"

# Resolve dependencies and check the reported daemon version against Bookworm.
docker run --rm --init --mount "type=bind,src=$(realpath "$stage"),dst=/stage" \
    debian:bookworm bash -ec '
        apt-get update -qq > /tmp/apt.log 2>&1
        apt-get install -qq -y --no-install-recommends libbsd0 libmd0 >> /tmp/apt.log 2>&1 || { tail -50 /tmp/apt.log; exit 1; }
        cp -L /usr/lib/x86_64-linux-gnu/libbsd.so.0 /stage/usr/lib/x86_64-linux-gnu/
        cp -L /usr/lib/x86_64-linux-gnu/libmd.so.0 /stage/usr/lib/x86_64-linux-gnu/
        export LD_LIBRARY_PATH=/stage/usr/lib/x86_64-linux-gnu:/stage/lib/x86_64-linux-gnu:/stage/usr/lib/ganesha-extra
        ldd /stage/usr/sbin/ganesha.nfsd > /tmp/ldd.log
        if grep -q "not found" /tmp/ldd.log; then cat /tmp/ldd.log; exit 1; fi
        /stage/usr/sbin/ganesha.nfsd -v 2>&1 | grep -F "15.6"
    '
mkdir -p "$(dirname "$out")"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -czf "$out" -C "$stage" .
{
    echo 'nfs-ganesha=V15.6'
    echo 'commit=98eb4beb642674d4188361008495bb6d585d393d'
    echo 'libntirpc=848ab93b63174338ad72875bddd5680113f64b39'
    sha256sum "$base" "$out" "$daemon" "$core" "$plugin" "$ntirpc"
} > "$work/provenance.txt"
echo "wrote $out"
cat "$work/provenance.txt"
