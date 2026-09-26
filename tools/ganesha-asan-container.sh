#!/usr/bin/env bash
# Runs inside debian:bookworm from tools/build-ganesha-asan.sh.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -qq -y --no-install-recommends \
    build-essential cmake pkg-config bison flex patch ca-certificates python3 \
    libntirpc-dev libdbus-1-dev libnfsidmap-dev libwbclient-dev libkrb5-dev \
    libblkid-dev libattr1-dev libacl1-dev liburcu-dev libcap-dev uuid-dev \
    libtirpc-dev libasan8 binutils > /work/apt.log 2>&1 || {
        tail -100 /work/apt.log >&2; exit 1;
    }

# Reusing --work only reuses downloaded, pinned tarballs; always configure
# from a fresh extraction so stale local edits cannot change the source.
rm -rf /work/source /work/build
mkdir -p /work/source
tar -xzf /work/nfs-ganesha_4.3.orig.tar.gz -C /work/source --strip-components=1
tar -xJf /work/nfs-ganesha_4.3-2.debian.tar.xz -C /work/source
while IFS= read -r p; do
    [ -z "$p" ] || patch -s -d /work/source -p1 \
        < "/work/source/debian/patches/$p"
done < /work/source/debian/patches/series

# Global compiler and linker flags cover all the core OBJECT targets, the
# Ganesha executable, the shared core library and the dlopen()ed VFS module.
# CMake's add_sanitizers() on its own need not cover every target.
cmake -S /work/source/src -B /work/build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
    -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address' \
    -DSANITIZE_ADDRESS=ON -DUSE_SYSTEM_NTIRPC=ON \
    -DBUILD_CONFIG=debian -DLIB_INSTALL_DIR=/usr/lib/ganesha \
    -DFSAL_DESTINATION=/usr/lib/x86_64-linux-gnu/ganesha \
    -DUSE_DBUS=ON -DUSE_NFSIDMAP=ON -DUSE_FSAL_VFS=ON \
    -DUSE_FSAL_XFS=OFF -DUSE_FSAL_LUSTRE=OFF \
    -DUSE_FSAL_CEPH=OFF -DUSE_FSAL_RGW=OFF -DUSE_FSAL_GPFS=OFF \
    -DUSE_FSAL_KVSFS=OFF -DUSE_FSAL_GLUSTER=OFF \
    -DUSE_FSAL_PROXY_V4=OFF -DUSE_FSAL_PROXY_V3=OFF \
    -DUSE_RADOS_RECOV=OFF -DRADOS_URLS=OFF \
    -DUSE_LTTNG=OFF -DUSE_ADMIN_TOOLS=OFF -DUSE_MAN_PAGE=OFF \
    -DUSE_9P=OFF -DUSE_FSAL_NULL=OFF -DUSE_FSAL_MEM=OFF \
    -D_MSPAC_SUPPORT=ON \
    > /work/configure.log 2>&1 || { tail -140 /work/configure.log >&2; exit 1; }

cmake --build /work/build -j 4 --target ganesha.nfsd fsalvfs \
    > /work/build.log 2>&1 || { tail -140 /work/build.log >&2; exit 1; }

daemon=/work/build/ganesha.nfsd
core=/work/build/MainNFSD/libganesha_nfsd.so.4.3
plugin=/work/build/FSAL/FSAL_VFS/vfs/libfsalvfs.so
for file in "$daemon" "$core" "$plugin"; do
    [ -s "$file" ] || { echo "expected build output missing: $file" >&2; exit 1; }
    readelf -d "$file" | grep -q 'Shared library: \[libasan.so.8\]' || {
        echo "missing libasan DT_NEEDED: $file" >&2; exit 1;
    }
    nm -D "$file" | grep '__asan_init' >/dev/null || {
        echo "missing ASan instrumentation: $file" >&2; exit 1;
    }
done

rm -rf /work/stage
mkdir -p /work/stage
tar -xzf /inputs/baseline.tar.gz -C /work/stage
dest=/work/stage/usr/lib/x86_64-linux-gnu
install -m 0755 "$daemon" /work/stage/usr/sbin/ganesha.nfsd
install -m 0644 "$core" "$dest/libganesha_nfsd.so.4.3"
install -m 0644 "$core" "$dest/libganesha_nfsd.so"
install -m 0644 "$plugin" /work/stage/usr/lib/ganesha/libfsalvfs.so
install -m 0644 "$plugin" "$dest/ganesha/libfsalvfs.so"

# Build and link against bookworm's ASan runtime, not the Ubuntu host's.
runtime=$(gcc -print-file-name=libasan.so.8)
[ -f "$runtime" ] || runtime=/usr/lib/x86_64-linux-gnu/libasan.so.8
runtime=$(readlink -f "$runtime")
[ -s "$runtime" ] || { echo 'libasan.so.8 missing in bookworm container' >&2; exit 1; }
install -m 0644 "$runtime" "$dest/$(basename "$runtime")"
ln -s "$(basename "$runtime")" "$dest/libasan.so.8"

# A guest uses glibc 2.36. The injected binaries, plugin, and runtime may not
# require newer GLIBC versions; inspect before packaging, not after a boot.
for file in "$daemon" "$core" "$plugin" "$runtime"; do
    if readelf --version-info "$file" | grep -E 'Name: GLIBC_2\.(3[7-9]|[4-9][0-9])' ; then
        echo "guest-incompatible glibc requirement: $file" >&2
        exit 1
    fi
done

# Check actual dynamic resolution with the same global path as the fixture.
export LD_LIBRARY_PATH="$dest:/work/stage/lib/x86_64-linux-gnu"
ldd /work/stage/usr/sbin/ganesha.nfsd > /work/ldd.log
if grep -q 'not found' /work/ldd.log; then
    cat /work/ldd.log >&2
    exit 1
fi

(
    cd /work/stage
    tar -czf /work/guest-deps-ganesha-asan.tar.gz .
)
{
    echo 'source=nfs-ganesha 4.3-2 (Debian source patches applied)'
    sha256sum /work/nfs-ganesha_4.3.orig.tar.gz /work/nfs-ganesha_4.3-2.debian.tar.xz
    sha256sum /inputs/baseline.tar.gz /work/guest-deps-ganesha-asan.tar.gz
    sha256sum "$daemon" "$core" "$plugin" "$runtime"
    gcc --version | head -1
    cmake --version | head -1
    dpkg-query -W -f='${Package}=${Version}\n' gcc-12 libasan8 libntirpc4.3 libntirpc-dev
    grep '^USE_\|^SANITIZE_ADDRESS' /work/build/CMakeCache.txt | grep -E '(USE_DBUS|USE_NFSIDMAP|USE_FSAL_VFS|USE_SYSTEM_NTIRPC|SANITIZE_ADDRESS)' || true
} > /work/provenance.txt
chown "$1:$2" /work/guest-deps-ganesha-asan.tar.gz /work/provenance.txt
echo 'ASan instrumentation, guest ABI, dynamic dependency checks: PASS'
