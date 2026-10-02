#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -qq -y --no-install-recommends \
    build-essential cmake pkg-config bison flex patch ca-certificates python3 git \
    libdbus-1-dev libnfsidmap-dev libwbclient-dev libkrb5-dev \
    libblkid-dev libattr1-dev libacl1-dev liburcu-dev libcap-dev uuid-dev \
    libtirpc-dev libntirpc-dev libssl-dev binutils > /work/apt.log 2>&1 || {
        tail -100 /work/apt.log >&2; exit 1;
    }

rm -rf /work/source /work/build
mkdir -p /work/source
cp -a /src/. /work/source/
git config --global --add safe.directory /work/source
cmake -S /work/source/src -B /work/build \
    -DCMAKE_BUILD_TYPE=Release -DUSE_SYSTEM_NTIRPC=OFF \
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
    -DUSE_FSAL_SAUNAFS=OFF -DUSE_MONITORING=OFF \
    > /work/configure.log 2>&1 || { tail -140 /work/configure.log >&2; exit 1; }

cmake --build /work/build -j 4 --target ganesha.nfsd fsalvfs \
    > /work/build.log 2>&1 || { tail -140 /work/build.log >&2; exit 1; }

find /work/build -type f \( -name 'ganesha.nfsd' -o -name 'libganesha_nfsd.so*' -o -name 'libfsalvfs.so*' -o -name 'libntirpc.so*' \) -print
