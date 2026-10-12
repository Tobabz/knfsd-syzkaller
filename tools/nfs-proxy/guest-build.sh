#!/usr/bin/env bash
# Called in debian:bookworm by build-guest.sh to build the guest ABI binary.
# Sanitizer checks run in the host build before this script.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# The guest is x86_64 (see build-guest.sh).  Check the container before the
# build and the binary after it: neither check implies the other.
arch=$(dpkg --print-architecture)
if [ "$arch" != amd64 ]; then
    echo "the guest relay is built for amd64; this container is $arch" >&2
    exit 1
fi
apt-get update -qq
apt-get install -qq -y --no-install-recommends gcc libc6-dev binutils \
    > /work/apt.log 2>&1 || { tail -80 /work/apt.log >&2; exit 1; }
gcc -std=c11 -O2 -g -pthread -Wall -Wextra -Werror -Wshadow \
    -Wconversion -Wsign-conversion -Wpointer-arith -Wcast-qual \
    -Wwrite-strings -Wmissing-prototypes -Wstrict-prototypes -Wformat=2 \
    -I/src -o /work/nfs-proxy /src/main.c /src/proxy.c /src/framing.c \
    /src/control.c /src/delta.c /src/walk.c /src/edit.c
if readelf --version-info /work/nfs-proxy | \
    grep -E 'Name: GLIBC_2\.(3[7-9]|[4-9][0-9])'; then
    echo 'the relay needs a newer glibc than the bookworm guest' >&2
    exit 1
fi
if readelf -d /work/nfs-proxy | grep -E 'NEEDED.*libasan|NEEDED.*libubsan'; then
    echo 'guest relay was accidentally built with sanitizers' >&2
    exit 1
fi
elf=$(readelf -h /work/nfs-proxy)
class=$(printf '%s\n' "$elf" | sed -n 's/^ *Class: *//p')
machine=$(printf '%s\n' "$elf" | sed -n 's/^ *Machine: *//p')
if [ "$class" != ELF64 ] || [ "$machine" != 'Advanced Micro Devices X86-64' ]; then
    echo "the guest relay is '$class $machine', not ELF64 x86-64" >&2
    exit 1
fi
{
    echo "platform: $(uname -m), dpkg $arch, Debian $(cat /etc/debian_version)"
    echo "elf: $class $machine"
    gcc --version | head -1
    readelf --version | head -1
    sha256sum /src/main.c /src/proxy.c /src/proxy.h /src/framing.c /src/framing.h \
        /src/control.c /src/control.h /src/delta.c /src/delta.h \
        /src/walk.c /src/walk.h /src/edit.c /src/edit.h
    sha256sum /work/nfs-proxy
} > /work/provenance.txt
chown "$1:$2" /work/nfs-proxy /work/provenance.txt
echo 'bookworm x86-64 guest relay ABI: PASS'
