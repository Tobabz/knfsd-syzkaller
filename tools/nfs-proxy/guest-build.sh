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
    /src/rpc_record.c \
    /src/control.c /src/delta.c /src/walk.c /src/edit.c \
    /src/semantic.c /src/txn.c /src/nfs_decode.c /src/schema.c \
    /src/schema_nfs4.c /src/schema_nfs3.c /src/schema_nlm4.c /src/rpc_decode.c \
    /src/resolver.c /src/mutation_apply.c /src/activation.c /src/rule.c \
    /src/target.c /src/journal.c /src/jsonw.c /src/sha256.c \
    /src/lifecycle.c /src/cld.c
gcc -std=c11 -O2 -g -Wall -Wextra -Werror -Wshadow -Wconversion \
    -Wsign-conversion -Wpointer-arith -Wcast-qual -Wwrite-strings \
    -Wmissing-prototypes -Wstrict-prototypes -Wformat=2 \
    -o /work/guest-delta-replay /test/guest-delta-replay.c

validate_binary() {
    binary=$1
    label=$2
    if readelf --version-info "$binary" | \
        grep -E 'Name: GLIBC_2\.(3[7-9]|[4-9][0-9])'; then
        echo "the $label needs a newer glibc than the bookworm guest" >&2
        exit 1
    fi
    if readelf -d "$binary" | grep -E 'NEEDED.*libasan|NEEDED.*libubsan'; then
        echo "guest $label was accidentally built with sanitizers" >&2
        exit 1
    fi
    elf=$(readelf -h "$binary")
    class=$(printf '%s\n' "$elf" | sed -n 's/^ *Class: *//p')
    machine=$(printf '%s\n' "$elf" | sed -n 's/^ *Machine: *//p')
    if [ "$class" != ELF64 ] || \
        [ "$machine" != 'Advanced Micro Devices X86-64' ]; then
        echo "the guest $label is '$class $machine', not ELF64 x86-64" >&2
        exit 1
    fi
}

max_glibc() {
    readelf --version-info "$1" | grep -oE 'GLIBC_[0-9.]+' | \
        sort -Vu | tail -1 || true
}

validate_binary /work/nfs-proxy relay
validate_binary /work/guest-delta-replay replay-probe
{
    echo "platform: $(uname -m), dpkg $arch, Debian $(cat /etc/debian_version)"
    echo "relay_elf: $(readelf -h /work/nfs-proxy | sed -n 's/^ *Class: */class=/p; s/^ *Machine: */machine=/p' | paste -sd ' ' -)"
    echo "probe_elf: $(readelf -h /work/guest-delta-replay | sed -n 's/^ *Class: */class=/p; s/^ *Machine: */machine=/p' | paste -sd ' ' -)"
    echo "relay_glibc_max: $(max_glibc /work/nfs-proxy)"
    echo "probe_glibc_max: $(max_glibc /work/guest-delta-replay)"
    gcc --version | sed -n '1p'
    ldd --version 2>&1 | sed -n '1p'
    readelf --version | sed -n '1p'
    sha256sum /src/main.c /src/proxy.c /src/proxy.h /src/framing.c /src/framing.h \
        /src/rpc_record.c /src/rpc_record.h \
        /src/control.c /src/control.h /src/delta.c /src/delta.h \
        /src/walk.c /src/walk.h /src/edit.c /src/edit.h \
        /src/semantic.c /src/semantic.h /src/txn.c /src/txn.h \
        /src/nfs_decode.c /src/nfs_decode.h /src/schema.c /src/schema.h \
        /src/schema_nfs4.c /src/schema_nfs3.c /src/schema_nlm4.c /src/rpc_decode.c \
        /src/rpc_decode.h \
        /src/resolver.c /src/resolver.h /src/mutation_apply.c \
        /src/mutation_apply.h /src/activation.c /src/activation.h \
        /src/rule.c /src/rule.h /src/target.c /src/target.h \
        /src/journal.c /src/journal.h /src/jsonw.c /src/jsonw.h \
        /src/sha256.c /src/sha256.h /src/lifecycle.c /src/lifecycle.h \
        /src/cld.c /src/cld.h \
        /src/concrete_edit.h \
        /test/guest-delta-replay.c
    sha256sum /work/nfs-proxy /work/guest-delta-replay
} > /work/provenance.txt
chown "$1:$2" /work/nfs-proxy /work/guest-delta-replay /work/provenance.txt
echo 'bookworm x86-64 guest relay and replay probe ABI: PASS'
