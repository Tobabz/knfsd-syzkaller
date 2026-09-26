#!/usr/bin/env bash
# tools/build-ganesha-deps.sh -- build the guest-side NFS-Ganesha userspace.
#
# WHAT THIS PRODUCES
#
#   bundle/src/guest-deps-ganesha.tar.gz
#
# extracted by the runner into /opt/kcov-nfs/deps, whose usr/sbin, sbin and
# lib trees are prepended to the guest PATH and LD_LIBRARY_PATH.  The lane
# fixture (tools/ganesha-lane.sh) then starts ganesha.nfsd and dbus-daemon from
# there.  No guest image is rebuilt and no root is required anywhere.
#
# WHY A SEPARATE TARBALL
#
# bundle/src/guest-deps.tar.gz is an input to already-recorded AB / S3 / S4
# evidence.  Extending it would silently redefine that evidence, so this script
# writes a SECOND tarball that embeds the original bytes verbatim plus the
# Ganesha delta.  Each tarball keeps its own recorded hash, and only the
# Ganesha runner points at the new one.  bundle/src/* is gitignored except for
# the original, so this tarball is a site-generated asset: THIS SCRIPT is its
# provenance, which is why it lives in tools/.
#
# WHY DEBIAN PACKAGES AND NOT A SOURCE BUILD
#
# The host has no development headers at all -- libtirpc, libsqlite3,
# libjansson, libevent, libcap and the rest are absent from /usr/include -- and
# no sudo and no pip, so a source build would mean building that entire
# dependency chain from source.  Debian already ships a working
# nfs-ganesha 4.3-2, and the runner's existing deps-tarball mechanism is
# precisely the sanctioned way to carry extra userspace into the guest.
#
# CONSEQUENCE: this is NOT an ASAN or UBSAN build.  ASAN was wanted to catch
# memory bugs in Ganesha itself, but the axis measures kernel coverage, and a
# Ganesha crash is caught by the fixture's liveness gate.  Building the
# dependency chain from source to obtain ASAN is not a good trade.
# ganesha.nfsd honours ASAN_OPTIONS and UBSAN_OPTIONS regardless, so a
# sanitized build can be dropped in later without touching the fixture.
#
# REQUIREMENTS: curl, dpkg-deb, xz, find, readelf.  No root, no sudo.
# Network access to deb.debian.org.  A few hundred MiB of scratch space.
#
# USAGE
#   tools/build-ganesha-deps.sh [--out FILE] [--work DIR] [--keep] [--suite S]
#
#   --out     output tarball  (default: bundle/src/guest-deps-ganesha.tar.gz)
#   --work    scratch dir     (default: a fresh mktemp -d, removed on exit)
#   --keep    keep the scratch dir, including the extracted .debs
#   --suite   Debian suite    (default: bookworm)
#
# The build prints, for every shipped shared object, whether it is injected
# here or expected from the guest base image.  That list is the honest record
# of the remaining assumption: anything marked "FROM GUEST BASE" is untested
# until a guest runs it, and the guest loader names the first wrong guess
# exactly (it did: libdbus-1.so.3 was assumed present and was not).
set -eu

SUITE=bookworm
MIRROR=http://deb.debian.org/debian
OUT=
WORK=
KEEP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        --suite) SUITE=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,/^set -eu/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

TOOLS=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$TOOLS")
[ -n "$OUT" ] || OUT="$REPO/bundle/src/guest-deps-ganesha.tar.gz"
ORIG="$REPO/bundle/src/guest-deps.tar.gz"
[ -s "$ORIG" ] || { echo "missing $ORIG" >&2; exit 2; }

if [ -z "$WORK" ]; then
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/ganesha-deps.XXXXXX")
    [ "$KEEP" = 1 ] || trap 'rm -rf "$WORK"' EXIT
else
    mkdir -p "$WORK"
fi
IDX="$WORK/Packages"
DEBS="$WORK/debs"
TREE="$WORK/tree"
STAGE="$WORK/stage"
EXTRADEB="$WORK/extradebs"
EXTRA="$STAGE/usr/lib/ganesha-extra"
LIBD="$STAGE/usr/lib/x86_64-linux-gnu"
mkdir -p "$DEBS" "$TREE" "$STAGE/usr/sbin" "$STAGE/usr/lib/ganesha" \
         "$LIBD" "$LIBD/ganesha" "$EXTRA" "$EXTRADEB"

echo "=== 0. bookworm index ==="
if [ ! -s "$IDX" ]; then
    curl -sS --retry 2 -o "$WORK/Packages.xz" \
        "$MIRROR/dists/$SUITE/main/binary-amd64/Packages.xz"
    xz -dc "$WORK/Packages.xz" > "$IDX"
fi
echo "   $SUITE: $(wc -l < "$IDX") index lines"

# ---------------------------------------------------------------------------
# 1. dependency closure
# ---------------------------------------------------------------------------
# Packages assumed to come from the guest base image, which is a debootstrap
# bookworm carrying syzkaller's NFS set (nfs-utils and its util-linux chain).
#
# NOT assumed, and deliberately absent from this list: libdbus-1-3.  nfs-utils
# and util-linux imply libacl1, libblkid1, libcap2, libnfsidmap1, krb5 and
# libcom-err2, but nothing in the base implies dbus, and Ganesha links
# libdbus-1.so.3 unconditionally.  The guest loader named it.  Do not re-add it.
python3 - "$IDX" "$WORK/closure.txt" <<'PY'
import re
import sys

idx, out = sys.argv[1], sys.argv[2]
pkgs, cur = {}, {}


def flush():
    name = cur.get('Package')
    if name and name not in pkgs:
        pkgs[name] = cur


for line in open(idx, encoding='utf-8', errors='replace'):
    line = line.rstrip('\n')
    if not line:
        flush()
        cur = {}
        continue
    m = re.match(r'^([A-Za-z0-9-]+): (.*)$', line)
    if m:
        cur[m.group(1)] = m.group(2)
flush()

SKIP = {
    # the toolchain / libc / init packages
    'libc6', 'libgcc-s1', 'libstdc++6', 'libc-bin', 'debconf', 'dpkg',
    'install-info', 'multiarch-support', 'ucf', 'init-system-helpers',
    'libpam0g', 'libaudit1', 'libcap2', 'libacl1', 'adduser', 'passwd',
    'sysvinit-utils', 'libcrypt1', 'libdb5.3', 'libdebconfclient0',
    'dconf-service', 'libdconf1', 'libgtk-3-0', 'libgdk-pixbuf-2.0-0',
    'libglib2.0-0', 'libpango-1.0-0', 'libcairo2', 'libudev1',
    # implied by the base's NFS + util-linux set
    'libnfsidmap1', 'rpcbind', 'nfs-common',
    'libgssapi-krb5-2', 'libkrb5-3', 'libcom-err2', 'libk5crypto3',
    'libkrb5support0', 'libkeyutils1', 'libtirpc3', 'libntirpc4',
    'libuuid1', 'libblkid1', 'libmount1', 'libselinux1', 'libpcre2-8-0',
    'libffi8', 'libsystemd0', 'libcap-ng0', 'libexpat1',
    'libnsl2', 'libtirpc3', 'libevent-2.1-7', 'libbsd0', 'libmd0',
}


def deps_of(name):
    entry = pkgs.get(name)
    if not entry:
        return []
    found = []
    for alternative in entry.get('Depends', '').split(','):
        alternative = alternative.strip()
        if not alternative:
            continue
        first = alternative.split('|')[0].strip()
        first = re.sub(r'\s*\(.*\)$', '', first).strip()
        first = re.sub(r'\s*\[.*\]$', '', first).strip()
        if first:
            found.append(first)
    return found


WANT = ['nfs-ganesha', 'nfs-ganesha-vfs']
seen, order, queue = set(), [], list(WANT)
while queue:
    name = queue.pop(0)
    if name in seen:
        continue
    seen.add(name)
    if name in SKIP or name not in pkgs:
        continue
    order.append(name)
    queue.extend(deps_of(name))

with open(out, 'w') as handle:
    for name in order:
        handle.write('%s\t%s\t%s\n' % (name, pkgs[name].get('Version', '?'),
                                       pkgs[name].get('Filename', '?')))

# The SKIP list is an assumption about the guest base, and assumptions here are
# where this build has actually gone wrong: libdbus-1-3 was skipped on the
# reasoning that the base "surely" has it, ganesha.nfsd then could not exec at
# all, and a whole guest boot was spent on it.  The comment above the set says
# so explicitly -- and then the entry was re-added anyway while this script was
# being consolidated, which only the byte-identity check caught.  Assert the
# invariant in code so the prose and the list cannot drift apart again.
MUST_FETCH = ('libdbus-1-3',)
present = {line.split('\t')[0] for line in open(out, encoding='utf-8')}
for required in MUST_FETCH:
    if required in SKIP:
        sys.exit('FATAL: %s is in SKIP but must be fetched: Ganesha links '
                 'libdbus-1.so.3 unconditionally and the guest base does not '
                 'have it (the guest loader proved that).' % required)
    if required not in present:
        sys.exit('FATAL: %s is missing from the resolved closure.' % required)

print('   closure: %d packages' % len(order))
for name in order:
    print('     %-24s %s' % (name, pkgs[name].get('Version', '?')))
PY

echo
echo "=== 1b. fetch the dbus-daemon private libraries (staged in step 4) ==="
# dbus-daemon links libaudit / libcap-ng / libexpat / libselinux / libsystemd.
# They are assumed present in the base by the same SKIP list that wrongly
# assumed libdbus, so they are shipped -- but into a directory that is NOT the
# global LD_LIBRARY_PATH.  Putting a different libsystemd or libselinux on the
# global path would make every guest process prefer our copies over the system
# ones, which is a far larger hazard than the one being fixed.  The fixture
# applies this directory to the dbus-daemon process alone.
#
# Only the .debs are fetched here.  Staging them into $STAGE happens in step 4,
# so that the "original guest-deps files" count in step 3 reports the original
# tarball's own contents and not this script's additions.
for pkg in libaudit1 libcap-ng0 libexpat1 libselinux1 libsystemd0; do
    fname=$(awk -v want="Package: $pkg" '
        $0 == want { hit = 1; next }
        hit && /^Filename: / { sub(/^Filename: /, ""); print; exit }
        hit && /^$/ { exit }
    ' "$IDX")
    if [ -z "$fname" ]; then
        echo "   FATAL: $pkg is not in the $SUITE index" >&2
        exit 6
    fi
    deb="$EXTRADEB/$(basename "$fname")"
    [ -s "$deb" ] || curl -sS --retry 2 -o "$deb" "$MIRROR/$fname"
    printf '   fetched %s\n' "$(basename "$fname")"
done

echo
echo "=== 2. download and extract the closure ==="
while IFS="$(printf '\t')" read -r name version filename; do
    [ -n "$filename" ] || continue
    deb="$DEBS/$(basename "$filename")"
    [ -s "$deb" ] || curl -sS --retry 2 -o "$deb" "$MIRROR/$filename"
    dpkg-deb -x "$deb" "$TREE"
    printf '   %-46s %8s bytes\n' "$(basename "$filename")" \
        "$(stat -c %s "$deb")"
done < "$WORK/closure.txt"

echo
echo "=== 3. stage the tree ==="
# The original guest-deps content, byte for byte: this is what keeps the
# already-recorded evidence reproducible while adding a second tarball.
tar -xzf "$ORIG" -C "$STAGE"
echo "   original guest-deps files: $(find "$STAGE" -type f | wc -l) (the original tarball, verbatim)"

# PATH PLACEMENT RULE, learned the hard way twice.  The fixture sets
#   PATH=/opt/kcov-nfs/deps/usr/sbin:/opt/kcow-nfs/deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin
# so the only injected directory that is actually on PATH is usr/sbin.
# Debian installs both ganesha.nfsd and dbus-daemon into /usr/bin, which the
# lane cannot see; the fixture precondition check caught each one in turn.
# Every executable the lane must exec therefore goes to usr/sbin.
for b in ganesha.nfsd dbus-daemon dbus-uuidgen; do
    if [ -f "$TREE/usr/bin/$b" ]; then
        install -m 0755 "$TREE/usr/bin/$b" "$STAGE/usr/sbin/$b"
        echo "   shipped usr/sbin/$b"
    else
        echo "   FATAL: $b is absent from the closure" >&2
        exit 7
    fi
done

# Every shared object the closure provides, flattened onto the directory the
# fixture already puts on LD_LIBRARY_PATH, so no LD_LIBRARY_PATH edit is needed.
# NOTE: the .so.N sonames ship as symlinks (libwbclient.so.0, liburcu*.so.8,
# libapparmor.so.1, ...).  A `-name '*.so*' -type f` filter misses all of them,
# which is how libwbclient.so.0 went missing once.  Resolve each symlink and
# install the target under the link's own name.
find "$TREE" -name '*.so*' -type f | while read -r f; do
    install -m 0644 "$f" "$LIBD/$(basename "$f")"
done
find "$TREE" -name '*.so*' -type l | while read -r l; do
    target=$(readlink -f "$l" 2>/dev/null || true)
    if [ -n "$target" ] && [ -f "$target" ]; then
        install -m 0644 "$target" "$LIBD/$(basename "$l")"
    else
        echo "   WARNING dangling soname link: $l" >&2
    fi
done
echo "   loader-path libraries: $(ls "$LIBD"/*.so* 2>/dev/null | wc -l)"

echo
echo "=== 4. FSAL plugin, and dbus-daemon's own libraries ==="
# Ganesha 4.3 has NO -p option: fsal_manager.c builds the plugin path as
# "%s/libfsal%s.so" from the NFS_CORE_PARAM key Plugins_Dir.  The fixture sets
# Plugins_Dir to <deps>/usr/lib/ganesha, so that is the one directory that must
# hold the VFS plugin.  A copy also goes to the x86_64 plugin dir, which is the
# second path 4.3 searches, in case a future config omits Plugins_Dir.
FSAL=$(find "$TREE" -name 'libfsalvfs.so' | head -1)
[ -n "$FSAL" ] || { echo "   FATAL: libfsalvfs.so absent (nfs-ganesha-vfs)" >&2; exit 3; }
install -m 0644 "$FSAL" "$STAGE/usr/lib/ganesha/libfsalvfs.so"
mkdir -p "$LIBD/ganesha"
install -m 0644 "$FSAL" "$LIBD/ganesha/libfsalvfs.so"
echo "   usr/lib/ganesha/libfsalvfs.so            (Plugins_Dir target)"
echo "   usr/lib/x86_64-linux-gnu/ganesha/...      (4.3 fallback dir)"

# Now stage the dbus-daemon private libraries (fetched in step 1b).  Each
# package is unpacked separately so the soname symlinks can be resolved against
# their own targets.
for deb in "$EXTRADEB"/*.deb; do
    build="$WORK/extrabuild"
    rm -rf "$build"
    mkdir -p "$build"
    dpkg-deb -x "$deb" "$build"
    find "$build" -name '*.so*' -type f -exec cp -a {} "$EXTRA/" \;
    for link in $(find "$build" -name '*.so*' -type l); do
        target=$(readlink -f "$link" 2>/dev/null || true)
        if [ -n "$target" ] && [ -f "$target" ]; then
            cp -a "$target" "$EXTRA/$(basename "$link")"
        fi
    done
done
for so in libaudit.so.1 libcap-ng.so.0 libexpat.so.1 libselinux.so.1 \
          libsystemd.so.0; do
    [ -e "$EXTRA/$so" ] || { echo "   FATAL: missing $so" >&2; exit 6; }
done
echo "   usr/lib/ganesha-extra/                   (dbus-daemon only, $(ls "$EXTRA" | wc -l) files)"

# Package bookkeeping that has no business in a lane.  NOT dbus-daemon: Ganesha
# calls dbus_bus_get(DBUS_BUS_SYSTEM) and exposes no knob to disable it, so
# with no bus the service thread exits and the server shuts down again right
# after printing NFS SERVER INITIALIZED.
rm -f "$STAGE/usr/bin/ganesha.nfsd"
rm -rf "$STAGE/var/log/ganesha" "$STAGE/lib/systemd" \
       "$STAGE/etc/systemd" "$STAGE/usr/lib/systemd" \
       "$STAGE/etc/dbus-1" "$STAGE/usr/bin/dbus-send" \
       "$STAGE/usr/bin/dbus-update-activation-environment" \
       "$STAGE/etc/init.d" "$STAGE/etc/logrotate.d" 2>/dev/null || true
# keep the shipped example config: it is the syntax reference
mkdir -p "$STAGE/usr/share/ganesha"
if [ -f "$TREE/etc/ganesha/ganesha.conf" ]; then
    install -m 0644 "$TREE/etc/ganesha/ganesha.conf" \
        "$STAGE/usr/share/ganesha/ganesha.conf.example"
fi

echo
echo "=== 5. injected vs expected from the guest base ==="
# The honest record of what is still an assumption.  Anything listed as FROM
# GUEST BASE is unverified until a guest runs it.
for obj in "$TREE/usr/bin/ganesha.nfsd" "$TREE/usr/bin/dbus-daemon" \
           "$TREE/usr/lib/ganesha/libganesha_nfsd.so.4.3"; do
    [ -f "$obj" ] || continue
    echo "   [$(basename "$obj")]"
    readelf -d "$obj" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' \
        | sort -u | while read -r so; do
            if find "$TREE" "$EXTRA" -name "$so" -print -quit | grep -q .; then
                printf '      %-26s injected\n' "$so"
            else
                printf '      %-26s FROM GUEST BASE\n' "$so"
            fi
        done
done

echo
echo "=== 6. sanity gates ==="
for required in usr/sbin/ganesha.nfsd usr/sbin/dbus-daemon \
                usr/lib/ganesha/libfsalvfs.so \
                usr/lib/x86_64-linux-gnu/ganesha/libfsalvfs.so; do
    printf '   %-48s ' "$required"
    if [ -f "$STAGE/$required" ]; then
        echo present
    else
        echo MISSING
        exit 4
    fi
done
printf '   %-48s ' "usr/lib/x86_64-linux-gnu/libganesha_nfsd.so.4.3"
[ -f "$LIBD/libganesha_nfsd.so.4.3" ] && echo present || { echo MISSING; exit 4; }
for exec in ganesha.nfsd dbus-daemon; do
    printf '   %-48s ' "$exec on PATH (usr/sbin)"
    [ -x "$STAGE/usr/sbin/$exec" ] && echo yes || { echo NO; exit 5; }
done
# deps/usr/bin is invisible to the lane.  rpcinfo is there and has always been
# there, because the lane has always resolved rpcinfo from the system /usr/sbin.
# Do NOT "fix" that: moving it would change knfsd-mode behaviour and with it the
# comparability of the already-recorded AB / S3 / S4 evidence.
strays=$(find "$STAGE/usr/bin" -type f -perm -u+x 2>/dev/null || true)
if [ -n "$strays" ]; then
    echo "   note: in deps/usr/bin, NOT on the lane PATH (pre-existing):"
    echo "$strays" | sed "s|$STAGE|      deps|"
fi
if LD_LIBRARY_PATH="$LIBD" ldd "$STAGE/usr/sbin/ganesha.nfsd" 2>&1 \
        | grep -q 'not found'; then
    echo "   daemon: unresolved against this tree (host libs differ from the"
    echo "           guest; the guest loader is the final authority):"
    LD_LIBRARY_PATH="$LIBD" ldd "$STAGE/usr/sbin/ganesha.nfsd" 2>&1 \
        | grep 'not found' | sed 's/^/      /'
else
    echo "   ganesha.nfsd: fully resolved offline"
fi

echo
echo "=== 7. pack ==="
tar -czf "$OUT" -C "$STAGE" .
echo "   $OUT"
echo "   $(stat -c %s "$OUT") bytes"
echo "   sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
echo "   original guest-deps.tar.gz sha256 $(sha256sum "$ORIG" | cut -d' ' -f1) (unchanged)"
