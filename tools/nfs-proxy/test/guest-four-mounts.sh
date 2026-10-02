#!/bin/sh
# Guest-side NFS 2-client x 2-backend relay check.  The first mount for
# each client retains the legacy /mnt alias; its other backend is explicit.
set -eu
root=${1:?usage: guest-four-mounts.sh ROOT}
version=${NFS_VERSION:-4.${NFS_MINOR_VERSION:-1}}
case "$version" in 3|4.0|4.1|4.2) ;; *) exit 2 ;; esac
mount_type=nfs4
if [ "$version" = 3 ]; then mount_type=nfs; fi
source_root=/syz-nfs-lanes/proc-0
case "$root" in /tmp/frozen-phase9.*) ;; *) exit 2 ;; esac
k0=$root/lane0/client0/mnt
k1=$root/lane0/client1/knfsd
g0=$root/lane0/client0/ganesha
g1=$root/lane0/client1/mnt

for path in "$k0" "$k1" "$g0" "$g1"; do
    mountpoint -q "$path"
    test "$(findmnt -n -o FSTYPE -- "$path")" = "$mount_type"
    grep -Eq " $path $mount_type .*vers=$version.*proto=tcp" /proc/mounts
done
knfsd_source=10.89.0.1:/
ganesha_source=10.89.0.5:/
if [ "$version" = 3 ]; then
    knfsd_source=10.89.0.1:$root/lane0/server/export
    ganesha_source=10.89.0.5:$root/lane0/server/export-ganesha
fi
test "$(findmnt -n -o SOURCE -- "$k0")" = "$knfsd_source"
test "$(findmnt -n -o SOURCE -- "$k1")" = "$knfsd_source"
test "$(findmnt -n -o SOURCE -- "$g0")" = "$ganesha_source"
test "$(findmnt -n -o SOURCE -- "$g1")" = "$ganesha_source"
for client in 0 1; do
    test "$(findmnt -n -o SOURCE -- "$source_root/client$client")" = "$knfsd_source"
done

test "$(cat "$k0/shared/fixture")" = "$(cat "$k1/shared/fixture")"
test "$(cat "$g0/shared/fixture")" = "$(cat "$g1/shared/fixture")"
test "$(cat "$k0/shared/fixture")" != "$(cat "$g0/shared/fixture")"

trap 'rm -f "$k0/shared/relay-route-k" "$g0/shared/relay-route-g"' EXIT
test ! -e "$k0/shared/relay-route-k"
test ! -e "$g0/shared/relay-route-g"
printf 'knfsd route 0 to 1\n' > "$k0/shared/relay-route-k"
printf 'ganesha route 0 to 1\n' > "$g0/shared/relay-route-g"
test "$(cat "$k1/shared/relay-route-k")" = 'knfsd route 0 to 1'
for client in 0 1; do
    test "$(cat "$source_root/client$client/shared/relay-route-k")" = 'knfsd route 0 to 1'
done
test "$(cat "$g1/shared/relay-route-g")" = 'ganesha route 0 to 1'
test ! -e "$g1/shared/relay-route-k"
test ! -e "$k1/shared/relay-route-g"
rm "$k1/shared/relay-route-k" "$g1/shared/relay-route-g"
test ! -e "$k0/shared/relay-route-k"
test ! -e "$g0/shared/relay-route-g"
trap - EXIT
printf 'client=0 backend=knfsd source=10.89.0.1 shared=1\n'
printf 'client=0 backend=ganesha source=10.89.0.5 shared=1\n'
printf 'client=1 backend=knfsd source=10.89.0.1 shared=1\n'
printf 'client=1 backend=ganesha source=10.89.0.5 shared=1\n'
printf 'four_mounts=pass backend_isolation=pass\n'
