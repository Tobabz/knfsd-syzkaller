#!/bin/sh
# Guest-side NFSv4 2-client x 2-backend relay check.  The first mount for
# each client retains the legacy /mnt alias; its other backend is explicit.
set -eu
root=${1:?usage: guest-four-mounts.sh ROOT}
minor=${NFS_MINOR_VERSION:-1}
case "$minor" in 1|2) ;; *) exit 2 ;; esac
source_root=/syz-nfs-lanes/proc-0
case "$root" in /tmp/frozen-phase9.*) ;; *) exit 2 ;; esac
k0=$root/lane0/client0/mnt
k1=$root/lane0/client1/knfsd
g0=$root/lane0/client0/ganesha
g1=$root/lane0/client1/mnt

for path in "$k0" "$k1" "$g0" "$g1"; do
    mountpoint -q "$path"
    test "$(findmnt -n -o FSTYPE -- "$path")" = nfs4
    mount_minor=$minor
    case "$path" in "$g0"|"$g1") mount_minor=1 ;; esac
    grep -Eq " $path nfs4 .*vers=4\.$mount_minor.*proto=tcp" /proc/mounts
done
test "$(findmnt -n -o SOURCE -- "$k0")" = 10.89.0.1:/
test "$(findmnt -n -o SOURCE -- "$k1")" = 10.89.0.1:/
test "$(findmnt -n -o SOURCE -- "$g0")" = 10.89.0.5:/
test "$(findmnt -n -o SOURCE -- "$g1")" = 10.89.0.5:/
for client in 0 1; do
    test "$(findmnt -n -o SOURCE -- "$source_root/client$client")" = 10.89.0.1:/
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
