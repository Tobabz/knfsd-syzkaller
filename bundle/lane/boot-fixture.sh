#!/bin/sh
# Load the lane script from the host at boot; keep one guest copy for this VM.
set -eu

fixture=/run/frozen-phase9/lane.sh
source_dir=/run/frozen-phase9-source
root=/tmp/frozen-phase9.manager
lanes=4
minor=1
version=
fixture_mode=single
expected_sha=

for arg in $(cat /proc/cmdline); do
	case "$arg" in
		koov.nfs_minor=*) minor=${arg#koov.nfs_minor=} ;;
		koov.nfs_version=*) version=${arg#koov.nfs_version=} ;;
		koov.nfs_fixture=*) fixture_mode=${arg#koov.nfs_fixture=} ;;
		koov.lane_sha256=*) expected_sha=${arg#koov.lane_sha256=} ;;
	esac
done
case "$fixture_mode" in
	single)
		if [ -z "$version" ]; then
			version=4.$minor
		fi
		case "$version" in
			3|4.0|4.1|4.2) ;;
			*) echo "unsupported NFS version: $version" >&2; exit 2 ;;
		esac
		NFS_VERSION=$version
		export NFS_VERSION
		;;
	broad-knfsd)
		test -z "$version" || {
			echo "koov.nfs_version cannot be combined with broad-knfsd" >&2
			exit 2
		}
		NFS_FIXTURE=broad-knfsd
		export NFS_FIXTURE
		;;
	*) echo "unsupported NFS fixture: $fixture_mode" >&2; exit 2 ;;
esac
case "$expected_sha" in
	????????????????????????????????????????????????????????????????) ;;
	*) echo "missing or invalid koov.lane_sha256" >&2; exit 2 ;;
esac
mkdir -p /run/frozen-phase9 "$source_dir"
mount -t 9p -o trans=virtio,version=9p2000.L,ro koov-lane "$source_dir"
install -m 0755 "$source_dir/lane.sh" "$fixture"
umount "$source_dir"
actual_sha=$(sha256sum "$fixture")
case "$actual_sha" in
	"$expected_sha "*) ;;
	*) echo "host lane script hash mismatch" >&2; exit 1 ;;
esac
printf '%s\n' "$actual_sha" > /run/frozen-phase9/lane.sha256

mkdir -p /sys/kernel/debug
if ! mountpoint -q /sys/kernel/debug; then
	mount -t debugfs debugfs /sys/kernel/debug
fi

exec "$fixture" setup "$root" "$lanes"
