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
trace=0
target=0
nlm_relay_experiment=0
expected_sha=

for arg in $(cat /proc/cmdline); do
	case "$arg" in
		koov.nfs_minor=*) minor=${arg#koov.nfs_minor=} ;;
		koov.nfs_version=*) version=${arg#koov.nfs_version=} ;;
		koov.nfs_fixture=*) fixture_mode=${arg#koov.nfs_fixture=} ;;
		koov.nfs_trace=*) trace=${arg#koov.nfs_trace=} ;;
		koov.nfs_target=*) target=${arg#koov.nfs_target=} ;;
		koov.nlm_relay_experiment=*) nlm_relay_experiment=${arg#koov.nlm_relay_experiment=} ;;
		koov.lane_sha256=*) expected_sha=${arg#koov.lane_sha256=} ;;
	esac
done
case "$trace" in
	0|1) NFS_TRACE=$trace; export NFS_TRACE ;;
	*) echo "koov.nfs_trace must be 0 or 1" >&2; exit 2 ;;
esac
case "$target" in
	0|1) ;;
	*) echo "koov.nfs_target must be 0 or 1" >&2; exit 2 ;;
esac
case "$nlm_relay_experiment" in
	0|1) ;;
	*) echo "koov.nlm_relay_experiment must be 0 or 1" >&2; exit 2 ;;
esac
if [ "$nlm_relay_experiment" = 1 ]; then
	[ "$target" = 1 ] && [ "$fixture_mode" = nlm-knfsd ] || {
		echo "NLM relay experiment needs NLM target mode" >&2
		exit 2
	}
	KOOV_NLM_RELAY_EXPERIMENT=1
	export KOOV_NLM_RELAY_EXPERIMENT
fi
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
	broad-knfsd|nlm-knfsd)
		test -z "$version" || {
			echo "koov.nfs_version cannot be combined with $fixture_mode" >&2
			exit 2
		}
		NFS_FIXTURE=$fixture_mode
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
virtio_device_matches()
{
	virtio_path=$1
	virtio_major=$2
	virtio_minor=$3
	actual=$(stat -L -c '%t:%T' "$virtio_path") || return 1
	expected=$(printf '%x:%x' "$virtio_major" "$virtio_minor")
	test "$actual" = "$expected"
}
if [ "$target" = 1 ]; then
	# Minimal guests may expose the virtio-port class before udev creates the
	# device node or its name link. Resolve only the four expected host ports.
	for lane in 0 1 2 3; do
		journal=/dev/virtio-ports/nfsp-journal-$lane
		journal_found=0
		for port in /sys/class/virtio-ports/*; do
			[ -f "$port/name" ] || continue
			[ "$(cat "$port/name")" = "nfsp-journal-$lane" ] || continue
			device_number=$(cat "$port/dev") || continue
			major=${device_number%%:*}
			minor=${device_number#*:}
			case "$major:$minor" in
				*[!0-9:]*|:*|*:) continue ;;
			esac
			device=/dev/$(basename "$port")
			if [ ! -c "$device" ]; then
				[ ! -e "$device" ] && [ ! -L "$device" ] || continue
				mknod "$device" c "$major" "$minor" || {
					[ -c "$device" ] || continue
				}
				chmod 0600 "$device"
			fi
			virtio_device_matches "$device" "$major" "$minor" || {
				echo "journal device identity mismatch: $device" >&2
				exit 1
			}
			mkdir -p /dev/virtio-ports
			if [ -e "$journal" ] || [ -L "$journal" ]; then
				virtio_device_matches "$journal" "$major" "$minor" || {
					echo "journal link identity mismatch: $journal" >&2
					exit 1
				}
			else
				ln -s "$device" "$journal"
			fi
			journal_found=1
			break
		done
		[ "$journal_found" = 1 ] && [ -c "$journal" ] || {
			echo "missing journal port nfsp-journal-$lane" >&2
			exit 1
		}
	done
	# Proxy target mode: per-lane rule sets and session ids from the host
	# share (tools/prepare-live-lane-config.py --nfs-target).  The host sink
	# checks each relay RULESET against the rule set it was started with.
	rm -rf /run/frozen-phase9/target
	mkdir -m 0700 /run/frozen-phase9/target
	cp "$source_dir"/target/lane*.nfsprul1 "$source_dir"/target/lane*.session \
		/run/frozen-phase9/target/ || {
		umount "$source_dir"
		echo "koov.nfs_target=1 but the lane share has no target/ files" >&2
		exit 1
	}
	NFS_PROXY_TARGET_DIR=/run/frozen-phase9/target
	export NFS_PROXY_TARGET_DIR
fi
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
