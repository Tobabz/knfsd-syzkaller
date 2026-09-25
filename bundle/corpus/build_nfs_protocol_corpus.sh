#!/bin/sh
set -eu

if test "$#" -ne 2; then
	echo "usage: $0 v41|v42|raw OUTPUT.db" >&2
	exit 2
fi

campaign=$1
output=$2
# Portable defaults: derive the repo from this script's location; allow
# explicit overrides for hosts where the trees live elsewhere.
repo=${REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
syz_root=${SYZ_TREE:-/home/fuzzer/tools/syzkaller-frozen-attribution}
case "$campaign" in
	v41) seeds=$repo/corpus/knfsd-protocol-v41-seeds ;;
	v42)
		# NFSv4.2 is a strict superset campaign: retain the v4.1 state and
		# namespace seeds, then add v4.2 COPY/ALLOCATE/SEEK/xattr coverage.
		staging=$(mktemp -d /tmp/nfs-protocol-v42-seeds.XXXXXX)
		trap 'rm -rf "$staging"' EXIT
		for source in "$repo"/corpus/knfsd-protocol-v41-seeds/*.prog; do
			cp "$source" "$staging/v41-$(basename "$source")"
		done
		for source in "$repo"/corpus/knfsd-protocol-v42-seeds/*.prog; do
			cp "$source" "$staging/v42-$(basename "$source")"
		done
		seeds=$staging
		;;
	raw) seeds=$repo/corpus/knfsd-protocol-raw-seeds ;;
	*) echo "unknown campaign: $campaign" >&2; exit 2 ;;
esac

test -d "$seeds"
test ! -e "$output"
"$syz_root/bin/syz-db" pack "$seeds" "$output"
"$repo/scripts/audit_nfs_protocol_corpus.sh" "$campaign" "$output"
sha256sum "$output"
