#!/bin/sh
set -eu

if test "$#" -ne 2; then
	echo "usage: $0 v41|v42|raw CORPUS.db" >&2
	exit 2
fi

campaign=$1
corpus=$2
syz_root=/home/fuzzer/tools/syzkaller-frozen-attribution
test -s "$corpus"
case "$campaign" in v41|v42|raw) ;; *) exit 2 ;; esac

audit_dir=$(mktemp -d /tmp/nfs-protocol-audit.XXXXXX)
trap 'rm -rf "$audit_dir"' EXIT
"$syz_root/bin/syz-db" unpack "$corpus" "$audit_dir/programs" >/dev/null
"$syz_root/bin/syz-nfs-corpus" -input "$audit_dir/programs" \
	-campaign "$campaign"
