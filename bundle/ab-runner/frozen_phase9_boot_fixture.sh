#!/bin/sh
# Persistent-VM wrapper for the frozen four-lane NFS fixture.
set -eu

fixture=/opt/frozen-phase9/lane.sh
root=/tmp/frozen-phase9.manager
lanes=4

mkdir -p /sys/kernel/debug
if ! mountpoint -q /sys/kernel/debug; then
	mount -t debugfs debugfs /sys/kernel/debug
fi

exec "$fixture" setup "$root" "$lanes"
