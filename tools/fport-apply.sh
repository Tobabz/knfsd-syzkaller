#!/bin/sh
# tools/fport-apply.sh - apply the checked-in patch series to a target repo.
#
# usage: fport-apply.sh [--dry-run] <kernel|syzkaller> <target-repo>
#
# bundle/patches/BASE records the base the series is known to apply to. A target
# at another base is still tried with `git am -3`; a newer kernel may conflict,
# and tools/bump-kernel.py moves the series (and BASE) to a newer release or rc.
# Commits are applied deterministically (fixed committer, committer date =
# author date), so an unchanged base and series always give the same HEAD.
set -eu

DRY_RUN=0
# derive workspace root from script location (portable); override via env
prep_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

while test "$#" -gt 0; do
    case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
    esac
done

test "$#" -eq 2 || { echo "usage: $0 [--dry-run] kind target" >&2; exit 2; }
kind=$1
target=$2
# script lives in <root>/tools; series live in <root>/bundle/patches
bundle_root=${KOOV_BUNDLE:-"$prep_dir/../bundle/patches"}
base_file=$bundle_root/BASE
test -f "$base_file" || { echo "missing $base_file" >&2; exit 2; }
base_value() { sed -n "s/^$1=//p" "$base_file" | head -1; }

case "$kind" in
kernel)
    bundle=$bundle_root/kernel
    expected_base=$(base_value kernel_commit)
    ;;
syzkaller)
    bundle=$bundle_root/syzkaller
    expected_base=$(base_value syzkaller_commit)
    ;;
*) echo "unknown patch series: $kind" >&2; exit 2 ;;
esac
test -n "$expected_base" || { echo "no base recorded for $kind in $base_file" >&2; exit 2; }

git -C "$target" rev-parse --is-inside-work-tree >/dev/null
actual_base=$(git -C "$target" rev-parse HEAD)
clean=$(git -C "$target" status --porcelain)

echo "[fport-apply] kind=$kind target=$target"
echo "[fport-apply] expected_base=$expected_base actual_base=$actual_base"
echo "[fport-apply] clean=$(test -z "$clean" && echo yes || echo no) dry_run=$DRY_RUN"

if test -n "$clean"; then
    echo "[fport-apply] target worktree is not clean:" >&2
    printf '%s\n' "$clean" >&2
    exit 1
fi

if test "$actual_base" = "$expected_base"; then
    echo "[fport-apply] base matches BASE"
else
    echo "[fport-apply] base differs from BASE; applying with git am -3 anyway"
fi

if test "$DRY_RUN" -eq 1; then
    echo "[fport-apply] dry-run: would run git am -3 on $bundle/*.patch"
    if test -d "$bundle_root/kcsan/$kind"; then
        echo "[fport-apply] dry-run: would then apply $bundle_root/kcsan/$kind/*.patch"
    fi
    exit 0
fi

apply_series() {
    patch_dir=$1
    label=$2
    found=0
    for p in "$patch_dir"/*.patch; do
        test -f "$p" || continue
        found=1
        name=$(basename "$p")
        # Stable committer identity and date makes a base plus both ordered
        # series reproducible, regardless of the applying host's clock.
        if GIT_COMMITTER_NAME=knfsd-fuzz GIT_COMMITTER_EMAIL=knfsd-fuzz@localhost \
            git -C "$target" am -3 --committer-date-is-author-date "$p"; then
            echo "[fport-apply] applied ($label): $name"
        else
            echo "[fport-apply] FAILED ($label): $name" >&2
            git -C "$target" am --show-current-patch > /tmp/apply-failing.patch 2>/dev/null || true
            echo "[fport-apply] failing hunk preview:" >&2
            grep -n -m 10 '^@@' /tmp/apply-failing.patch 2>/dev/null >&2 || true
            git -C "$target" am --abort >/dev/null 2>&1 || true
            git -C "$target" reset --hard "$actual_base" >/dev/null
            echo "[fport-apply] aborted am and restored the starting commit." >&2
            echo "[fport-apply] For a newer kernel, resolve the conflict with" >&2
            echo "[fport-apply] tools/bump-kernel.py, then re-run." >&2
            return 1
        fi
    done
    if test "$found" -eq 0; then
        echo "[fport-apply] no patches in $patch_dir" >&2
        git -C "$target" reset --hard "$actual_base" >/dev/null
        return 1
    fi
}

apply_series "$bundle" "$kind" || exit 1
kcsan_bundle=$bundle_root/kcsan/$kind
if test -d "$kcsan_bundle"; then
    apply_series "$kcsan_bundle" "kcsan/$kind" || exit 1
fi

echo "[fport-apply] series applied cleanly ($(git -C "$target" log --oneline "$actual_base"..HEAD | wc -l) commits)"
echo "[fport-apply] applied HEAD=$(git -C "$target" rev-parse HEAD)"
exit 0
