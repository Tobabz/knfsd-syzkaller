#!/bin/sh
# tools/fport-apply.sh - apply checked-in patch series to a target repo.
set -eu

DRY_RUN=0
# derive workspace root from script location (portable); override via env
prep_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VARIANT_DIR=${KOOV_PATCH_VARIANTS:-$prep_dir/patch-variants}

while test "$#" -gt 0; do
    case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --variant-dir) VARIANT_DIR=$2; shift 2 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
    esac
done

test "$#" -eq 2 || { echo "usage: $0 [--dry-run] [--variant-dir DIR] kind target" >&2; exit 2; }
kind=$1
target=$2
# script lives in <root>/tools; series live in <root>/bundle/patches
bundle_root=${KOOV_BUNDLE:-"$prep_dir/../bundle/patches"}
load_variant_base=0

case "$kind" in
kernel)
    bundle=$bundle_root/kernel
    expected_base=93f51579e7df248780214094418f205253383cc5
    ;;
syzkaller)
    bundle=$bundle_root/syzkaller
    expected_base=801f0966669a37e048adabf9e5f38ce52825ea82
    ;;
*) echo "unknown patch series: $kind" >&2; exit 2 ;;
esac

git -C "$target" rev-parse --is-inside-work-tree >/dev/null
actual_base=$(git -C "$target" rev-parse HEAD)
clean=$(git -C "$target" status --porcelain)

echo "[fport-apply] kind=$kind target=$target"
echo "[fport-apply] expected_base=$expected_base actual_base=$actual_base"
echo "[fport-apply] clean=$(test -z "$clean" && echo yes || echo no) dry_run=$DRY_RUN"

# ---- provenance, always ----

if test -n "$clean"; then
    echo "[fport-apply] target worktree is not clean:" >&2
    printf '%s\n' "$clean" >&2
    exit 1
fi

# ---- apply mode: single self-contained series apply (git am -3) ----
if test "$actual_base" = "$expected_base"; then
    echo "[fport-apply] base match: self-contained series apply on validated base"
else
    echo "[fport-apply] drift path: target base differs from validated base"
    echo "[fport-apply]   (forward-port: rc-to-rc window. rerere replays recorded resolutions.)"

    mkdir -p "$VARIANT_DIR/$kind"
    git -C "$target" config rerere.enabled true
    git -C "$target" config rerere.autoUpdate true
    echo "[fport-apply] rerere enabled locally on target (.git/rr-cache)"

    # variant inventory: stored re-based bundles, chosen by "target contains base"
    variants=""
    for v in "$VARIANT_DIR/$kind"/*/META; do
        test -f "$v" || continue
        base_name=$(dirname "$v"); base_name=$(basename "$base_name")
        vbase=$(sed -n 's/^variant_base=//p' "$VARIANT_DIR/$kind/$base_name/META" 2>/dev/null | head -1)
        test -n "$vbase" || continue
        if git -C "$target" merge-base --is-ancestor "$vbase" "$actual_base" 2>/dev/null; then
            variants="$variants $base_name($vbase)"
            echo "[fport-apply] candidate variant: $base_name base=$vbase (target contains it)"
        fi
    done
    if test -n "$variants"; then
        echo "[fport-apply] usable variants:$variants"
        # seed recorded conflict resolutions into the fresh clone's rerere cache
        mkdir -p "$target/.git/rr-cache"
        for v in "$VARIANT_DIR/$kind"/*/rr-cache; do
            test -d "$v" || continue
            cp -rn "$v/"* "$target/.git/rr-cache/" 2>/dev/null || true
            echo "[fport-apply] seeded rerere cache from $(basename "$(dirname "$v")")"
        done
    else
        echo "[fport-apply] no recorded variants for $kind (run fport-variant.sh after each rc rebase)"
    fi
fi

if test "$DRY_RUN" -eq 1; then
    echo "[fport-apply] dry-run: would run git am -3 on $bundle/*.patch with rerere+3way"
    exit 0
fi

# ---- apply: per-patch am -3 with rerere replay ----
fails=0
for p in "$bundle"/*.patch; do
    name=$(basename "$p")
    if git -C "$target" am -3 --resolvemsg="[fport-apply] conflict in $name; record resolution with git rerere" "$p"; then
        echo "[fport-apply] applied: $name"
    else
        fails=$((fails + 1))
        echo "[fport-apply] FAILED: $name" >&2
        git -C "$target" am --show-current-patch > /tmp/apply-failing.patch 2>/dev/null || true
        echo "[fport-apply] failing hunk preview:" >&2
        grep -n -m 10 '^@@' /tmp/apply-failing.patch 2>/dev/null >&2 || true
        git -C "$target" am --abort
        echo "[fport-apply] aborted am; tree restored. Fix one patch, record resolution with" >&2
        echo "[fport-apply]   rerere, then re-run. If the construct was refactored upstream," >&2
        echo "[fport-apply]   regenerate the patch from the design-intent record (§3)" >&2
        break
    fi
done

if test "$fails" -eq 0; then
    echo "[fport-apply] series applied cleanly ($(git -C "$target" log --oneline "$actual_base"..HEAD | wc -l) commits)"
    echo "[fport-apply] applied HEAD=$(git -C "$target" rev-parse HEAD)"
    if test -n "${PREP_POST_APPLY_HOOK:-}"; then
        echo "[fport-apply] running PREP_POST_APPLY_HOOK: $PREP_POST_APPLY_HOOK"
        sh -c "$PREP_POST_APPLY_HOOK"
    fi
    exit 0
fi
exit 1
