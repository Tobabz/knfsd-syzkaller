#!/bin/sh
# tools/fport-variant.sh - record a re-based variant of a patch series
# onto a newer mainline base (run once per rc boundary).
#
# Why: a text patch series cannot apply "as-is" to an arbitrary future
# kernel. This script keeps the series evergreen for the rc-to-rc window:
#   1. clones the target repo into a scratch worktree (target untouched)
#   2. seeds the recorded rerere resolutions from previous variants
#   3. git am -3 with rerere on; conflicts are recorded once and replayed
#      forever after (autoUpdate)
#   4. exports the re-based series + sha256sums + META + rr-cache into
#      $VARIANT_DIR/<kind>/<variant-name>/, consumed by fport-apply.sh
#
# POSIX sh. Usage:
#   fport-variant.sh <kind> <target-repo> <new-base> [variant-name]
set -eu

kind=$1; target=$2; new_base=$3
variant_name=${4:-rc-$(git -C "$target" show -s --format=%cs "$new_base" | tr -d '-')}
prep_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bundle_root=${KOOV_BUNDLE:-$prep_dir/../bundle/patches}
variants=${KOOV_PATCH_VARIANTS:-$prep_dir/patch-variants}

case "$kind" in
kernel)
    bundle=$bundle_root/kernel ;;
syzkaller)
    bundle=$bundle_root/syzkaller ;;
*) echo "unknown kind: $kind" >&2; exit 2 ;;
esac

echo "[fport-variant] kind=$kind new_base=$new_base variant=$variant_name bundle=$bundle"

# scratch worktree: never touch target
scratch=$(mktemp -d /tmp/fport-variant-XXXXXX)
git clone -q --no-checkout "$target" "$scratch/wt"
git -C "$scratch/wt" checkout -q "$new_base"
git -C "$scratch/wt" config rerere.enabled true
git -C "$scratch/wt" config rerere.autoUpdate true
git -C "$scratch/wt" config user.email replay@variant.invalid
git -C "$scratch/wt" config user.name "variant replay"

# seed recorded resolutions from previous variants of this kind
mkdir -p "$scratch/wt/.git/rr-cache" 2>/dev/null || true
seeded=0
for v in "$variants/$kind"/*/rr-cache; do
    test -d "$v" || continue
    cp -rn "$v/"* "$scratch/wt/.git/rr-cache/" 2>/dev/null || true
    seeded=1
done
echo "[fport-variant] seeded prior rerere resolutions from $seeded variant(s)"

# apply with rerere replay
fails=0
for p in "$bundle"/*.patch; do
    if ! git -C "$scratch/wt" am -3 "$p"; then
        name=$(basename "$p")
        echo "[fport-variant] conflict in $name; record the resolution and continue:" >&2
        echo "[fport-variant]   cd $scratch/wt; edit; git add .; git rerere; git am --continue" >&2
        fails=$((fails + 1))
        break
    fi
done
if test "$fails" -ne 0; then
    echo "[fport-variant] aborting; re-run after resolving the conflict" >&2
    rm -rf "$scratch"
    exit 1
fi

applied=$(git -C "$scratch/wt" rev-parse HEAD)
count=$(git -C "$scratch/wt" log --oneline "$new_base"..HEAD | wc -l)
echo "[fport-variant] applied $count commits; applied HEAD=$applied"

# export variant
out="$variants/$kind/$variant_name"
rm -rf "$out"; mkdir -p "$out"
git -C "$scratch/wt" format-patch -q -o "$out" "$new_base"..HEAD
# format-patch writes 000x-*.patch; keep series ordering identical
suffix=0
for f in "$out"/*.patch; do
    suffix=$((suffix + 1))
    mv "$f" "$out/$(printf '%04d' "$suffix")-$(basename "$f" | sed 's/^[0-9]*-//')"
done
cp -rn "$scratch/wt/.git/rr-cache" "$out/rr-cache" 2>/dev/null || true
cat > "$out/META" <<EOF
series=$kind
bundle=$bundle
variant_base=$new_base
applied_base=$applied
commits=$count
variant_name=$variant_name
EOF

echo "[fport-variant] exported: $out"
echo "[fport-variant]   variant_base=$new_base"
echo "[fport-variant]   applied_base=$applied ($count commits)"
echo "[fport-variant]   rr-cache=$((count)) resolutions carried"
rm -rf "$scratch"
