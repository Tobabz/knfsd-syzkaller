#!/bin/bash
# Verify proxy changes in a guest with the bootstrap's own kernel, syzkaller and image.
#
#   usage: run-verify.sh ENV_DIR VARIANT ARM [ARM...]
#     ENV_DIR  bootstrap output directory (contains images/, syzkaller/)
#     VARIANT  kasan | kcsan
#     ARM      direct | proxy | raw | copy
#
# Prerequisites (see README.md, section 8.2):
#   python3 mkinputs.py                         # once; recreates ~/prune-evidence/inputs
#   qemu-img convert -O raw ENV_DIR/images/bookworm-kcov-fresh.qcow2 ~/prune-env-image.raw
# To test a rebuilt proxy, build it elsewhere and rebuild the deps tarball:
#   tools/nfs-proxy/build-guest.sh --out ~/nfsp-build/nfs-proxy-v2
#   NFSP_PROXY=~/nfsp-build/nfs-proxy-v2 python3 mkinputs.py
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
env_dir=${1:?ENV_DIR}; v=${2:?VARIANT}; shift 2
inputs=$HOME/prune-evidence/inputs
image=${IMAGE:-$HOME/prune-env-image.raw}
out=${OUT:-$HOME/prune-evidence/proxy-$v}
kdir=$HOME/kv-$v
mkdir -p "$kdir/arch/x86/boot" "$out"
ln -sfn "$env_dir/images/$v/bzImage" "$kdir/arch/x86/boot/bzImage"
ln -sfn "$env_dir/images/$v/vmlinux" "$kdir/vmlinux"
for arm in "$@"; do
  deps=$inputs/deps-ganesha-proxy.tar.gz
  case "$arm" in
    direct) fix=$inputs/lane-direct.sh; w=$inputs/workload-direct.prog ;;
    proxy)  fix=$inputs/lane-proxy.sh;  w=$inputs/workload-proxy.prog ;;
    raw)    fix=$inputs/lane-proxy.sh;  w=${WORKLOAD:-$inputs/workload-raw.prog} ;;
    copy)   fix=$inputs/lane-v42.sh;    w=$inputs/workload-copy.prog ;;
    *) echo "unknown arm $arm" >&2; continue ;;
  esac
  rm -rf "${out:?}/$arm"
  python3 "$here/verify-lane.py" --kernel "$kdir/arch/x86/boot/bzImage" --vmlinux "$kdir/vmlinux" \
    --image "$image" --ssh-key "$repo/artifacts/bookworm.id_rsa" --deps "$deps" \
    --fixture "$fix" --workload "$w" --syz-dir "$env_dir/syzkaller" \
    --executions "${EXECUTIONS:-30}" --procs 1 --output "$out/$arm" > "$out/$arm.log" 2>&1
  echo "$v $arm rc=$?"
done
