#!/bin/bash
# Verify proxy changes in a guest with the bootstrap's own kernel, syzkaller and image.
#
#   usage: [PROCS=N] run-verify.sh ENV_DIR VARIANT ARM [ARM...]
#     ENV_DIR  bootstrap output directory (contains images/, syzkaller/)
#     VARIANT  kasan | kcsan
#     ARM      direct | proxy | raw | copy | legacy-v1 | legacy-v2 |
#              legacy-v2-refusal
#
# Prerequisites (see README.md, section 8.2):
#   python3 mkinputs.py                         # once; recreates ~/prune-evidence/inputs
#   qemu-img convert -O raw ENV_DIR/images/bookworm-kcov-fresh.qcow2 ~/prune-env-image.raw
# To test a rebuilt proxy, build it elsewhere and rebuild the deps tarball:
#   tools/nfs-proxy/build-guest.sh --out ~/nfsp-build/nfs-proxy-v2 \
#     --probe-out ~/nfsp-build/guest-delta-replay
#   NFSP_PROXY=~/nfsp-build/nfs-proxy-v2 python3 mkinputs.py
#   REPLAY_PROBE=~/nfsp-build/guest-delta-replay run-verify.sh ... legacy-v1
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
env_dir=$(cd "${1:?ENV_DIR}" && pwd); v=${2:?VARIANT}; shift 2
inputs=$HOME/prune-evidence/inputs
image=${IMAGE:-$HOME/prune-env-image.raw}
out=${OUT:-$HOME/prune-evidence/proxy-$v}
procs=${PROCS:-1}
kdir=$HOME/kv-$v
mkdir -p "$kdir/arch/x86/boot" "$out"
: > "$out/arm-status.tsv"
ln -sfn "$env_dir/images/$v/bzImage" "$kdir/arch/x86/boot/bzImage"
ln -sfn "$env_dir/images/$v/vmlinux" "$kdir/vmlinux"
status=0
for arm in "$@"; do
  deps=$inputs/deps-ganesha-proxy.tar.gz
  profile=
  executions=${EXECUTIONS:-30}
  arm_procs=$procs
  case "$arm" in
    direct) fix=$inputs/lane-direct.sh; w=$inputs/workload-direct.prog ;;
    proxy)  fix=$inputs/lane-proxy.sh;  w=$inputs/workload-proxy.prog ;;
    raw)    fix=$inputs/lane-proxy.sh;  w=${WORKLOAD:-$inputs/workload-raw.prog} ;;
    copy)   fix=$inputs/lane-v42.sh;    w=$inputs/workload-copy.prog ;;
    legacy-v1)
      fix=$inputs/lane-proxy.sh; w=$inputs/workload-legacy-v1.prog
      profile=v1; executions=1; arm_procs=1 ;;
    legacy-v2)
      fix=$inputs/lane-proxy.sh; w=$inputs/workload-legacy-v2.prog
      profile=v2; executions=1; arm_procs=1 ;;
    legacy-v2-refusal)
      fix=$inputs/lane-proxy.sh; w=$inputs/workload-legacy-v2-refusal.prog
      profile=v2-refusal; executions=1; arm_procs=1 ;;
    *)
      echo "unknown arm $arm" >&2
      printf '%s\t%s\trc=2\n' "$v" "$arm" | tee -a "$out/arm-status.tsv"
      status=1
      continue ;;
  esac
  rm -rf "${out:?}/$arm"
  args=(--kernel "$kdir/arch/x86/boot/bzImage" --vmlinux "$kdir/vmlinux"
        --image "$image" --ssh-key "$repo/artifacts/bookworm.id_rsa" --deps "$deps"
        --fixture "$fix" --workload "$w" --syz-dir "$env_dir/syzkaller"
        --executions "$executions" --procs "$arm_procs" --output "$out/$arm")
  if [ -n "$profile" ]; then
    replay_probe=${REPLAY_PROBE:?legacy profiles require the guest-built replay probe from build-guest.sh}
    args+=(--legacy-profile "$profile" --replay-probe "$replay_probe")
  fi
  rc=0
  python3 "$here/verify-lane.py" "${args[@]}" > "$out/$arm.log" 2>&1 || rc=$?
  printf '%s\t%s\trc=%s\n' "$v" "$arm" "$rc" | tee -a "$out/arm-status.tsv"
  [ "$rc" -eq 0 ] || status=1
done
exit "$status"
