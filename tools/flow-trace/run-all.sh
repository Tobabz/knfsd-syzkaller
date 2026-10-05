#!/bin/sh
# Record one trace per scenario run. Usage: run-all.sh OUT_DIR [run-name ...]
# Each run boots a fresh guest (capture.py), so runs are independent.
# Evidence stays outside the repository; the report cites OUT_DIR and the commit.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${1:?usage: run-all.sh OUT_DIR [run-name ...]}
shift
corpus=$repo/bundle/corpus/nfs-normal
mkdir -p "$out"

run() {
    name=$1
    shift
    case " ${selected:-} " in
    " "|"  ") ;;
    *) case " $selected " in *" $name "*) ;; *) return 0 ;; esac ;;
    esac
    echo "== $name: $*"
    timeout 1500 python3 "$here/capture.py" "$@" --out "$out/$name" >"$out/$name.log" 2>&1
    echo "   exit=$? $(tail -1 "$out/$name.log" | cut -c1-200)"
}

selected="$*"
# negative control for the COPY-specific transitions: no COPY, no callback expected
run ctl-v41-basic  --version 4.1 --seed "$corpus/basic-v41-tcp.prog" --settle 3
# S1: NFSv3 server start, mounts, I/O, stop
# (settle 75 s: lockd grace is longer than nfsd grace)
run s1-v3-basic    --version 3   --restart-fixture --stop-fixture --seed "$corpus/basic-v3-tcp.prog" --settle 75
# S2: NFSv4.0 SETCLIENTID, delegation grant, recall on a separate callback connection
run s2-v40-deleg   --version 4.0 --restart-fixture --stop-fixture --seed "$corpus/deleg-recall-v40-tcp.prog" --settle 3
# S3: NFSv4.2 session setup, async COPY, CB_OFFLOAD on the session backchannel
run s3-v42-copy    --version 4.2 --restart-fixture --stop-fixture --seed "$corpus/async-copy-v42-tcp.prog" --settle 3
# S3b: NFSv4.1 delegation recall on the session backchannel
run s3b-v41-deleg  --version 4.1 --restart-fixture --stop-fixture --seed "$corpus/delegation-recall-v41-tcp.prog" --settle 3
# S4: NFSv4.1 state lifetime and cleanup work
run s4-v41-state   --version 4.1 --shell "$here/stimulus/s4-state-lifetime.sh"
# S4b: NFSv4.1 server start and grace end (grace is 10 s; wait past it)
run s4b-v41-grace  --version 4.1 --restart-fixture --stop-fixture --settle 14
