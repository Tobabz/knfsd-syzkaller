#!/usr/bin/env python3
"""Emit composable guest-side attribution hooks as machine-readable JSON."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

SCHEMA: Final[str] = "attr-hook/v1"
PHASE8_CONTROL: Final[str] = "/sys/kernel/debug/sunrpc_fuzz/phase8_control"
PHASE8_STATS: Final[str] = "/sys/kernel/debug/sunrpc_fuzz/phase8_stats"
PHASE9_STATS: Final[str] = "/sys/kernel/debug/sunrpc_fuzz/phase9_stats"


@dataclass(frozen=True, slots=True)
class Hook:
    hook_id: str
    target: str
    commands: tuple[dict[str, str], ...]
    proof: tuple[dict[str, object], ...]
    requirements: tuple[str, ...]
    failure: tuple[str, str] | None = None


def _command(stage: str, command: str) -> dict[str, str]:
    return {"stage": stage, "command": command}


def _proof(file: str, counter: str, delta: int) -> dict[str, object]:
    return {"file": file, "counter": counter, "delta": delta}


def _write(path: str, value: str) -> str:
    return f"printf '%s\\n' '{value}' > {path}"


def _phase8_arm(hook_id: str, target: str, value: str,
                counters: tuple[str, ...]) -> Hook:
    return Hook(
        hook_id,
        target,
        (_command("arm", _write(PHASE8_CONTROL, value)),),
        tuple(_proof("phase8_stats", name, 1) for name in counters),
        ("evidence_level=kernel-control-source-supported",
         "phase8_control and phase8_stats are mounted in debugfs"),
    )


def _pause_hook(kind: str) -> Hook:
    return Hook(
        f"v4.pause-release-{kind}-after-grant",
        f"B0{4 if kind == 'deferred' else 5}-V3 pause after grant candidate",
        (
            _command("arm", _write(
                PHASE8_CONTROL, f"fault-arm pause-next-{kind}-after-grant")),
            _command("observe-entered", f"cat {PHASE8_STATS}"),
            _command("release", _write(
                PHASE8_CONTROL, f"fault-release pause-{kind}-after-grant")),
        ),
        (
            _proof("phase8_stats", f"{kind}_pause_after_grant_entered", 1),
            _proof("phase8_stats", f"{kind}_pause_after_grant_released", 1),
            _proof("phase8_stats", f"{kind}_pause_after_grant_timed_out", 0),
        ),
        ("evidence_level=kernel-control-source-supported",
         "the runner must observe entered before abort/release",
         "release belongs in cleanup and a timeout is failure"),
    )


GENERATION_ABORT_COMMAND: Final[str] = r'''set -eu
out=${ATTR_HOOK_DIR:?}
cat > "$out/generation-abort.c" <<'EOF'
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
struct kcov_remote_generation {
    uint64_t generation;
    uint32_t timeout_ms;
    uint32_t flags;
};
#define KCOV_REMOTE_GENERATION_ABORT _IOW('c', 112, struct kcov_remote_generation)
int main(int argc, char **argv)
{
    struct kcov_remote_generation request = {};
    char *end = NULL;
    int fd;
    if (argc != 3)
        return 64;
    errno = 0;
    fd = (int)strtol(argv[1], &end, 10);
    if (errno || !end || *end || fd < 0)
        return 65;
    errno = 0;
    request.generation = strtoull(argv[2], &end, 10);
    if (errno || !end || *end || !request.generation)
        return 66;
    if (ioctl(fd, KCOV_REMOTE_GENERATION_ABORT, &request)) {
        perror("KCOV_REMOTE_GENERATION_ABORT");
        return 1;
    }
    return 0;
}
EOF
gcc -O2 -Wall -Wextra -Werror -o "$out/generation-abort" "$out/generation-abort.c"
"$out/generation-abort" "${KCOV_FD:?}" "${KCOV_GENERATION:?}"'''

RETRY_RUN_COMMAND: Final[str] = r'''set -eu
out=${ATTR_HOOK_DIR:?}
probe=${ATTR_PHASE7_PROBE:-/opt/frozen-phase7/phase7-probe}
test -x "$probe"
cat > "$out/socket-audit.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
static void note(const char *format, ...)
{
    va_list args;
    int fd = open(getenv("ATTR_SOCKET_AUDIT"), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        _exit(120);
    va_start(args, format);
    vdprintf(fd, format, args);
    va_end(args);
    close(fd);
}
int socket(int domain, int type, int protocol)
{
    static int (*real_socket)(int, int, int);
    int fd;
    if (!real_socket)
        real_socket = dlsym(RTLD_NEXT, "socket");
    fd = real_socket(domain, type, protocol);
    note("SOCKET fd=%d domain=%d type=%d protocol=%d\n", fd, domain, type, protocol);
    return fd;
}
int connect(int fd, const struct sockaddr *address, socklen_t length)
{
    static int (*real_connect)(int, const struct sockaddr *, socklen_t);
    if (!real_connect)
        real_connect = dlsym(RTLD_NEXT, "connect");
    note("CONNECT fd=%d\n", fd);
    return real_connect(fd, address, length);
}
ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
    static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
    if (!real_sendmsg)
        real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    note("SENDMSG fd=%d\n", fd);
    return real_sendmsg(fd, message, flags);
}
EOF
gcc -shared -fPIC -Wall -Wextra -Werror -o "$out/socket-audit.so" "$out/socket-audit.c" -ldl
: > "$out/retry-same-socket.audit"
ATTR_SOCKET_AUDIT="$out/retry-same-socket.audit" LD_PRELOAD="$out/socket-audit.so" \
    "$probe" retry-final > "$out/retry-same-socket.json"'''
RETRY_VERIFY_COMMAND: Final[str] = r'''set -eu
out=${ATTR_HOOK_DIR:?}
fd=$(awk '
$1 == "SOCKET" { sockets++; split($2, value, "="); if (!fd) fd=value[2]; else if (fd != value[2]) bad=1 }
$1 == "CONNECT" { connects++; split($2, value, "="); if (fd != value[2]) bad=1 }
$1 == "SENDMSG" { sends++; split($2, value, "="); if (fd != value[2]) bad=1 }
END { if (sockets != 1 || connects != 1 || sends != 3 || bad) exit 1; print fd }
' "$out/retry-same-socket.audit")
grep -Eq '"status":"pass","scenario":"retry-final"' "$out/retry-same-socket.json"
grep -Eq '"sends":3,"replies":3' "$out/retry-same-socket.json"
printf '{"status":"pass","socket_fd":%s,"connects":1,"sendmsg_calls":3,"reconnected":false}\n' "$fd"'''

REDEFER_HOLD_INITIAL: Final[str] = (
    "set -eu; out=${ATTR_HOOK_DIR:?}; server=${ATTR_SERVER_PID:?}; "
    "mountd=$(nsenter -t \"$server\" -m -n -- pgrep -xo rpc.mountd); "
    "printf '%s\\n' \"$mountd\" > \"$out/redefer.mountd\"; kill -STOP \"$mountd\"; "
    "timeout 5s sh -c 'while ! awk '\"'\"'$1 == \"State:\" && $2 ~ /^T/ {ok=1} END {exit !ok}'\"'\"' "
    "\"/proc/$1/status\"; do :; done' sh \"$mountd\"; "
    "nsenter -t \"$server\" -m -n -- sh -c 'printf \"1\\n\" > /proc/net/rpc/auth.unix.ip/flush; "
    "printf \"1\\n\" > /proc/net/rpc/nfsd.export/flush'"
)
REDEFER_INVALIDATE_REPLAY: Final[str] = (
    "set -eu; out=${ATTR_HOOK_DIR:?}; server=${ATTR_SERVER_PID:?}; mountd=$(cat \"$out/redefer.mountd\"); "
    "kill -STOP \"$mountd\"; timeout 5s sh -c 'while ! awk '\"'\"'$1 == \"State:\" && $2 ~ /^T/ "
    "{ok=1} END {exit !ok}'\"'\"' \"/proc/$1/status\"; do :; done' sh \"$mountd\"; "
    "nsenter -t \"$server\" -m -n -- sh -c 'printf \"1\\n\" > /proc/net/rpc/auth.unix.ip/flush; "
    "printf \"1\\n\" > /proc/net/rpc/nfsd.export/flush'"
)
REDEFER_RESUME: Final[str] = (
    "set -eu; mountd=$(cat \"${ATTR_HOOK_DIR:?}/redefer.mountd\"); kill -CONT \"$mountd\""
)

CROSS_LANE_COMMAND: Final[str] = r'''set -eu
root=${ATTR_PHASE9_ROOT:?}
out=${ATTR_HOOK_DIR:?}/cross-lane
lane0=${ATTR_LANE0_WORKLOAD:?}
lane1=${ATTR_LANE1_WORKLOAD:?}
rm -rf "$out"
mkdir -p "$out"
mkfifo "$out/l0.go" "$out/l0.event" "$out/l1.go" "$out/l1.event"
cleanup() {
    test ! -s "$out/l0.pid" || kill "$(cat "$out/l0.pid")" 2>/dev/null || true
    test ! -s "$out/l1.pid" || kill "$(cat "$out/l1.pid")" 2>/dev/null || true
    rm -f "$out/l0.go" "$out/l0.event" "$out/l1.go" "$out/l1.event"
}
trap cleanup EXIT HUP INT TERM
worker() {
    lane=$1
    workload=$2
    pid=$(cat "$root/lane$lane/client0.pid")
    nsenter -t "$pid" -m -n -- sh -c '
        set -eu
        go=$1
        event=$2
        workload=$3
        lane=$4
        exec 3<>"$go" 4<>"$event"
        printf "READY %s\n" "$lane" >&4
        IFS= read -r token <&3
        test "$token" = GO1
        "$workload" "$lane" 1
        printf "DONE1 %s\n" "$lane" >&4
        IFS= read -r token <&3
        test "$token" = GO2
        "$workload" "$lane" 2
        printf "DONE2 %s\n" "$lane" >&4
    ' sh "$out/l$lane.go" "$out/l$lane.event" "$workload" "$lane" &
    printf '%s\n' "$!" > "$out/l$lane.pid"
}
worker 0 "$lane0"
worker 1 "$lane1"
exec 5<>"$out/l0.go" 6<>"$out/l0.event" 7<>"$out/l1.go" 8<>"$out/l1.event"
IFS= read -r event0 <&6
IFS= read -r event1 <&8
test "$event0" = 'READY 0'
test "$event1" = 'READY 1'
printf 'GO1\n' >&5
IFS= read -r event0 <&6
test "$event0" = 'DONE1 0'
printf 'GO1\n' >&7
IFS= read -r event1 <&8
test "$event1" = 'DONE1 1'
printf 'GO2\n' >&5
IFS= read -r event0 <&6
test "$event0" = 'DONE2 0'
printf 'GO2\n' >&7
IFS= read -r event1 <&8
test "$event1" = 'DONE2 1'
wait "$(cat "$out/l0.pid")"
wait "$(cat "$out/l1.pid")"
trap - EXIT HUP INT TERM
cleanup'''


HOOKS: Final[dict[str, Hook]] = {
    "v4.abort-next-deferred": _phase8_arm(
        "v4.abort-next-deferred", "B04-V2 abort before deferred grant",
        "abort-next-deferred",
        ("deferred_abort_before_grant", "deferred_owner_none", "deferred_dropped")),
    "v4.abort-next-async": _phase8_arm(
        "v4.abort-next-async", "B05-V2 abort before async grant",
        "abort-next-async",
        ("async_abort_before_grant", "async_owner_none", "async_dropped")),
    "v4.pause-release-deferred-after-grant": _pause_hook("deferred"),
    "v4.pause-release-async-after-grant": _pause_hook("async"),
    "v4.generation-abort-ioctl": Hook(
        "v4.generation-abort-ioctl",
        "B04/B05-V3 abort a granted live generation",
        (_command("abort", GENERATION_ABORT_COMMAND),),
        (_proof("phase4_stats", "generation_aborted", 1),),
        ("evidence_level=vm-live-generation-abort-confirmed",
         "KCOV_FD is an inherited live owner fd",
         "KCOV_GENERATION was created on that fd"),
    ),
    "v5.redefer-cache-revisit": Hook(
        "v5.redefer-cache-revisit",
        "B04-V5 source-supported cache re-defer candidate",
        (
            _command("hold-initial-cache", REDEFER_HOLD_INITIAL),
            _command("arm-replay-pause", _write(
                PHASE8_CONTROL, "fault-arm pause-next-deferred-after-grant")),
            _command("resume-first-cache", REDEFER_RESUME),
            _command("observe-replay-pause", f"cat {PHASE8_STATS}"),
            _command("invalidate-at-replay", REDEFER_INVALIDATE_REPLAY),
            _command("release-replay", _write(
                PHASE8_CONTROL, "fault-release pause-deferred-after-grant")),
            _command("observe-redefer", f"cat {PHASE8_STATS}"),
            _command("resume-second-cache-cleanup", REDEFER_RESUME),
        ),
        (
            _proof("phase8_stats", "deferred_redeferred", 1),
            _proof("phase8_stats", "deferred_pause_after_grant_entered", 1),
            _proof("phase8_stats", "deferred_pause_after_grant_released", 1),
            _proof("phase8_stats", "deferred_pause_after_grant_timed_out", 0),
        ),
        ("evidence_level=vm-transition-confirmed-task6-phase8-candidates",
         "runner starts one lookup after hold-initial-cache",
         "runner observes each named counter before the next stage",
         "cleanup always resumes rpc.mountd"),
    ),
    "v5.cancel-saved-work": Hook(
        "v5.cancel-saved-work",
        "B04-V4 saved-work cancellation",
        (), (), (),
        failure=(
            "isolated live_saved_work=1; ss -K one matching client socket; then isolated "
            "live_saved_work=1; stop nfsd service to invoke cache_clean_deferred",
            "The baked guest rejected ss -K with RTNETLINK EINVAL. Service teardown did "
            "increment deferred_dropped and drain live_saved_work, but root_token_canceled "
            "and work_owner_none_after_abort stayed zero; nfsd could not restart and fixture "
            "cleanup timed out. No tested user-space teardown both proves the requested root "
            "ownerlessness and restores the fixture."),
    ),
    "v6.retry-same-cookie-same-socket": Hook(
        "v6.retry-same-cookie-same-socket",
        "B01/B02/B03/B11/B12-V6 raw NEW/RETRY/FINAL on one TCP fd",
        (
            _command("run", RETRY_RUN_COMMAND),
            _command("verify-socket-identity", RETRY_VERIFY_COMMAND),
        ),
        (
            _proof("phase7_stats", "raw_retry_same_cookie", 2),
            _proof("phase7_stats", "raw_retry_new_ordinal", 2),
            _proof("phase7_stats", "raw_cmsg_retry", 1),
            _proof("phase7_stats", "raw_cmsg_retry_final", 1),
            _proof("phase7_stats", "raw_tag_completed", 1),
        ),
        ("evidence_level=vm-exact-same-socket-confirmed",
         "LD_PRELOAD audit requires one AF_INET socket, one connect, and three sendmsg calls on one fd",
         "the disconnecting phase3 fault-arm sunrpc-retry control is not used"),
    ),
    "v7.concurrent-cross-lane": Hook(
        "v7.concurrent-cross-lane",
        "B03/B04/B05/B11-V7 fixed-lane READY/GO interleaving candidate",
        (
            _command("snapshot-before", f"cat {PHASE9_STATS}"),
            _command("interleave", CROSS_LANE_COMMAND),
            _command("snapshot-after", f"cat {PHASE9_STATS}"),
        ),
        (
            _proof("phase9_stats", "owner_lane_match", 1),
            _proof("phase9_stats", "cross_lane_attribution", 0),
        ),
        ("evidence_level=source-supported-candidate-unconfirmed-in-vm",
         "owner_lane_match proof is a delta_ge lower bound, not exact equality",
         "Gate 9 fixed lane0/lane1 roots already exist",
         "each executable workload segment emits completion before the next GO",
         "matrix cells remain NEW until per-lane VM coverage and counter proof pass"),
    ),
}

_SOCKET_RE: Final[re.Pattern[str]] = re.compile(
    r"^SOCKET fd=(\d+) domain=2 type=\d+ protocol=6$", re.MULTILINE)


def verify_retry_trace(trace_text: str, result_text: str) -> dict[str, object]:
    lines = trace_text.splitlines()
    sockets = _SOCKET_RE.findall(trace_text)
    if len(sockets) != 1:
        raise ValueError(f"expected one TCP socket, observed {len(sockets)}")
    fd = sockets[0]
    expected_connect = f"CONNECT fd={fd}"
    expected_send = f"SENDMSG fd={fd}"
    socket_line = next((line for line in lines if _SOCKET_RE.fullmatch(line)), "")
    expected_lines = [socket_line, expected_connect,
                      expected_send, expected_send, expected_send]
    if lines != expected_lines:
        raise ValueError(
            f"socket fd {fd}: expected only one socket, one connect and three sendmsg "
            f"records; observed lines={lines!r}")
    result = json.loads(result_text)
    expected = {"status": "pass", "scenario": "retry-final", "sends": 3, "replies": 3}
    for name, value in expected.items():
        if result.get(name) != value:
            raise ValueError(f"retry probe {name}: expected {value!r}, got {result.get(name)!r}")
    return {"status": "pass", "socket_fd": int(fd), "connects": 1,
            "sendmsg_calls": 3, "reconnected": False}


_ARG_ENV: Final[dict[str, dict[str, str]]] = {
    "v4.generation-abort-ioctl": {
        "hook_dir": "ATTR_HOOK_DIR", "kcov_fd": "KCOV_FD",
        "generation": "KCOV_GENERATION"},
    "v5.redefer-cache-revisit": {
        "hook_dir": "ATTR_HOOK_DIR", "server_pid": "ATTR_SERVER_PID"},
    "v6.retry-same-cookie-same-socket": {
        "hook_dir": "ATTR_HOOK_DIR", "phase7_probe": "ATTR_PHASE7_PROBE"},
    "v7.concurrent-cross-lane": {
        "phase9_root": "ATTR_PHASE9_ROOT", "hook_dir": "ATTR_HOOK_DIR",
        "lane0_workload": "ATTR_LANE0_WORKLOAD",
        "lane1_workload": "ATTR_LANE1_WORKLOAD"},
}


def _render_commands(hook: Hook, args: dict[str, object]) -> list[dict[str, str]]:
    allowed = _ARG_ENV.get(hook.hook_id, {})
    unknown = sorted(set(args) - set(allowed))
    if unknown:
        raise ValueError("unsupported hook args: " + ", ".join(unknown))
    assignments: list[str] = []
    for name in sorted(args):
        value = args[name]
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise ValueError(f"hook arg {name} must be a string or integer")
        assignments.append(f"{allowed[name]}={shlex.quote(str(value))}")
    if not assignments:
        return list(hook.commands)
    prefix = "env " + " ".join(assignments) + " sh -c "
    return [_command(item["stage"], prefix + shlex.quote(item["command"]))
            for item in hook.commands]


def hook_result(hook_id: str, *, dry_run: bool = False,
                args: dict[str, object] | None = None) -> dict[str, object]:
    hook = HOOKS[hook_id]
    rendered = _render_commands(hook, {} if args is None else args)
    base: dict[str, object] = {
        "schema": SCHEMA,
        "hook_id": hook.hook_id,
        "target": hook.target,
        "dry_run": dry_run,
        "commands": rendered,
        "proof": list(hook.proof),
    }
    if hook.failure is not None:
        attempted_trigger, reason = hook.failure
        base.update({"status": "UNFORCEABLE", "failure": {
            "type": "UNFORCEABLE", "attempted_trigger": attempted_trigger,
            "reason": reason}})
    else:
        base.update({"status": "FORCEABLE",
                     "requirements": list(hook.requirements)})
    return base


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hook_id", nargs="?")
    parser.add_argument("--list", action="store_true", dest="list_hooks")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--args-json", default="{}")
    parser.add_argument("--verify-retry-trace", nargs=2, metavar=("TRACE", "RESULT"))
    args = parser.parse_args(argv)
    if args.verify_retry_trace:
        trace, result = (Path(item) for item in args.verify_retry_trace)
        try:
            value = verify_retry_trace(
                trace.read_text(encoding="utf-8"), result.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(json.dumps({"schema": SCHEMA, "status": "INVALID_RETRY_TRACE",
                              "failure": str(error)}, sort_keys=True), file=sys.stderr)
            return 65
        print(json.dumps(value, sort_keys=True))
        return 0
    if args.list_hooks:
        if args.hook_id:
            parser.error("hook_id cannot be combined with --list")
        print(json.dumps({"schema": SCHEMA, "hooks": sorted(HOOKS)},
                         indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if not args.hook_id:
        parser.error("hook_id is required unless --list is used")
    if args.hook_id not in HOOKS:
        print(json.dumps({"schema": SCHEMA, "status": "INVALID_HOOK",
                          "failure": {"type": "INVALID_HOOK", "hook_id": args.hook_id}},
                         sort_keys=True), file=sys.stderr)
        return 64
    try:
        hook_args = json.loads(args.args_json)
        if not isinstance(hook_args, dict):
            raise ValueError("--args-json must decode to an object")
        result = hook_result(args.hook_id, dry_run=args.dry_run, args=hook_args)
    except (json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "INVALID_ARGS",
                          "failure": str(error)}, sort_keys=True), file=sys.stderr)
        return 66
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 2 if result["status"] == "UNFORCEABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
