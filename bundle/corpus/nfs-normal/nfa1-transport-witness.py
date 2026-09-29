#!/usr/bin/env python3
"""Run the corpus COPY workload with a direct NF-A1 transport witness."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REACH_RUNNER = ROOT / "tools" / "run-reach-adapted-window.py"
for import_root in (ROOT, ROOT / "tools"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

# The retained COPY log contains calls 0..10, all successful. These must be
# established before the shared runner reads its module-level environment.
os.environ["KOOV_EXPECTED_CALLS"] = "11"
os.environ["KOOV_CONFLICT_CALL"] = "-1"

COPY_WORKLOAD = HERE / "async-copy-v42-tcp.prog"
COPY_SHA256 = "b7b2ed5bba3004c354f61a5f8b648bca25e54d4189c866229d26c4590ea18068"
VMLINUX_SHA256 = "d2a133ed2d68b2269fa32c4059fe5051efec2fce0d92eb3b595f1f9fecdfc44f"
PROBE_SYMBOLS = {
    "__traceiter_svcsock_data_ready", "svc_xprt_enqueue",
    "__traceiter_svc_xprt_dequeue", "svc_process",
}
KINDS = ("ready", "enqueue", "dequeue", "process")
BUILTINS = {
    "svcsock_data_ready", "svc_xprt_enqueue", "svc_xprt_dequeue", "svc_process",
}
LINE_RE = re.compile(
    r"-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+\S+\s+"
    r"(?P<seconds>\d+\.\d+):\s+(?P<event>[^:]+):\s*(?P<body>.*)$"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_reach() -> Any:
    spec = importlib.util.spec_from_file_location("nfa1_reach", REACH_RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {REACH_RUNNER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args(argv: list[str] | None = None) -> tuple[Any, argparse.Namespace]:
    """Use the existing runner parser without creating its output directory."""
    reach = _load_reach()
    return reach, reach.parse_args(argv)


def preflight(args: argparse.Namespace) -> None:
    """Refuse a build whose probe ABI differs from the pinned COPY build."""
    if args.workload != COPY_WORKLOAD or _sha256(args.workload) != COPY_SHA256:
        raise ValueError("--workload is not the pinned nfs-normal COPY program")
    if _sha256(args.vmlinux) != VMLINUX_SHA256:
        raise ValueError("--vmlinux is not the pinned NF-A1 kernel artifact")
    config = args.vmlinux.parent / ".config"
    config_text = config.read_text() if config.is_file() else ""
    required_config = {"CONFIG_KPROBE_EVENTS=y", "CONFIG_HAVE_STATIC_CALL_INLINE=y"}
    missing_config = sorted(required_config - set(config_text.splitlines()))
    if missing_config:
        raise ValueError("pinned kernel config lacks: " + ", ".join(missing_config))
    for tool in ("nm", "pahole"):
        if shutil.which(tool) is None:
            raise ValueError(f"required preflight tool is unavailable: {tool}")
    symbols = subprocess.run(
        ["nm", "-n", str(args.vmlinux)], check=True, capture_output=True, text=True
    ).stdout
    present = {line.split()[-1] for line in symbols.splitlines() if line.split()}
    missing = sorted(PROBE_SYMBOLS - present)
    if missing:
        raise ValueError("pinned vmlinux lacks probe symbols: " + ", ".join(missing))
    layout = subprocess.run(
        ["pahole", "-C", "svc_rqst", str(args.vmlinux)],
        check=True, capture_output=True, text=True,
    ).stdout
    if not re.search(r"struct svc_xprt \*\s*rq_xprt;\s*/\*\s*40\s+8\s*\*/", layout):
        raise ValueError("struct svc_rqst.rq_xprt is not an 8-byte field at offset 40")


def _field(body: str, name: str) -> str:
    match = re.search(rf"(?:^|\s){name}=(\S+)", body)
    return match[1] if match else ""


def _service(body: str) -> str:
    match = re.search(r"(?:^|\s)service=(.*?)\s+vers=\d+\s+proc=", body)
    return match[1] if match else ""


def _out_of_scope_backchannel_process(event: dict[str, Any]) -> bool:
    return bool(
        event["event"] == "svc_process"
        and _field(event["body"], "addr") == "(null)"
        and _service(event["body"]) == "NFSv4 callback"
    )


def witness_trace(text: str) -> dict[str, Any]:
    """Accept one lossless endpoint- and request-correlated NF-A1 chain."""
    header = re.search(r"entries-in-buffer/entries-written:\s*(\d+)/(\d+)", text)
    begin = re.search(r"tracing_mark_write:\s+nfa1-begin-[0-9a-f]+", text)
    end = re.search(r"tracing_mark_write:\s+nfa1-end-[0-9a-f]+", text)
    checks = {
        "trace_present": bool(text),
        "trace_lossless": bool(
            header and header[1] == header[2]
            and not re.search(r"\bLOST\s+\d+\s+EVENTS\b", text, re.IGNORECASE)
        ),
        "workload_bracketed": bool(begin and end and begin.start() < end.start()),
        "trace_ordered": True,
        "matching_tracepoints_present": False,
        "context_pairs_complete": False,
        "correlated_xprt_chain": False,
        "nfsd_svc_process": False,
    }
    window = text[begin.end():end.start()] if checks["workload_bracketed"] else ""
    events: list[dict[str, Any]] = []
    timestamps: list[float] = []
    builtins: set[str] = set()
    for order, line in enumerate(window.splitlines()):
        match = LINE_RE.search(line)
        if not match:
            continue
        event = match["event"]
        body = match["body"]
        record: dict[str, Any] = {
            "event": event, "body": body, "pid": int(match["pid"]),
            "cpu": int(match["cpu"]), "order": order,
            "seconds": float(match["seconds"]),
        }
        timestamps.append(record["seconds"])
        if event in BUILTINS:
            builtins.add(event)
        dynamic = re.fullmatch(r"(ready|enqueue|dequeue|process)_[0-9a-f]+", event)
        if dynamic:
            pointer = re.search(r"\bxprt=(0x[0-9a-fA-F]+)\b", body)
            rqst = re.search(r"\brqst=(0x[0-9a-fA-F]+)\b", body)
            record["kind"] = dynamic[1]
            record["pointer"] = int(pointer[1], 16) if pointer else 0
            record["rqst"] = int(rqst[1], 16) if rqst else 0
        events.append(record)

    checks["trace_ordered"] = timestamps == sorted(timestamps)
    checks["matching_tracepoints_present"] = builtins == BUILTINS
    expected_builtin = {
        "ready": "svcsock_data_ready", "enqueue": "svc_xprt_enqueue",
        "dequeue": "svc_xprt_dequeue", "process": "svc_process",
    }
    pairs: list[dict[str, Any]] = []
    pairing_valid = True
    out_of_scope_backchannel_process = 0
    contexts = {(event["pid"], event["cpu"]) for event in events}
    for context in contexts:
        pending: dict[str, Any] | None = None
        for event in (item for item in events
                      if (item["pid"], item["cpu"]) == context):
            kind = event.get("kind")
            if kind in expected_builtin:
                if pending is not None:
                    pairing_valid = False
                pending = event
                continue
            if event["event"] not in BUILTINS:
                continue
            if pending is None:
                if _out_of_scope_backchannel_process(event):
                    out_of_scope_backchannel_process += 1
                    continue
                pairing_valid = False
                continue
            if event["event"] != expected_builtin[pending["kind"]]:
                pairing_valid = False
                pending = None
                continue
            pair = dict(pending)
            pair.update({
                "addr": _field(event["body"], "addr"),
                "server": _field(event["body"], "server"),
                "client": _field(event["body"], "client"),
                "flags": set(filter(None, _field(event["body"], "flags").split("|"))),
                "service": _service(event["body"]),
            })
            pairs.append(pair)
            pending = None
        if pending is not None:
            pairing_valid = False
    pairs.sort(key=lambda item: item["order"])
    dynamic_count = sum(event.get("kind") in KINDS for event in events)
    builtin_count = sum(event["event"] in BUILTINS for event in events)
    checks["context_pairs_complete"] = (
        pairing_valid and len(pairs) == dynamic_count
        and len(pairs) + out_of_scope_backchannel_process == builtin_count
    )

    def first_pointer_event(after: int, pointer: int,
                            kinds: set[str]) -> dict[str, Any] | None:
        return next((item for item in pairs
                     if item["order"] > after and item["pointer"] == pointer
                     and item["kind"] in kinds), None)

    matched_pointer: str | None = None
    for ready in (item for item in pairs
                  if item["kind"] == "ready" and item["pointer"] != 0
                  and ready_flags_valid(item)):
        enqueue = first_pointer_event(ready["order"], ready["pointer"],
                                      {"enqueue", "dequeue", "process"})
        if not (enqueue and enqueue["kind"] == "enqueue"
                and (enqueue["pid"], enqueue["cpu"]) ==
                    (ready["pid"], ready["cpu"])
                and enqueue["client"] == ready["addr"]
                and endpoint_valid(enqueue)
                and not ({"BUSY", "CLOSE"} & enqueue["flags"])):
            continue
        dequeue = first_pointer_event(enqueue["order"], ready["pointer"],
                                      {"enqueue", "dequeue", "process"})
        if not (dequeue and dequeue["kind"] == "dequeue"
                and dequeue["rqst"] != 0 and endpoint_valid(dequeue)
                and "CLOSE" not in dequeue["flags"]
                and (dequeue["server"], dequeue["client"]) ==
                    (enqueue["server"], enqueue["client"])):
            continue
        process = next((item for item in pairs
                        if item["order"] > dequeue["order"]
                        and item["pointer"] == ready["pointer"]
                        and item["kind"] == "process"), None)
        if process is None:
            continue
        between = [item for item in pairs
                   if dequeue["order"] < item["order"] < process["order"]]
        invalidating = any(
            item["kind"] == "dequeue" and item["pid"] == dequeue["pid"]
            or item["pointer"] == ready["pointer"] and item["kind"] == "dequeue"
            or item["pointer"] == ready["pointer"] and item["kind"] == "enqueue"
            and not receive_reenqueue_valid(item, dequeue)
            for item in between
        )
        receive_reenqueues = [item for item in between
                              if item["pointer"] == ready["pointer"]
                              and item["kind"] == "enqueue"]
        if not (not invalidating and len(receive_reenqueues) <= 1
                and process["pid"] == dequeue["pid"]
                and process["rqst"] == dequeue["rqst"]
                and process["addr"] == dequeue["client"]):
            continue
        checks["correlated_xprt_chain"] = True
        checks["nfsd_svc_process"] = process["service"] == "nfsd"
        matched_pointer = f"0x{ready['pointer']:x}"
        if checks["nfsd_svc_process"]:
            break
    return {
        "assert": all(checks.values()), "checks": checks,
        "matched_xprt": matched_pointer,
        "out_of_scope_backchannel_process": out_of_scope_backchannel_process,
        "event_counts": {
            name: sum(event.get("kind") == name for event in events)
            for name in KINDS
        } | {"svc_process": sum(event["event"] == "svc_process" for event in events)},
    }


def endpoint_valid(event: dict[str, Any]) -> bool:
    return bool(event["server"] and event["client"])


def receive_reenqueue_valid(event: dict[str, Any], dequeue: dict[str, Any]) -> bool:
    return bool(
        (event["pid"], event["cpu"]) == (dequeue["pid"], dequeue["cpu"])
        and endpoint_valid(event)
        and (event["server"], event["client"]) ==
            (dequeue["server"], dequeue["client"])
        and not ({"BUSY", "CLOSE"} & event["flags"])
    )


def ready_flags_valid(event: dict[str, Any]) -> bool:
    return bool(event["addr"] and "CLOSE" not in event["flags"])


class NFATransportPlan:
    """attr_plan implementation that owns one unique trace setup per trial."""

    def __init__(self, output: Path) -> None:
        self.output = output
        self.counts = {"off": 0, "on": 0}
        self.active: dict[str, str] | None = None

    def before_workload(self, vm: Any, mode: str) -> None:
        self.counts[mode] += 1
        token = secrets.token_hex(6)
        group = f"nfa1_{token}"
        instance = f"nfa1_{token}"
        self.active = {"mode": mode, "token": token, "group": group,
                       "instance": instance, "trial": str(self.counts[mode])}
        definitions = (
            f"p:{group}/ready_{token} __traceiter_svcsock_data_ready xprt=$arg2:x64\n"
            f"p:{group}/enqueue_{token} svc_xprt_enqueue xprt=$arg1:x64\n"
            f"p:{group}/dequeue_{token} __traceiter_svc_xprt_dequeue "
            "rqst=$arg2:x64 xprt=+40($arg2):x64\n"
            f"p:{group}/process_{token} svc_process "
            "rqst=$arg1:x64 xprt=+40($arg1):x64\n"
        )
        command = f"""set -eu
T=/sys/kernel/tracing
mountpoint -q "$T" || mount -t tracefs tracefs "$T"
test ! -e "$T/instances/{instance}"
test ! -e "$T/instances/{instance}_dispatch"
mkdir "$T/instances/{instance}"
mkdir "$T/instances/{instance}_dispatch"
I="$T/instances/{instance}"
D="$T/instances/{instance}_dispatch"
cat >> "$T/dynamic_events" <<'NFA1_EVENTS'
{definitions}NFA1_EVENTS
for e in sunrpc/svcsock_data_ready sunrpc/svc_xprt_dequeue; do
    test -r "$D/events/$e/format"
    echo 1 > "$D/events/$e/enable"
    test "$(cat "$D/events/$e/enable")" = 1
done
for e in sunrpc/svcsock_data_ready sunrpc/svc_xprt_enqueue sunrpc/svc_xprt_dequeue sunrpc/svc_process {group}/ready_{token} {group}/enqueue_{token} {group}/dequeue_{token} {group}/process_{token}; do
    test -r "$I/events/$e/format"
    cat "$I/events/$e/format"
    echo 1 > "$I/events/$e/enable"
done
echo global > "$I/trace_clock"
echo 4096 > "$I/buffer_size_kb"
echo > "$I/trace"
echo 1 > "$I/tracing_on"
echo nfa1-begin-{token} > "$I/trace_marker"
"""
        vm.guest(f"nfa1-{token}-arm", command)

    def during_workload(self, vm: Any, mode: str) -> None:
        del vm, mode

    def after_workload(self, vm: Any, mode: str) -> None:
        if self.active is None or self.active["mode"] != mode:
            raise RuntimeError("NF-A1 trace state is not active")
        state = self.active
        result = vm.guest(f"nfa1-{state['token']}-capture", f"""set -eu
I=/sys/kernel/tracing/instances/{state['instance']}
echo nfa1-end-{state['token']} > "$I/trace_marker"
echo 0 > "$I/tracing_on"
cat "$I/trace"
echo 0 > "$I/events/enable"
""")
        trial = self.output / f"remote_{mode}" / f"trial_{int(state['trial']):02d}"
        raw = trial / "nfa1-transport-trace.txt"
        raw.write_text(result.stdout, encoding="utf-8")
        verdict = witness_trace(result.stdout)
        (trial / "nfa1-transport-verdict.json").write_text(
            json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if not verdict["assert"]:
            failed = sorted(name for name, passed in verdict["checks"].items()
                            if not passed)
            raise ValueError("NF-A1 transport witness failed: " + ", ".join(failed))

    def cleanup(self, vm: Any, mode: str) -> None:
        del mode
        if self.active is None:
            return
        state = self.active
        token, group, instance = state["token"], state["group"], state["instance"]
        vm.guest(f"nfa1-{token}-cleanup", f"""set -eu
T=/sys/kernel/tracing
I="$T/instances/{instance}"
D="$T/instances/{instance}_dispatch"
if test -d "$I"; then
    echo 0 > "$I/tracing_on" || true
    echo 0 > "$I/events/enable" || true
fi
if test -d "$D"; then
    echo 0 > "$D/events/enable" || true
fi
for event in process_{token} dequeue_{token} enqueue_{token} ready_{token}; do
    echo "-:{group}/$event" >> "$T/dynamic_events" 2>/dev/null || true
done
if test -d "$I"; then rmdir "$I"; fi
if test -d "$D"; then rmdir "$D"; fi
test ! -e "$I"
test ! -e "$D"
! grep -q "^[pr]:{group}/" "$T/dynamic_events"
""")
        self.active = None


def main(argv: list[str] | None = None) -> int:
    reach, args = parse_args(argv)
    preflight(args)
    plan = NFATransportPlan(args.output)
    try:
        reach.main(argv, attr_plan=plan)
    except Exception as error:
        print(f"NF-A1 FAIL: {error}", file=sys.stderr)
        return 1
    status = "READY" if args.preflight else "PASS"
    print(f"NF-A1 {status}: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
