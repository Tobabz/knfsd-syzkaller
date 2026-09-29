"""Physical, ownerless callback trace parsing and causal delivery witnesses."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict

CALLBACK_EVENTS: Final = (
    "nfsd_cb_offload", "nfsd_cb_start", "nfsd_cb_offload_done",
    "nfs4_copy", "nfs4_cb_offload", "nfsd_cb_queue",
    "workqueue_queue_work", "workqueue_execute_start", "workqueue_execute_end",
)
B06_EVENTS: Final = (
    "nfs4_set_delegation", "nfsd_cb_recall", "nfsd_cb_queue",
    "workqueue_queue_work", "workqueue_execute_start", "nfsd_cb_start",
    "workqueue_execute_end", "svc_process_bc_entry", "nfs4_cb_recall",
    "nfsd_cb_recall_done",
)
CallbackVerdict = TypedDict("CallbackVerdict", {
    "assert": bool, "checks": dict[str, bool], "expected_copies": int,
    "matched_copies": int, "event_counts": dict[str, int],
    "max_delivery_seconds": float | None,
})


@dataclass(frozen=True, slots=True)
class CallbackEvent:
    order: int
    pid: int
    seconds: float
    fields: dict[str, str]
    payload: str = ""


def callback_witness(path: Path, expected: int, bound: float) -> CallbackVerdict:
    """Require lossless, workload-scoped worker activation and COPY delivery.

    cb_start is inside nfsd4_run_cb_work, not the enqueue function.
    Client cb_offload follows complete() (or saves an early pending result).
    Work identity and enqueuer/worker task ordering exclude other callbacks.
    """
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    header = re.search(r"entries-in-buffer/entries-written: (\d+)/(\d+)", text)
    begin = text.find(": reach-copy-begin\n")
    end = text.find(": reach-copy-end\n")
    checks = {
        "trace_present": bool(text),
        "trace_lossless": bool(header and header[1] == header[2]),
        "workload_bracketed": 0 <= begin < end,
        "trace_fields_valid": True,
    }
    events: dict[str, list[CallbackEvent]] = {name: [] for name in CALLBACK_EVENTS}
    window = text[begin:end] if checks["workload_bracketed"] else ""
    timestamps: list[float] = []
    for order, line in enumerate(window.splitlines()):
        match = re.search(r"-(\d+)\s+\[\d+\]\s+\S+\s+(\d+\.\d+): (\w+): (.*)$", line)
        if match and match[3] in events:
            fields: dict[str, str] = {}
            # One token pass: never overwrite duplicates or truncate a symbol.
            for token in re.finditer(
                    r"(?<!\S)(?:(\w+)=|(client|stateid|struct|function) )(\S+)", match[4]):
                key = token[1] or token[2]
                value = token[3]
                if key in fields:
                    checks["trace_fields_valid"] = False
                    continue
                fields[key] = value.removesuffix(":") if key == "struct" else value
            seconds = float(match[2])
            timestamps.append(seconds)
            events[match[3]].append(CallbackEvent(order, int(match[1]), seconds, fields))
    checks["trace_ordered"] = timestamps == sorted(timestamps)
    checks["copy_count_exact"] = len(events["nfs4_copy"]) == expected > 0
    checks["callback_event_counts_exact"] = all(
        len(values) == expected for values in events.values())
    matched = 0
    latencies: list[float] = []
    used_callbacks: set[int] = set()
    used_queues: set[int] = set()
    for copy in events["nfs4_copy"]:
        fields = copy.fields
        if not (fields.get("error") == "0" and fields.get("intra") == "1"
                and fields.get("sync") == fields.get("res_sync") == "0"
                and fields.get("len", "").isdigit() and int(fields["len"]) > 0
                and fields.get("cb_stateid") and fields.get("dst_fhandle")):
            continue
        callbacks = [(index, event) for index, event in enumerate(events["nfs4_cb_offload"])
                     if index not in used_callbacks
                     and event.fields.get("cb_stateid") == fields["cb_stateid"]
                     and event.fields.get("fhandle") == fields["dst_fhandle"]
                     and event.fields.get("error") == "0"
                     and event.fields.get("cb_count") == fields["len"]
                     and copy.order < event.order
                     and 0 <= event.seconds - copy.seconds < bound]
        if len(callbacks) != 1:
            continue
        callback_index, callback = callbacks[0]
        queues = [(index, event) for index, event in enumerate(events["nfsd_cb_offload"])
                  if index not in used_queues and event.fields.get("status") == "0"
                  and event.fields.get("fh_hash") == fields["dst_fhandle"]
                  and event.fields.get("count") == fields["len"]
                  and event.fields.get("client") and event.fields.get("stateid")
                  and copy.order < event.order < callback.order
                  and 0 <= callback.seconds - event.seconds < bound]
        if len(queues) != 1:
            continue
        queue_index, queued = queues[0]
        cb_queues = [event for event in events["nfsd_cb_queue"]
                     if event.pid == queued.pid
                     and event.fields.get("client") == queued.fields["client"]
                     and event.fields.get("opcode") == "CB_OFFLOAD"
                     and queued.order < event.order < callback.order]
        if len(cb_queues) != 1:
            continue
        work_queues = [event for event in events["workqueue_queue_work"]
                       if event.pid == queued.pid
                       and event.fields.get("function") == "nfsd4_run_cb_work"
                       and event.fields.get("struct")
                       and cb_queues[0].order < event.order < callback.order]
        if len(work_queues) != 1:
            continue
        work = work_queues[0]
        executions = [event for event in events["workqueue_execute_start"]
                      if event.fields.get("struct") == work.fields["struct"]
                      and event.fields.get("function") == "nfsd4_run_cb_work"
                      and work.order < event.order < callback.order]
        if len(executions) != 1:
            continue
        execution = executions[0]
        work_end = next((event for event in events["workqueue_execute_end"]
                         if event.pid == execution.pid
                         and event.fields.get("struct") == work.fields["struct"]
                         and event.fields.get("function") == "nfsd4_run_cb_work"
                         and execution.order < event.order), None)
        starts = [event for event in events["nfsd_cb_start"]
                  if event.pid == execution.pid
                  and event.fields.get("client") == queued.fields["client"]
                  and work_end is not None
                  and execution.order < event.order < work_end.order
                  and event.order < callback.order]
        done = [event for event in events["nfsd_cb_offload_done"]
                if event.fields.get("client") == queued.fields["client"]
                and event.fields.get("stateid") == queued.fields["stateid"]
                and event.fields.get("status") == "0"
                and callback.order < event.order
                and 0 <= event.seconds - callback.seconds < bound]
        if len(starts) == len(done) == 1:
            matched += 1
            used_callbacks.add(callback_index)
            used_queues.add(queue_index)
            latencies.append(callback.seconds - copy.seconds)
    checks["all_copies_delivered_by_worker"] = matched == expected > 0
    return {"assert": all(checks.values()), "checks": checks,
            "expected_copies": expected, "matched_copies": matched,
            "event_counts": {name: len(values) for name, values in events.items()},
            "max_delivery_seconds": max(latencies, default=None)}


def _b06_events(text: str) -> tuple[dict[str, bool], dict[str, list[CallbackEvent]]]:
    header = re.search(r"entries-in-buffer/entries-written: (\d+)/(\d+)", text)
    begin_token, end_token = ": b06-recall-begin\n", ": b06-recall-end\n"
    begin, end = text.find(begin_token), text.find(end_token)
    checks = {
        "trace_present": bool(text),
        "trace_lossless": bool(header and header[1] == header[2]),
        "workload_bracketed": (begin >= 0 and end > begin and
                                 text.count(begin_token) == text.count(end_token) == 1),
        "trace_fields_valid": True,
    }
    events: dict[str, list[CallbackEvent]] = {name: [] for name in B06_EVENTS}
    window = text[begin:end] if checks["workload_bracketed"] else ""
    timestamps: list[float] = []
    for order, line in enumerate(window.splitlines()):
        match = re.search(r"-(\d+)\s+\[\d+\]\s+\S+\s+(\d+\.\d+): (\w+):\s*(.*)$", line)
        if not match or match[3] not in events:
            continue
        fields: dict[str, str] = {}
        for token in re.finditer(
                r"(?<!\S)(?:(\w+)=|(client|stateid|struct|function) )(\S+)", match[4]):
            key, value = token[1] or token[2], token[3]
            if key in fields:
                checks["trace_fields_valid"] = False
                continue
            fields[key] = value.removesuffix(":") if key == "struct" else value
        seconds = float(match[2])
        timestamps.append(seconds)
        events[match[3]].append(
            CallbackEvent(order, int(match[1]), seconds, fields, match[4]))
    checks["trace_ordered"] = timestamps == sorted(timestamps)
    return checks, events


def b06_recall_witness(path: Path, counter_before: int, counter_after: int,
                       bound: float, remote_on: bool,
                       svc_process_bc_in_remote_kcov: bool) -> dict[str, object]:
    """Correlate a granted delegation through callback ACK and server completion."""
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    checks, events = _b06_events(text)
    counter_delta = counter_after - counter_before
    checks["record_backchannel_monotonic"] = counter_delta >= 0
    checks["record_backchannel_positive"] = counter_delta >= 1
    checks["delegation_grant_observed"] = bool(events["nfs4_set_delegation"])
    required_fields = {
        "nfs4_set_delegation": ("fhandle",),
        "nfsd_cb_recall": ("addr", "client", "stateid"),
        "nfsd_cb_queue": ("addr", "client", "cb", "opcode"),
        "workqueue_queue_work": ("struct", "function"),
        "workqueue_execute_start": ("struct", "function"),
        "nfsd_cb_start": ("addr", "client", "state"),
        "workqueue_execute_end": ("struct", "function"),
        "nfs4_cb_recall": ("error", "fhandle", "stateid", "dstaddr"),
        "nfsd_cb_recall_done": ("client", "stateid", "status"),
    }
    checks["required_identities_present"] = all(
        all(event.fields.get(field) for field in fields)
        for name, fields in required_fields.items() for event in events[name]
    ) and all("svc_process_bc" in event.payload
              for event in events["svc_process_bc_entry"])
    matched = 0
    used_recalls: set[int] = set()
    for grant in events["nfs4_set_delegation"]:
        grant_fhandle = grant.fields.get("fhandle")
        if not grant_fhandle:
            continue
        for recall_index, recall in enumerate(events["nfsd_cb_recall"]):
            recall_client = recall.fields.get("client")
            recall_stateid = recall.fields.get("stateid")
            recall_addr = recall.fields.get("addr")
            if (recall_index in used_recalls or not recall_client
                    or not recall_stateid or not recall_addr
                    or grant.order >= recall.order):
                continue
            if any(other.fields.get("fhandle") == grant_fhandle
                   and grant.order < other.order < recall.order
                   for other in events["nfs4_set_delegation"]):
                continue
            later_recalls = [event.order for event in events["nfsd_cb_recall"]
                             if event.order > recall.order]
            upper = min(later_recalls, default=len(text.splitlines()) + 1)
            queues = [event for event in events["nfsd_cb_queue"]
                      if event.pid == recall.pid
                      and event.fields.get("client") == recall_client
                      and event.fields.get("addr") == recall_addr
                      and event.fields.get("cb")
                      and event.fields.get("opcode") == "CB_RECALL"
                      and recall.order < event.order < upper]
            if len(queues) != 1:
                continue
            work_queues = [event for event in events["workqueue_queue_work"]
                           if event.pid == recall.pid
                           and event.fields.get("function") == "nfsd4_run_cb_work"
                           and event.fields.get("struct")
                           and queues[0].order < event.order < upper]
            if len(work_queues) != 1:
                continue
            work = work_queues[0]
            starts = [event for event in events["workqueue_execute_start"]
                      if event.fields.get("struct") == work.fields["struct"]
                      and event.fields.get("function") == "nfsd4_run_cb_work"
                      and work.order < event.order < upper]
            if len(starts) != 1:
                continue
            start = starts[0]
            ends = [event for event in events["workqueue_execute_end"]
                    if event.pid == start.pid
                    and event.fields.get("struct") == work.fields["struct"]
                    and event.fields.get("function") == "nfsd4_run_cb_work"
                    and start.order < event.order < upper]
            if len(ends) != 1:
                continue
            end = ends[0]
            cb_starts = [event for event in events["nfsd_cb_start"]
                         if event.pid == start.pid
                         and event.fields.get("client") == recall_client
                         and event.fields.get("addr") == recall_addr
                         and start.order < event.order < end.order]
            probes = [event for event in events["svc_process_bc_entry"]
                      if cb_starts and "svc_process_bc" in event.payload
                      and end.order < event.order < upper]
            acks = [event for event in events["nfs4_cb_recall"]
                    if probes and probes[0].order < event.order < upper
                    and event.pid == probes[0].pid
                    and event.fields.get("error") == "0"
                    and event.fields.get("fhandle") == grant_fhandle
                    and event.fields.get("stateid")
                    and event.fields.get("dstaddr")]
            done = [event for event in events["nfsd_cb_recall_done"]
                    if acks and acks[0].order < event.order < upper
                    and event.fields.get("client") == recall_client
                    and event.fields.get("stateid") == recall_stateid
                    and event.fields.get("status") == "0"
                    and 0 <= event.seconds - grant.seconds < bound]
            if len(cb_starts) == len(probes) == len(acks) == len(done) == 1:
                matched += 1
                used_recalls.add(recall_index)
                break
    checks["complete_recall_chain_observed"] = matched >= 1
    observed = all(checks.values())
    if remote_on:
        checks["svc_process_bc_ownerless"] = not svc_process_bc_in_remote_kcov
        status = ("OBSERVED_OWNERLESS_KCOV" if observed and checks["svc_process_bc_ownerless"]
                  else "OBSERVED_ATTRIBUTED_KCOV" if observed else "NOT_OBSERVED")
    else:
        status = "OBSERVED_REMOTE_KCOV_DISABLED" if observed else "NOT_OBSERVED"
    return {
        "assert": all(checks.values()), "status": status, "checks": checks,
        "matched_recalls": matched,
        "event_counts": {name: len(values) for name, values in events.items()},
        "record_backchannel": {"before": counter_before, "after": counter_after,
                               "delta": counter_delta},
        "remote_kcov": {"enabled": remote_on,
                        "svc_process_bc_observed": svc_process_bc_in_remote_kcov},
    }
