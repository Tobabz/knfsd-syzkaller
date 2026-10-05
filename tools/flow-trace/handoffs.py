#!/usr/bin/env python3
"""Judge handoffs (submit -> execute pairs) in a trace recorded by capture.py.

A scenario file lists transitions. Each transition names a submit event and an
execute event. The judge pairs every submit with the first later execute that
satisfies the rule, then reports one verdict per transition:

  LINKED    keyed rule: a submit and an execute share the same key value
  ORDERED   unkeyed rule: an execute by a different task follows a submit
            (weaker than LINKED: no value ties the two events together)
  UNPAIRED  the submit event occurred, but no execute satisfied the rule
  MISSING   the submit event never occurred

Only LINKED and ORDERED count as observed. A PC or a file effect never does.
"""
import argparse
import gzip
import json
import re
import sys
from pathlib import Path

LINE = re.compile(r"^\s*(?P<comm>.+)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+(?P<flags>\S+)\s+"
                  r"(?P<ts>\d+\.\d+):\s+(?P<name>\w+):\s*(?P<detail>.*)$")


def parse(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    events = []
    with opener(path, "rt", errors="replace") as handle:
        for text in handle:
            if text.startswith("#"):
                continue
            match = LINE.match(text.rstrip("\n"))
            if not match:
                continue
            e = match.groupdict()
            flags = e["flags"]
            third = flags[2] if len(flags) > 2 else "."
            e["ctx"] = "softirq" if third in "sH" else "hardirq" if third == "h" else "task"
            e["pid"] = int(e["pid"])
            e["ts"] = float(e["ts"])
            e["idx"] = len(events)
            e["task"] = (e["comm"], e["pid"])
            events.append(e)
    return events


def buffer_loss(path):
    """Return (in_buffer, written) from the trace header, or None if the header is absent."""
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", errors="replace") as handle:
        for text in handle:
            if not text.startswith("#"):
                break
            found = re.search(r"entries-in-buffer/entries-written:\s*(\d+)/(\d+)", text)
            if found:
                return int(found.group(1)), int(found.group(2))
    return None


def side_matches(side, e):
    """Return the regex match object (possibly empty) if event e fits the side filter."""
    if e["name"] != side["event"]:
        return None
    if "comm" in side and not re.search(side["comm"], e["comm"]):
        return None
    if "ctx" in side and side["ctx"] != e["ctx"]:
        return None
    found = re.search(side.get("detail", ""), e["detail"])
    return found


def key_of(found):
    groups = found.groupdict() if found else {}
    return groups.get("k")


def judge(events, rule, results):
    submit, execute = rule["submit"], rule["execute"]
    keyed = rule.get("link", "key") == "key"
    chain = submit.get("after")
    anchors = []
    if chain:
        side = chain.get("side", "execute") + "_event"
        anchors = [p[side] for p in results.get(chain["rule"], [])]
    submits = []
    for e in events:
        found = side_matches(submit, e)
        if found is None:
            continue
        if chain and not any(
                0 <= e["ts"] - a["ts"] <= chain.get("window_us", 1e12) / 1e6 and e["idx"] > a["idx"]
                and (not chain.get("same_task") or e["task"] == a["task"])
                for a in anchors):
            continue
        submits.append((e, key_of(found)))
    # Pair from the execute side: each execute takes the latest earlier submit
    # that is still unused, has the same key, and lies inside the optional window.
    window = rule.get("within_us")
    pairs, taken = [], set()
    for e in events:
        found = side_matches(execute, e)
        if found is None:
            continue
        ekey = key_of(found)
        for s, skey in reversed([x for x in submits if x[0]["idx"] < e["idx"]]):
            if s["idx"] in taken:
                continue
            if window is not None and (e["ts"] - s["ts"]) * 1e6 > window:
                break
            if keyed and (skey is None or skey != ekey):
                continue
            if not keyed and s["task"] == e["task"] and not rule.get("same_task_ok"):
                continue
            taken.add(s["idx"])
            pairs.append({"submit_event": s, "execute_event": e, "key": skey})
            break
    results[rule["id"]] = pairs
    if not submits:
        verdict = "MISSING"
    elif not pairs:
        verdict = "UNPAIRED"
    else:
        verdict = "LINKED" if keyed else "ORDERED"
    return verdict, len(submits), pairs


def describe(e):
    return "%s-%d[%s]" % (e["comm"], e["pid"], e["ctx"])


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("trace", type=Path)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--json", type=Path, help="write the full result as JSON")
    parser.add_argument("--only", help="comma-separated transition ids to judge (earlier chain "
                        "rules they depend on are judged too but not printed)")
    parser.add_argument("--control", action="store_true",
                        help="negative control: succeed only if every transition marked "
                        "'specific' in the scenario is absent from the trace")
    args = parser.parse_args()
    events = parse(args.trace)
    spec = json.loads(args.scenario.read_text())
    results, table, observed, leaked = {}, [], 0, 0
    only = set(args.only.split(",")) if args.only else None
    for rule in spec["transitions"]:
        verdict, nsubmit, pairs = judge(events, rule, results)
        if only is not None and rule["id"] not in only:
            continue
        first = pairs[0] if pairs else None
        row = {"id": rule["id"], "flow": rule.get("flow", ""), "text": rule["text"],
               "verdict": verdict, "submits": nsubmit, "pairs": len(pairs)}
        if first:
            s, e = first["submit_event"], first["execute_event"]
            row.update(submit=describe(s), execute=describe(e), key=first["key"],
                       latency_us=round((e["ts"] - s["ts"]) * 1e6))
        table.append(row)
        row["specific"] = bool(rule.get("specific"))
        observed += verdict in ("LINKED", "ORDERED")
        leaked += row["specific"] and verdict in ("LINKED", "ORDERED")
    loss = buffer_loss(args.trace)
    if loss is None:
        note = "buffer header missing"
    elif loss[0] == loss[1]:
        note = "no loss"
    else:
        note = "LOSS: %d of %d entries overwritten; MISSING is not trustworthy" % (
            loss[1] - loss[0], loss[1])
    print("trace events: %d   scenario: %s   [%s]" % (len(events), spec["scenario"], note))
    for row in table:
        line = "%-7s %-9s %-8s submits=%-3d pairs=%-3d %s" % (
            row["id"], row["flow"], row["verdict"], row["submits"], row["pairs"], row["text"])
        if "submit" in row:
            line += "\n          %s -> %s  key=%s  +%dus" % (
                row["submit"], row["execute"], row["key"], row["latency_us"])
        print(line)
    print("observed %d of %d transitions" % (observed, len(table)))
    if args.json:
        args.json.write_text(json.dumps({"scenario": spec["scenario"], "rows": table}, indent=2))
    if args.control:
        print("control: %d specific transitions observed (must be 0)" % leaked)
        return 0 if leaked == 0 else 1
    return 0 if observed == len(table) else 1


if __name__ == "__main__":
    sys.exit(main())
