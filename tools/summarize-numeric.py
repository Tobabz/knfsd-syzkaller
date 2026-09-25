#!/usr/bin/env python3
"""Numeric summary of AB trials: functional + counter deltas for all trials."""
import json
import os
from pathlib import Path

root = (Path(os.environ.get("KOOV_WORK_ROOT",
                      Path(__file__).resolve().parent.parent)) / "evidence")
for mode in ("remote_off", "remote_on"):
    for trial in ("trial_01", "trial_02"):
        path = root / mode / trial / "trial_evidence.json"
        data = json.loads(path.read_text())
        print("==== %s/%s ====" % (mode, trial))
        print("status:", data.get("status"))
        summary = {}
        for key in ("functional", "coverage", "perf", "phase3", "phase4",
                    "phase5", "phase6", "executor"):
            value = data.get(key)
            if value is not None:
                print("  %s: %s" % (key, json.dumps(value)[:400]))
        print("  ---- counters (delta) ----")
        for key, value in data.items():
            if isinstance(value, dict) and "delta" in value and key not in (
                    "functional", "coverage", "perf", "phase3", "phase4",
                    "phase5", "phase6", "executor", "remote_off_counters",
                    "remote_on_counters", "memory_before", "memory_after",
                    "cpu_before", "cpu_after"):
                print("  %s: %s" % (key, json.dumps(value)[:300]))
        print("  extra_files:", data.get("extra_files"),
              "executions:", data.get("executions"),
              "remote_off=False, remote_on=True got:",
              data.get("remote_auto_attribution") is not None)