#!/usr/bin/env python3
"""Summarize the AB experiment: manifest + per-trial key gates."""
import json
import os
from pathlib import Path

root = (Path(os.environ.get("KOOV_WORK_ROOT",
                      Path(__file__).resolve().parent.parent)) / "evidence")
manifest = json.loads((root / "experiment_manifest.json").read_text())
print("=== experiment_manifest.json ===")
print(json.dumps(manifest, indent=2))

KEY = ("status", "failed_checks", "mode",
       "remote_start_ok", "extra_files", "executions", "extra_files_zero",
       "managed_generations", "cross_lane_attribution", "conflict_errno",
       "remote_stop_exact", "scratch_overflow", "merge_truncation",
       "ordinal_mismatch", "remote_start_nested", "lane_seen_mask",
       "base_image_unchanged", "executor", "functional", "coverage",
       "perf", "calls_per_execution", "bindings", "local_coverage_records",
       "wire_work_attached", "wire_work_ownerless")

for mode in ("remote_off", "remote_on"):
    for trial in ("trial_01", "trial_02"):
        path = root / mode / trial / "trial_evidence.json"
        if not path.is_file():
            print("MISSING", path)
            continue
        data = json.loads(path.read_text())
        print("=== %s/%s ===" % (mode, trial))
        for key in KEY:
            if key in data:
                print("  %s: %s" % (key, data[key]))
        print("  ---- counter deltas ----")
        for key, value in data.items():
            if isinstance(value, dict) and "delta" in value:
                print("  %s.delta: %s" % (key, value["delta"]))