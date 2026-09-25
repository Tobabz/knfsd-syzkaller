#!/usr/bin/env python3
"""Dump full trial evidence (key gates) for OFF/ON trial_01."""
import json
import os
from pathlib import Path

root = (Path(os.environ.get("KOOV_WORK_ROOT",
                      Path(__file__).resolve().parent.parent)) / "evidence")
for mode in ("remote_off", "remote_on"):
    path = root / mode / "trial_01" / "trial_evidence.json"
    data = json.loads(path.read_text())
    print("======== %s/trial_01 ========" % mode)
    print(json.dumps(data, indent=1)[:8000])