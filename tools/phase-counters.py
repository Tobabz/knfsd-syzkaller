#!/usr/bin/env python3
"""Pull phase3..phase6 + counter details from AB trial evidence for the report."""
import json
import os
from pathlib import Path

root = (Path(os.environ.get("KOOV_WORK_ROOT",
                      Path(__file__).resolve().parent.parent)) / "evidence")
for mode in ("remote_off", "remote_on"):
    data = json.loads((root / mode / "trial_01" / "trial_evidence.json").read_text())
    print("==== %s/trial_01 diagnostics ====" % mode)
    diag = data.get("diagnostics", {})
    for key, value in diag.items():
        print("  %s: %s" % (key, json.dumps(value)[:500]))
    print("  coverage_export:", json.dumps(data.get("coverage_export"))[:300])

# ON trial_02 to confirm stability across trials
data = json.loads((root / "remote_on" / "trial_02" / "trial_evidence.json").read_text())
print("==== remote_on/trial_02 diagnostics (stability) ====")
diag = data.get("diagnostics", {})
for key, value in diag.items():
    print("  %s: %s" % (key, json.dumps(value)[:300]))