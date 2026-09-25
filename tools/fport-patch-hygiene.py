#!/usr/bin/env python3
"""Patch forward-port risk analysis for the knfsd remote-KCOV series.

For each .patch in a series directory, report:
  - files touched and hunk counts
  - new files vs modifications
  - C-modification hunks whose context overlaps a struct body, enum, or
    switch (higher mainline-drift risk)
  - additions that look like new functions / guarded blocks (safer)
This grounds the forward-port configuration recommendations.

Usage: python3 fport-patch-hygiene.py [PATCH_DIR]
"""
import os
import re
import sys
from pathlib import Path

_DEF_BUNDLE = Path(__file__).resolve().parent.parent / "bundle" / "patches"
_bundle = Path(os.environ.get("KOOV_BUNDLE", str(_DEF_BUNDLE)))
_default_series = _bundle / "kernel"
SERIES = Path(sys.argv[1] if len(sys.argv) > 1 else _default_series)


def parse_patch(path):
    text = path.read_text(errors="replace")
    hunks = []
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@.*$",
                         text, re.M):
        context = text[m.start():].split("\n@@ ", 1)[0]
        lines = [l for l in context.split("\n")[1:] if l]
        added = [l[1:] for l in lines if l.startswith("+") and not l.startswith("+++")]
        removed = [l[1:] for l in lines if l.startswith("-") and not l.startswith("---")]
        body = [l[1:] for l in lines if l[:1] in "+-"]
        hunks.append({"raw": m.group(0), "added": added, "removed": removed,
                      "body": body})
    return hunks


def classify(added, removed):
    """Categorize hunk risk against mainline drift."""
    if any(re.match(r"^\s*(static\s+)?(int|void|bool|u(?:8|16|32|64)|s(?:8|16|32|64)|"
                    r"struct\s+\w+|unsigned|atomic_t|long|size_t)\s+[a-zA-Z_]\w*\s*\(", l)
           for l in added):
        kind = "new-func"
    elif any(re.match(r"^\s*#\s*(if|ifdef|ifndef|endif|define|include)", l)
             for l in added):
        kind = "guarded"
    elif any("switch " in l for l in added) or any("case " in l for l in added):
        kind = "switch"
    elif any(re.match(r"^\s*[a-zA-Z_]\w*\s+", l) and ";" in l for l in added):
        kind = "field/decl"
    else:
        kind = "misc"
    return kind


def main():
    print("series dir: %s\n" % SERIES)
    totals = {"new-func": 0, "guarded": 0, "switch": 0, "field/decl": 0,
              "misc": 0}
    for path in sorted(SERIES.glob("*.patch")):
        print("==== %s ====" % path.name)
        current = None
        files = {}
        for line in path.read_text(errors="replace").splitlines():
            m = re.match(r"^diff --git a/(\S+) b/(\S+)", line)
            if m:
                current = m.group(2)
                files[current] = {"hunks": 0, "new": False, "kinds": {}}
                continue
            if current and line.startswith("new file mode"):
                files[current]["new"] = True
            if current and line.startswith("@@ "):
                files[current]["hunks"] += 1
        for fname, info in sorted(files.items()):
            flag = "NEW " if info["new"] else "mod "
            print("  %s %-52s hunks=%d" % (flag, fname, info["hunks"]))
        # per-hunk classification
        for h in parse_patch(path):
            kind = classify(h["added"], h["removed"])
            totals[kind] += 1
        print("  hunk kinds:", {k: v for k, v in sorted(totals.items())})
        print()
    print("TOTAL hunk kind distribution:", totals)
    print("\nTOOLS: git=2.53.0 python3=stdlib-only (no spatch: intent-based patch "
          "regeneration replaces coccinelle, see patch-forward-compat.md §3)")


if __name__ == "__main__":
    main()