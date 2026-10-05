#!/usr/bin/env python3
"""Report which execution subjects each trace shows, using subjects.json markers."""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("handoffs", here / "handoffs.py")
handoffs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoffs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("traces", nargs="+", type=Path, help="name=path or path")
    parser.add_argument("--subjects", type=Path, default=here / "subjects.json")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    subjects = json.loads(args.subjects.read_text())["subjects"]
    columns, counts = [], {}
    for item in args.traces:
        name, _, path = str(item).partition("=")
        if not path:
            name, path = Path(name).parent.name, name
        columns.append(name)
        events = handoffs.parse(Path(path))
        for s in subjects:
            m = s["marker"]
            n = 0
            for e in events:
                if handoffs.side_matches(m, e) is not None:
                    n += 1
            counts[(s["id"], name)] = n
    width = max(len(s["name"]) for s in subjects)
    print("%-5s %-*s %s" % ("id", width, "subject", " ".join("%12s" % c[:12] for c in columns)))
    for s in subjects:
        print("%-5s %-*s %s" % (s["id"], width, s["name"],
                               " ".join("%12d" % counts[(s["id"], c)] for c in columns)))
    if args.json:
        args.json.write_text(json.dumps(
            {s["id"]: {c: counts[(s["id"], c)] for c in columns} for s in subjects}, indent=2))


if __name__ == "__main__":
    sys.exit(main())
