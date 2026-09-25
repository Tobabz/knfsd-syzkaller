#!/usr/bin/env python3
"""Rename numbered tools/ scripts to descriptive names and re-point all references.

Rule: the immutable handoff bundle (repo/) is never touched. Only OUR working
files under tools/ and report/ are renamed / text-replaced.

Keeps a machine-readable rename map at report/script-rename-map.md.
Run from anywhere; paths are absolute.
"""
import os
import re
import shutil
from pathlib import Path

PREP = Path(__file__).resolve().parent
REPORT = Path(os.environ.get("KOOV_WORK_ROOT", PREP.parent)) / "report"

# old exact filename -> new descriptive filename
MAPPING = {
    "convert-ab-image.sh": "convert-ab-image.sh",
    "run-ab.sh": "run-ab.sh",
    "analyze-ab.sh": "analyze-ab.sh",
    "diag-fixture.py": "diag-fixture.py",      # REMOVED 2026-09-25 (일회성 진단 도구 제거)
    "make-ab-lane-fixture.sh": "make-ab-lane-fixture.sh",
    "parse-executor-log.py": "parse-executor-log.py",  # REMOVED 2026-09-25 (일회성 진단 도구 제거)
    "fix-workload-tail.py": "fix-workload-tail.py",    # REMOVED 2026-09-25 (일회성 진단 도구 제거)
    "check-bind-re.py": "check-bind-re.py",           # REMOVED 2026-09-25 (일회성 진단 도구 제거)
    "check-args.py": "check-args.py",                 # REMOVED 2026-09-25 (일회성 진단 도구 제거)
    "summarize-ab.py": "summarize-ab.py",
    "dump-trial.py": "dump-trial.py",
    "summarize-numeric.py": "summarize-numeric.py",
    "list-keys.py": "list-keys.py",           # REMOVED 2026-09-25 (일회성 진단 도구 제거)
    "phase-counters.py": "phase-counters.py",
    "evidence-hashes.sh": "evidence-hashes.sh",
    "fport-patch-hygiene.py": "fport-patch-hygiene.py",
    "fport-patch-risk.py": "fport-patch-risk.py",
    "fport-apply.sh": "fport-apply.sh",
    "fport-cocci-demo.sh": "fport-cocci-demo.sh",
    "cocci-demo": "cocci-demo",          # demo artifact directory
    "fport-variant.sh": "fport-variant.sh",
    "fport-evidence.sh": "fport-evidence.sh",
    "fport-design-gate.sh": "fport-design-gate.sh",
    "fport-pipeline.sh": "fport-pipeline.sh",
    "probe-diag-tools.sh": "probe-diag-tools.sh",   # removed 2026-09-25 (diagram toolchain dropped)
    "gen-architecture.py": "gen-architecture.py",   # removed 2026-09-25 (SVG diagram dropped)
    "validate-svg.sh": "validate-svg.sh",           # removed 2026-09-25 (SVG diagram dropped)
    "inspect-handoff.sh": "inspect-handoff.sh",   # REMOVED 2026-09-25 (번들 재구성 - repo 트리 제거)
}

# longest old names first so no partial overlap during text replacement
ORDERED = sorted(MAPPING.items(), key=lambda kv: len(kv[0]), reverse=True)

def text_files_under(root):
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in (".sh", ".py", ".md", ".txt"):
            yield p

def main():
    # 1) rename files/dirs (prep only)
    moved = []
    for old, new in ORDERED:
        src = PREP / old
        dst = PREP / new
        if not src.exists():
            if src.is_dir() and dst.exists():
                continue
            print("MISSING (skip):", src)
            continue
        if dst.exists():
            raise SystemExit("target exists: %s" % dst)
        if src.is_dir():
            src.rename(dst)
        else:
            src.rename(dst)
        moved.append((old, new))
    print("renamed %d entries" % len(moved))

    # 2) replace references in tools/ + report/ text files (never repo/)
    changed = []
    for p in list(text_files_under(PREP)) + list(text_files_under(REPORT)):
        text = p.read_text(encoding="utf-8", errors="replace")
        new_text = text
        for old, new in ORDERED:
            new_text = new_text.replace(old, new)
        if new_text != text:
            p.write_text(new_text, encoding="utf-8")
            changed.append(str(p))
    print("content-repointed %d files" % len(changed))

    # 3) write the rename map document
    lines = [
        "# tools/ 스크립트 개명 기록 (2026-09-23)",
        "",
        "넘버링 단계 코드(prefix) 대신 **설명적 이름**을 사용합니다. "
        "forward-port 패밀리는 `fport-` 접두사로 묶습니다. "
        "불변 번들 `repo/`는 건드리지 않았습니다.",
        "",
        "| 구 (넘버링) | 신규 (설명적) | 계열 |",
        "|---|---|---|",
    ]
    for old, new in ORDERED:
        family = "forward-port" if new.startswith("fport-") else "core/other"
        lines.append("| `%s` | `%s` | %s |" % (old, new, family))
    lines += [
        "",
        "파일 이동 + 내부 참조 치환 + 증거 해시 재기록까지 이 문서로 감사 가능합니다.",
        "",
    ]
    (REPORT / "script-rename-map.md").write_text("\n".join(lines), encoding="utf-8")

    # 4) verification: any leftover numbered filenames?
    leftover = []
    pat = re.compile(r"(?<![A-Za-z0-9])(?:00|10|20|30|40|50|51|60|70|80|9[0-9]|10[0-6]|11[0-5]|12[0-3]|13[0-4])-[a-z]")
    for p in list(text_files_under(PREP)) + list(text_files_under(REPORT)):
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.search(line):
                leftover.append("%s:%d %s" % (p, i, line.strip()[:100]))
    if leftover:
        print("\nLEFT OVER (numbered references):")
        print("\n".join(leftover))
    else:
        print("\nverification: no numbered script references remain")
    print("map:", REPORT / "script-rename-map.md")

if __name__ == "__main__":
    main()