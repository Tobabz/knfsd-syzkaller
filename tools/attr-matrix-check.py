#!/usr/bin/env python3
"""Validate the attribution boundary x variant matrix."""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Final

VARIANTS: Final = tuple(f"V{number}" for number in range(1, 8))
STATES: Final = {"EXISTING", "NEW", "NA", "UNFORCEABLE"}
INPUT_KEYS: Final = ("kernel", "vmlinux", "image", "deps_tar", "syz_execprog", "syz_executor")
BOUNDARY_RE = re.compile(r"^\|\s*(B\d{2})\s*\|")
CELL_RE = re.compile(r"^(EXISTING|NEW|NA|UNFORCEABLE)\((.*)\)$")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc


def inventory_ids(path: Path) -> tuple[str, ...]:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read boundary inventory {path}: {exc}") from exc
    ids = tuple(match.group(1) for line in text.splitlines() if (match := BOUNDARY_RE.match(line)))
    if not ids:
        raise ValueError(f"boundary inventory has no B rows: {path}")
    if len(ids) != len(set(ids)):
        raise ValueError(f"boundary inventory has duplicate B ids: {path}")
    return ids


def resolve_check(document: Any, check_name: str) -> Any:
    value = document
    for component in check_name.split("."):
        if not component:
            raise KeyError(check_name)
        if isinstance(value, dict) and component in value:
            value = value[component]
        elif isinstance(value, list) and component.isdecimal() and int(component) < len(value):
            value = value[int(component)]
        else:
            raise KeyError(check_name)
    return value


def passed(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "pass")


def input_sha(inputs: Any, key: str) -> str | None:
    if not isinstance(inputs, dict):
        return None
    item = inputs.get(key)
    if not isinstance(item, dict):
        return None
    value = item.get("sha256")
    return value if isinstance(value, str) and value else None


def evidence_eligibility(file_path: Path, baseline: dict[str, Any]) -> list[str]:
    resolved = file_path.resolve()
    matches: list[dict[str, Any]] = []
    records = baseline.get("existing_evidence")
    if isinstance(records, list):
        for item in records:
            if not isinstance(item, dict):
                continue
            raw_root = item.get("path")
            if not isinstance(raw_root, str) or not raw_root:
                continue
            try:
                resolved.relative_to(Path(raw_root).resolve())
            except ValueError:
                continue
            matches.append(item)
    if not matches:
        return [f"evidence is not inside a baseline existing_evidence path: {file_path}"]

    item = matches[0]
    problems: list[str] = []
    if item.get("sha_match") is not True:
        problems.append("matching baseline evidence sha_match is not boolean true")
    metadata_value = item.get("metadata")
    if not isinstance(metadata_value, str) or not metadata_value:
        return problems + ["matching baseline evidence has no metadata path"]
    metadata_path = Path(metadata_value)
    if not metadata_path.is_file():
        return problems + [f"matching baseline evidence metadata does not exist: {metadata_path}"]
    try:
        metadata = load_json(metadata_path)
    except ValueError as exc:
        return problems + [str(exc)]
    metadata_inputs = metadata.get("inputs") if isinstance(metadata, dict) else None
    baseline_inputs = baseline.get("inputs")
    for key in INPUT_KEYS:
        expected = input_sha(baseline_inputs, key)
        actual = input_sha(metadata_inputs, key)
        if expected is None:
            problems.append(f"baseline input {key} has no sha256")
        if actual is None:
            problems.append(f"evidence metadata input {key} has no sha256")
        elif expected is not None and actual != expected:
            problems.append(f"evidence metadata input {key} sha256 does not match baseline")
    return problems


def check_existing(cell_id: str, ref: str, baseline: dict[str, Any]) -> list[str]:
    if "#" not in ref:
        return [f"{cell_id}: EXISTING ref must be path#check-name"]
    path_text, check_name = ref.rsplit("#", 1)
    if not path_text or not check_name:
        return [f"{cell_id}: EXISTING ref must have a non-empty path and check name"]
    evidence_file = Path(path_text)
    if not evidence_file.is_file():
        return [f"{cell_id}: EXISTING evidence file does not exist: {evidence_file}"]
    problems = [
        f"{cell_id}: EXISTING {problem}"
        for problem in evidence_eligibility(evidence_file, baseline)
    ]
    try:
        value = resolve_check(load_json(evidence_file), check_name)
    except (ValueError, KeyError) as exc:
        problems.append(f"{cell_id}: EXISTING check {check_name!r} cannot be resolved: {exc}")
    else:
        if not passed(value):
            problems.append(f"{cell_id}: EXISTING check {check_name!r} did not pass (value={value!r})")
    return problems


def validate_matrix(matrix: Any, boundaries: tuple[str, ...], baseline: dict[str, Any]) -> list[str]:
    if not isinstance(matrix, dict):
        return ["matrix root must be an object"]
    problems: list[str] = []
    expected = set(boundaries)
    for boundary in sorted(expected - set(matrix)):
        problems.append(f"{boundary}: missing boundary row")
    for boundary in sorted(set(matrix) - expected):
        problems.append(f"{boundary}: boundary is not present in attribution-boundaries.md")
    for boundary in boundaries:
        row = matrix.get(boundary)
        if not isinstance(row, dict):
            if boundary in matrix:
                problems.append(f"{boundary}: row must be an object")
            continue
        for variant in sorted(set(VARIANTS) - set(row)):
            problems.append(f"{boundary}-{variant}: missing cell")
        for variant in sorted(set(row) - set(VARIANTS)):
            problems.append(f"{boundary}-{variant}: unexpected variant")
        for variant in VARIANTS:
            cell_id = f"{boundary}-{variant}"
            cell = row.get(variant)
            if not isinstance(cell, dict):
                if variant in row:
                    problems.append(f"{cell_id}: cell must be an object")
                continue
            if set(cell) != {"state", "ref"}:
                problems.append(f"{cell_id}: cell keys must be exactly state and ref")
                continue
            state, ref = cell.get("state"), cell.get("ref")
            if not isinstance(state, str) or state not in STATES:
                problems.append(f"{cell_id}: invalid state {state!r}")
            elif not isinstance(ref, str) or not ref.strip():
                problems.append(f"{cell_id}: {state} requires a non-empty ref or reason")
            elif state == "NEW" and ref != cell_id:
                problems.append(f"{cell_id}: NEW ref must be exactly {cell_id}")
            elif state == "EXISTING":
                problems.extend(check_existing(cell_id, ref, baseline))
    return problems


def parse_markdown(path: Path) -> tuple[dict[str, dict[str, dict[str, str]]], list[str]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        return {}, [f"cannot read markdown matrix {path}: {exc}"]
    parsed: dict[str, dict[str, dict[str, str]]] = {}
    problems: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        match = BOUNDARY_RE.match(line)
        if not match:
            continue
        boundary = match.group(1)
        cells = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(cells) != 8:
            problems.append(f"{boundary}: markdown line {line_number} must have 8 columns")
            continue
        if boundary in parsed:
            problems.append(f"{boundary}: duplicate markdown row")
            continue
        parsed[boundary] = {}
        for variant, expression in zip(VARIANTS, cells[1:]):
            cell_match = CELL_RE.fullmatch(expression)
            if not cell_match:
                problems.append(f"{boundary}-{variant}: invalid markdown cell {expression!r}")
            else:
                parsed[boundary][variant] = {"state": cell_match.group(1), "ref": cell_match.group(2)}
    return parsed, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--mode", choices=("structure",), required=True)
    args = parser.parse_args(argv)
    try:
        matrix = load_json(args.matrix)
        baseline = load_json(args.baseline)
        if not isinstance(baseline, dict):
            raise ValueError("baseline root must be an object")
        boundaries = inventory_ids(args.matrix.with_name("attribution-boundaries.md"))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    problems = validate_matrix(matrix, boundaries, baseline)
    markdown = args.matrix.with_suffix(".md")
    markdown_matrix, markdown_problems = parse_markdown(markdown)
    problems.extend(markdown_problems)
    if markdown_matrix != matrix:
        problems.append(f"markdown matrix {markdown} does not agree with JSON matrix {args.matrix}")
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 1
    cell_count = len(boundaries) * len(VARIANTS)
    new_count = sum(cell["state"] == "NEW" for row in matrix.values() for cell in row.values())
    print(f"structure PASS: {len(boundaries)} boundaries, {cell_count} cells, {new_count} NEW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
