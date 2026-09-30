#!/usr/bin/env python3
"""Verify one captured attribution scenario and emit a machine verdict."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.attr_counters import drained, snapshot_from_texts
from tools.attr_env import resolve_env_path
from tools.reach_callback import callback_witness

BAD_DMESG = re.compile(
    r"(?:BUG:|WARNING:|KASAN:|\bOops:|refcount(?:_t)?:|\bWARN(?:_ON)?\b)"
)
KCSAN_FINDING = re.compile(r"\bBUG:\s*KCSAN\b", re.IGNORECASE)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PC = re.compile(r"0x[0-9a-fA-F]+\Z")
SCENARIO_ID = re.compile(r"B(?:0[1-9]|1[0-2])-V[1-7](?:-[1-9][0-9]*)?\Z")
HOOK_IDS = {
    "v4.abort-next-deferred", "v4.abort-next-async",
    "v4.pause-release-deferred-after-grant", "v4.pause-release-async-after-grant",
    "v4.generation-abort-ioctl", "v5.redefer-cache-revisit",
    "v5.cancel-saved-work", "v6.retry-same-cookie-same-socket",
    "v7.concurrent-cross-lane",
}
JsonObject = dict[str, Any]
Checks = dict[str, JsonObject]


class InputError(ValueError):
    """Captured input is malformed or incomplete."""


def _reach_module() -> ModuleType:
    path = Path(__file__).with_name("reach-assert.py")
    spec = importlib.util.spec_from_file_location("attr_reach_assert", path)
    if spec is None or spec.loader is None:
        raise InputError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _check(checks: Checks, name: str, ok: bool, **details: Any) -> None:
    checks[name] = {"verdict": "PASS" if ok else "FAIL", **details}


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise InputError(f"{label} must be a JSON object")
    return cast(JsonObject, value)


def _validate_manifest(document: object, schema: object) -> JsonObject:
    try:
        import jsonschema
    except ImportError as exc:
        raise InputError("jsonschema is required to validate scenario manifests") from exc
    typed_schema = cast(Any, schema)
    typed_document = cast(Any, document)
    jsonschema.Draft202012Validator.check_schema(typed_schema)
    errors = sorted(
        jsonschema.Draft202012Validator(typed_schema).iter_errors(typed_document),
        key=lambda error: [str(part) for part in error.path],
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise InputError(f"manifest schema violation at {location}: {error.message}")
    manifest = _object(document, "manifest")
    expected_id = f"{manifest['boundary']}-{manifest['variant']}"
    if manifest["id"] != expected_id and not str(manifest["id"]).startswith(expected_id + "-"):
        raise InputError("manifest id does not match boundary and variant")
    return manifest


def _capture_texts(directory: Path) -> dict[str, str]:
    if not directory.is_dir():
        raise InputError(f"missing counter directory: {directory}")
    files = sorted(directory.glob("*.txt"))
    if not files:
        raise InputError(f"no counter captures in {directory}")
    return {path.stem: path.read_text(encoding="utf-8") for path in files}


def _captured_sha(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if SHA256.fullmatch(value) is None:
        raise InputError(f"malformed image digest: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _hook_contract(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    hook = cast(JsonObject, value)
    base = {"schema", "hook_id", "target", "dry_run", "status", "commands", "proof"}
    status = hook.get("status")
    expected = base | ({"requirements"} if status == "FORCEABLE" else {"failure"})
    if set(hook) != expected or hook.get("schema") != "attr-hook/v1":
        return False
    if (status not in {"FORCEABLE", "UNFORCEABLE"}
            or not _string(hook.get("hook_id")) or hook.get("hook_id") not in HOOK_IDS
            or not _string(hook.get("target")) or not isinstance(hook.get("dry_run"), bool)):
        return False
    commands = hook.get("commands")
    proof = hook.get("proof")
    if not isinstance(commands, list) or not isinstance(proof, list):
        return False
    if status == "FORCEABLE":
        requirements = hook.get("requirements")
        if not isinstance(requirements, list) or not all(_string(item) for item in requirements):
            return False
    else:
        failure = hook.get("failure")
        if (commands or proof or not isinstance(failure, dict)
                or set(failure) != {"type", "attempted_trigger", "reason"}
                or failure.get("type") != "UNFORCEABLE"
                or not _string(failure.get("attempted_trigger"))
                or not _string(failure.get("reason"))):
            return False
    commands_ok = all(
        isinstance(command, dict) and set(command) == {"stage", "command"}
        and _string(command.get("stage")) and _string(command.get("command"))
        for command in commands
    )
    proof_ok = all(
        isinstance(item, dict) and set(item) == {"file", "counter", "delta"}
        and _string(item.get("file")) and _string(item.get("counter"))
        and isinstance(item.get("delta"), int) and not isinstance(item.get("delta"), bool)
        for item in proof
    )
    return commands_ok and proof_ok


def _run_contract(manifest: JsonObject, run_value: object) -> tuple[bool, list[str]]:
    if not isinstance(run_value, dict):
        return False, []
    run = cast(JsonObject, run_value)
    if set(run) != {"id", "mode", "procs", "executions", "hooks", "inputs"}:
        return False, []
    if any(run.get(key) != manifest[key] for key in ("id", "mode", "procs", "executions")):
        return False, []
    scenario_hooks = manifest["hooks"]
    captured_hooks = run.get("hooks")
    if not isinstance(scenario_hooks, list) or not isinstance(captured_hooks, list):
        return False, []
    statuses: list[str] = []
    if len(captured_hooks) != len(scenario_hooks):
        return False, statuses
    counter_expectations = manifest["counter_expect"]
    for expected, captured in zip(scenario_hooks, captured_hooks, strict=True):
        if not isinstance(captured, dict) or set(captured) != {"id", "args", "manifest"}:
            return False, statuses
        if captured.get("id") != expected["id"] or captured.get("args") != expected["args"]:
            return False, statuses
        hook_manifest = captured.get("manifest")
        if not _hook_contract(hook_manifest):
            return False, statuses
        typed_hook = cast(JsonObject, hook_manifest)
        statuses.append(str(typed_hook["status"]))
        if (typed_hook["hook_id"] != expected["id"]
                or typed_hook["dry_run"] is not False
                or typed_hook["status"] != "FORCEABLE"):
            return False, statuses
        for proof in typed_hook["proof"]:
            compatible = any(
                item["file"] == proof["file"]
                and item["name"] == proof["counter"]
                and item["value"] == proof["delta"]
                and (item["op"] == "delta_eq"
                     or (proof["delta"] > 0 and item["op"] == "delta_ge"))
                for item in counter_expectations
            )
            if not compatible:
                return False, statuses
    return True, statuses


def _validate_inputs(manifest: JsonObject, run: JsonObject, manifest_path: Path,
                     vmlinux: Path) -> tuple[bool, JsonObject]:
    inputs_value = run.get("inputs")
    if not isinstance(inputs_value, dict) or set(inputs_value) != {
            "image", "workload", "lane_fixture", "vmlinux"}:
        return False, {}
    inputs = cast(JsonObject, inputs_value)
    expected_paths = {
        "workload": (manifest_path.parent / manifest["workload"]).resolve(),
        "lane_fixture": (manifest_path.parent / manifest["lane_fixture"]).resolve(),
        "vmlinux": vmlinux.resolve(),
    }
    details: JsonObject = {}
    ok = True
    for name in ("image", "workload", "lane_fixture", "vmlinux"):
        value = inputs.get(name)
        if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
            details[name] = {"valid": False}
            ok = False
            continue
        entry = cast(JsonObject, value)
        path_value = entry.get("path")
        digest = entry.get("sha256")
        path = Path(path_value) if isinstance(path_value, str) else Path("")
        actual = _sha256(path) if path.is_file() else None
        path_ok = name == "image" or path.resolve() == expected_paths[name]
        digest_ok = isinstance(digest, str) and SHA256.fullmatch(digest) is not None
        item_ok = path.is_file() and path_ok and digest_ok and actual == digest
        if name == "workload":
            item_ok = item_ok and digest == manifest["sha256"]
        details[name] = {"valid": item_ok, "path": str(path),
                         "captured_sha256": digest, "actual_sha256": actual}
        ok = ok and item_ok
    baseline = _object(
        _load_json(ROOT / "report/attr-env-baseline.json"), "environment baseline")
    baseline_inputs = _object(baseline.get("inputs"), "environment baseline inputs")
    baseline_image = _object(baseline_inputs.get("image"), "baseline image")
    captured_image = cast(JsonObject, inputs.get("image", {}))
    image_path = captured_image.get("path")
    baseline_match = (
        isinstance(image_path, str)
        and Path(image_path).resolve()
        == Path(resolve_env_path(baseline_image["path"])).resolve()
        and captured_image.get("sha256") == baseline_image.get("sha256")
    )
    details["baseline_image_match"] = baseline_match
    return ok and baseline_match, details


def _counter_value(snapshots: dict[str, dict[str, int]], file: str, name: str) -> int:
    if file not in snapshots:
        raise InputError(f"missing counter capture: {file}")
    if name not in snapshots[file]:
        raise InputError(f"missing counter: {file}:{name}")
    return snapshots[file][name]


def _compare(actual: int, op: str, expected: int) -> bool:
    return {
        "eq": actual == expected,
        "ge": actual >= expected,
        "le": actual <= expected,
        "delta_eq": actual == expected,
        "delta_ge": actual >= expected,
    }[op]


def _load_pc_file(path: Path) -> set[str]:
    if not path.is_file():
        raise InputError(f"missing coverage capture: {path}")
    values: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        if PC.fullmatch(value) is None:
            raise InputError(f"{path}:{number}: malformed PC: {value!r}")
        values.add(value)
    return values


def _coverage_checks(manifest: JsonObject, results: Path, vmlinux: Path,
                     checks: Checks) -> None:
    reach = _reach_module()
    coverage = results / "coverage_sets"
    if not coverage.is_dir():
        raise InputError(f"missing coverage directory: {coverage}")
    details: JsonObject = {}
    captures_ok = True
    sentinel_ok = True
    for module_name, spec_value in manifest["sentinel"].items():
        spec = cast(JsonObject, spec_value)
        stem = reach.MODULE_STEM[module_name]
        raw_sets: dict[str, set[str]] = {}
        symbols: dict[str, set[str]] = {}
        for set_name in ("on_union", "on_only", "off_union"):
            path = coverage / f"{stem}_{set_name}.pcs"
            raw_sets[set_name] = _load_pc_file(path)
            symbols[set_name] = reach.symbolize(str(vmlinux), sorted(raw_sets[set_name]))
            if raw_sets[set_name] and not symbols[set_name]:
                captures_ok = False
        derived_on_only = raw_sets["on_union"] - raw_sets["off_union"]
        on_only_consistent = raw_sets["on_only"] == derived_on_only
        captures_ok = captures_ok and on_only_consistent
        if not raw_sets["on_union"] or not symbols["on_union"]:
            captures_ok = False
        absent_names = spec.get("absent-on-only", [])
        if absent_names and (not raw_sets["on_only"] or not symbols["on_only"]):
            captures_ok = False
        pool = {"on-only": "on_only", "on-union": "on_union"}[spec["rule"]]
        required = {name: name in symbols[pool] for name in spec["required"]}
        absent = {name: name not in symbols["on_only"] for name in absent_names}
        observed = {
            name: {where: name in names for where, names in symbols.items()}
            for name in spec["observed"]
        }
        module_ok = all((*required.values(), *absent.values()))
        sentinel_ok = sentinel_ok and module_ok
        details[module_name] = {
            "rule": spec["rule"], "required": required,
            "absent-on-only": absent, "observed": observed,
            "pcs": {name: len(values) for name, values in raw_sets.items()},
            "symbols": {name: len(values) for name, values in symbols.items()},
            "derived_on_only_pcs": len(derived_on_only),
            "on_only_consistent": on_only_consistent,
        }
    _check(checks, "coverage_evidence", captures_ok, modules=details)
    _check(checks, "symbolized_sentinel", sentinel_ok and captures_ok, modules=details)


def _negative_checks(manifest: JsonObject, results: Path,
                     post: dict[str, dict[str, int]], checks: Checks) -> None:
    if manifest["polarity"] != "negative":
        return
    spec = cast(JsonObject, manifest["negative_expect"])
    absent_count = sum(
        len(item.get("absent-on-only", []))
        for item in manifest["sentinel"].values()
    )
    contract_ok = absent_count > 0 and manifest["mode"] == "both"
    publication_results: list[JsonObject] = []
    for item_value in spec.get("publication_zero", []):
        item = cast(JsonObject, item_value)
        if item["source"] == "counter":
            actual = _counter_value(post, item["file"], item["name"])
        else:
            document = _object(_load_json(results / item["file"]), item["file"])
            actual = document.get(item["name"])
        ok = isinstance(actual, int) and not isinstance(actual, bool) and actual == 0
        publication_results.append({"file": item["file"], "name": item["name"],
                                    "actual": actual, "assert": ok})
    if publication_results:
        _check(checks, "publication_zero",
               all(item["assert"] for item in publication_results),
               assertions=publication_results)
    worker_spec = spec.get("ownerless_worker")
    worker_supported = False
    if worker_spec is not None:
        worker = cast(JsonObject, worker_spec)
        absent_symbols = {
            symbol
            for sentinel in manifest["sentinel"].values()
            for symbol in sentinel.get("absent-on-only", [])
        }
        worker_supported = (
            manifest["boundary"] == "B07"
            and worker.get("kind") == "nfsd4-callback-trace"
            and worker.get("boundary") == "B07"
            and worker.get("sentinel") == "nfsd4_run_cb_work"
            and worker.get("required") == ["nfsd4_run_cb_work"]
            and "nfsd4_run_cb_work" in absent_symbols
        )
        results_by_mode: JsonObject = {}
        worker_ok = worker_supported
        if worker_supported:
            modes = ("off", "on") if manifest["mode"] == "both" else ("on",)
            expected = manifest["executions"] * worker["copies_per_execution"]
            for mode in modes:
                directory = f"remote_{mode}/trial_01"
                verdict = callback_witness(
                    results / directory / worker["trace_file"], expected,
                    worker["completion_before_seconds"],
                )
                results_by_mode[directory] = verdict
                worker_ok = worker_ok and verdict["assert"]
        _check(checks, "ownerless_worker", worker_ok,
               kind=worker.get("kind"), boundary=worker.get("boundary"),
               sentinel=worker.get("sentinel"), modes=results_by_mode)
    cross_results: list[JsonObject] = []
    for item_value in spec.get("cross_lane_zero", []):
        item = cast(JsonObject, item_value)
        actual = _counter_value(post, item["file"], item["name"])
        cross_results.append({"file": item["file"], "name": item["name"],
                              "actual": actual, "assert": actual == 0})
    if cross_results:
        _check(checks, "cross_lane_zero",
               all(item["assert"] for item in cross_results), assertions=cross_results)
    if manifest["boundary"] == "B07":
        contract_ok = contract_ok and worker_supported
    elif manifest["boundary"] in {"B08", "B09", "B10"}:
        contract_ok = False
    elif manifest["variant"] == "V7":
        contract_ok = contract_ok and bool(cross_results)
    elif manifest["variant"] in {"V2", "V3", "V4"}:
        contract_ok = contract_ok and bool(publication_results)
    else:
        contract_ok = contract_ok and bool(publication_results or worker_supported)
    if manifest["variant"] != "V7" and cross_results:
        contract_ok = False
    _check(checks, "negative_contract", contract_ok,
           absent_on_only=absent_count,
           publication=bool(publication_results), worker=worker_spec is not None,
           worker_supported=worker_supported, cross_lane=bool(cross_results))


def _diagnostic_checks(results: Path, checks: Checks) -> JsonObject:
    findings: list[JsonObject] = []
    fatal: list[JsonObject] = []
    missing: list[str] = []
    malformed: list[JsonObject] = []
    sources: list[str] = []
    for mode in ("off", "on"):
        for name in ("dmesg.txt", "serial.log"):
            relative = f"remote_{mode}/trial_01/{name}"
            path = results / relative
            if not path.is_file():
                missing.append(relative)
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                malformed.append({
                    "mode": mode, "source": relative, "error": str(exc),
                })
                continue
            if not text.strip(" \t\r\n\v\f\x00"):
                malformed.append({
                    "mode": mode, "source": relative,
                    "error": "diagnostic log contains no text content",
                })
                continue
            sources.append(relative)
            for number, line in enumerate(text.splitlines(), 1):
                if KCSAN_FINDING.search(line):
                    findings.append({
                        "mode": mode, "source": relative,
                        "line": number, "text": line,
                    })
                if BAD_DMESG.search(KCSAN_FINDING.sub("", line)):
                    fatal.append({
                        "mode": mode, "source": relative,
                        "line": number, "text": line,
                    })
    _check(checks, "dmesg_hygiene", not missing and not malformed and not fatal,
           sources=sources, missing=missing, malformed=malformed, matches=fatal)
    return {
        "clean": not findings,
        "status": "CLEAN" if not findings else "NON_CLEAN",
        "findings": findings,
    }


def evaluate(document: object, manifest_path: Path, results: Path,
             vmlinux: Path) -> JsonObject:
    schema = _load_json(ROOT / "bundle/corpus/attr-scenarios/schema.json")
    manifest = _validate_manifest(document, schema)
    checks: Checks = {}

    workload = (manifest_path.parent / manifest["workload"]).resolve()
    workload_sha = _sha256(workload) if workload.is_file() else None
    _check(checks, "workload_sha256", workload_sha == manifest["sha256"],
           expected=manifest["sha256"], actual=workload_sha)
    lane = (manifest_path.parent / manifest["lane_fixture"]).resolve()
    _check(checks, "lane_fixture", lane.is_file(), path=str(lane))

    run_value = _load_json(results / "run.json")
    run_ok, hook_statuses = _run_contract(manifest, run_value)
    _check(checks, "run_contract", run_ok,
           expected_hooks=manifest["hooks"], statuses=hook_statuses,
           actual=run_value)
    run = cast(JsonObject, run_value) if isinstance(run_value, dict) else {}
    input_ok, input_details = _validate_inputs(manifest, run, manifest_path, vmlinux)
    _check(checks, "input_identity", input_ok, inputs=input_details)

    pre = snapshot_from_texts(_capture_texts(results / "counters/pre"))
    post = snapshot_from_texts(_capture_texts(results / "counters/post"))
    for index, expectation in enumerate(manifest["counter_expect"], 1):
        file = expectation["file"]
        name = expectation["name"]
        op = expectation["op"]
        before = _counter_value(pre, file, name)
        after = _counter_value(post, file, name)
        actual = after - before if op.startswith("delta_") else after
        _check(checks, f"counter:{index}:{file}:{name}:{op}",
               _compare(actual, op, expectation["value"]),
               file=file, counter=name, op=op, expected=expectation["value"],
               actual=actual, pre=before, post=after)
    for key in manifest["drain_keys"]:
        file = key["file"]
        name = key["name"]
        value = _counter_value(post, file, name)
        is_drained = drained({file: {name: value}}, [name])
        _check(checks, f"drain:{file}:{name}", is_drained,
               file=file, counter=name, actual=value)

    if not vmlinux.is_file():
        raise InputError(f"missing vmlinux: {vmlinux}")
    _coverage_checks(manifest, results, vmlinux, checks)
    _negative_checks(manifest, results, post, checks)

    sanitizer = _diagnostic_checks(results, checks)

    before_sha = _captured_sha(results / "image-before.sha256")
    after_sha = _captured_sha(results / "image-after.sha256")
    image_input = input_details.get("image", {})
    captured_input_sha = image_input.get("captured_sha256") if isinstance(image_input, dict) else None
    actual_image_sha = image_input.get("actual_sha256") if isinstance(image_input, dict) else None
    image_ok = (input_ok and before_sha == after_sha == captured_input_sha == actual_image_sha)
    _check(checks, "image_unchanged", image_ok, before=before_sha, after=after_sha,
           captured_input=captured_input_sha, actual=actual_image_sha)

    overall = "PASS" if all(item["verdict"] == "PASS" for item in checks.values()) else "FAIL"
    return {"scenario": manifest["id"], "checks": checks,
            "sanitizer": sanitizer, "overall": overall}


def _scenario_name(document: object) -> str:
    if isinstance(document, dict):
        value = document.get("id")
        if isinstance(value, str) and SCENARIO_ID.fullmatch(value):
            return value
    return "invalid"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--vmlinux", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    document: object = {}
    try:
        document = _load_json(args.scenario)
    except (OSError, json.JSONDecodeError) as exc:
        load_error: Exception | None = exc
    else:
        load_error = None
    scenario_name = _scenario_name(document)
    out = args.out or args.results / f"attr_verdict_{scenario_name}.json"
    try:
        if load_error is not None:
            raise InputError(str(load_error))
        verdict = evaluate(document, args.scenario, args.results, args.vmlinux)
        code = 0 if verdict["overall"] == "PASS" else 1
    except (OSError, InputError, ValueError, KeyError, TypeError,
            RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        checks: Checks = {
            "input": {"verdict": "FAIL", "error": str(exc)},
        }
        sanitizer = _diagnostic_checks(args.results, checks)
        verdict = {"scenario": scenario_name, "checks": checks,
                   "sanitizer": sanitizer, "overall": "ERROR"}
        code = 2
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"overall: {verdict['overall']} -> {out}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
