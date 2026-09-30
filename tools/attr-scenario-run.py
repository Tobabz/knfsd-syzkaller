#!/usr/bin/env python3
"""Manifest-driven one-command baked-VM attribution scenario runner.

Boots the baked VM through the existing reach boot/lane/coverage plumbing
(tools/run-reach-adapted-window.py, which itself drives the frozen phase1..9
runners) -- it does not fork a third QEMU path.  Around that single boot it
snapshots the sunrpc_fuzz debugfs stats before the workload and after drains,
applies the manifest's forcing hooks in order, builds the paired coverage sets,
captures the raw evidence (coverage tar, serial.log, dmesg.txt, image SHA
before/after, input SHAs), and invokes the approved combined oracle
(tools/attr-scenario-assert.py) to emit attr_verdict_<id>.json.

Preflight (before any output dir or boot) refuses to run when the workload
.prog is missing or its SHA-256 does not match the manifest, when a baseline
input is missing, or when a requested hook is UNFORCEABLE.  --reuse copies an
existing PASS verdict only for a matrix cell marked EXISTING whose SHA is still
eligible; it never boots a VM in that case.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.attr_counters import snapshot_from_texts  # noqa: E402
from tools.attr_env import resolve_env_path  # noqa: E402
from tools.attr_hooks import HOOKS, hook_result  # noqa: E402

TOOLS = ROOT / "tools"
SCHEMA_PATH = ROOT / "bundle/corpus/attr-scenarios/schema.json"
BASELINE_PATH = ROOT / "report/attr-env-baseline.json"
MATRIX_PATH = ROOT / "report/attribution-scenario-matrix.json"
ASSERT_TOOL = TOOLS / "attr-scenario-assert.py"
ANALYZE_TOOL = TOOLS / "analyze_ab_adapted.py"
REACH_RUNNER = TOOLS / "run-reach-adapted-window.py"
MATRIX_CHECK_TOOL = TOOLS / "attr-matrix-check.py"
SSH_KEY = ROOT / "artifacts/bookworm.id_rsa"

DEBUGFS = "/sys/kernel/debug/sunrpc_fuzz"
JsonObject = dict[str, Any]

# Every hook stage maps to exactly one lifecycle role, dispatched around the
# reach executor's real lifecycle (arm -> executor starts -> during -> executor
# completes -> drain -> verify). A stage with no role is rejected at preflight,
# never silently skipped.
#   arm      : before the executor starts (set a fault the workload will hit).
#   during   : while the executor is running (trigger the transition, observe the
#              named counter increment, then release so a blocked executor can
#              finish). This is where abort/re-defer/retry/pause release live.
#   verify   : after the drain and POST snapshot (verify identity, read result).
#   cleanup  : a successful-path teardown while the executor is live; until it
#              succeeds it also remains an outstanding failure-path cleanup.
_STAGE_ROLE = {
    "arm": "arm", "hold-initial-cache": "arm", "arm-replay-pause": "arm",
    "snapshot-before": "arm",
    "observe-entered": "during", "release": "during",
    "resume-first-cache": "during", "observe-replay-pause": "during",
    "invalidate-at-replay": "during", "release-replay": "during",
    "observe-redefer": "during", "run": "during", "interleave": "during",
    "verify-socket-identity": "verify", "snapshot-after": "verify",
    "resume-second-cache-cleanup": "during",
}
_OBSERVE_STAGES = frozenset({"observe-entered", "observe-replay-pause", "observe-redefer"})
# Substring of the proof counter each observe stage must see INCREMENT past its
# pre-trigger baseline (a real state handshake, not "any positive counter").
_OBSERVE_TARGET = {
    "observe-entered": "pause_after_grant_entered",
    "observe-replay-pause": "pause_after_grant_entered",
    "observe-redefer": "redeferred",
}
# Stages re-run best-effort on the failure path; their errors are surfaced.
_CLEANUP_STAGES = ("resume-second-cache-cleanup", "release", "release-replay")
OBSERVE_TIMEOUT_S = 60.0
OBSERVE_POLL_S = 0.25


class PreflightError(RuntimeError):
    """A precondition failed before any output directory or VM boot."""


class BootTimeout(RuntimeError):
    """The guest never became reachable over SSH within the boot budget."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _count_prog_calls(path: Path) -> int:
    """Number of executable syzkaller calls (non-blank, non-comment lines).

    The reach runner defaults to the AB workload's 34-call / conflict-at-14
    shape; an attribution workload declares its own call count by its .prog, and
    attribution scenarios inject no lock conflict, so the runner derives the
    executor-log expectations from the workload rather than the AB defaults.
    """
    count = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            count += 1
    if count < 1:
        raise PreflightError(f"workload has no executable calls: {path}")
    return count


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_manifest(document: object) -> JsonObject:
    import jsonschema
    schema = _load_json(SCHEMA_PATH)
    jsonschema.Draft202012Validator.check_schema(schema)
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(document),
        key=lambda error: [str(part) for part in error.path],
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise PreflightError(f"manifest schema violation at {location}: {error.message}")
    if not isinstance(document, dict):
        raise PreflightError("manifest must be a JSON object")
    manifest = dict(document)
    expected = f"{manifest['boundary']}-{manifest['variant']}"
    if manifest["id"] != expected and not str(manifest["id"]).startswith(expected + "-"):
        raise PreflightError("manifest id does not match boundary and variant")
    return manifest


def validate_hook_stages(hook_manifests: list[JsonObject]) -> None:
    """Reject any hook that emits a stage the runner does not dispatch.

    Called at preflight (before boot) so a supported-looking hook whose stage has
    no lifecycle role -- e.g. v4.generation-abort-ioctl's 'abort' before it was
    wired in -- fails loudly instead of being silently skipped at run time.
    """
    for hook in hook_manifests:
        for command in hook["manifest"]["commands"]:
            stage = command["stage"]
            if stage not in _STAGE_ROLE:
                reason = (
                    "; generation abort requires an ioctl on the executor's live "
                    "KCOV owner fd, which a separate guest command cannot inherit"
                    if stage == "abort" else ""
                )
                raise PreflightError(
                    f"hook {hook['id']} emits stage {stage!r} with no lifecycle "
                    f"role{reason}; refusing before boot")
        for stage in _OBSERVE_STAGES:
            if any(c["stage"] == stage for c in hook["manifest"]["commands"]):
                _observe_target(hook, stage)  # raises if the target is missing


def _observe_target(hook: JsonObject, stage: str) -> tuple[str, str]:
    """The (file, counter) an observe stage must see increment, from hook proof."""
    substring = _OBSERVE_TARGET[stage]
    for item in hook["manifest"]["proof"]:
        counter = str(item.get("counter", ""))
        delta = item.get("delta")
        if substring in counter and isinstance(delta, int) and delta > 0:
            return str(item["file"]), counter
    raise PreflightError(
        f"hook {hook['id']} stage {stage}: no positive proof counter matching "
        f"{substring!r}")


class AttrPlan:
    """The seam run-reach-adapted-window.py calls in the ON trial.

    It snapshots the manifest's counter files before the workload (before any
    counter-producing trigger) and after the drains, and drives the manifest's
    forcing hooks across the reach executor's REAL lifecycle:
      before_workload : snapshot_pre, then arm-role stages (before executor).
      during_workload : while the executor runs -- for each trigger, snapshot the
                        pre-trigger baseline, run the trigger, then each following
                        observe must see its named counter INCREMENT past that
                        baseline; release happens here too so a blocked executor
                        can finish.
      after_workload  : snapshot_post (after drain), then verify-role stages.
      cleanup         : retries outstanding release/cleanup on every exit; errors surfaced.
    Only files the manifest references are captured, so a manifest can never drag
    an unparseable multi-lane *_state file into the oracle's snapshot.
    """

    def __init__(self, output: Path, manifest: JsonObject,
                 hook_manifests: list[JsonObject]) -> None:
        self.output = output
        self.manifest = manifest
        self.hook_manifests = hook_manifests
        self.counter_files = sorted(
            {entry["file"] for entry in manifest["counter_expect"]}
            | {key["file"] for key in manifest["drain_keys"]}
        )
        self.captured: dict[str, bool] = {"pre": False, "post": False}
        self._stage_index = 0
        self._started = False
        self._observe_baselines: dict[tuple[str, str, str], int] = {}
        self._completed_cleanup: set[tuple[str, str]] = set()

    def _snapshot(self, vm: Any, phase: str) -> None:
        destination = self.output / "counters" / phase
        destination.mkdir(parents=True, exist_ok=True)
        for name in self.counter_files:
            text = vm.guest(f"attr-{phase}-{name}",
                            f"cat {DEBUGFS}/{name}", timeout=30).stdout
            # Fail loudly here rather than let the oracle report a vague ERROR:
            # every captured counter file must parse without ambiguity.
            snapshot_from_texts({name: text})
            (destination / f"{name}.txt").write_text(text, encoding="utf-8")
        self.captured[phase] = True

    def _record(self, hook_id: str, stage: str, stdout: str) -> None:
        directory = self.output / "hooks" / hook_id
        directory.mkdir(parents=True, exist_ok=True)
        self._stage_index += 1
        (directory / f"{self._stage_index:02d}-{stage}.stdout").write_text(
            stdout, encoding="utf-8")

    def _run_stage(self, vm: Any, hook_id: str, stage: str, command: str,
                   *, check: bool = True) -> str:
        result = vm.guest(f"hook-{hook_id}-{stage}", command, timeout=120,
                          check=check)
        self._record(hook_id, stage, result.stdout)
        return result.stdout

    def _read_counter(self, vm: Any, file: str, counter: str) -> int:
        text = vm.guest(f"attr-baseline-{file}",
                        f"cat {DEBUGFS}/{file}", timeout=30).stdout
        counters = next(iter(snapshot_from_texts({file: text}).values()))
        if counter not in counters:
            raise RuntimeError(f"counter {file}:{counter} missing from guest snapshot")
        return counters[counter]

    def _observe(self, vm: Any, hook_id: str, stage: str, command: str,
                 file: str, counter: str, baseline: int) -> None:
        """Poll until the EXACT stage counter increments past its pre-trigger
        baseline; parse errors are surfaced, never swallowed into empty counters."""
        deadline = time.monotonic() + OBSERVE_TIMEOUT_S
        while True:
            stdout = vm.guest(f"hook-{hook_id}-{stage}", command, timeout=120).stdout
            counters = next(iter(snapshot_from_texts({file: stdout}).values()))
            if counter not in counters:
                raise RuntimeError(
                    f"hook {hook_id} stage {stage}: counter {file}:{counter} "
                    "missing from guest observation")
            if counters[counter] > baseline:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"hook {hook_id} stage {stage}: {file}:{counter} did not "
                    f"increment past {baseline} within the observe budget")
            time.sleep(OBSERVE_POLL_S)
        self._record(hook_id, stage, stdout)

    def _stages(self, hook: JsonObject, role: str) -> list[dict[str, str]]:
        return [c for c in hook["manifest"]["commands"]
                if _STAGE_ROLE.get(c["stage"]) == role]

    def before_workload(self, vm: Any, mode: str) -> None:
        if mode != "on":
            return
        self._snapshot(vm, "pre")   # before any counter-producing trigger
        self._started = True
        for hook in self.hook_manifests:
            for command in self._stages(hook, "arm"):
                self._run_stage(vm, hook["id"], command["stage"], command["command"])
            # The executor is the trigger for pause/re-defer hooks. Capture each
            # exact proof counter after arming but before launch, so stale values
            # and increments of neighboring counters cannot satisfy observation.
            for command in hook["manifest"]["commands"]:
                if command["stage"] in _OBSERVE_STAGES:
                    file, counter = _observe_target(hook, command["stage"])
                    key = (hook["id"], file, counter)
                    if key not in self._observe_baselines:
                        self._observe_baselines[key] = self._read_counter(
                            vm, file, counter)

    def during_workload(self, vm: Any, mode: str) -> None:
        """Run while the executor is live: trigger, prove the increment, release."""
        if mode != "on":
            return
        self._started = True
        for hook in self.hook_manifests:
            for command in self._stages(hook, "during"):
                stage = command["stage"]
                if stage in _OBSERVE_STAGES:
                    file, counter = _observe_target(hook, stage)
                    key = (hook["id"], file, counter)
                    if key not in self._observe_baselines:
                        raise RuntimeError(
                            f"hook {hook['id']} stage {stage}: no pre-trigger "
                            "counter baseline")
                    self._observe(vm, hook["id"], stage, command["command"],
                                  file, counter, self._observe_baselines[key])
                else:
                    self._run_stage(vm, hook["id"], stage, command["command"])
                    if stage in _CLEANUP_STAGES:
                        self._completed_cleanup.add((hook["id"], stage))

    def after_workload(self, vm: Any, mode: str) -> None:
        if mode != "on":
            return
        self._snapshot(vm, "post")
        for hook in self.hook_manifests:
            for command in self._stages(hook, "verify"):
                self._run_stage(vm, hook["id"], command["stage"], command["command"])

    def cleanup(self, vm: Any, mode: str) -> None:
        """Best-effort release/cleanup on the failure path; errors are surfaced."""
        if mode != "on" or not self._started:
            return
        errors: list[str] = []
        for hook in self.hook_manifests:
            for command in hook["manifest"]["commands"]:
                stage = command["stage"]
                if (stage in _CLEANUP_STAGES and
                        (hook["id"], stage) not in self._completed_cleanup):
                    try:
                        self._run_stage(vm, hook["id"], stage, command["command"])
                        self._completed_cleanup.add((hook["id"], stage))
                    except Exception as error:  # noqa: BLE001 - collect, then raise
                        errors.append(f"{hook['id']}/{stage}: {error}")
        if errors:
            raise RuntimeError("hook cleanup errors: " + "; ".join(errors))


def _preflight(scenario: Path) -> tuple[JsonObject, JsonObject, list[JsonObject]]:
    """Validate everything that must hold before an output dir or boot exists."""
    if not scenario.is_file():
        raise PreflightError(f"scenario manifest not found: {scenario}")
    manifest = _validate_manifest(_load_json(scenario))

    workload = (scenario.parent / manifest["workload"]).resolve()
    if not workload.is_file():
        raise PreflightError(f"workload .prog missing: {workload}")
    actual = _sha256(workload)
    if actual != manifest["sha256"]:
        raise PreflightError(
            f"workload SHA-256 mismatch: manifest {manifest['sha256']} != actual {actual}")

    lane_fixture = (scenario.parent / manifest["lane_fixture"]).resolve()
    if not lane_fixture.is_file():
        raise PreflightError(f"lane fixture missing: {lane_fixture}")

    if not BASELINE_PATH.is_file():
        raise PreflightError(f"environment baseline missing: {BASELINE_PATH}")
    baseline = _load_json(BASELINE_PATH)
    inputs = baseline["inputs"]
    for entry in inputs.values():
        entry["path"] = resolve_env_path(entry["path"])
    for name in ("kernel", "image", "vmlinux", "deps_tar",
                 "syz_execprog", "syz_executor"):
        path = Path(inputs[name]["path"])
        if not path.is_file():
            raise PreflightError(f"baseline input missing: {name} -> {path}")
    if not SSH_KEY.is_file():
        raise PreflightError(f"ssh key missing: {SSH_KEY}")

    hook_manifests: list[JsonObject] = []
    for hook in manifest["hooks"]:
        if hook["id"] not in HOOKS:
            raise PreflightError(f"unknown hook: {hook['id']}")
        rendered = hook_result(hook["id"], dry_run=False, args=hook["args"])
        if rendered["status"] != "FORCEABLE":
            raise PreflightError(
                f"hook {hook['id']} is {rendered['status']}; refusing to run a "
                "non-forceable, dry-run, or proof-only scenario")
        hook_manifests.append({"id": hook["id"], "args": hook["args"],
                               "manifest": rendered})
    validate_hook_stages(hook_manifests)
    return manifest, baseline, hook_manifests


def _reach_argv(manifest: JsonObject, scenario: Path, baseline: JsonObject,
                output: Path, boot_timeout: int) -> list[str]:
    inputs = baseline["inputs"]
    workload = (scenario.parent / manifest["workload"]).resolve()
    lane_fixture = (scenario.parent / manifest["lane_fixture"]).resolve()
    return [
        "--kernel", inputs["kernel"]["path"],
        "--image", inputs["image"]["path"],
        "--ssh-key", str(SSH_KEY),
        "--deps-tar", inputs["deps_tar"]["path"],
        "--vmlinux", inputs["vmlinux"]["path"],
        "--output", str(output),
        "--lane-fixture", str(lane_fixture),
        "--workload", str(workload),
        "--syz-executor", inputs["syz_executor"]["path"],
        "--syz-execprog", inputs["syz_execprog"]["path"],
        "--mode", manifest["mode"],
        "--trials", "1",
        "--executions", str(manifest["executions"]),
        "--procs", str(manifest["procs"]),
        "--boot-timeout", str(boot_timeout),
    ]


def _run_vm(reach: Any, manifest: JsonObject, scenario: Path, baseline: JsonObject,
            output: Path, plan: AttrPlan) -> None:
    """Run via the reach runner; retry ONLY a literal boot SSH deadline once.

    An early QEMU exit ('QEMU exited before SSH became ready') and every other
    failure are surfaced verbatim, never relabelled or retried. The first
    attempt's evidence is preserved under <output>.boot-timeout-attempt1 rather
    than deleted, so a completed OFF trial or serial/diagnostics are not lost.
    """
    def once(boot_timeout: int) -> None:
        argv = _reach_argv(manifest, scenario, baseline, output, boot_timeout)
        try:
            reach.main(argv, attr_plan=plan)
        except Exception as error:  # noqa: BLE001 - classify then re-raise
            # Only the SSH deadline is a retryable boot timeout. An exited QEMU
            # is a distinct failure and must not be reclassified.
            if "timed out waiting for guest SSH" in str(error):
                raise BootTimeout(str(error)) from error
            raise

    try:
        once(180)
    except BootTimeout as first:
        if output.exists():
            preserved = output.with_name(output.name + ".boot-timeout-attempt1")
            if preserved.exists():
                shutil.rmtree(preserved)
            output.rename(preserved)
            print(f"boot SSH timeout; preserved first attempt at {preserved}",
                  file=sys.stderr)
        print(f"retrying once with --boot-timeout 360 ({first})", file=sys.stderr)
        once(360)


def _assemble_inputs(manifest: JsonObject, scenario: Path, baseline: JsonObject,
                     vmlinux: Path, image: Path) -> JsonObject:
    workload = (scenario.parent / manifest["workload"]).resolve()
    lane_fixture = (scenario.parent / manifest["lane_fixture"]).resolve()
    return {
        "image": {"path": baseline["inputs"]["image"]["path"],
                  "sha256": _sha256(image)},
        "workload": {"path": str(workload), "sha256": _sha256(workload)},
        "lane_fixture": {"path": str(lane_fixture), "sha256": _sha256(lane_fixture)},
        "vmlinux": {"path": str(vmlinux), "sha256": _sha256(vmlinux)},
    }


def _write_run_json(output: Path, manifest: JsonObject, hook_manifests: list[JsonObject],
                    inputs: JsonObject) -> None:
    run = {
        "id": manifest["id"], "mode": manifest["mode"],
        "procs": manifest["procs"], "executions": manifest["executions"],
        "hooks": hook_manifests, "inputs": inputs,
    }
    (output / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")


def _modes(manifest: JsonObject) -> tuple[str, ...]:
    return ("off", "on") if manifest["mode"] == "both" else ("on",)


def _expose_logs(output: Path, modes: tuple[str, ...]) -> None:
    """Expose BOTH per-mode dmesg/serial to the oracle without dropping any.

    The per-mode files stay in their trial directories (canonical). This also
    writes root per-mode copies (dmesg.remote_<mode>.txt / serial.remote_<mode>.txt)
    and a combined, mode-labelled root dmesg.txt/serial.log so an OFF-only
    BUG/WARN/KASAN/Oops/refcount is never invisible to a root-reading oracle.
    Missing required per-mode logs are a hard error, never silently skipped.
    """
    for name in ("dmesg.txt", "serial.log"):
        parts: list[str] = []
        for mode in modes:
            source = output / f"remote_{mode}" / "trial_01" / name
            if not source.is_file():
                raise RuntimeError(f"required per-mode log missing: remote_{mode}/{name}")
            text = source.read_text(encoding="utf-8", errors="replace")
            stem = name.split(".")[0]
            (output / f"{stem}.remote_{mode}.txt").write_text(text, encoding="utf-8")
            parts.append(f"===== remote_{mode} {name} =====\n{text}")
        (output / name).write_text("\n".join(parts), encoding="utf-8")


def _tar_raw_evidence(output: Path, modes: tuple[str, ...]) -> None:
    required = ("serial.log", "dmesg.txt", "coverage.tar.gz")
    optional = ("coverage", "executor.log", "callback-trace.txt")
    archive = output / "raw-evidence.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for mode in modes:
            trial = output / f"remote_{mode}" / "trial_01"
            for name in required:
                member = trial / name
                if not member.exists():
                    raise RuntimeError(
                        f"required raw evidence missing: remote_{mode}/{name}")
                tar.add(member, arcname=f"remote_{mode}/{name}")
            for name in optional:
                member = trial / name
                if member.exists():
                    tar.add(member, arcname=f"remote_{mode}/{name}")


def _reuse(manifest: JsonObject, baseline: JsonObject, output: Path,
           matrix_check: Any) -> int:
    """Copy an EXISTING cell's verdict without booting, or fail loudly.

    Eligibility uses the SAME evidence-file#named-check contract as
    tools/attr-matrix-check.py: the ref resolves to a JSON file, the named check
    must pass, and the matched baseline entry must have sha_match true, an
    existing metadata file, and metadata input SHAs equal to the baseline's.
    On top of that the runner recomputes the ACTUAL SHA-256 of every required
    input file (never trusting a cached sha_match alone) before reusing.
    """
    if not MATRIX_PATH.is_file():
        raise PreflightError(f"matrix missing for --reuse: {MATRIX_PATH}")
    matrix = _load_json(MATRIX_PATH)
    cell = matrix.get(manifest["boundary"], {}).get(manifest["variant"], {})
    if cell.get("state") != "EXISTING":
        raise PreflightError(
            f"--reuse refused: {manifest['id']} is {cell.get('state')!r}, not EXISTING")
    ref = cell.get("ref", "")
    problems = matrix_check.check_existing(manifest["id"], ref, baseline)
    if problems:
        raise PreflightError("--reuse refused: " + "; ".join(problems))
    for key in matrix_check.INPUT_KEYS:
        entry = baseline.get("inputs", {}).get(key, {})
        path = Path(entry.get("path", ""))
        recorded = entry.get("sha256")
        if not path.is_file():
            raise PreflightError(f"--reuse refused: input {key} file missing: {path}")
        actual = _sha256(path)
        if actual != recorded:
            raise PreflightError(
                f"--reuse refused: input {key} actual SHA-256 {actual} "
                f"!= baseline {recorded}")
    verdict_path = Path(ref.rsplit("#", 1)[0])
    verdict = _load_json(verdict_path)
    output.mkdir(parents=True, exist_ok=True)
    for name in (f"attr_verdict_{manifest['id']}.json", "attr_verdict.json"):
        (output / name).write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
    print(f"reuse: matrix-eligible EXISTING verdict for {manifest['id']} -> {output}")
    return 0


def run(scenario: Path, output: Path, reuse: bool) -> int:
    manifest, baseline, hook_manifests = _preflight(scenario)
    vmlinux = Path(baseline["inputs"]["vmlinux"]["path"])
    image = Path(baseline["inputs"]["image"]["path"])

    if reuse:
        matrix_check = _load_module("attr_matrix_check", MATRIX_CHECK_TOOL)
        return _reuse(manifest, baseline, output, matrix_check)

    if output.exists() or output.is_symlink():
        raise PreflightError(f"--output must be a new path: {output}")

    image_before = _sha256(image)
    plan = AttrPlan(output, manifest, hook_manifests)
    reach = _load_module("attr_reach_runner", REACH_RUNNER)
    workload = (scenario.parent / manifest["workload"]).resolve()
    reach.EXPECTED_CALLS = _count_prog_calls(workload)
    reach.CONFLICT_CALL = -1
    _run_vm(reach, manifest, scenario, baseline, output, plan)

    if not (plan.captured["pre"] and plan.captured["post"]):
        raise RuntimeError("counter snapshots were not captured during the ON trial")

    analyze = subprocess.run(
        [sys.executable, str(ANALYZE_TOOL), "--results", str(output),
         "--vmlinux", str(vmlinux)],
        capture_output=True, text=True)
    (output / "analyze.log").write_text(analyze.stdout + analyze.stderr, encoding="utf-8")
    if analyze.returncode != 0:
        raise RuntimeError(f"coverage-set analysis failed: {analyze.stderr.strip()}")

    image_after = _sha256(image)
    (output / "image-before.sha256").write_text(image_before + "\n", encoding="utf-8")
    (output / "image-after.sha256").write_text(image_after + "\n", encoding="utf-8")

    modes = _modes(manifest)
    _expose_logs(output, modes)

    inputs = _assemble_inputs(manifest, scenario, baseline, vmlinux, image)
    _write_run_json(output, manifest, hook_manifests, inputs)
    _tar_raw_evidence(output, modes)

    verdict_path = output / f"attr_verdict_{manifest['id']}.json"
    assert_run = subprocess.run(
        [sys.executable, str(ASSERT_TOOL), "--scenario", str(scenario),
         "--results", str(output), "--vmlinux", str(vmlinux),
         "--out", str(verdict_path)],
        capture_output=True, text=True)
    sys.stdout.write(assert_run.stdout)
    sys.stderr.write(assert_run.stderr)
    if verdict_path.is_file():
        shutil.copy(verdict_path, output / "attr_verdict.json")
    if image_after != image_before:
        print(f"FAIL: base image changed {image_before} -> {image_after}", file=sys.stderr)
        return 1
    return assert_run.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse", action="store_true")
    args = parser.parse_args(argv)
    try:
        return run(args.scenario.resolve(), args.output.resolve(), args.reuse)
    except PreflightError as error:
        print(f"preflight: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
