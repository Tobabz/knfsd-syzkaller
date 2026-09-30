"""End-to-end checks for the attribution scenario verdict CLI."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import os
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from tools.attr_hooks import hook_result

ROOT = Path(__file__).resolve().parents[2]
ENV_DIR = Path(os.environ.get("KOOV_ENV_DIR", str(ROOT / "env")))
TOOL = ROOT / "tools" / "attr-scenario-assert.py"
SCHEMA = ROOT / "bundle/corpus/attr-scenarios/schema.json"
DATA = Path(__file__).parent / "data/attr-scenario"
VMLINUX = ENV_DIR / "images/kcsan/vmlinux"
BASE_IMAGE = ENV_DIR / "images/bookworm-kcov-fresh-v1.raw"
BASE_IMAGE_SHA = "cb54598517cb4646f00c3a79e9e8ff9e1ec4a5159318c568b52f1b180e786cbd"
ATTR_EVIDENCE = Path(os.environ.get(
    "KOOV_ATTR_EVIDENCE", str(Path.home() / "attr-scenario-evidence")))
KCSAN_LOG = ATTR_EVIDENCE / "_baseline-reach/remote_on/trial_01/dmesg.txt"
JsonObject = dict[str, Any]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs(case: Path) -> JsonObject:
    for artifact in (BASE_IMAGE, VMLINUX):
        if not artifact.is_file():
            pytest.skip("environment artifact not present: %s" % artifact)
    paths = {
        "image": BASE_IMAGE,
        "workload": case / "workload.prog",
        "lane_fixture": case / "lane.sh",
        "vmlinux": VMLINUX,
    }
    return {
        name: {"path": str(path.resolve()),
               "sha256": BASE_IMAGE_SHA if name == "image" else _sha256(path)}
        for name, path in paths.items()
    }


def _positive_manifest(case: Path) -> JsonObject:
    return {
        "id": "B05-V1", "boundary": "B05", "variant": "V1",
        "polarity": "positive", "workload": "workload.prog",
        "sha256": _sha256(case / "workload.prog"),
        "lane_fixture": "lane.sh", "hooks": [], "mode": "both",
        "counter_expect": [
            {"file": "phase8_stats", "name": "async_child_created", "op": "delta_eq", "value": 1},
            {"file": "phase8_stats", "name": "async_grant_ok", "op": "delta_ge", "value": 1},
            {"file": "phase8_stats", "name": "live_saved_work", "op": "eq", "value": 0},
            {"file": "phase8_stats", "name": "async_completed", "op": "ge", "value": 1},
            {"file": "phase8_stats", "name": "async_dropped", "op": "le", "value": 0},
        ],
        "drain_keys": [
            {"file": "phase8_stats", "name": "live_saved_work"},
            {"file": "phase5_state", "name": "live_tickets"},
            {"file": "phase5_state", "name": "remote_refs"},
            {"file": "phase6_state", "name": "live_scratch"},
            {"file": "phase6_state", "name": "remote_refs"},
            {"file": "phase6_state", "name": "scratch_in_use"},
        ],
        "sentinel": {
            "fs/nfsd": {
                "rule": "on-only", "required": ["nfsd4_do_async_copy"],
                "observed": ["nfsd4_copy"],
                "absent-on-only": ["nfsd4_run_cb_work"],
            }
        },
        "procs": 2, "executions": 10,
    }


def _callback_worker() -> JsonObject:
    return {
        "kind": "nfsd4-callback-trace", "boundary": "B07",
        "sentinel": "nfsd4_run_cb_work", "rule": "trace-both",
        "required": ["nfsd4_run_cb_work"], "trace_file": "callback-trace.txt",
        "copies_per_execution": 1, "completion_before_seconds": 3.0,
    }


def _negative_manifest(case: Path) -> JsonObject:
    manifest = _positive_manifest(case)
    manifest.update({
        "id": "B05-V2", "variant": "V2", "polarity": "negative",
        "hooks": [{"id": "v4.abort-next-async", "args": {}}],
        "counter_expect": [
            {"file": "phase8_stats", "name": "async_child_created", "op": "delta_eq", "value": 1},
            {"file": "phase8_stats", "name": "async_abort_before_grant", "op": "delta_eq", "value": 1},
            {"file": "phase8_stats", "name": "async_owner_none", "op": "delta_eq", "value": 1},
            {"file": "phase8_stats", "name": "async_dropped", "op": "delta_eq", "value": 1},
            {"file": "phase8_stats", "name": "async_grant_ok", "op": "eq", "value": 1},
        ],
        "negative_expect": {
            "publication_zero": [{
                "source": "json", "file": "probe.json", "name": "remote_entries"
            }]
        },
    })
    return manifest


def _write_contract(case: Path, results: Path, manifest: JsonObject) -> Path:
    scenario = case / "scenario.json"
    scenario.write_text(json.dumps(manifest), encoding="utf-8")
    captured_hooks = []
    for hook in manifest["hooks"]:
        captured_hooks.append({
            "id": hook["id"], "args": hook["args"],
            "manifest": hook_result(hook["id"], args=hook["args"]),
        })
    run = {
        "id": manifest["id"], "mode": manifest["mode"],
        "procs": manifest["procs"], "executions": manifest["executions"],
        "hooks": captured_hooks, "inputs": _inputs(case),
    }
    (results / "run.json").write_text(json.dumps(run), encoding="utf-8")
    return scenario


def _fixture(tmp_path: Path, polarity: str = "positive") -> tuple[Path, Path, Path, Path]:
    case = tmp_path / "case"
    results = tmp_path / "results"
    shutil.copytree(DATA, case)
    shutil.copytree(case / "coverage_sets", results / "coverage_sets")
    source = case / ("negative" if polarity == "negative" else "positive")
    shutil.copytree(source / "pre", results / "counters/pre")
    shutil.copytree(source / "post", results / "counters/post")
    if polarity == "negative":
        shutil.copy(source / "probe.json", results / "probe.json")
    for mode in ("on", "off"):
        target = results / f"remote_{mode}/trial_01"
        target.mkdir(parents=True)
        shutil.copy(case / f"remote_{mode}/trial_01/callback-trace.txt", target)
        shutil.copy(case / "dmesg.txt", target / "dmesg.txt")
        shutil.copy(case / "dmesg.txt", target / "serial.log")
    image_sha = BASE_IMAGE_SHA + "\n"
    (results / "image-before.sha256").write_text(image_sha, encoding="utf-8")
    (results / "image-after.sha256").write_text(image_sha, encoding="utf-8")
    manifest = _negative_manifest(case) if polarity == "negative" else _positive_manifest(case)
    scenario = _write_contract(case, results, manifest)
    return scenario, results, VMLINUX, results / f"attr_verdict_{manifest['id']}.json"


def _run(paths: tuple[Path, Path, Path, Path], *, explicit_out: bool = False) -> subprocess.CompletedProcess[str]:
    scenario, results, vmlinux, out = paths
    command = [sys.executable, str(TOOL), "--scenario", str(scenario),
               "--results", str(results), "--vmlinux", str(vmlinux)]
    if explicit_out:
        command.extend(("--out", str(out)))
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _verdict(paths: tuple[Path, Path, Path, Path]) -> JsonObject:
    return json.loads(paths[3].read_text(encoding="utf-8"))


def _rewrite_manifest(paths: tuple[Path, Path, Path, Path], mutate: Any) -> JsonObject:
    document = json.loads(paths[0].read_text(encoding="utf-8"))
    mutate(document)
    _write_contract(paths[0].parent, paths[1], document)
    return document


def test_schema_and_real_derived_positive_cli_pass(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(json.loads(paths[0].read_text()), schema)
    completed = _run(paths)
    assert completed.returncode == 0, completed.stderr
    verdict = _verdict(paths)
    assert verdict["overall"] == "PASS"
    assert all(check["verdict"] == "PASS" for check in verdict["checks"].values())
    assert paths[3].name == "attr_verdict_B05-V1.json"
    assert {key.rsplit(":", 1)[-1] for key in verdict["checks"] if key.startswith("counter:")} >= {
        "eq", "ge", "le", "delta_eq", "delta_ge"
    }


def test_real_derived_negative_abort_requires_zero_publication(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, "negative")
    completed = _run(paths)
    assert completed.returncode == 0, completed.stderr
    assert _verdict(paths)["checks"]["publication_zero"]["verdict"] == "PASS"
    probe = json.loads((paths[1] / "probe.json").read_text())
    probe["remote_entries"] = 1
    (paths[1] / "probe.json").write_text(json.dumps(probe))
    completed = _run(paths)
    assert completed.returncode == 1
    assert _verdict(paths)["checks"]["publication_zero"]["verdict"] == "FAIL"


def test_wrong_async_abort_counter_fails_named_check(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, "negative")
    post = paths[1] / "counters/post/phase8_stats.txt"
    post.write_text(post.read_text().replace("async_abort_before_grant 1", "async_abort_before_grant 0"))
    completed = _run(paths)
    assert completed.returncode == 1
    check = _verdict(paths)["checks"]["counter:2:phase8_stats:async_abort_before_grant:delta_eq"]
    assert check["verdict"] == "FAIL" and check["actual"] == 0


def test_schema_accepts_contract_and_rejects_nonsense() -> None:
    schema = json.loads(SCHEMA.read_text())
    validator = jsonschema.Draft202012Validator(schema)
    document: JsonObject = {
        "id": "B05-V1-2", "boundary": "B05", "variant": "V1", "polarity": "positive",
        "workload": "x.prog", "sha256": "0" * 64, "lane_fixture": "lane.sh",
        "hooks": [], "mode": "both",
        "counter_expect": [{"file": "phase8_stats", "name": "x", "op": op, "value": 0}
                           for op in ("eq", "ge", "le", "delta_eq", "delta_ge")],
        "drain_keys": [{"file": "phase5_state", "name": "remote_refs"},
                       {"file": "phase6_state", "name": "remote_refs"}],
        "sentinel": {"fs/nfsd": {"rule": "on-only", "required": ["x"], "observed": []}},
        "procs": 1, "executions": 1,
    }
    assert not list(validator.iter_errors(document))
    with_args = copy.deepcopy(document)
    with_args["hooks"] = [{
        "id": "v4.generation-abort-ioctl",
        "args": {"kcov_fd": 7, "generation": 9},
    }]
    assert not list(validator.iter_errors(with_args))
    for mutation in (
        lambda value: value.update(id="nonsense"),
        lambda value: value.update(boundary="nonsense"),
        lambda value: value.update(variant="V999"),
        lambda value: value.update(mode="off"),
        lambda value: value.update(hooks=[{"id": "nonsense", "args": {}}]),
    ):
        candidate = copy.deepcopy(document)
        mutation(candidate)
        assert list(validator.iter_errors(candidate))


def test_gauge_can_decrease_to_qualified_drains(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    pre = paths[1] / "counters/pre/phase5_state.txt"
    pre.write_text(pre.read_text().replace("live_tickets 0", "live_tickets 1"))
    completed = _run(paths)
    assert completed.returncode == 0, completed.stderr
    verdict = _verdict(paths)
    assert verdict["checks"]["drain:phase5_state:live_tickets"]["verdict"] == "PASS"
    assert verdict["checks"]["drain:phase5_state:remote_refs"]["verdict"] == "PASS"
    assert verdict["checks"]["drain:phase6_state:remote_refs"]["verdict"] == "PASS"


@pytest.mark.parametrize("mutation", ["missing_on", "missing_off", "malformed", "unresolved"])
def test_absence_needs_valid_paired_coverage(tmp_path: Path, mutation: str) -> None:
    paths = _fixture(tmp_path, "negative")
    on_only = paths[1] / "coverage_sets/fs_nfsd_on_only.pcs"
    if mutation == "missing_on":
        on_only.unlink()
    elif mutation == "missing_off":
        (paths[1] / "coverage_sets/fs_nfsd_off_union.pcs").unlink()
    elif mutation == "malformed":
        on_only.write_text("not-a-pc\n")
    else:
        on_only.write_text("0x1\n")
    completed = _run(paths)
    assert completed.returncode != 0
    verdict = _verdict(paths)
    if verdict["overall"] == "FAIL":
        assert verdict["checks"]["coverage_evidence"]["verdict"] == "FAIL"
    else:
        assert verdict["overall"] == "ERROR"


def test_negative_ownerless_requires_independent_worker_trace(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    def ownerless(document: JsonObject) -> None:
        document.update({
            "id": "B07-V1", "boundary": "B07", "polarity": "negative",
            "negative_expect": {"ownerless_worker": _callback_worker()},
        })
    _rewrite_manifest(paths, ownerless)
    paths = (paths[0], paths[1], paths[2], paths[1] / "attr_verdict_B07-V1.json")
    completed = _run(paths)
    assert completed.returncode == 0, completed.stderr
    (paths[1] / "remote_on/trial_01/callback-trace.txt").unlink()
    completed = _run(paths)
    assert completed.returncode == 1
    assert _verdict(paths)["checks"]["ownerless_worker"]["verdict"] == "FAIL"


def test_abort_cannot_substitute_cross_lane_for_publication(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, "negative")
    (paths[1] / "probe.json").unlink()
    for side in ("pre", "post"):
        (paths[1] / f"counters/{side}/phase9_stats.txt").write_text(
            "cross_lane_attribution 0\n")
    document = json.loads(paths[0].read_text())
    document["negative_expect"] = {"cross_lane_zero": [{
        "file": "phase9_stats", "name": "cross_lane_attribution"
    }]}
    paths[0].write_text(json.dumps(document))
    assert _run(paths).returncode == 1
    check = _verdict(paths)["checks"]["negative_contract"]
    assert check["verdict"] == "FAIL"
    assert check["publication"] is False and check["cross_lane"] is True


def test_laundromat_rejects_unrelated_callback_worker_witness(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    def laundromat(document: JsonObject) -> None:
        document.update({
            "id": "B08-V1", "boundary": "B08", "polarity": "negative",
            "hooks": [],
            "negative_expect": {"ownerless_worker": _callback_worker()},
        })
        document["sentinel"]["fs/nfsd"].update({
            "required": [], "absent-on-only": ["nfs4_laundromat"],
        })
    _rewrite_manifest(paths, laundromat)
    paths = (paths[0], paths[1], paths[2], paths[1] / "attr_verdict_B08-V1.json")
    assert _run(paths).returncode == 1
    verdict = _verdict(paths)
    assert verdict["checks"]["ownerless_worker"]["verdict"] == "FAIL"
    assert verdict["checks"]["ownerless_worker"]["boundary"] == "B07"
    assert verdict["checks"]["negative_contract"]["verdict"] == "FAIL"
    assert verdict["checks"]["negative_contract"]["worker_supported"] is False


def test_contradictory_off_union_invalidates_on_only(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    coverage = paths[1] / "coverage_sets"
    shutil.copy(coverage / "fs_nfsd_on_only.pcs", coverage / "fs_nfsd_off_union.pcs")
    assert _run(paths).returncode == 1
    check = _verdict(paths)["checks"]["coverage_evidence"]
    assert check["verdict"] == "FAIL"
    assert check["modules"]["fs/nfsd"]["on_only_consistent"] is False
    assert check["modules"]["fs/nfsd"]["derived_on_only_pcs"] == 0


def test_cross_lane_negative_requires_zero_counter(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    for side, text in (("pre", "owner_lane_match 0\ncross_lane_attribution 0\n"),
                       ("post", "owner_lane_match 1\ncross_lane_attribution 0\n")):
        (paths[1] / f"counters/{side}/phase9_stats.txt").write_text(text)
    def cross_lane(document: JsonObject) -> None:
        document.update({
            "id": "B11-V7", "boundary": "B11", "variant": "V7", "polarity": "negative",
            "hooks": [{"id": "v7.concurrent-cross-lane", "args": {}}],
            "counter_expect": [*document["counter_expect"],
                {"file": "phase9_stats", "name": "owner_lane_match", "op": "delta_ge", "value": 1},
                {"file": "phase9_stats", "name": "cross_lane_attribution", "op": "delta_eq", "value": 0},
            ],
            "negative_expect": {"cross_lane_zero": [
                {"file": "phase9_stats", "name": "cross_lane_attribution"}
            ]},
        })
    _rewrite_manifest(paths, cross_lane)
    paths = (paths[0], paths[1], paths[2], paths[1] / "attr_verdict_B11-V7.json")
    assert _run(paths).returncode == 0
    post = paths[1] / "counters/post/phase9_stats.txt"
    original = post.read_text()
    post.write_text(original.replace("owner_lane_match 1", "owner_lane_match 0"))
    assert _run(paths).returncode == 1
    lower_bound = _verdict(paths)["checks"]["counter:6:phase9_stats:owner_lane_match:delta_ge"]
    assert lower_bound["verdict"] == "FAIL" and lower_bound["actual"] == 0
    post.write_text(original.replace("cross_lane_attribution 0", "cross_lane_attribution 1"))
    assert _run(paths).returncode == 1
    assert _verdict(paths)["checks"]["cross_lane_zero"]["verdict"] == "FAIL"


def test_matching_stale_image_digests_fail_actual_identity(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    for name in ("before", "after"):
        (paths[1] / f"image-{name}.sha256").write_text("0" * 64 + "\n")
    assert _run(paths).returncode == 1
    assert _verdict(paths)["checks"]["image_unchanged"]["verdict"] == "FAIL"


@pytest.mark.parametrize("mutation", ["missing", "malformed", "altered"])
def test_missing_malformed_or_altered_image_digest_is_rejected(
        tmp_path: Path, mutation: str) -> None:
    paths = _fixture(tmp_path)
    after = paths[1] / "image-after.sha256"
    if mutation == "missing":
        after.unlink()
    elif mutation == "malformed":
        after.write_text("not-a-sha\n")
    else:
        after.write_text(hashlib.sha256(b"different image").hexdigest() + "\n")
    completed = _run(paths)
    assert completed.returncode == (1 if mutation == "altered" else 2)
    verdict = _verdict(paths)
    if mutation == "altered":
        assert verdict["checks"]["image_unchanged"]["verdict"] == "FAIL"
    else:
        assert verdict["overall"] == "ERROR"


def test_negative_without_witness_or_absence_cannot_pass(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    document = json.loads(paths[0].read_text())
    document["polarity"] = "negative"
    paths[0].write_text(json.dumps(document))
    assert _run(paths).returncode == 2
    document["negative_expect"] = {"publication_zero": [{
        "source": "counter", "file": "phase8_stats", "name": "live_saved_work"
    }]}
    document["sentinel"]["fs/nfsd"].pop("absent-on-only")
    paths[0].write_text(json.dumps(document))
    assert _run(paths).returncode == 1
    assert _verdict(paths)["checks"]["negative_contract"]["verdict"] == "FAIL"


def test_changed_workload_cannot_reuse_stale_captured_inputs(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    workload = paths[0].parent / "workload.prog"
    workload.write_text(workload.read_text() + "\n# changed\n")
    document = json.loads(paths[0].read_text())
    document["sha256"] = _sha256(workload)
    paths[0].write_text(json.dumps(document))
    assert _run(paths).returncode == 1
    verdict = _verdict(paths)
    assert verdict["checks"]["workload_sha256"]["verdict"] == "PASS"
    assert verdict["checks"]["input_identity"]["verdict"] == "FAIL"


@pytest.mark.parametrize("mutation", ["dry_run", "proof"])
def test_hook_declaration_is_not_runtime_proof(tmp_path: Path, mutation: str) -> None:
    paths = _fixture(tmp_path, "negative")
    run = json.loads((paths[1] / "run.json").read_text())
    hook = run["hooks"][0]["manifest"]
    if mutation == "dry_run":
        hook["dry_run"] = True
    else:
        hook["proof"][0]["delta"] = 999
    (paths[1] / "run.json").write_text(json.dumps(run))
    assert _run(paths).returncode == 1
    assert _verdict(paths)["checks"]["run_contract"]["verdict"] == "FAIL"


def test_typed_unforceable_is_valid_machine_shape_but_not_success(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, "negative")
    run = json.loads((paths[1] / "run.json").read_text())
    hook = run["hooks"][0]["manifest"]
    hook.pop("requirements")
    hook.update({
        "status": "UNFORCEABLE", "commands": [], "proof": [],
        "failure": {
            "type": "UNFORCEABLE", "attempted_trigger": "candidate trigger",
            "reason": "not established by this capture",
        },
    })
    (paths[1] / "run.json").write_text(json.dumps(run))
    assert _run(paths).returncode == 1
    check = _verdict(paths)["checks"]["run_contract"]
    assert check["verdict"] == "FAIL"
    assert check["statuses"] == ["UNFORCEABLE"]


def test_fake_image_path_cannot_replace_baseline_identity(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    fake = paths[0].parent / "fake.raw"
    fake.write_bytes(b"not the baseline image")
    digest = _sha256(fake)
    run = json.loads((paths[1] / "run.json").read_text())
    run["inputs"]["image"] = {"path": str(fake), "sha256": digest}
    (paths[1] / "run.json").write_text(json.dumps(run))
    for name in ("before", "after"):
        (paths[1] / f"image-{name}.sha256").write_text(digest + "\n")
    assert _run(paths).returncode == 1
    verdict = _verdict(paths)
    assert verdict["checks"]["input_identity"]["verdict"] == "FAIL"
    assert verdict["checks"]["image_unchanged"]["verdict"] == "FAIL"


def test_hooks_null_still_writes_named_error_verdict(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    run = json.loads((paths[1] / "run.json").read_text())
    run["hooks"] = None
    (paths[1] / "run.json").write_text(json.dumps(run))
    completed = _run(paths)
    assert completed.returncode == 1
    verdict = _verdict(paths)
    assert verdict["overall"] == "FAIL"
    assert verdict["checks"]["run_contract"]["verdict"] == "FAIL"


def test_id_must_match_boundary_and_variant(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    document = json.loads(paths[0].read_text())
    document["id"] = "B04-V1"
    paths[0].write_text(json.dumps(document))
    completed = _run(paths)
    assert completed.returncode == 2
    mismatched = paths[1] / "attr_verdict_B04-V1.json"
    assert "does not match" in json.loads(mismatched.read_text())["checks"]["input"]["error"]


def test_schema_malformed_hooks_still_writes_named_error_verdict(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    document = json.loads(paths[0].read_text())
    document["hooks"] = None
    paths[0].write_text(json.dumps(document))
    completed = _run(paths)
    assert completed.returncode == 2
    assert paths[3].is_file()
    assert _verdict(paths)["overall"] == "ERROR"


def test_actual_kcsan_bug_log_is_non_clean_without_changing_kcov_verdict(
        tmp_path: Path) -> None:
    if not KCSAN_LOG.is_file():
        pytest.skip("retained KCSAN evidence not present: %s" % KCSAN_LOG)
    paths = _fixture(tmp_path)
    shutil.copy(KCSAN_LOG, paths[1] / "remote_on/trial_01/dmesg.txt")
    assert _run(paths).returncode == 0
    verdict = _verdict(paths)
    assert verdict["overall"] == "PASS"
    assert verdict["checks"]["dmesg_hygiene"]["verdict"] == "PASS"
    assert verdict["sanitizer"]["clean"] is False
    assert verdict["sanitizer"]["status"] == "NON_CLEAN"
    assert all(item["mode"] == "on" and item["source"].endswith("dmesg.txt")
               and isinstance(item["line"], int) and "BUG: KCSAN" in item["text"]
               for item in verdict["sanitizer"]["findings"])


def test_off_only_kcsan_is_visible_and_nonfatal(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    off = paths[1] / "remote_off/trial_01/dmesg.txt"
    original = off.read_text()
    line = len(original.splitlines()) + 2
    off.write_text(original + "\nBUG: KCSAN: data-race in off_reader / off_writer\n")
    assert _run(paths).returncode == 0
    verdict = _verdict(paths)
    assert verdict["overall"] == "PASS"
    assert verdict["sanitizer"]["clean"] is False
    assert verdict["sanitizer"]["findings"] == [{
        "mode": "off", "source": "remote_off/trial_01/dmesg.txt",
        "line": line, "text": "BUG: KCSAN: data-race in off_reader / off_writer",
    }]


def test_off_kcsan_mixed_with_non_kcsan_bug_is_fatal(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    off = paths[1] / "remote_off/trial_01/serial.log"
    original = off.read_text()
    fatal_line = len(original.splitlines()) + 3
    off.write_text(original + "\nBUG: KCSAN: data-race in a / b\nBUG: fatal off-mode fault\n")
    assert _run(paths).returncode == 1
    verdict = _verdict(paths)
    assert verdict["overall"] == "FAIL"
    assert verdict["sanitizer"]["status"] == "NON_CLEAN"
    check = verdict["checks"]["dmesg_hygiene"]
    assert check["verdict"] == "FAIL"
    assert check["matches"] == [{
        "mode": "off", "source": "remote_off/trial_01/serial.log",
        "line": fatal_line, "text": "BUG: fatal off-mode fault",
    }]


@pytest.mark.parametrize("mutation", ["missing", "malformed"])
def test_off_diagnostic_evidence_is_required_and_well_formed(
        tmp_path: Path, mutation: str) -> None:
    paths = _fixture(tmp_path)
    off = paths[1] / "remote_off/trial_01/dmesg.txt"
    if mutation == "missing":
        off.unlink()
    else:
        off.write_bytes(b"\xff")
    assert _run(paths).returncode == 1
    check = _verdict(paths)["checks"]["dmesg_hygiene"]
    assert check["verdict"] == "FAIL"
    assert check[mutation]


@pytest.mark.parametrize("relative", [
    "remote_off/trial_01/dmesg.txt",
    "remote_off/trial_01/serial.log",
    "remote_on/trial_01/dmesg.txt",
    "remote_on/trial_01/serial.log",
])
@pytest.mark.parametrize("payload", [b" \t\r\n", b"\x00" * 80],
                         ids=["whitespace", "nul-only"])
def test_contentless_diagnostic_log_is_malformed(
        tmp_path: Path, relative: str, payload: bytes) -> None:
    paths = _fixture(tmp_path)
    (paths[1] / relative).write_bytes(payload)
    assert _run(paths).returncode == 1
    verdict = _verdict(paths)
    check = verdict["checks"]["dmesg_hygiene"]
    mode = "off" if relative.startswith("remote_off/") else "on"
    assert check["verdict"] == "FAIL"
    assert check["matches"] == []
    assert check["malformed"] == [{
        "mode": mode, "source": relative,
        "error": "diagnostic log contains no text content",
    }]
    assert relative not in check["sources"]
    assert len(check["sources"]) == 3


def test_meaningful_diagnostic_text_is_not_rejected_for_nul_or_whitespace(
        tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    content = b"\x00 \t\r\n[    0.000000] normal kernel boot\n\x00"
    for mode in ("off", "on"):
        for name in ("dmesg.txt", "serial.log"):
            (paths[1] / f"remote_{mode}/trial_01/{name}").write_bytes(content)
    assert _run(paths).returncode == 0
    verdict = _verdict(paths)
    assert verdict["overall"] == "PASS"
    assert verdict["checks"]["dmesg_hygiene"]["malformed"] == []


@pytest.mark.parametrize(("mutation", "expected_error"), [
    ("coverage", "missing coverage capture:"),
    ("counter_file", "missing counter capture: phase8_stats"),
    ("counter_field", "missing counter: phase8_stats:async_child_created"),
])
def test_error_verdict_preserves_available_kcsan_findings(
        tmp_path: Path, mutation: str, expected_error: str) -> None:
    paths = _fixture(tmp_path)
    shutil.copy(KCSAN_LOG, paths[1] / "remote_on/trial_01/dmesg.txt")
    if mutation == "coverage":
        (paths[1] / "coverage_sets/fs_nfsd_off_union.pcs").unlink()
    elif mutation == "counter_file":
        (paths[1] / "counters/post/phase8_stats.txt").unlink()
    else:
        counter = paths[1] / "counters/post/phase8_stats.txt"
        counter.write_text("\n".join(
            line for line in counter.read_text().splitlines()
            if not line.startswith("async_child_created ")) + "\n")
    assert _run(paths).returncode == 2
    verdict = _verdict(paths)
    assert verdict["overall"] == "ERROR"
    assert expected_error in verdict["checks"]["input"]["error"]
    assert verdict["checks"]["dmesg_hygiene"]["verdict"] == "PASS"
    assert verdict["sanitizer"]["status"] == "NON_CLEAN"
    assert verdict["sanitizer"]["findings"]
    assert all("BUG: KCSAN" in item["text"]
               for item in verdict["sanitizer"]["findings"])


def test_error_verdict_preserves_non_kcsan_fatal_diagnostic(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    shutil.copy(KCSAN_LOG, paths[1] / "remote_on/trial_01/dmesg.txt")
    serial = paths[1] / "remote_off/trial_01/serial.log"
    serial.write_text(serial.read_text() + "\nBUG: fatal with incomplete coverage\n")
    (paths[1] / "coverage_sets/fs_nfsd_off_union.pcs").unlink()
    assert _run(paths).returncode == 2
    verdict = _verdict(paths)
    assert "missing coverage capture:" in verdict["checks"]["input"]["error"]
    check = verdict["checks"]["dmesg_hygiene"]
    assert check["verdict"] == "FAIL"
    assert any(item["mode"] == "off"
               and item["source"] == "remote_off/trial_01/serial.log"
               and item["text"] == "BUG: fatal with incomplete coverage"
               for item in check["matches"])
    assert verdict["sanitizer"]["status"] == "NON_CLEAN"


def test_malformed_counter_is_input_error(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    (paths[1] / "counters/post/phase8_stats.txt").write_text("not a counter\n")
    assert _run(paths).returncode == 2
    assert _verdict(paths)["overall"] == "ERROR"

