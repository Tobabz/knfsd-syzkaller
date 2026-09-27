"""Behavioral checks for the machine-readable attribution matrix."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
CHECKER = ROOT / "tools" / "attr-matrix-check.py"
MATRIX = ROOT / "report" / "attribution-scenario-matrix.json"
BASELINE = ROOT / "report" / "attr-env-baseline.json"
INPUT_KEYS = ("kernel", "vmlinux", "image", "deps_tar", "syz_execprog", "syz_executor")


def run_checker(matrix: Path, baseline: Path = BASELINE) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--matrix", str(matrix), "--baseline", str(baseline), "--mode", "structure"],
        check=False, capture_output=True, text=True,
    )


def write_existing_fixture(root: Path) -> tuple[Path, Path, Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    evidence = root / "evidence"
    evidence.mkdir()
    metadata = evidence / "manifest.json"
    result = evidence / "result.json"
    hashes = {key: {"sha256": f"{index:064x}"} for index, key in enumerate(INPUT_KEYS, 1)}
    metadata.write_text(json.dumps({"inputs": hashes}), encoding="utf-8")
    result.write_text(json.dumps({"checks": {"passed": True}}), encoding="utf-8")
    baseline = root / "baseline.json"
    baseline.write_text(json.dumps({
        "inputs": hashes,
        "existing_evidence": [{
            "path": str(evidence), "metadata": str(metadata), "sha_match": True,
        }],
    }), encoding="utf-8")
    ref = f"{result}#checks.passed"
    matrix_data = json.loads(MATRIX.read_text(encoding="utf-8"))
    matrix_data["B01"]["V1"] = {"state": "EXISTING", "ref": ref}
    matrix = root / MATRIX.name
    matrix.write_text(json.dumps(matrix_data), encoding="utf-8")
    (root / "attribution-boundaries.md").write_text(
        (ROOT / "report" / "attribution-boundaries.md").read_text(encoding="utf-8"), encoding="utf-8"
    )
    markdown = (ROOT / "report" / "attribution-scenario-matrix.md").read_text(encoding="utf-8")
    (root / "attribution-scenario-matrix.md").write_text(
        markdown.replace("NEW(B01-V1)", f"EXISTING({ref})", 1), encoding="utf-8"
    )
    return matrix, baseline, metadata, result


def test_structure_accepts_checked_in_matrix() -> None:
    result = run_checker(MATRIX)
    assert result.returncode == 0, result.stderr


def test_structure_accepts_fully_eligible_existing_evidence(tmp_path: Path) -> None:
    matrix, baseline, _, _ = write_existing_fixture(tmp_path)
    result = run_checker(matrix, baseline)
    assert result.returncode == 0, result.stderr


def test_structure_rejects_nonexistent_existing_evidence(tmp_path: Path) -> None:
    matrix, baseline, _, _ = write_existing_fixture(tmp_path)
    data = json.loads(matrix.read_text(encoding="utf-8"))
    old_ref = data["B01"]["V1"]["ref"]
    new_ref = "/nonexistent#checks.pass"
    data["B01"]["V1"]["ref"] = new_ref
    matrix.write_text(json.dumps(data), encoding="utf-8")
    markdown = matrix.with_suffix(".md")
    markdown.write_text(markdown.read_text(encoding="utf-8").replace(old_ref, new_ref), encoding="utf-8")
    result = run_checker(matrix, baseline)
    assert result.returncode != 0
    assert "B01-V1" in result.stderr
    assert "does not exist" in result.stderr


def test_structure_rejects_non_boolean_sha_match(tmp_path: Path) -> None:
    matrix, baseline, _, _ = write_existing_fixture(tmp_path)
    data = json.loads(baseline.read_text(encoding="utf-8"))
    data["existing_evidence"][0]["sha_match"] = "false"
    baseline.write_text(json.dumps(data), encoding="utf-8")
    result = run_checker(matrix, baseline)
    assert result.returncode != 0
    assert "B01-V1" in result.stderr
    assert "not boolean true" in result.stderr


def test_structure_rejects_missing_provenance_metadata(tmp_path: Path) -> None:
    matrix, baseline, metadata, _ = write_existing_fixture(tmp_path)
    metadata.unlink()
    result = run_checker(matrix, baseline)
    assert result.returncode != 0
    assert "B01-V1" in result.stderr
    assert "metadata does not exist" in result.stderr


def test_structure_rejects_each_stale_input_hash(tmp_path: Path) -> None:
    for key in INPUT_KEYS:
        matrix, baseline, _, _ = write_existing_fixture(tmp_path / key)
        data = json.loads(baseline.read_text(encoding="utf-8"))
        data["inputs"][key]["sha256"] = "f" * 64
        baseline.write_text(json.dumps(data), encoding="utf-8")
        result = run_checker(matrix, baseline)
        assert result.returncode != 0
        assert "B01-V1" in result.stderr
        assert f"input {key} sha256 does not match baseline" in result.stderr


def test_structure_rejects_failed_named_check(tmp_path: Path) -> None:
    matrix, baseline, _, result_path = write_existing_fixture(tmp_path)
    result_path.write_text(json.dumps({"checks": {"passed": False}}), encoding="utf-8")
    result = run_checker(matrix, baseline)
    assert result.returncode != 0
    assert "B01-V1" in result.stderr
    assert "did not pass" in result.stderr
