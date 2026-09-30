"""Fail-closed parser and real-symbol checks for observational NF-A1 KCOV."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
ENV_DIR = Path(os.environ.get("KOOV_ENV_DIR", str(ROOT / "env")))
HELPER = ROOT / "bundle/corpus/nfs-normal/nfa1-kcov-presence.py"
VMLINUX = ENV_DIR / "images/kcsan/vmlinux"
NORMAL_EVIDENCE = Path(os.environ.get(
    "KOOV_NORMAL_EVIDENCE", str(Path.home() / "normal-flow-evidence")))
V2_ON = NORMAL_EVIDENCE / "NF-A1-KCOV-V2-20260928/remote_on/trial_01"


def _require(*paths: Path) -> None:
    missing = [str(p) for p in paths if not Path(p).exists()]
    if missing:
        pytest.skip("environment artifact not present: " + ", ".join(missing))
spec = importlib.util.spec_from_file_location("nfa1_kcov_presence", HELPER)
assert spec is not None and spec.loader is not None
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def _meta(*, count: int = 1, capacity: int = 8,
          handle: str = "0x0200000000000001", saturated: int = 0) -> str:
    return (f"handle={handle}\ncapacity={capacity}\ncount={count}\n"
            f"saturated={saturated}\nstatus=stopped\n")


def test_observer_pc_normalizes_return_address_only_once() -> None:
    assert observer.parse_observer("0xffffffff831c45fa\n", _meta()) == [
        0xffffffff831c45f5
    ]


@pytest.mark.parametrize(
    ("pcs", "meta"),
    [
        ("0xffffffff831c45fa\n", _meta(handle="0x0100000000000001")),
        ("0xffffffff831c45fa\n", _meta(count=2)),
        ("0xffffffff831c45fa\n", _meta(capacity=1, saturated=0)),
        ("0xffffffff831c45fa\n", _meta() + "unexpected=value\n"),
        ("0xffffffff831c45fa\n", _meta().replace("count=1\n", "count=1\ncount=1\n")),
        ("garbage\n", _meta()),
        ("0x1\n", _meta()),
        ("", _meta()),
    ],
)
def test_observer_rejects_unowned_malformed_or_incomplete_exports(
        pcs: str, meta: str) -> None:
    with pytest.raises(ValueError):
        observer.parse_observer(pcs, meta)


def test_v2_pc_samples_resolve_into_all_required_stages() -> None:
    _require(V2_ON, VMLINUX)
    observer_pcs = observer.parse_observer(
        (V2_ON / "nfa1-observer.pcs").read_text(),
        (V2_ON / "nfa1-observer.meta").read_text(),
    )
    transport = [0xffffffff8319dd69, 0xffffffff831c4ae0, 0xffffffff831c8a55]
    process = 0xffffffff8319bee2
    assert all(pc in observer_pcs for pc in transport)
    assert f"{process:#x}" in (
        V2_ON / "coverage/cover_prog1.extra"
    ).read_text().splitlines()
    assert observer.stage_presence(VMLINUX, transport, [process]) == {
        "svc_data_ready": True, "svc_xprt_enqueue": True,
        "svc_xprt_dequeue": True, "svc_process": True,
    }
    verdict = observer.stage_presence(
        VMLINUX, [transport[1]], [process]
    )
    assert verdict == {
        "svc_data_ready": False, "svc_xprt_enqueue": True,
        "svc_xprt_dequeue": False, "svc_process": True,
    }


def test_empty_channels_report_no_stage_presence() -> None:
    assert observer.stage_presence(VMLINUX, [], []) == {
        "svc_data_ready": False, "svc_xprt_enqueue": False,
        "svc_xprt_dequeue": False, "svc_process": False,
    }


def test_full_buffer_cannot_pass_despite_positive_stage_pcs() -> None:
    stages = dict.fromkeys((*observer.STAGES, "svc_process"), True)
    assert observer.coverage_complete("on", stages, False, 100)
    assert not observer.coverage_complete("on", stages, True, 100)
    stages["svc_xprt_dequeue"] = False
    assert not observer.coverage_complete("on", stages, False, 100)


def test_managed_off_requires_no_managed_pcs_without_process_claim() -> None:
    stages = dict.fromkeys((*observer.STAGES, "svc_process"), True)
    stages["svc_process"] = False
    assert observer.coverage_complete("off", stages, False, 0)
    assert not observer.coverage_complete("off", stages, False, 1)


def test_literal_cli_preflight_loads_runner_without_creating_output(
        tmp_path: Path) -> None:
    _require(ENV_DIR / "images/nfa1-kcov-observer",
             ENV_DIR / "images/kcsan/bzImage", ENV_DIR / "images/kcsan/vmlinux",
             ENV_DIR / "images/bookworm-kcov-fresh-v1.raw",
             ENV_DIR / "syzkaller/bin/linux_amd64/syz-executor")
    output = tmp_path / "evidence"
    result = subprocess.run(
        [
            "/usr/bin/python3", "-B", str(HELPER),
            "--observer-binary", str(ENV_DIR / "images/nfa1-kcov-observer"),
            "--kernel", str(ENV_DIR / "images/kcsan/bzImage"),
            "--image", str(ENV_DIR / "images/bookworm-kcov-fresh-v1.raw"),
            "--ssh-key", str(ROOT / "artifacts/bookworm.id_rsa"),
            "--deps-tar", str(ROOT / "bundle/src/guest-deps.tar.gz"),
            "--vmlinux", str(VMLINUX),
            "--lane-fixture", str(ROOT / "bundle/corpus/nfs-normal/ab-lane-fixture-v42.sh"),
            "--workload", str(ROOT / "bundle/corpus/nfs-normal/async-copy-v42-tcp.prog"),
            "--syz-bin", str(ENV_DIR / "syzkaller"),
            "--mode", "on", "--trials", "1", "--executions", "10",
            "--sample-every", "10", "--procs", "2", "--cpus", "8",
            "--memory", "8192", "--output", str(output), "--preflight",
        ],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "READY" in result.stdout
    assert not output.exists()
