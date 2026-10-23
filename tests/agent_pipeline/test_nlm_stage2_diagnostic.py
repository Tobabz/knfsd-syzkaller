"""Diagnostic runner verdicts must distinguish execution from mutation."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def _module():
    path = Path(__file__).parents[2] / "tools" / "test-nlm-stage2-gate-kvm.py"
    spec = spec_from_file_location("nlm_stage2_diagnostic", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _relay_module():
    path = Path(__file__).parents[2] / "tools" / "test-nlm-relay-kvm.py"
    spec = spec_from_file_location("nlm_relay_diagnostic", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def test_focused_seed_includes_resource_producers():
    calls = _module()._focused_seed_syscalls()
    assert {"fcntl$lock", "nanosleep", "getpid", "clock_gettime"} <= set(calls)


def test_lock_rule_can_preserve_seed_contention(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "tools"))
    module = _module()
    moved = module._lock_rules(client=0, offset=1)
    unchanged = module._lock_rules(client=0, offset=0)
    assert moved != unchanged
    assert len(moved) == len(unchanged)


def test_relay_rules_separate_identity_break_and_preserving_mutations():
    module = _relay_module()
    control = module.diagnostic_rules("offset_noop_control")
    broken = module.diagnostic_rules("offset_identity_break")
    preserving = module.diagnostic_rules("cookie_identity_preserving")
    assert len({control, broken, preserving}) == 3
    assert b"nlm4.request.LOCK.args.alock.l_offset" in control
    assert b"nlm4.request.LOCK.args.alock.l_offset" in broken
    assert b"nlm4.request.LOCK.args.cookie" in preserving
    assert module.COOKIE_REPLACEMENT in preserving


def test_campaign_verdict_requires_forwarded_exposure_per_execution():
    status = _module()._campaign_status
    summary = {
        "executions": 4, "matched_forward_complete_executions": 0,
        "mutation_exposures": 0, "journal_clean": True,
        "apply_refusals": 0, "forward_failed": 0,
    }
    assert status(summary) == "host_campaign_executed_no_exposure_diagnostic_only"
    summary["mutation_exposures"] = 4
    summary["matched_forward_complete_executions"] = 3
    assert status(summary) == "host_campaign_exposure_unconfirmed_diagnostic_only"
    summary["matched_forward_complete_executions"] = 4
    assert status(summary) == "host_campaign_mutation_forwarded_diagnostic_only"
    summary["journal_clean"] = False
    assert status(summary) == "host_campaign_exposure_unconfirmed_diagnostic_only"


def test_fixture_failure_is_not_attribution_failure(tmp_path):
    classify = _module()._campaign_failure_phase
    work = tmp_path / "work"
    work.mkdir()
    (work / "manager-debug.log").write_bytes(
        b"9pnet_virtio: no channels available for device koov-lane\n")
    error = RuntimeError("no generation-attributed campaign execution")
    assert classify(tmp_path, error) == "fixture_preparation"
    (work / "manager-debug.log").write_bytes(b"NFS fuzz lane bound\n")
    assert classify(tmp_path, error) == "campaign_attribution"


def test_capture_stats_never_assert_completeness(tmp_path):
    parse = _module()._capture_stats
    stats = tmp_path / "capture.stats"
    assert parse(stats)["drop_count_known"] is False
    stats.write_text("captured=376 packets=379 drops=0\n")
    clean = parse(stats)
    assert clean["socket_drop_free"] is True
    assert clean["capture_complete"] is False
    stats.write_text("captured=376 packets=379 drops=2\n")
    assert parse(stats)["socket_drop_free"] is False
    stats.write_text("bad stats\n")
    assert parse(stats)["status"] == "invalid"


def test_contention_diagnostic_separates_callback_from_fcntl_completion():
    status = _relay_module()._contention_diagnostic_status
    denied = {
        "mutation_forwarded": True, "callback_received": True,
        "mutation_value_changed": True,
        "callback_client_status": "LCK_DENIED",
        "granted_res_status": "LCK_DENIED",
        "waiting_fcntl_completed": False,
    }
    assert status(denied, "offset_identity_break") == (
        "offset_identity_break_callback_denied_diagnostic_only")
    denied["waiting_fcntl_completed"] = True
    assert status(denied, "offset_identity_break") == (
        "offset_identity_break_callback_denied_diagnostic_only")
    accepted = {**denied, "callback_client_status": "LCK_GRANTED",
                "granted_res_status": "LCK_GRANTED"}
    assert status(accepted, "cookie_identity_preserving") == (
        "cookie_identity_preserving_callback_accepted_and_fcntl_completed_diagnostic_only")
    accepted["waiting_fcntl_completed"] = False
    assert status(accepted, "cookie_identity_preserving") == (
        "cookie_identity_preserving_diagnostic_incomplete")
    control = {**accepted, "waiting_fcntl_completed": True,
               "mutation_value_changed": False}
    assert status(control, "offset_noop_control") == (
        "offset_noop_control_callback_accepted_and_fcntl_completed_diagnostic_only")
