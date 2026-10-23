"""A successful diagnostic smoke must never lift the Stage 2 gate."""

import json
from types import SimpleNamespace

from tools import nlm_stage2_readiness as readiness


def test_typed_cookie_acceptance_requires_all_distinct_observations():
    result = {
        "status": readiness._POSITIVE_STATUS,
        "mutation_mode": "cookie_identity_preserving",
        "mutation_forwarded": True,
        "mutation_value_changed": True,
        "callback_received": True,
        "callback_client_status": "LCK_GRANTED",
        "granted_res_status": "LCK_GRANTED",
        "waiting_fcntl_completed": True,
        "client1_output": "LOCK_BEGIN\nLOCK_OK\nUNLOCK_OK\n",
    }
    assert readiness._blocked_grant(result) == (
        True, "typed_callback_acceptance")
    for key in ("mutation_forwarded", "mutation_value_changed",
                "callback_received", "waiting_fcntl_completed"):
        assert readiness._blocked_grant({**result, key: False}) == (
            False, "typed_callback_acceptance")
    assert readiness._blocked_grant(
        {**result, "granted_res_status": "LCK_DENIED"}) == (
            False, "typed_callback_acceptance")


def test_offset_identity_break_is_a_negative_control():
    result = {
        "status": "offset_identity_break_callback_denied_diagnostic_only",
        "mutation_mode": "offset_identity_break",
        "mutation_forwarded": True, "mutation_value_changed": True,
        "callback_received": True, "callback_client_status": "LCK_DENIED",
        "granted_res_status": "LCK_DENIED",
        "waiting_fcntl_completed": False, "client1_output": "LOCK_BEGIN\n",
    }
    assert readiness._blocked_grant(result) == (
        False, "typed_callback_acceptance")


def test_historical_smoke_remains_an_explicit_fallback():
    result = {
        "status": readiness._HISTORICAL_STATUS,
        "client1_output": "LOCK_OK\nUNLOCK_OK\n",
        "grant_trace_available": True, "grant_trace_count": 1,
    }
    assert readiness._blocked_grant(result) == (
        True, "historical_callback_observation")


def test_smoke_success_still_blocks_stage2(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, "_smoke", lambda *_: {"passed": True})
    monkeypatch.setattr(readiness.Stage1Config, "load",
                        lambda *_: SimpleNamespace(stage2=None))
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"capabilities": [{"id": "HCAP-13",
        "usable_stage": ["stage1"], "usable_by": ["agent_stage1"]}]}))
    report = readiness.assess(tmp_path, tmp_path, tmp_path, spec)
    assert report["smoke_e2e_passed"] is True
    assert report["stage2_ready"] is False
    assert "hcap13_stage2_authority_absent" in report["blockers"]
    assert "stage2_backend_unconfigured" in report["blockers"]


def test_diagnostic_is_not_promotion_even_if_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, "_smoke", lambda *_: {"passed": True})
    monkeypatch.setattr(readiness.Stage1Config, "load",
                        lambda *_: SimpleNamespace(stage2=object()))
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"capabilities": [{"id": "HCAP-13",
        "usable_stage": ["stage1", "stage2"],
        "usable_by": ["agent_stage1", "agent_stage2"]}]}))
    report = readiness.assess(tmp_path, tmp_path, tmp_path, spec)
    assert report["smoke_e2e_passed"] is True
    assert report["stage2_ready"] is False
    assert "independent_stage2_gate_campaign_strict_replay_absent" in report["blockers"]


def test_failed_smoke_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(readiness, "_smoke", lambda *_: {"passed": False})
    monkeypatch.setattr(readiness.Stage1Config, "load",
                        lambda *_: SimpleNamespace(stage2=None))
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"capabilities": []}))
    report = readiness.assess(tmp_path, tmp_path, tmp_path, spec)
    assert report["smoke_e2e_passed"] is False
    assert "smoke_evidence_failed" in report["blockers"]
