#!/usr/bin/env python3
"""Read-only verdict for NLM KVM smoke evidence and Stage 2 readiness.

Smoke is not the Stage 2 service and cannot authorize a production job.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agent_pipeline.semantic_delta import SealedJournal
from agent_pipeline.stage1.config import Stage1Config
from tools.nlm_callback_attribution import calls
from tools.nlm_callback_verify import verify


_POSITIVE_STATUS = (
    "cookie_identity_preserving_callback_accepted_and_fcntl_completed_diagnostic_only"
)
_HISTORICAL_STATUS = "blocked_grant_completed_route_unproven"


def _blocked_grant(result: dict) -> tuple[bool, str]:
    """Prefer typed callback acceptance; retain explicit legacy fallback."""
    status = result.get("status")
    completed = (result.get("waiting_fcntl_completed") is True
                 and "LOCK_OK" in result.get("client1_output", "")
                 and "UNLOCK_OK" in result.get("client1_output", ""))
    typed = any(key in result for key in (
        "callback_client_status", "granted_res_status",
        "mutation_value_changed"))
    if typed:
        passed = (status == _POSITIVE_STATUS
                  and result.get("mutation_mode") ==
                      "cookie_identity_preserving"
                  and result.get("mutation_forwarded") is True
                  and result.get("mutation_value_changed") is True
                  and result.get("callback_received") is True
                  and result.get("callback_client_status") == "LCK_GRANTED"
                  and result.get("granted_res_status") == "LCK_GRANTED"
                  and completed)
        return passed, "typed_callback_acceptance"
    passed = (status == _HISTORICAL_STATUS
              and "LOCK_OK" in result.get("client1_output", "")
              and "UNLOCK_OK" in result.get("client1_output", "")
              and result.get("grant_trace_available") is True
              and result.get("grant_trace_count") == 1)
    return passed, "historical_callback_observation"


def _smoke(directory: Path, expected_callback: str) -> dict:
    result_path = directory / "result.json"
    pcap = directory / "nlm-callback-diagnostic.pcap"
    result_bytes = result_path.read_bytes()
    result = json.loads(result_bytes)
    pcap_digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
    observed = list(calls(pcap, deduplicate=False))
    if hashlib.sha256(pcap.read_bytes()).hexdigest() != pcap_digest:
        raise ValueError("pcap changed during verification")
    comparison = verify(SealedJournal(directory / "journal", "smoke"),
                        observed, "nlm-smoke-vm", pcap_digest)
    callbacks = result.get("callback_diagnostic", {})
    attribution = callbacks.get("attribution", [])
    anchors = comparison["anchors"]
    blocked_grant, evidence_mode = _blocked_grant(result)
    checks = {
        "blocked_grant_completed": blocked_grant,
        "journal_clean": comparison["journal_clean"]
                         and result.get("rejections") == [],
        "backend_lock_bytes_observed": bool(anchors) and all(
            a["reason"] == "journal_backend_lock_bytes_observed"
            for a in anchors),
        "callback_boundary_observed": (
            callbacks.get("status") == "diagnostic_only"
            and len(attribution) == 1
            and attribution[0].get("status") == expected_callback
            and callbacks.get("callback_calls") == 1
            and attribution[0].get("generation") == (
                1 if expected_callback == "matched_diagnostic" else None)),
        "diagnostic_only": (comparison["status"] == "diagnostic_only"
                            and comparison["capture_complete"] is False),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "pcap_sha256": pcap_digest,
        "journal_manifest_sha256": comparison["journal_manifest_sha256"],
        "journal_anchors": len(anchors),
        "callback_evidence_mode": evidence_mode,
        "capture_complete": comparison["capture_complete"],
        "evidence_class": comparison["status"],
    }


def assess(normal: Path, late: Path, stage1: Path, spec: Path) -> dict:
    normal_result = _smoke(normal, "matched_diagnostic")
    late_result = _smoke(late, "outside_activation_window")
    config = Stage1Config.load(stage1)
    template = json.loads(spec.read_bytes())
    hcap = next((cap for cap in template["capabilities"]
                 if cap["id"] == "HCAP-13"), None)
    hcap_approved = (hcap is not None
                     and "stage2" in hcap["usable_stage"]
                     and "agent_stage2" in hcap["usable_by"])
    blockers = []
    if not normal_result["passed"] or not late_result["passed"]:
        blockers.append("smoke_evidence_failed")
    blockers.extend((
        "complete_ordered_vm_bound_callback_capture_absent",
        "crash_context_and_remote_kcov_attribution_unverified",
        "restart_counterexample_unverified",
        "production_proxy_and_guest_pins_unpromoted",
        "independent_stage2_gate_campaign_strict_replay_absent",
    ))
    if config.stage2 is None:
        blockers.append("stage2_backend_unconfigured")
    if not hcap_approved:
        blockers.append("hcap13_stage2_authority_absent")
    return {
        "schema_version": "nlm-stage2-readiness.v1",
        "normal": normal_result,
        "late": late_result,
        "smoke_e2e_passed": normal_result["passed"] and late_result["passed"],
        "stage2_ready": False,
        "blockers": blockers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal", required=True, type=Path)
    parser.add_argument("--late", required=True, type=Path)
    parser.add_argument("--stage1", required=True, type=Path)
    parser.add_argument("--spec", type=Path, default=Path(
        "agent_pipeline/stage1/host/template/host-spec.json"))
    args = parser.parse_args()
    report = assess(args.normal, args.late, args.stage1, args.spec)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["smoke_e2e_passed"]:
        return 1
    return 0 if report["stage2_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
