"""The append-only Stage 2 authority store: immutability and the snapshot
limits, which must refuse a row before it is stored."""

from __future__ import annotations

import json

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.evidence import EvidenceStore
from agent_pipeline.runner.q1_receipts import Q1ReceiptRejected
from agent_pipeline.stage2 import authority
from agent_pipeline.stage2.authority import (Stage2AuthorityStore,
                                             Stage2Publication)

from .fakes import sha

HARNESS = sha("execution-harness")


def publication(n: int) -> Stage2Publication:
    task_id = f"job-1.t{n}"
    return Stage2Publication.model_validate_json(json.dumps({
        "task_id": task_id,
        "task_input": {"job_id": "job-1", "harness_ref": sha("harness"),
                       "execution_harness_id": HARNESS, "step": "replay",
                       "compiled_ref": sha("compiled"), "campaign_id": "c1",
                       "crash_bundle_ref": sha("crash")},
        "bundle_fact_sha256": sha(f"fact-{n}"),
        "evidence_receipt_sha256": sha(f"receipt-{n}"),
        "execution": {
            "bundle_ref": sha(f"bundle-{n}"), "step": "replay", "index": 0,
            "lease_generation": 1,
            "correlation": {"job_id": "job-1", "task_id": task_id,
                            "execution_harness_id": HARNESS,
                            "vm_instance_id": "vm-1", "lane": 0,
                            "generation_id": 1},
            "candidate": {"candidate_id": "VC-1", "kernel_commit": "a" * 40,
                          "kind": "function", "path": "fs/nfsd/x.c",
                          "symbol": "target", "start_line": 1,
                          "end_line": 2},
            "compiled": {"rule_set_ref": sha("rules"),
                         "compiled_ref": sha("compiled"),
                         "hcap_revision": "hcap-1"},
            "identity": {"execution_harness_id": HARNESS,
                         "kernel_commit": "a" * 40,
                         "instrumentation_sha256": sha("instrumentation"),
                         "vmlinux_sha256": sha("vmlinux"),
                         "kaslr_enabled": False, "kaslr_offset": 0},
            "mapping_ref": sha("mapping"), "crash_bundle_ref": sha("crash"),
            "crash_window_bound": 4, "m1_profile_ref": sha("m1"),
            "q2_profile_ref": sha("q2"), "replay_profile_ref": sha("replay")},
    }))


def open_store(tmp_path) -> Stage2AuthorityStore:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    return Stage2AuthorityStore(tmp_path / "stage2.sqlite",
                                artifacts=artifacts,
                                evidence=EvidenceStore(artifacts))


def test_published_authority_is_immutable(tmp_path):
    store = open_store(tmp_path)
    store.publish(publication(1))
    store.publish(publication(1))               # the same entry again
    changed = publication(1).model_copy(
        update={"evidence_receipt_sha256": sha("other")})
    with pytest.raises(Q1ReceiptRejected):
        store.publish(changed)
    store.close()


def _rejected_is_absent(tmp_path, kept: int, refused: int) -> None:
    store = open_store(tmp_path)
    store.close()
    store = open_store(tmp_path)                # reopening still loads
    known = store.snapshot().executions
    assert len(known) == kept
    assert publication(refused).execution.bundle_ref not in known
    with pytest.raises(KeyError):
        store.publication(publication(refused).execution.bundle_ref)
    store.close()


def test_a_record_over_the_count_limit_is_never_stored(tmp_path, monkeypatch):
    monkeypatch.setattr(authority, "MAX_SNAPSHOT_RECORDS", 2)
    store = open_store(tmp_path)
    store.publish(publication(1))
    store.publish(publication(2))
    with pytest.raises(Q1ReceiptRejected, match="capacity"):
        store.publish(publication(3))
    store.close()
    _rejected_is_absent(tmp_path, kept=2, refused=3)


def test_a_record_over_the_byte_limit_is_never_stored(tmp_path, monkeypatch):
    one = len(authority.canonical_json(publication(1)))
    monkeypatch.setattr(authority, "MAX_SNAPSHOT_BYTES", one + one // 2)
    store = open_store(tmp_path)
    store.publish(publication(1))
    with pytest.raises(Q1ReceiptRejected, match="byte limit"):
        store.publish(publication(2))
    store.close()
    _rejected_is_absent(tmp_path, kept=1, refused=2)
