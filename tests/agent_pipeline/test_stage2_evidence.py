"""The sealed ``stage2-host`` facts and journal artifacts of a Stage 2
bundle (stage2.evidence)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_pipeline.stage2.evidence import (JOURNAL_TYPE, Stage2HostFacts,
                                            is_journal_segment, unpack_journal)

from .stage2_host import program_digest, rules_bytes, write_journal

CAMPAIGN = {"journal_name": "c", "executions": 1, "console_log_identity": None,
            "console_log_completeness": "missing",
            "vm_termination": "runner_stopped",
            "collection_window": {"start_marker": "s", "end_marker": "e"}}


def facts(**data) -> Stage2HostFacts:
    # As the engine and the judge read them: from the sealed JSON.
    return Stage2HostFacts.model_validate_json(json.dumps(data))


def test_one_report_per_step():
    facts(step="gate", gate={"journal_name": "g"})
    facts(step="campaign", campaign=CAMPAIGN)
    with pytest.raises(ValidationError):
        facts(step="gate")
    with pytest.raises(ValidationError):
        facts(step="gate", gate={"journal_name": "g"}, campaign=CAMPAIGN)
    with pytest.raises(ValidationError):
        facts(step="gate", gate={"journal_name": "g"}, plan_error="x")


def test_replay_is_planned_with_its_gate_or_records_why_not():
    planned = {"step": "replay", "production_end": "guest_crash",
               "compatibility": {"ok": True, "line": "ok"},
               "replay": {"journal_name": "r", "replay_end": "guest_crash"}}
    facts(**planned)
    facts(step="replay", plan_error="no window entry")
    with pytest.raises(ValidationError):
        facts(**{**planned, "compatibility": None})
    with pytest.raises(ValidationError):
        facts(**{**planned, "plan_error": "x"})


def test_journal_segment_names():
    assert is_journal_segment("lane0.0000.njnl", "lane0")
    assert not is_journal_segment("lane0.0000.njnl", "lane1")
    assert not is_journal_segment("lane0.000.njnl", "lane0")
    assert not is_journal_segment("../lane0.0000.njnl", "lane0")


def _bundle(items):
    return SimpleNamespace(artifacts=tuple(SimpleNamespace(
        descriptor=SimpleNamespace(identity=identity, type=type_), data=data)
        for identity, type_, data in items))


def test_unpack_takes_only_the_named_journal(tmp_path):
    segs = write_journal(tmp_path / "src", "lane0", vm="vm-1", lane=0,
                         candidate_id="VC-1", rules=rules_bytes("VC-1"),
                         generations=[(1, program_digest(1), True)])
    items = [("journal/" + p.name, JOURNAL_TYPE, p.read_bytes()) for p in segs]
    journal = unpack_journal(_bundle(items), "lane0", tmp_path / "a")
    assert [g for s in journal.sessions.values() for g in s.generations] == [1]
    with pytest.raises(ValueError):
        unpack_journal(_bundle(items), "lane1", tmp_path / "b")
    with pytest.raises(ValueError):
        unpack_journal(_bundle(items + [("journal/x", JOURNAL_TYPE, b"")]),
                       "lane0", tmp_path / "c")
    with pytest.raises(ValueError):
        unpack_journal(_bundle([]), "lane0", tmp_path / "d")
