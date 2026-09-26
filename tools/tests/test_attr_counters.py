"""Behavior checks for strict real-format debugfs counter snapshots."""

from pathlib import Path

import pytest

from tools.attr_counters import CounterParseError, delta, drained, snapshot_from_texts

DATA = Path(__file__).parent / "data"


def _fixture(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def test_parses_real_phase_captures() -> None:
    captures = snapshot_from_texts({
        "phase3_stats": _fixture("phase3-stats.txt"),
        "phase8_stats": _fixture("phase8-stats.txt"),
        "phase5_state": _fixture("phase5-state.txt"),
        "phase6_state": _fixture("phase6-state.txt"),
    })
    assert len(captures["phase3_stats"]) == 43
    assert captures["phase3_stats"]["wire_attempt_created"] == 132
    assert len(captures["phase8_stats"]) == 36
    assert captures["phase8_stats"]["async_child_created"] == 3
    assert captures["phase5_state"] == {
        "live_tickets": 0,
        "live_svc_attachments": 0,
        "remote_refs": 0,
        "global_lane_unhealthy": 0,
        "lane_id": 0,
        "lane_epoch": 0,
        "valid": 0,
        "unhealthy": 0,
    }
    assert captures["phase6_state"] == {
        "live_scratch": 0,
        "live_sections": 0,
        "remote_refs": 0,
        "publish_readers": 0,
        "scratch_in_use": 0,
        "scratch_peak": 1,
    }


def test_delta_tracks_per_file_increases() -> None:
    before = {"phase": {"created": 2, "completed": 1}}
    after = {"phase": {"created": 5, "completed": 3}}
    assert delta(before, after) == {"phase": {"created": 3, "completed": 2}}


def test_delta_rejects_counter_regression() -> None:
    before = {"phase": {"created": 2}}
    after = {"phase": {"created": 1}}
    with pytest.raises(ValueError, match="phase:created"):
        delta(before, after)


def test_drained_accepts_zero_named_counters() -> None:
    post = {"phase5_state": {"live_tickets": 0, "remote_refs": 0}}
    assert drained(post, ["live_tickets", "remote_refs"])


def test_drained_rejects_a_nonzero_counter() -> None:
    post = {"phase5_state": {"live_tickets": 0, "remote_refs": 1}}
    assert not drained(post, ["live_tickets", "remote_refs"])


@pytest.mark.parametrize("post", [
    {"phase5_state": {"remote_refs": 1}, "phase6_state": {"remote_refs": 0}},
    {"phase6_state": {"remote_refs": 0}, "phase5_state": {"remote_refs": 1}},
])
def test_drained_rejects_ambiguous_cross_file_names(post: dict[str, dict[str, int]]) -> None:
    with pytest.raises(ValueError, match="ambiguous.*remote_refs"):
        drained(post, ["remote_refs"])


def test_malformed_line_reports_capture_and_line() -> None:
    with pytest.raises(CounterParseError, match=r"phase8_stats:2: malformed"):
        snapshot_from_texts({"phase8_stats": "good 1\ngarbage line\n"})


def test_rejects_unknown_line_prefix() -> None:
    with pytest.raises(CounterParseError, match=r"phase8_stats:1: malformed"):
        snapshot_from_texts({"phase8_stats": "garbage x 1"})


def test_rejects_inter_token_garbage() -> None:
    with pytest.raises(CounterParseError, match=r"phase8_stats:1: malformed"):
        snapshot_from_texts({"phase8_stats": "x 1 garbage y 2"})


def test_rejects_corrupted_pool_header() -> None:
    corrupted = _fixture("phase6-state.txt").replace("pool ", "garbage ", 1)
    with pytest.raises(CounterParseError, match=r"phase6_state:2: malformed"):
        snapshot_from_texts({"phase6_state": corrupted})


def test_rejects_duplicate_name_across_lines() -> None:
    with pytest.raises(CounterParseError, match=r"phase8_stats:2: malformed"):
        snapshot_from_texts({"phase8_stats": "x 1\nx 2"})


def test_rejects_duplicate_name_on_state_line() -> None:
    with pytest.raises(CounterParseError, match=r"phase5_state:1: malformed"):
        snapshot_from_texts({"phase5_state": "x 1 x 2"})
