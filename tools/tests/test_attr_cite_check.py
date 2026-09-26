"""Behavioral regression checks for mechanism-bound source citations."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
REPORT = ROOT / "report" / "attribution-boundaries.md"
CHECKER = ROOT / "tools" / "attr-cite-check.py"
KERNEL = Path("/home/idealinsane/kcsan-env-0012/linux")
VALID_TRANSMIT_CITATION = (
    "[cite:net/sunrpc/xprt.c:1604:fuzz_attributable:assign]"
)
VALID_LANE_DECISION_CITATION = (
    "[cite:net/sunrpc/fuzz_conn.c:1182:owner_lane_match:assign]"
)


def run_checker(report: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), str(report), str(KERNEL)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_accepts_current_inventory() -> None:
    # Given the checked-in current-kernel inventory
    # When the real CLI validates it
    result = run_checker(REPORT)

    # Then every declared mechanism resolves.
    assert result.returncode == 0, result.stderr
    assert "0 misses" in result.stdout


@pytest.mark.parametrize(
    "replacement",
    [
        "[cite:net/sunrpc/svc.c:1663:START_GRANTED:call]",
        "[cite:net/sunrpc/xprt.c:1804:task:call]",
    ],
)
def test_rejects_comment_or_unrelated_site(
    tmp_path: Path, replacement: str
) -> None:
    # Given a structurally valid citation that replaces the required mechanism
    text = REPORT.read_text(encoding="utf-8")
    mutated = tmp_path / "mutated.md"
    mutated.write_text(
        text.replace(VALID_TRANSMIT_CITATION, replacement, 1), encoding="utf-8"
    )

    # When the real CLI validates the mutation
    result = run_checker(mutated)

    # Then B01 fails because the required mechanism is no longer cited.
    assert result.returncode == 1
    assert "B01" in result.stderr



def test_rejects_name_table_role_for_lane_decision(tmp_path: Path) -> None:
    # Given the expected B11 anchor cited as a name-table entry instead of assignment
    text = REPORT.read_text(encoding="utf-8")
    mutated = tmp_path / "bad-role.md"
    mutated.write_text(
        text.replace(
            VALID_LANE_DECISION_CITATION,
            "[cite:net/sunrpc/fuzz_conn.c:206:owner_lane_match:name]",
            1,
        ),
        encoding="utf-8",
    )

    # When the real CLI validates the role downgrade
    result = run_checker(mutated)

    # Then B11 fails even though the anchor spelling still exists.
    assert result.returncode == 1
    assert "B11" in result.stderr
