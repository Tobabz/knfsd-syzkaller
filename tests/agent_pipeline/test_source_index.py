"""Tests for the immutable host-side Git kernel source index."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys

import pytest

from agent_pipeline.agent_tasks.source_index import (
    GitCommandError,
    GitKernelSourceIndex,
    GitOutputLimitError,
    GitTimeoutError,
    InvalidCommitError,
    InvalidSourcePathError,
    MalformedGitOutputError,
    RepositoryError,
    SourceContentError,
    SourceIndexLimitError,
    _BoundedProcess,
)
from agent_pipeline.agent_tasks.tools import MAX_SOURCE_BYTES, Stage1Toolbox


SAMPLE_V1 = """\
static int leaf(void) { return 1; }
static int helper(int value) { return value; }
static void literal_meta(const char *value) { (void)value; }
static void nested_call(void) { }
static void after_target(void) { }
static const char *version = "FIRST_COMMIT";

int target(int value)
{
    /* comment_call(); */
    const char *text = "string_call() [*].$";
    literal_meta("[*].$");
    helper(value);
    if (value)
        nested_call();
    return leaf();
}

int caller_one(void)
{
    target(1);
    after_target();
    return 0;
}
"""

SAMPLE_V2 = SAMPLE_V1.replace("FIRST_COMMIT", "SECOND_COMMIT")


@dataclass(frozen=True)
class SyntheticRepo:
    path: Path
    first_commit: str
    second_commit: str
    malformed_commit: str
    sample_blob: str


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repo), *args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        shell=False,
        timeout=10,
    )
    return result.stdout.decode("ascii", errors="strict").strip()


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "--", ".")
    git(repo, "commit", "-q", "-m", message)
    commit = git(repo, "rev-parse", "HEAD")
    assert len(commit) == 40
    return commit


@pytest.fixture()
def synthetic_repo(tmp_path: Path) -> SyntheticRepo:
    repo = tmp_path / "kernel"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Source Index Test")
    git(repo, "config", "user.email", "source-index@example.invalid")

    nfsd = repo / "fs/nfsd"
    nfsd.mkdir(parents=True)
    (repo / "drivers").mkdir()
    (nfsd / "sample.c").write_text(SAMPLE_V1, encoding="utf-8")
    (nfsd / "a_first.c").write_text(
        "int BOUND_MATCH_first;\n", encoding="utf-8")
    (nfsd / "z_calls.c").write_text(
        "int BOUND_MATCH_last;\n"
        "void caller_two(void) { target(2); }\n",
        encoding="utf-8",
    )
    (nfsd / "-dash.c").write_text(
        "int dash_path_is_data;\n", encoding="utf-8")
    (repo / "drivers/hidden.c").write_text(
        "int BOUND_MATCH_outside_trust;\n", encoding="utf-8")
    first = commit_all(repo, "first")

    (nfsd / "sample.c").write_text(
        SAMPLE_V2 + "int BOUND_MATCH_middle;\n", encoding="utf-8")
    second = commit_all(repo, "second")
    sample_blob = git(repo, "rev-parse", f"{second}:fs/nfsd/sample.c")

    (nfsd / "binary.c").write_bytes(b"int prefix;\x00\xffbinary")
    (nfsd / "bad\nname.c").write_text(
        "int malformed_path;\n", encoding="utf-8")
    malformed = commit_all(repo, "malformed fixtures")

    # The live worktree intentionally disagrees with every pinned commit.
    (nfsd / "sample.c").write_text(
        "WORKTREE_ONLY\n", encoding="utf-8")
    return SyntheticRepo(repo, first, second, malformed, sample_blob)


def test_reads_only_exact_commit_blobs_and_ignores_worktree(
    synthetic_repo: SyntheticRepo,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)

    first = index.read(
        synthetic_repo.first_commit, "fs/nfsd/sample.c", 1, 100, 32_768)
    second = index.read(
        synthetic_repo.second_commit, "fs/nfsd/sample.c", 1, 100, 32_768)

    assert first is not None and "FIRST_COMMIT" in first
    assert "SECOND_COMMIT" not in first
    assert second is not None and "SECOND_COMMIT" in second
    assert "FIRST_COMMIT" not in second
    assert "WORKTREE_ONLY" not in second
    assert index.read(
        synthetic_repo.second_commit, "fs/nfsd/sample.c", 6, 6, 100
    ) == 'static const char *version = "SECOND_COMMIT";\n'
    assert index.read(
        synthetic_repo.second_commit, "fs/nfsd/missing.c", 1, 1, 100
    ) is None

    # A dash-leading filename remains data because Git path operands follow --.
    dash = index.read(
        synthetic_repo.second_commit, "fs/nfsd/-dash.c", 1, 1, 100)
    assert dash == "int dash_path_is_data;\n"

    # A local replace ref must not substitute another commit's tree.
    git(
        synthetic_repo.path,
        "replace",
        synthetic_repo.second_commit,
        synthetic_repo.first_commit,
    )
    replaced = index.read(
        synthetic_repo.second_commit, "fs/nfsd/sample.c", 1, 100, 32_768)
    assert replaced is not None and "SECOND_COMMIT" in replaced
    assert "FIRST_COMMIT" not in replaced


@pytest.mark.parametrize("source,truncated", [
    ("".join(f"/* line {i:03}: " + "x" * 84 + " */\n"
             for i in range(1, 401)), True),
    ("x" * MAX_SOURCE_BYTES, False),
    ("x" * MAX_SOURCE_BYTES + "\n", True),
    ("한" * (MAX_SOURCE_BYTES // 3 + 1), True),
    ("x" * (MAX_SOURCE_BYTES - 1) + "한", True),
    ("first\nlast", False),
    ("", False),
], ids=["400-lines", "exact-limit", "one-byte-over", "multibyte",
        "split-codepoint", "short", "empty"])
def test_git_read_truncation_survives_toolbox(
        synthetic_repo, source, truncated):
    path = "fs/nfsd/excerpt.c"
    (synthetic_repo.path / path).write_text(source, encoding="utf-8")
    commit = commit_all(synthetic_repo.path, "excerpt")
    index = GitKernelSourceIndex(synthetic_repo.path)
    toolbox = Stage1Toolbox(index, None, kernel_commit=commit,
                            hcap_revision="a" * 64)
    # Still serve the pinned Git object, including when the worktree differs.
    (synthetic_repo.path / path).write_text("worktree only\n", encoding="utf-8")

    excerpt = toolbox.invoke("read_kernel_source", {
        "path": path, "start_line": 1, "end_line": 400})
    expected = source.encode("utf-8")[:MAX_SOURCE_BYTES].decode(
        "utf-8", errors="ignore")
    assert excerpt.text == expected
    assert excerpt.truncated is truncated
    assert excerpt.end_line == len(expected.splitlines())
    assert len(excerpt.text.encode("utf-8")) <= MAX_SOURCE_BYTES
    # Direct callers retain the original str API and exact byte bound.
    direct = index.read(commit, path, 1, 400, MAX_SOURCE_BYTES)
    assert isinstance(direct, str)
    assert direct == excerpt.text
    assert direct.truncated is truncated


def test_git_read_reports_only_truncation_of_requested_range(synthetic_repo):
    path = "fs/nfsd/excerpt.c"
    (synthetic_repo.path / path).write_text(
        "prefix\n한\nsuffix\n" + "x" * MAX_SOURCE_BYTES, encoding="utf-8")
    commit = commit_all(synthetic_repo.path, "range")
    index = GitKernelSourceIndex(synthetic_repo.path)
    toolbox = Stage1Toolbox(index, None, kernel_commit=commit,
                            hcap_revision="a" * 64)
    excerpt = toolbox.invoke("read_kernel_source", {
        "path": path, "start_line": 2, "end_line": 3})
    assert (excerpt.text, excerpt.start_line, excerpt.end_line,
            excerpt.truncated) == ("한\nsuffix\n", 2, 3, False)
    # A byte budget smaller than one code point produces an empty prefix,
    # which must still be marked truncated.
    direct = index.read(commit, path, 2, 2, 1)
    assert direct == ""
    assert direct.truncated is True


def test_literal_search_handles_metacharacters_and_stays_in_roots(
    synthetic_repo: SyntheticRepo,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)

    matches = index.search(
        synthetic_repo.second_commit, "[*].$", ("fs/nfsd/",), 10)

    assert [(match.path, match.line) for match in matches] == [
        ("fs/nfsd/sample.c", 11),
        ("fs/nfsd/sample.c", 12),
    ]
    assert all("[*].$" in match.text for match in matches)
    assert index.search(
        synthetic_repo.second_commit, "WORKTREE_ONLY", ("fs/nfsd/",), 10
    ) == ()
    assert all(
        match.path != "drivers/hidden.c"
        for match in index.search(
            synthetic_repo.second_commit, "BOUND_MATCH", ("fs/nfsd/",), 10)
    )


@pytest.mark.parametrize("path", [
    "/fs/nfsd/sample.c",
    "../fs/nfsd/sample.c",
    "fs/nfsd/../nfs/sample.c",
    "fs\\nfsd\\sample.c",
    "fs/nfsd//sample.c",
    "--help",
])
def test_paths_reject_traversal_absolute_and_option_attempts(
    synthetic_repo: SyntheticRepo,
    path: str,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)
    with pytest.raises(InvalidSourcePathError):
        index.read(synthetic_repo.second_commit, path, 1, 1, 100)


@pytest.mark.parametrize("root", [
    "../fs/nfsd/",
    "/fs/nfsd/",
    "--help",
    "drivers/",
    "fs/nfsd/../nfs/",
])
def test_search_roots_must_be_normalized_and_trusted(
    synthetic_repo: SyntheticRepo,
    root: str,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)
    with pytest.raises(InvalidSourcePathError):
        index.search(synthetic_repo.second_commit, "target", (root,), 10)


def test_commit_must_be_full_existing_and_directly_a_commit(
    synthetic_repo: SyntheticRepo,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)
    invalid = (
        "HEAD",
        synthetic_repo.second_commit[:12],
        synthetic_repo.second_commit.upper(),
        "f" * 40,
        synthetic_repo.sample_blob,
    )

    for revision in invalid:
        with pytest.raises(InvalidCommitError):
            index.read(revision, "fs/nfsd/sample.c", 1, 1, 100)


def test_search_order_and_hard_result_bound_are_deterministic(
    synthetic_repo: SyntheticRepo,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)

    first = index.search(
        synthetic_repo.second_commit, "BOUND_MATCH", ("fs/nfsd/",), 2)
    second = index.search(
        synthetic_repo.second_commit, "BOUND_MATCH", ("fs/nfsd/",), 2)

    assert first == second
    assert [(match.path, match.line) for match in first] == [
        ("fs/nfsd/a_first.c", 1),
        ("fs/nfsd/sample.c", 25),
    ]
    with pytest.raises(SourceIndexLimitError):
        index.search(
            synthetic_repo.second_commit, "BOUND_MATCH", ("fs/nfsd/",), 0)
    with pytest.raises(SourceIndexLimitError):
        index.search(
            synthetic_repo.second_commit, "BOUND_MATCH", ("fs/nfsd/",), 257)


def test_callers_and_callees_are_bounded_lexical_matches(
    synthetic_repo: SyntheticRepo,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)

    callers = index.callers(
        synthetic_repo.second_commit, "target", ("fs/nfsd/",), 20)
    assert callers
    assert all(match.symbol == "target" for match in callers)
    assert any(
        match.path == "fs/nfsd/sample.c" and "target(1)" in match.text
        for match in callers)
    assert any(
        match.path == "fs/nfsd/z_calls.c" and "target(2)" in match.text
        for match in callers)

    callees = index.callees(
        synthetic_repo.second_commit, "fs/nfsd/sample.c", "target", 20)
    symbols = [match.symbol for match in callees]
    assert symbols == ["literal_meta", "helper", "nested_call", "leaf"]
    assert "if" not in symbols
    assert "comment_call" not in symbols
    assert "string_call" not in symbols
    assert "after_target" not in symbols
    assert index.callees(
        synthetic_repo.second_commit, "fs/nfsd/sample.c", "target", 2
    ) == tuple(callees[:2])


def test_binary_blobs_and_malformed_git_paths_fail_closed(
    synthetic_repo: SyntheticRepo,
) -> None:
    index = GitKernelSourceIndex(synthetic_repo.path)

    with pytest.raises(SourceContentError, match="binary source blob"):
        index.read(
            synthetic_repo.malformed_commit,
            "fs/nfsd/binary.c",
            1,
            10,
            1000,
        )
    with pytest.raises(MalformedGitOutputError, match="malformed source path"):
        index.search(
            synthetic_repo.malformed_commit,
            "malformed_path",
            ("fs/nfsd/",),
            10,
        )


def test_process_timeout_and_output_limit_do_not_use_sleeps(tmp_path: Path) -> None:
    runner = _BoundedProcess()
    environment = {"PATH": str(Path(sys.executable).parent)}

    with pytest.raises(GitTimeoutError):
        runner.run(
            (sys.executable, "-c", "import signal; signal.pause()"),
            cwd=tmp_path,
            env=environment,
            timeout=0.05,
            stdout_limit=16,
            stderr_limit=16,
        )
    with pytest.raises(GitOutputLimitError):
        runner.run(
            (sys.executable, "-c",
             "import sys; sys.stdout.buffer.write(b'x' * 1024)"),
            cwd=tmp_path,
            env=environment,
            timeout=1.0,
            stdout_limit=16,
            stderr_limit=16,
        )
    with pytest.raises(GitCommandError):
        runner.run(
            (str(tmp_path / "missing-git"),),
            cwd=tmp_path,
            env=environment,
            timeout=1.0,
            stdout_limit=16,
            stderr_limit=16,
        )


def test_non_repository_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RepositoryError):
        GitKernelSourceIndex(tmp_path)
