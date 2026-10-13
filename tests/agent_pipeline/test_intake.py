"""02 §3 intake validation, over a fake tree and over a real git repo."""

import subprocess

import pytest

from agent_pipeline.contracts import (CandidateSubmission, LocationKind,
                                      LocationRequest)
from agent_pipeline.intake import (GitSourceTree, IntakeRejected,
                                   find_function, normalized, validate)

from .fakes import COMMIT, SOURCE, FakeTree

PATH = "fs/nfsd/nfs4xdr.c"
TREE = FakeTree({COMMIT: {PATH: SOURCE}})


def sub(kind=LocationKind.FUNCTION, path=PATH, symbol=None, start=None,
        end=None, commit=COMMIT):
    return CandidateSubmission(kernel_commit=commit, location=LocationRequest(
        kind=kind, path=path, symbol=symbol, start_line=start, end_line=end))


def reason(result):
    assert isinstance(result, IntakeRejected), result
    return result.reason


def test_function_resolves_to_its_lines():
    c = validate(sub(symbol="nfsd4_target"), TREE, "VC-1")
    assert (c.location.start_line, c.location.end_line) == (6, 12)
    c = validate(sub(symbol="helper"), TREE, "VC-2")
    assert (c.location.start_line, c.location.end_line) == (14, 17)


def test_function_lines_given_must_match():
    assert validate(sub(symbol="nfsd4_target", start=6, end=12), TREE,
                    "VC-1").location.end_line == 12
    assert reason(validate(sub(symbol="nfsd4_target", start=7, end=12),
                           TREE, "VC-1")) == "range_mismatch"


@pytest.mark.parametrize("s,expected", [
    (sub(symbol="twice"), "symbol_ambiguous"),
    (sub(symbol="missing"), "symbol_not_found"),
    (sub(symbol=None), "symbol_missing"),
    (sub(symbol="a b"), "symbol_missing"),
    (sub(commit="A" * 40, symbol="helper"), "commit_not_exact"),
    (sub(commit="abc", symbol="helper"), "commit_not_exact"),
    (sub(commit="c" * 40, symbol="helper"), "commit_not_found"),
    (sub(path="fs/nfsd/../nfsd/nfs4xdr.c", symbol="helper"),
     "path_not_normalized"),
    (sub(path="/fs/nfsd/nfs4xdr.c", symbol="helper"), "path_not_normalized"),
    (sub(path="fs/nfsd/nope.c", symbol="helper"), "path_not_found"),
    (sub(kind=LocationKind.SOURCE_RANGE, start=3, end=2),
     "range_invalid"),
    (sub(kind=LocationKind.SOURCE_RANGE, start=1, end=999),
     "range_outside_file"),
    (sub(kind=LocationKind.SOURCE_RANGE, symbol="helper", start=1, end=2),
     "symbol_not_allowed"),
])
def test_refusals(s, expected):
    assert reason(validate(s, TREE, "VC-1")) == expected


def test_source_range():
    c = validate(sub(kind=LocationKind.SOURCE_RANGE, start=9, end=10), TREE,
                 "VC-3")
    assert c.location.symbol is None
    assert (c.location.start_line, c.location.end_line) == (9, 10)


def test_declarations_and_calls_are_not_definitions():
    assert find_function("int foo(int);\nvoid bar(void)\n{\n\tfoo(1);\n}\n",
                         "foo") == []
    assert find_function("#define foo(x) (x)\n", "foo") == []


def test_normalized_paths():
    assert normalized("fs/nfsd/nfs4state.c")
    for bad in ("", "/fs/x.c", "fs//x.c", "fs/./x.c", "fs/../x.c",
                "fs\\x.c", "fs/x.c/"):
        assert not normalized(bad), bad


def test_git_source_tree(tmp_path):
    repo = tmp_path / "linux"
    (repo / "fs" / "nfsd").mkdir(parents=True)
    (repo / "fs" / "nfsd" / "nfs4xdr.c").write_text(SOURCE)

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid",
        "commit", "-q", "-m", "init")
    head = git("rev-parse", "HEAD")
    tree = GitSourceTree(repo)
    assert tree.has_commit(head) and not tree.has_commit("0" * 40)
    assert tree.read_text(head, "fs/nfsd") is None          # a tree
    c = validate(sub(symbol="helper", commit=head), tree, "VC-4")
    assert c.kernel_commit == head and c.location.start_line == 14
