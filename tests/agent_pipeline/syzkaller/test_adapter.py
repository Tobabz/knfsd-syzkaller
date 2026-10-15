"""Real bridge tests: set KNFSD_SYZ_BUNDLE to build.py's bundle directory."""

import hashlib
import os
from pathlib import Path
import shutil
import sys
import time

import pytest

from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.data import canonical_json
from agent_pipeline.materializer import SyzParseFailure
from agent_pipeline.syzkaller import BridgeLimits, PinnedSyzParser
from agent_pipeline.syzkaller.adapter import _run


@pytest.fixture(scope="module")
def bundle():
    value = os.environ.get("KNFSD_SYZ_BUNDLE")
    if not value:
        pytest.skip("build the pinned Go bridge and set KNFSD_SYZ_BUNDLE")
    return Path(value)


@pytest.fixture(scope="module")
def identity(bundle):
    return SyzkallerTargetIdentity.model_validate_json((bundle / "identity.json").read_bytes())


@pytest.fixture(scope="module")
def parser(bundle, identity):
    with PinnedSyzParser(bundle, identity=identity) as parser:
        yield parser


LANE = b"r0 = syz_open_nfs_lane_profile$client0_knfsd_v41(0x2, 0x0)\n"


def test_export_is_real_patched_target_table(parser, identity):
    table = parser.export_call_table()
    assert len(table.calls) > 1000
    assert "syz_open_nfs_lane_profile$client0_knfsd_v41" in table.calls
    assert "clone3" in table.calls  # resolution does not imply availability
    assert hashlib.sha256(canonical_json(table)).hexdigest() == identity.call_table_sha256


def test_actual_parsed_arguments_and_nfs_provenance(parser, identity):
    source = LANE + b'write(r0, &(0x7f0000000000)="616263", 0x3)\n'
    result = parser.parse(source, identity=identity)
    assert result.program_sha256 == hashlib.sha256(source).hexdigest()
    assert result.usage.program_bytes == len(source)
    assert result.usage.call_count == 2
    assert result.usage.resource_count == 4
    assert result.nfs_acquisitions[0].profile == "knfsd-v41"
    facts = result.calls[1].resource_facts
    assert facts.origins[0].origin == "nfs-profile:knfsd-v41:client0"
    assert facts.byte_lengths[0].argument_index == 1
    assert facts.byte_lengths[0].length_bytes == 3
    assert facts.integers[0].value == 3


@pytest.mark.parametrize("program", [
    b"", b"unknown_call()\n", b"getpid(1)\n", b"clone3(0x0, 0x0)\n",
    b"fsync(r99)\n", b"getpid() (async)\n", b"# fake nfs acquisition\n",
    LANE + b"syz_open_nfs_lane_profile$client0_knfsd_v41(0x3, 0x0)\n",
    LANE + b"syz_open_nfs_lane$client0(0x0)\n",
    b"#" * (256 * 1024 + 1),
])
def test_real_parser_refuses(program, parser, identity):
    with pytest.raises(SyzParseFailure):
        parser.parse(program, identity=identity)


@pytest.mark.parametrize("suffix", [
    b"fsync(r0+1)\n", b"fsync(r0/2)\n", b"close(r0)\nfsync(r0)\n",
    b"dup2(0x4, 0x5)\nfsync(r0)\n",
    b"r1 = openat$nfs_file(r0, &(0x7f0000000000)='./file\\x00', 0x0, 0x0)\nfsync(r1)\n",
])
def test_unknown_or_transformed_origins_are_absent(parser, identity, suffix):
    parsed = parser.parse(LANE + suffix, identity=identity)
    assert not parsed.calls[-1].resource_facts.origins


@pytest.mark.parametrize("field,value", [
    ("syzkaller_commit", "a" * 40), ("patch_series_sha256", "a" * 64),
    ("build_manifest_sha256", "a" * 64), ("call_table_sha256", "a" * 64),
    ("target", "linux/arm64"),
])
def test_every_identity_axis_is_bound(bundle, parser, identity, field, value):
    wrong = identity.model_copy(update={field: value})
    with pytest.raises(SyzParseFailure, match="identity mismatch"):
        parser.parse(b"getpid()\n", identity=wrong)
    with pytest.raises(SyzParseFailure, match="identity mismatch"):
        PinnedSyzParser(bundle, identity=wrong)


def test_changed_bundle_cannot_change_live_snapshot(bundle, identity, tmp_path):
    copy = tmp_path / "bundle"
    shutil.copytree(bundle, copy)
    with PinnedSyzParser(copy, identity=identity) as pinned:
        (copy / "bridge").write_bytes(b"tampered")
        assert pinned.parse(b"getpid()\n", identity=identity).calls[0].call == "getpid"
        with pytest.raises(SyzParseFailure, match="digest mismatch"):
            PinnedSyzParser(copy, identity=identity)


def test_symlink_and_manifest_drift_refused(bundle, identity, tmp_path):
    copy = tmp_path / "bundle"
    shutil.copytree(bundle, copy)
    (copy / "bridge").unlink()
    (copy / "bridge").symlink_to(bundle / "bridge")
    with pytest.raises(SyzParseFailure):
        PinnedSyzParser(copy, identity=identity)
    (copy / "build-manifest.json").write_bytes(b"{}")
    with pytest.raises(SyzParseFailure):
        PinnedSyzParser(copy, identity=identity)


def test_compiled_identity_checked_independently(bundle, identity, tmp_path):
    # Even a newly hashed manifest/table cannot re-label this executable's
    # embedded source/patch/target identity.
    import json
    copy = tmp_path / "bundle"
    shutil.copytree(bundle, copy)
    manifest = json.loads((copy / "build-manifest.json").read_bytes())
    manifest["syzkaller_commit"] = "a" * 40
    table = json.loads((copy / "call-table.json").read_bytes())
    table["syzkaller_commit"] = "a" * 40
    mb, tb = canonical_json(manifest), canonical_json(table)
    (copy / "build-manifest.json").write_bytes(mb)
    (copy / "call-table.json").write_bytes(tb)
    wrong = identity.model_copy(update={
        "syzkaller_commit": "a" * 40,
        "build_manifest_sha256": hashlib.sha256(mb).hexdigest(),
        "call_table_sha256": hashlib.sha256(tb).hexdigest(),
    })
    with pytest.raises(SyzParseFailure, match="response or identity"):
        PinnedSyzParser(copy, identity=wrong)


def test_actual_export_output_limit(bundle, identity):
    with pytest.raises(SyzParseFailure, match="stdout byte limit"):
        PinnedSyzParser(bundle, identity=identity, limits=BridgeLimits(max_stdout_bytes=16))


def test_oversized_data_allocation_refused_by_real_prog(parser, identity):
    with pytest.raises(SyzParseFailure):
        parser.parse(b'write(0xffffffffffffffff, &(0x7f0000000000)=""/0x1000000000, 0x0)\n', identity=identity)


def test_repeated_large_allocations_are_process_bounded(parser, identity):
    # Individually valid 1 MiB DataArgs, below the textual and call-count
    # limits, collectively exceed the helper's 2 GiB address-space budget.
    line = b'write(0xffffffffffffffff, &(0x7f0000000000)=""/0x100000, 0x100000)\n'
    program = line * 3000
    assert len(program) < 256 * 1024
    start = time.monotonic()
    with pytest.raises(SyzParseFailure):
        parser.parse(program, identity=identity)
    assert time.monotonic() - start < 15


def test_sealed_executable_cannot_be_written(parser):
    import fcntl
    assert fcntl.fcntl(parser._fd, getattr(fcntl, "F_GET_SEALS", 1034)) & 0xf == 0xf
    with pytest.raises(PermissionError):
        os.pwrite(parser._fd, b"changed", 0)


def run_helper(tmp_path, code, limits=BridgeLimits()):
    path = tmp_path / "helper"
    path.write_text(f"#!{sys.executable}\n" + code)
    path.chmod(0o700)
    with path.open("rb") as stream:
        return _run(stream.fileno(), "parse", b"", limits)


@pytest.mark.parametrize("stream", [1, 2])
def test_live_stream_limits_kill_helper(tmp_path, stream):
    start = time.monotonic()
    with pytest.raises(SyzParseFailure, match="byte limit exceeded"):
        run_helper(tmp_path, f"import os\nwhile True: os.write({stream}, b'x' * 4096)\n",
                   BridgeLimits(max_stdout_bytes=1024, max_stderr_bytes=1024))
    assert time.monotonic() - start < 5


def test_helper_killed_by_signal_is_a_host_failure(tmp_path):
    with pytest.raises(ChildProcessError, match="signal 9"):
        run_helper(tmp_path, "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")


def test_silent_helper_timeout_and_minimal_environment(tmp_path):
    # A timeout is a host failure (OSError), never a plan parse failure.
    with pytest.raises(TimeoutError, match="timed out"):
        run_helper(tmp_path, "import time\ntime.sleep(60)\n", BridgeLimits(timeout_seconds=.1))
    output = run_helper(tmp_path, "import os\nprint(','.join(sorted(os.environ)))\n")
    assert output.strip() in (b"GOMAXPROCS,GOTRACEBACK,LANG", b"GOMAXPROCS,GOTRACEBACK,LANG,LC_CTYPE")


@pytest.mark.parametrize("kwargs", [
    {"max_program_bytes": 256 * 1024 + 1}, {"max_stdout_bytes": 0},
    {"max_stderr_bytes": True}, {"timeout_seconds": float("nan")},
    {"timeout_seconds": float("inf")},
])
def test_limits_cannot_be_disabled(kwargs):
    with pytest.raises(ValueError):
        BridgeLimits(**kwargs)
