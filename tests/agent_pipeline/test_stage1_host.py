"""Host side of a real Stage 1 run, without KVM.

Real: record generation from a bootstrap-shaped env and a parser bundle,
pins, the collector's parsing and record building, target-PC mapping on a
gcc ``-fsanitize-coverage=trace-pc`` binary, and the wired service from
``stage1.json`` to ``s1_reached``.  Scripted: the guest (``host_fakes``),
the model responses and the syzkaller parser.
"""

from __future__ import annotations

import json
import runpy
import shutil
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_pipeline.admission import (BuildFile, SyzkallerBuildManifest,
                                      SyzkallerCallTable,
                                      SyzkallerTargetIdentity)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (CandidateSubmission, LocationKind,
                                      LocationRequest, Q1Status)
from agent_pipeline.controller.records import JobState
from agent_pipeline.data import canonical_json, load_record
from agent_pipeline.q1 import RemoteKcovObservation, TargetPcMapping
from agent_pipeline.sealed_q1 import PublishedCoverage
from agent_pipeline.stage1.cli import STOP_STATES, open_stage1
from agent_pipeline.stage1.config import EngineConfig, Stage1Config
from agent_pipeline.stage1.host import kcov
from agent_pipeline.stage1.host.__main__ import main as host_main
from agent_pipeline.stage1.host.collector import (CollectorConfig,
                                                  CollectorError, collect,
                                                  guest_cmdline)
from agent_pipeline.stage1.host.generate import generate, series_fingerprint
from agent_pipeline.stage1.host.target_pcs import (CallbackSites,
                                                   build_mapping, check_pcs,
                                                   parse_addr2line,
                                                   parse_branches,
                                                   parse_callsites,
                                                   path_matches)

from .fakes import policy
from .host_fakes import STATS_AFTER, STATS_BEFORE, FakeGuest
from .test_materializer import (SyntheticParser, _capabilities, empty_facts,
                                lane_facts, parsed, runtime)
from .test_stage1_service import ScriptedRuntime

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="Linux process supervision")
needs_gcc = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("gcc", "objdump", "addr2line")),
    reason="needs gcc and binutils")

REPO = Path(__file__).resolve().parents[2]
SOURCE = """int g;

void target(void)
{
\tif (g > 3)
\t\tg++;
\tg += 2;
}

int other(int x)
{
\tif (x)
\t\treturn 1;
\treturn 0;
}

int main(void)
{
\ttarget();
\treturn other(g);
}
"""
SCENARIO = b"synthetic scenario program\n"
NEUTRAL = b"synthetic repository neutral program\n"
CALLS = ("close", "openat$lane", "read$extra", "write$known")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
         *args], check=True, capture_output=True, text=True).stdout.strip()


def _repo(path: Path, files: dict[str, str]) -> str:
    for name, text in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text)
    _git(path, "init", "-q")
    _git(path, "add", ".")
    _git(path, "commit", "-qm", "synthetic")
    return _git(path, "rev-parse", "HEAD")


def _bundle(root: Path) -> SyzkallerTargetIdentity:
    """A tools/syzkaller/build.py-shaped output: checkout/ and bundle/."""
    checkout = root / "checkout"
    commit = _repo(checkout, {"README": "patched syzkaller\n"})
    bundle = root / "bundle"
    bundle.mkdir()
    for name in ("bridge", "go.mod", "go.sum", "target.gob.flate"):
        (bundle / name).write_bytes(f"synthetic {name}\n".encode())
    (bundle / "provenance.json").write_bytes(canonical_json({
        "source_commit": commit,
        "source_tree": _git(checkout, "rev-parse", "HEAD^{tree}")}))
    # tools/syzkaller/build.py's patch-series.bin of the checked-in series.
    patches = b"".join(
        p.name.encode() + b"\0" + p.read_bytes() + b"\0" for p in sorted(
            (REPO / "bundle" / "patches" / "syzkaller").glob("*.patch")))
    (bundle / "patch-series.bin").write_bytes(patches)
    import hashlib
    sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
    manifest = SyzkallerBuildManifest(
        syzkaller_commit=commit, patch_series_sha256=sha(patches),
        target="linux/amd64", files=tuple(
            BuildFile(path=p.name, artifact_ref=sha(p.read_bytes()))
            for p in sorted(bundle.iterdir()) if p.name != "patch-series.bin"))
    table = SyzkallerCallTable(syzkaller_commit=commit, target="linux/amd64",
                               calls=CALLS)
    (bundle / "build-manifest.json").write_bytes(canonical_json(manifest))
    (bundle / "call-table.json").write_bytes(canonical_json(table))
    identity = SyzkallerTargetIdentity(
        syzkaller_commit=commit, patch_series_sha256=sha(patches),
        build_manifest_sha256=sha(canonical_json(manifest)),
        call_table_sha256=sha(canonical_json(table)), target="linux/amd64")
    (bundle / "identity.json").write_bytes(canonical_json(identity))
    return identity


def _compile_vmlinux(linux: Path, out: Path) -> None:
    stub = out.parent / "cov-stub.c"
    stub.write_text("void __sanitizer_cov_trace_pc(void) {}\n")
    obj = out.parent / "synthetic.o"
    subprocess.run(["gcc", "-g", "-O1", "-fno-inline",
                    "-fsanitize-coverage=trace-pc", "-c",
                    "fs/nfsd/synthetic.c", "-o", str(obj)],
                   cwd=linux, check=True)
    subprocess.run(["gcc", "-O1", str(obj), str(stub), "-o", str(out)],
                   check=True)


def _write_syz_record(env: Path, **override) -> None:
    record = {"series_sha256": series_fingerprint("syzkaller"),
              "head": _git(env / "syzkaller", "rev-parse", "HEAD"),
              **override}
    (env / "syzkaller" / "bin" / "build.json").write_text(json.dumps(record))


@pytest.fixture
def host(tmp_path):
    """A bootstrap env, a parser bundle and a host spec over them."""
    env = tmp_path / "env"
    linux = env / "linux"
    kernel_commit = _repo(linux, {"fs/nfsd/synthetic.c": SOURCE})
    images = env / "images"
    variant = images / "kasan"
    variant.mkdir(parents=True)
    _compile_vmlinux(linux, variant / "vmlinux")
    (variant / "bzImage").write_bytes(b"synthetic bzImage")
    (variant / ".config").write_text("CONFIG_KCOV=y\nCONFIG_KASAN=y\n")
    (variant / "build.json").write_text(json.dumps({
        "head": kernel_commit, "series_sha256": series_fingerprint("kernel")}))
    (images / "bookworm-kcov-fresh.qcow2").write_bytes(b"synthetic image")
    identity = _bundle(tmp_path / "syz-build")
    subprocess.run(["git", "clone", "-q", str(tmp_path / "syz-build" /
                                              "checkout"),
                    str(env / "syzkaller")], check=True)
    bin_dir = env / "syzkaller" / "bin" / "linux_amd64"
    bin_dir.mkdir(parents=True)
    (bin_dir / "syz-executor").write_bytes(b"synthetic executor")
    (bin_dir / "syz-execprog").write_bytes(b"synthetic execprog")
    _write_syz_record(env)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "id_rsa").write_text("synthetic key\n")
    (tmp_path / "neutral.syz").write_bytes(NEUTRAL)
    selection = runtime()
    spec = {
        "schema_version": "stage1-host-spec.v1",
        "state_dir": "state", "artifact_root": "cas", "env_dir": "env",
        "variant": "kasan", "ssh_key": "artifacts/id_rsa",
        "syzkaller_bundle": "syz-build/bundle",
        "capabilities": [c.model_dump(mode="json") for c in _capabilities()],
        "missing_capability_ids": [],
        "runtime_selection_capability": "CAP-lane",
        "admission_source": {
            "schema_version": "call-admission-source.v1",
            "target": "linux/amd64",
            "limits": {"max_program_bytes": 4096,
                       "max_calls_per_program": 16,
                       "max_resources_per_program": 8},
            "entries": [
                {"call": "close", "capability_ids": ["CAP-lane"]},
                {"call": "openat$lane", "capability_ids": ["CAP-lane"],
                 "resource_constraints": [{
                     "kind": "resource_origin", "argument_index": 0,
                     "resource_type": "fd",
                     "allowed_origins": ["lane-root"]}]},
                {"call": "read$extra", "capability_ids": ["CAP-extra"]}]},
        "runtime_selections": [selection.model_dump(mode="json")],
        "neutral_controls": [{
            "runtime_selection": selection.model_dump(mode="json"),
            "program": "neutral.syz",
            "required_capability_ids": ["CAP-lane"]}],
        "judge_profile": {
            "name": "test", "revision": "1", "allowed_trace_modes": ["off"],
            "contexts": [{"context": "synthetic_worker",
                          "window": kcov.WINDOW,
                          "counters": [{"counter": "lane_owner_failed",
                                        "max_delta": 0}]}]},
        "support_boundary": {"name": "test", "revision": "1",
                             "supported_contexts": ["synthetic_worker"]},
        "policies": [policy().model_dump(mode="json")],
    }
    path = tmp_path / "host-spec.json"
    path.write_text(json.dumps(spec, indent=1))
    return SimpleNamespace(root=tmp_path, spec=path, env=env,
                           kernel_commit=kernel_commit, identity=identity,
                           selection=selection)


# ------------------------------------------------------------ parsing

def test_stats_parse_into_generation_counters_and_deltas():
    before, after = kcov.parse_stats(STATS_BEFORE), kcov.parse_stats(STATS_AFTER)
    assert before["phase4_stats"]["generation_begin"] == 5
    counters = kcov.generation_counters(before, after)
    assert counters.model_dump() == {
        "generation_begin": 1, "remote_start_ok": 2, "aggregate_published": 1,
        "generation_aborted": 0, "scratch_overflow": 0, "merge_truncation": 0,
        "outstanding_tokens": 0, "remote_refs": 0}
    deltas = {d.counter: d.value for d in kcov.counter_deltas(before, after)}
    assert deltas["lane_owner_failed"] == 0
    # remote_refs is in two files, so both are qualified.
    assert "remote_refs" not in deltas
    assert deltas["phase5_stats.remote_refs"] == 0


def test_missing_counter_is_unknown_not_zero():
    after = kcov.parse_stats(STATS_AFTER.replace("scratch_overflow 0\n", ""))
    counters = kcov.generation_counters(kcov.parse_stats(STATS_BEFORE), after)
    assert counters.scratch_overflow is None
    assert counters.generation_begin == 1


def test_window_starts_only_when_every_generation_settled():
    settled = ("owner 1 state COMMITTED outstanding_tokens 0 object_refs 1 "
               "active_roots 0 retry_deadline_active 0 generation 5\n"
               "owner 2 state ABORTED outstanding_tokens 0 object_refs 1 "
               "active_roots 0 retry_deadline_active 0 generation 6\n")
    assert kcov.unsettled_generations("") == []
    assert kcov.unsettled_generations(settled) == []
    draining = settled.replace("ABORTED outstanding_tokens 0",
                               "ABORTED outstanding_tokens 2")
    assert len(kcov.unsettled_generations(draining)) == 1
    assert len(kcov.unsettled_generations(
        settled.replace("COMMITTED", "OPEN"))) == 1


def test_cover_pcs_and_lane_state():
    assert kcov.parse_cover_pcs("0xffffffff81000010\n\n0x10\n") == {
        0xffffffff81000010, 0x10}
    with pytest.raises(ValueError):
        kcov.parse_cover_pcs("ffffffff81000010\n")
    assert kcov.lane_state_ok("lane_id 0 lane_epoch 1 valid 1 unhealthy 0 "
                              "owner 1")
    assert not kcov.lane_state_ok("lane_id 0 lane_epoch 1 valid 0 "
                                  "unhealthy 0 owner 1")
    assert kcov.fatal_dmesg("ok\nKASAN: use-after-free\nBUG: KCSAN: race") \
        == ["KASAN: use-after-free"]


def test_objdump_and_addr2line_parsing():
    lines = ["ffffffff81000010:\tcall   ffffffff81a00000 "
             "<__sanitizer_cov_trace_pc>",
             "ffffffff81000015:\tcall   ffffffff81b00000 <kfree>",
             "ffffffff81000020:\tcall   ffffffff81a00000 "
             "<__sanitizer_cov_trace_pc+0x4>",
             "ffffffff81000030:\tjmp    ffffffff81a00000 "
             "<__sanitizer_cov_trace_pc>"]
    assert list(parse_callsites(lines)) == [0xffffffff81000010]
    assert list(parse_branches(lines)) == [("call", 0xffffffff81000010),
                                           ("jmp", 0xffffffff81000030)]
    frames = parse_addr2line(
        "0xffffffff81000010\nhelper\n/b/include/x.h:7\n"
        "nfsd4_open\n/b/fs/nfsd/nfs4proc.c:120 (discriminator 2)\n"
        "0xffffffff81000020\n??\n??:?\n")
    assert [f.line for f in frames[0xffffffff81000010]] == [7, 120]
    assert frames[0xffffffff81000020][0].line is None
    assert path_matches("/b/fs/nfsd/nfs4proc.c", "fs/nfsd/nfs4proc.c")
    assert not path_matches("/b/fs/nfsd/xnfs4proc.c", "fs/nfsd/nfs4proc.c")


def test_mapping_refuses_a_vmlinux_with_callback_tail_jumps(tmp_path):
    # A tail jump makes KCOV record the caller's return address, so the
    # call-site mapping would silently miss the paths behind it.
    sha = "a" * 64
    (tmp_path / f"kcov-sites-{sha}.json").write_text(json.dumps(
        {"callsites": [0x1000], "tail_jumps": 3}))
    target = SimpleNamespace(path="fs/nfsd/x.c", start_line=1, end_line=2)
    with pytest.raises(RuntimeError, match="3 tail jumps"):
        build_mapping(tmp_path / "vmlinux", target, None, sha,
                      cache=tmp_path)
    assert check_pcs([0x1000], CallbackSites([0x1000], 3)) == {
        "published": 1, "callsites": 1, "callsite_plus_5": 0,
        "callback_tail_jumps": 3}


# ------------------------------------------------------------ generation

@needs_gcc
def test_generate_pins_files_and_writes_consistent_configs(host):
    result = generate(host.spec)
    config = Stage1Config.load(result.stage1_config)
    store = ArtifactStore(config.artifact_root)
    assert config.syzkaller_identity == host.identity
    from agent_pipeline.materializer import ExecutionHarnessApproval
    approval = load_record(store, config.execution_harness_approvals[0],
                           ExecutionHarnessApproval)
    d = approval.descriptor
    assert d.kernel_commit == host.kernel_commit
    assert [a.name for a in d.build_artifacts] == [
        "bzimage", "instrumentation", "kernel", "lane-script",
        "syz-execprog", "syz-executor", "vm-image"]
    assert "nokaslr" in d.guest_kernel_command_line.split()
    collector = CollectorConfig.load(result.collector_config)
    assert config.engine.argv[-2:] == ("{input}", "{output}")
    assert Path(config.engine.argv[0]).is_absolute()
    assert set(collector.files) == {"bzimage", "kernel", "vm-image",
                                    "lane-script", "syz-executor",
                                    "syz-execprog"}
    from agent_pipeline.hcap import ArtifactHcapChecker
    checker = ArtifactHcapChecker(store)
    assert checker.judge_versions(result.hcap_revision) == \
        config.judge_versions
    lane = next(c for c in checker.load_catalog(result.hcap_revision)
                .capabilities if c.id == "CAP-lane")
    assert any(canonical_json(host.selection).decode() in text
               for text in lane.constraints)


def test_template_spec_is_valid():
    from agent_pipeline.stage1.host.generate import HostSpec
    template = REPO / "agent_pipeline/stage1/host/template"
    spec = HostSpec.model_validate_json(
        (template / "host-spec.json").read_bytes())
    for item in spec.neutral_controls:
        assert (template / item.program).is_file()
    calls = {e.call for e in spec.admission_source.entries}
    for selection in spec.runtime_selections:
        assert set(selection.enabled_interfaces) - {"remote_cover"} <= calls


@needs_gcc
def test_generate_refuses_executor_built_from_another_tree(host):
    _git(host.env / "syzkaller", "commit", "-q", "--allow-empty", "-m", "x")
    (host.env / "syzkaller" / "extra").write_text("drift\n")
    _git(host.env / "syzkaller", "add", "extra")
    _git(host.env / "syzkaller", "commit", "-qm", "drift")
    with pytest.raises(ValueError, match="moved since the syzkaller build"):
        generate(host.spec)
    # Rebuilt from the drifted tree: the record is current, but the parser
    # bundle was built from another tree.
    _write_syz_record(host.env)
    with pytest.raises(ValueError, match="different trees"):
        generate(host.spec)


@needs_gcc
def test_generate_refuses_builds_of_another_patch_series(host):
    # Executor binaries built from an older syzkaller series.
    _write_syz_record(host.env, series_sha256="0" * 64)
    with pytest.raises(ValueError, match="syzkaller build used another"):
        generate(host.spec)
    (host.env / "syzkaller" / "bin" / "build.json").unlink()
    with pytest.raises(ValueError, match="missing or unreadable"):
        generate(host.spec)
    _write_syz_record(host.env)
    # A kernel built from an older kernel series: its instrumentation is
    # not the checked-in series the manifest would pin.
    record = host.env / "images" / "kasan" / "build.json"
    good = record.read_text()
    record.write_text(json.dumps({"head": host.kernel_commit,
                                  "series_sha256": "1" * 64}))
    with pytest.raises(ValueError, match="kernel build used another"):
        generate(host.spec)
    record.write_text(good)
    generate(host.spec)
    # A parser bundle whose patch-series.bin is not its identity's series.
    (host.root / "syz-build" / "bundle" / "patch-series.bin").write_bytes(
        b"older series\n")
    with pytest.raises(ValueError, match="parser bundle was built from"):
        generate(host.spec)


def test_series_fingerprint_is_the_bootstrap_record_digest():
    bootstrap = runpy.run_path(str(REPO / "tools" / "bootstrap-kcov-env.py"))
    for kind in ("kernel", "syzkaller"):
        assert series_fingerprint(kind) == \
            bootstrap["series_fingerprint"](kind)


# ------------------------------------------------------------ collector

def _inputs(tmp: Path, config: Stage1Config, harness_selection) -> Path:
    """An engine-shaped input directory for one lease."""
    from agent_pipeline.materializer import ExecutionHarnessApproval
    store = ArtifactStore(config.artifact_root)
    approval = load_record(store, config.execution_harness_approvals[0],
                           ExecutionHarnessApproval)
    from agent_pipeline.materializer import descriptor_id
    harness_id = descriptor_id(approval.descriptor)
    inp = tmp / "input"
    inp.mkdir(parents=True)
    (inp / "execution.json").write_text(json.dumps({
        "job_id": "job-1", "task_id": "job-1.t1", "harness_ref": "0" * 64,
        "execution_harness_id": harness_id, "lease_generation": 1}))
    (inp / "descriptor.json").write_bytes(canonical_json(approval.descriptor))
    (inp / "program.syz").write_bytes(SCENARIO)
    (inp / "neutral.syz").write_bytes(NEUTRAL)
    harness = {
        "candidate_id": "cand-1", "plan_ref": "1" * 64,
        "program_kind": "program", "program_ref": "2" * 64,
        "neutral_program_ref": "3" * 64,
        "runtime_selection": harness_selection.model_dump(mode="json"),
        "required_capability_ids": ["CAP-lane"],
        "selected_capability_ids": ["CAP-lane"],
        "q1_observation": {
            "target": {"kind": "function", "path": "fs/nfsd/synthetic.c",
                       "symbol": "target", "start_line": 3, "end_line": 8},
            "expected_context": "synthetic_worker",
            "capability_id": "CAP-observe"},
        "hcap_revision": "4" * 64, "call_admission_profile_ref": "5" * 64,
        "neutral_control_catalog_ref": "6" * 64,
        "execution_harness_id": harness_id,
        "scenario_parser_result_ref": "7" * 64,
        "neutral_parser_result_ref": "8" * 64,
        "review_manifest_sha256": "9" * 64}
    (inp / "harness.json").write_text(json.dumps(harness))
    return inp


def _collect(host, tmp, **fake):
    result = generate(host.spec)
    config = Stage1Config.load(result.stage1_config)
    collector = CollectorConfig.load(result.collector_config)
    inp = _inputs(tmp, config, host.selection)
    out = tmp / "output"
    out.mkdir()
    guests = []

    def factory(vm):
        guests.append(FakeGuest(vm, **fake))
        return guests[0]

    collect(collector, inp, out, guest_factory=factory, sleep=lambda s: None)
    observation = RemoteKcovObservation.model_validate_json(
        (out / "reachability.json").read_bytes())
    return SimpleNamespace(out=out, observation=observation, guest=guests[0],
                           capture=json.loads((out / "capture.json")
                                              .read_text()))


@needs_gcc
def test_collector_writes_a_generation_attributed_capture(host, tmp_path):
    run = _collect(host, tmp_path / "lease", pcs=["0x401000", "0x401010"])
    obs = run.observation
    assert (obs.boot_ok, obs.fixture_ok, obs.lane_ok, obs.runner_completed,
            obs.collection_started, obs.collection_completed,
            obs.generation_attributed) == (True,) * 7
    assert obs.runtime_errors == ()
    assert obs.published_pcs == (0x401000, 0x401010)
    # The machine check's own generation is before the gate, so the window
    # holds the program's generation alone.
    assert obs.generation.generation_begin == 1
    assert obs.generation.aggregate_published == 1
    commands = run.guest.commands
    stats = [i for i, c in enumerate(commands) if "*_stats" in c]
    released = commands.index("touch /tmp/stage1/gate.go")
    assert stats[0] < released < stats[1]
    assert obs.lane_trace_mode == "off"
    coverage = PublishedCoverage.model_validate_json(
        (run.out / "coverage.json").read_bytes())
    assert coverage.correlation == obs.correlation
    assert obs.correlation.lane == 0 and obs.correlation.generation_id == 1
    assert {a["identity"] for a in run.capture["artifacts"]} >= {
        "reachability", "coverage", "collector-result", "console-log",
        "executor-log", "dmesg-log"}
    assert run.guest.stopped
    cmdline = run.guest.config.cmdline.split()
    assert "nokaslr" in cmdline and "koov.nfs_version=4.1" in cmdline
    assert "koov.nfs_trace=0" in cmdline


@needs_gcc
def test_collector_records_guest_failures_as_facts(host, tmp_path):
    run = _collect(host, tmp_path / "a", pcs=[], fixture="failed")
    assert run.observation.boot_ok and not run.observation.fixture_ok
    assert "fixture_not_ready" in run.observation.runtime_errors
    run = _collect(host, tmp_path / "b", pcs=["0x401000"],
                   dmesg="BUG: KASAN: slab-out-of-bounds in nfsd4_open\n")
    assert any("KASAN" in e for e in run.observation.runtime_errors)
    run = _collect(host, tmp_path / "c", boot_error="no ssh")
    assert not run.observation.boot_ok
    assert run.observation.generation.generation_begin is None


@needs_gcc
def test_collector_needs_the_gate_and_a_settled_window(host, tmp_path):
    # An execprog without -gate exits before the program: no window at all.
    obs = _collect(host, tmp_path / "a", pcs=["0x401000"], gate="exited",
                   exec_rc="2").observation
    assert not obs.runner_completed and not obs.collection_started
    assert not obs.generation_attributed
    assert obs.generation.generation_begin is None
    assert "execprog_failed_before_gate:exited:rc=2" in obs.runtime_errors
    # A generation still draining at the gate would leak into the window.
    obs = _collect(host, tmp_path / "b", pcs=["0x401000"],
                   generations="owner 1 state CLOSING outstanding_tokens 1 "
                   "object_refs 2 active_roots 1 generation 5\n").observation
    assert obs.runner_completed and not obs.collection_started
    assert not obs.generation_attributed
    assert any(e.startswith("generation_unsettled_at_window_start")
               for e in obs.runtime_errors)


@needs_gcc
def test_collector_refuses_a_file_that_differs_from_its_pin(host, tmp_path):
    result = generate(host.spec)
    config = Stage1Config.load(result.stage1_config)
    collector = CollectorConfig.load(result.collector_config)
    (host.env / "images" / "kasan" / "bzImage").write_bytes(b"other kernel")
    inp = _inputs(tmp_path, config, host.selection)
    (tmp_path / "output").mkdir()
    with pytest.raises(Exception, match="does not match its pin"):
        collect(collector, inp, tmp_path / "output",
                guest_factory=lambda vm: FakeGuest(vm, pcs=[]))


def test_guest_cmdline_requires_nokaslr():
    d = SimpleNamespace(guest_kernel_command_line="root=/dev/sda")
    with pytest.raises(CollectorError, match="nokaslr"):
        guest_cmdline(d, runtime(), "0" * 64)
    d.guest_kernel_command_line = "nokaslr koov.nfs_version=3"
    with pytest.raises(CollectorError, match="koov"):
        guest_cmdline(d, runtime(), "0" * 64)


# ------------------------------------------------------------ end to end

COMMAND = r'''
import sys
sys.path.insert(0, {repo!r})
from pathlib import Path
from agent_pipeline.stage1.host.collector import CollectorConfig, collect
from tests.agent_pipeline.host_fakes import FakeGuest
collect(CollectorConfig.load(sys.argv[1]), Path(sys.argv[2]),
        Path(sys.argv[3]), guest_factory=FakeGuest, sleep=lambda s: None)
'''


@needs_gcc
def test_generated_host_runs_a_candidate_to_reached(host, tmp_path):
    """stage1.json from generate, the collector (scripted guest) as the
    engine command, and a mapping from target-pcs on the gcc binary."""
    result = generate(host.spec)
    config = Stage1Config.load(result.stage1_config)
    pcs_file = tmp_path / "cover-pcs.txt"
    config = config.model_copy(update={"engine": EngineConfig(
        argv=(sys.executable, "-I", "-c", COMMAND.format(repo=str(REPO)),
              str(result.collector_config), "{input}", "{output}"),
        cwd=tmp_path, resource_key="test-lane",
        env={"LANG": "C.UTF-8", "TEST_COVER_PCS": str(pcs_file)},
        timeout_s=60)})
    config_path = tmp_path / "stage1-test.json"
    config_path.write_text(config.model_dump_json())

    plan_source = SimpleNamespace(
        plan=_plan(result.hcap_revision), scenario_bytes=SCENARIO)
    parser = SyntheticParser({
        _sha(SCENARIO): parsed(SCENARIO, host.identity,
                               (("openat$lane", "available", lane_facts()),
                                ("close", "available", empty_facts()))),
        _sha(NEUTRAL): parsed(NEUTRAL, host.identity,
                              (("openat$lane", "available", lane_facts()),)),
    })
    with ExitStack() as stack:
        service = open_stage1(config, stack,
                              runtime=ScriptedRuntime(plan_source),
                              parser=parser)
        job_id = service.controller.submit(CandidateSubmission(
            kernel_commit=host.kernel_commit, location=LocationRequest(
                kind=LocationKind.FUNCTION, path="fs/nfsd/synthetic.c",
                symbol="target")), "p1")
        job = service.job(job_id)
        assert job.binding is not None, job
        mapping_path = tmp_path / "mapping.json"
        assert host_main(["target-pcs", "--stage1",
                          str(result.stage1_config), "--job", job_id,
                          "--out", str(mapping_path)]) == 0
        mapping = TargetPcMapping.model_validate_json(
            mapping_path.read_bytes())
        assert mapping.target.start_line == 3 and mapping.verified
        lo, hi = _symbol_range(host.env / "images/kasan/vmlinux", "target")
        assert all(lo <= pc < hi for pc in mapping.target_pcs)
        # The guest publishes the target's call sites plus one elsewhere.
        pcs_file.write_text("".join(f"0x{pc:x}\n"
                                    for pc in mapping.target_pcs))
        service.mappings.add(mapping)
        service.start_worker(idle_s=0.05)
        assert service.run(lambda: service.job(job_id).state in STOP_STATES,
                           interval_s=0.05, timeout_s=60)
        job = service.job(job_id)
        assert job.state is JobState.S1_REACHED, (
            [(t.to_state.value, t.reason) for t in
             service.store.transitions(job_id)],
            service.store.effect_failures(job_id), service.worker_errors)
        verdict = job.last_verdict.result
        assert verdict.status is Q1Status.REACHED
        assert service.controller.replay(job_id) == job
    coverage = next(Path(config.state_dir, "runs").glob("*/output/coverage.json"))
    assert host_main(["check-pcs", "--stage1", str(result.stage1_config),
                      "--coverage", str(coverage)]) == 0


def _symbol_range(binary: Path, name: str) -> tuple[int, int]:
    out = subprocess.run(["nm", "-S", str(binary)], check=True,
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] == name:
            start = int(parts[0], 16)
            return start, start + int(parts[1], 16)
    raise AssertionError(f"{name} not in {binary}")


def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _plan(hcap_revision: str):
    from agent_pipeline.hcap import (CapabilityUse, ProgramProposal,
                                     Q1Observation, ReachabilityPlan,
                                     ScenarioStep, SelectedPath)
    return ReachabilityPlan(
        candidate_id="replaced-by-runtime", hcap_revision=hcap_revision,
        selected_path=SelectedPath(entry_surface="nfs_request",
                                   path_summary="synthetic path"),
        nfs_version="4.1",
        scenario_steps=(ScenarioStep(
            capability_id="CAP-lane", action="open synthetic lane",
            expected_state_change="lane acquired"),),
        required_capabilities=("CAP-lane", "CAP-observe"),
        capability_uses=(
            CapabilityUse(capability_id="CAP-lane", status="validated",
                          scope=("lane",)),
            CapabilityUse(capability_id="CAP-observe", status="validated",
                          scope=("generation",))),
        q1_observation=Q1Observation(
            target={"kind": "function", "path": "fs/nfsd/synthetic.c",
                    "symbol": "target", "start_line": 3, "end_line": 8},
            expected_context="synthetic_worker", capability_id="CAP-observe"),
        program_proposal=ProgramProposal(kind="program",
                                         artifact_ref=_sha(SCENARIO)),
        runtime_selection=runtime())
