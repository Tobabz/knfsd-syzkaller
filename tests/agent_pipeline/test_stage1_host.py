"""Host side of a real Stage 1 run, without KVM.

Real: record generation from a bootstrap-shaped env and a parser bundle,
pins, the collector's parsing and record building, target-PC mapping on a
gcc ``-fsanitize-coverage=trace-pc`` binary, and the wired service from
``stage1.json`` to ``s1_reached``.  Scripted: the guest (``host_fakes``),
the model responses and the syzkaller parser.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import runpy
import shutil
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_pipeline.admission import (BuildFile, SyzkallerBuildManifest,
                                      SyzkallerCallTable,
                                      SyzkallerTargetIdentity)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (PIPELINE_GAP_IDS, CandidateSubmission,
                                      LocationKind, LocationRequest, Q1Status,
                                      Sanitizer)
from agent_pipeline.controller.records import JobState
from agent_pipeline.crash import CRASH_REPORT_TYPE, CrashKind, CrashReport
from agent_pipeline.data import canonical_json, load_record
from agent_pipeline.q1 import (KernelIdentity, RemoteKcovObservation,
                               TargetPcMapping)
from agent_pipeline.sealed_q1 import PublishedCoverage
from agent_pipeline.stage1.cli import STOP_STATES, open_stage1
from agent_pipeline.stage1.config import EngineConfig, Stage1Config
from agent_pipeline.stage1.host import kcov
from agent_pipeline.stage1.host.__main__ import main as host_main
from agent_pipeline.stage1.host.collector import (CollectorConfig,
                                                  CollectorError, collect,
                                                  guest_cmdline)
from agent_pipeline.stage1.host.generate import (GenerationError,
                                                 HCAP11_RECOVERY_ORDER,
                                                 Hcap11KvmEvidence,
                                                 Hcap13KvmEvidence,
                                                 generate,
                                                 series_fingerprint)
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
    (env / "syzkaller" / "bin" / "syz-manager").write_bytes(
        b"synthetic manager")
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
        "syz-execprog", "syz-executor", "syz-manager", "vm-image"]
    assert "nokaslr" in d.guest_kernel_command_line.split()
    collector = CollectorConfig.load(result.collector_config)
    assert config.engine.argv[-2:] == ("{input}", "{output}")
    assert Path(config.engine.argv[0]).is_absolute()
    assert set(collector.files) == {"bzimage", "kernel", "vm-image",
                                    "lane-script", "syz-executor",
                                    "syz-execprog", "syz-manager"}
    from agent_pipeline.hcap import ArtifactHcapChecker
    checker = ArtifactHcapChecker(store)
    assert checker.judge_versions(result.hcap_revision) == \
        config.judge_versions
    lane = next(c for c in checker.load_catalog(result.hcap_revision)
                .capabilities if c.id == "CAP-lane")
    assert any(canonical_json(host.selection).decode() in text
               for text in lane.constraints)


@needs_gcc
def test_generate_binds_declared_capability_evidence(host):
    evidence = host.root / "capability-evidence.json"
    evidence.write_text(
        '{"schema_version":"test-evidence.v1","result":"pass"}\n')
    spec = json.loads(host.spec.read_text())
    spec["capability_evidence"] = {
        "CAP-lane": ["capability-evidence.json"]}
    host.spec.write_text(json.dumps(spec, indent=1))

    result = generate(host.spec)
    store = ArtifactStore(host.root / "cas")
    from agent_pipeline.hcap import ArtifactHcapChecker
    capability = next(
        item for item in ArtifactHcapChecker(store).load_catalog(
            result.hcap_revision).capabilities
        if item.id == "CAP-lane")
    assert len(capability.evidence_refs) == 1
    assert store.get(capability.evidence_refs[0]) == evidence.read_bytes()


@needs_gcc
def test_generated_hcap_lists_the_pipeline_gap_ids(host):
    # #81 D6: the spec lists none, the generated revision has all three.
    result = generate(host.spec)
    from agent_pipeline.hcap import ArtifactHcapChecker
    catalog = ArtifactHcapChecker(ArtifactStore(host.root / "cas")) \
        .load_catalog(result.hcap_revision)
    assert set(catalog.missing_capability_ids) == set(PIPELINE_GAP_IDS)


def test_generate_refuses_a_mutate_policy(host):
    # #81 D16: generation configures no Stage 2 backend yet.
    spec = json.loads(host.spec.read_text())
    spec["policies"] = [policy(campaign_mode="mutate").model_dump(
        mode="json")]
    host.spec.write_text(json.dumps(spec, indent=1))
    with pytest.raises(GenerationError, match="campaign_mode mutate"):
        generate(host.spec)


@needs_gcc
def test_hcap11_evidence_is_typed_and_bound_to_generated_harness(host):
    initial = generate(host.spec)
    config = Stage1Config.load(initial.stage1_config)
    store = ArtifactStore(config.artifact_root)
    from agent_pipeline.materializer import ExecutionHarnessApproval
    from agent_pipeline.stage1.host.pins import HostFilePin
    approval = load_record(store, config.execution_harness_approvals[0],
                           ExecutionHarnessApproval)
    descriptor = approval.descriptor
    builds = {item.name: item.artifact_ref
              for item in descriptor.build_artifacts}
    lane_pin = load_record(store, builds["lane-script"], HostFilePin)
    identity = KernelIdentity(
        execution_harness_id=initial.execution_harness_id,
        kernel_commit=descriptor.kernel_commit,
        instrumentation_sha256=builds["instrumentation"],
        vmlinux_sha256=builds["kernel"],
        kaslr_enabled=False, kaslr_offset=0)
    evidence_value = {
        "schema_version": "hcap-kvm-evidence.v1",
        "capability_id": "HCAP-11",
        "observed_at": "2026-10-19",
        "scenario": "v41-client-expiry",
        "execution_harness_id": initial.execution_harness_id,
        "mapping_identity": identity.model_dump(mode="json"),
        "target_mapping_sha256": "a" * 64,
        "campaign_result_sha256": "b" * 64,
        "guest_lane_script_sha256": lane_pin.sha256,
        "guest_nfs_proxy_sha256": "c" * 64,
        "runs": {
            "control": {"completed": 1, "target_hit_counts": [0]},
            "stimulus": {"completed": 1, "target_hit_counts": [1]},
        },
        "generation_contract": {
            "generation_begin_each": 1,
            "aggregate_published_each": 1,
            "generation_aborted_each": 0,
            "scratch_overflow_each": 0,
            "merge_truncation_each": 0,
            "outstanding_tokens_after_each": 0,
            "remote_refs_after_each": 0,
            "minimum_remote_start_ok": 1,
        },
        "recovery_order": list(HCAP11_RECOVERY_ORDER),
        "crash_signature_count": 0,
        "raw_artifact_error_count": 0,
        "shareable_result_contains_target_metadata_or_addresses": False,
    }
    evidence = host.root / "hcap11-evidence.json"
    evidence.write_text(json.dumps(evidence_value))
    spec = json.loads(host.spec.read_text())
    spec["capabilities"].append({
        "id": "HCAP-11", "name": "lifecycle", "purpose": "test binding",
        "usable_stage": ["stage1"], "usable_by": ["agent_stage1"],
        "interface": {"runtime_features": ["lifecycle_recovery"]},
        "status": "validated", "scope": ["client0_recovery"],
    })
    spec["capability_evidence"] = {"HCAP-11": [evidence.name]}
    host.spec.write_text(json.dumps(spec, indent=1))

    result = generate(host.spec)
    from agent_pipeline.hcap import HcapCatalog
    catalog = load_record(store, result.hcap_revision, HcapCatalog)
    lifecycle = next(item for item in catalog.capabilities
                     if item.id == "HCAP-11")
    assert len(lifecycle.evidence_refs) == 1
    assert Hcap11KvmEvidence.model_validate_json(
        store.get(lifecycle.evidence_refs[0])).mapping_identity == identity

    evidence.write_text('{"proof":"not typed"}')
    with pytest.raises(GenerationError, match="invalid HCAP-11 KVM evidence"):
        generate(host.spec)

    evidence.write_text(json.dumps(evidence_value))
    spec["guest_kernel_command_line"] = \
        descriptor.guest_kernel_command_line + " audit=1"
    host.spec.write_text(json.dumps(spec, indent=1))
    with pytest.raises(GenerationError, match="mapping identity differs"):
        generate(host.spec)


def _kvm_evidence(identity, lane_sha256):
    """Fields every typed KVM campaign evidence record shares."""
    return {
        "schema_version": "hcap-kvm-evidence.v1",
        "observed_at": "2026-10-20",
        "execution_harness_id": identity.execution_harness_id,
        "mapping_identity": identity.model_dump(mode="json"),
        "campaign_result_sha256": "b" * 64,
        "guest_lane_script_sha256": lane_sha256,
        "guest_nfs_proxy_sha256": "c" * 64,
        "generation_contract": {
            "generation_begin_each": 1,
            "aggregate_published_each": 1,
            "generation_aborted_each": 0,
            "scratch_overflow_each": 0,
            "merge_truncation_each": 0,
            "outstanding_tokens_after_each": 0,
            "remote_refs_after_each": 0,
            "minimum_remote_start_ok": 1,
        },
        "crash_signature_count": 0,
        "raw_artifact_error_count": 0,
        "shareable_result_contains_target_metadata_or_addresses": False,
    }


EVIDENCE_IDENTITY = KernelIdentity(
    execution_harness_id="d" * 64, kernel_commit="e" * 40,
    instrumentation_sha256="f" * 64, vmlinux_sha256="9" * 64,
    kaslr_enabled=False, kaslr_offset=0)


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
    lifecycle = next(c for c in spec.capabilities if c.id == "HCAP-11")
    assert lifecycle.status == "validated"
    assert lifecycle.scope == ("client0_confirmed_expiry_recovery",)
    assert lifecycle.interface.syz_calls == (
        "syz_nfsd_client_ctl$expire_client0",)
    assert spec.capability_evidence["HCAP-11"] == (
        Path("capability-evidence/hcap11-kvm.json"),)
    evidence_path = template / spec.capability_evidence["HCAP-11"][0]
    assert evidence_path.is_file()
    evidence_json = json.loads(evidence_path.read_text())
    evidence = Hcap11KvmEvidence.model_validate(evidence_json)
    assert evidence.capability_id == "HCAP-11"
    assert evidence.shareable_result_contains_target_metadata_or_addresses is False
    assert not {"target_pcs", "candidate_id", "path", "symbol"} & set(
        evidence_json)
    assert any("syz_nfsd_client_ctl$expire_client0(0x0)" in item
               for item in lifecycle.constraints)
    expiry = next(e for e in spec.admission_source.entries
                  if e.call == "syz_nfsd_client_ctl$expire_client0")
    assert expiry.capability_ids == ("HCAP-11",)
    assert all("syz_nfsd_client_ctl$expire_client1" not in
               selection.enabled_interfaces
               for selection in spec.runtime_selections)

    # HCAP-12 (nfsdcld reconnect) was withdrawn (#98): stopping a server
    # daemon is not an NFS client action, so nothing admits nfsdcld control.
    assert all(c.id != "HCAP-12" for c in spec.capabilities)
    assert "HCAP-12" not in spec.capability_evidence
    assert all(not e.call.startswith("syz_nfsd_cld_ctl$")
               for e in spec.admission_source.entries)
    assert all(not call.startswith("syz_nfsd_cld_ctl$")
               for selection in spec.runtime_selections
               for call in selection.enabled_interfaces)
    assert all(not call.startswith("syz_nfsd_cld_ctl$")
               for item in spec.neutral_controls
               for call in item.runtime_selection.enabled_interfaces)
    v41 = [s for s in spec.runtime_selections if s.profile == "knfsd-v41"]
    assert len(v41) == 1
    assert "remote_kcov.context.cld" in spec.missing_capability_ids

    # HCAP-13 has its own nlm-knfsd NFSv3 selection, a neutral control on
    # it, and is promoted only by capability-evidence/hcap13-kvm.json.
    nlm = next(c for c in spec.capabilities if c.id == "HCAP-13")
    assert nlm.scope == ("nlm_lane_lock_rpc",)
    assert spec.capability_evidence["HCAP-13"] == (
        Path("capability-evidence/hcap13-kvm.json"),)
    nlm_evidence = template / spec.capability_evidence["HCAP-13"][0]
    if nlm_evidence.is_file():
        evidence_json = json.loads(nlm_evidence.read_text())
        assert Hcap13KvmEvidence.model_validate(
            evidence_json).capability_id == "HCAP-13"
    nlm_selections = [s for s in spec.runtime_selections
                      if s.fixture_mode == "nlm-knfsd"]
    assert len(nlm_selections) == 1
    assert (nlm_selections[0].profile, nlm_selections[0].nfs_version) == (
        "knfsd-v3", "3")
    assert any(item.runtime_selection == nlm_selections[0]
               for item in spec.neutral_controls)
    entries = {e.call: e for e in spec.admission_source.entries}
    for call in nlm.interface.syz_calls:
        assert entries[call].capability_ids == ("HCAP-13",)
    lock = entries["fcntl$lock"]
    assert [(c.kind, getattr(c, "minimum", None), getattr(c, "maximum", None))
            for c in lock.resource_constraints] == [
        ("resource_origin", None, None), ("integer_range", 5, 6)]
    # Kernel patch 0006 attributes the lockd thread grant and lockd rpciod
    # calls: lockd is a supported context, not a missing capability.
    assert "remote_kcov.context.lockd" not in spec.missing_capability_ids
    assert "lockd" in spec.support_boundary.supported_contexts
    assert "lockd" in {c.context for c in spec.judge_profile.contexts}


def _hcap13_run(completed=3, **hits):
    probes = dict.fromkeys(("clnt_grant", "svc_grant_blocked",
                            "svc_grant_callback", "svc_lock", "svc_share",
                            "svc_testlock", "svc_unlock"), 0)
    probes.update(hits)
    return {
        "completed": completed,
        "probe_hits": {name: [count] * completed
                       for name, count in probes.items()},
        "status_checks_passed": completed,
        "attributed_generations": completed,
    }


def _hcap13_evidence(identity, lane_sha256):
    value = _kvm_evidence(identity, lane_sha256)
    value.update({
        "capability_id": "HCAP-13",
        "scenario": "v3-nlm-lock",
        "probe_mapping_sha256": {name: "1" * 64 for name in (
            "clnt_grant", "svc_grant_blocked", "svc_grant_callback",
            "svc_lock", "svc_share", "svc_testlock", "svc_unlock")},
        "runs": {
            "control": _hcap13_run(),
            "lock": _hcap13_run(svc_lock=2, svc_unlock=1, svc_testlock=1),
            "rpc": _hcap13_run(svc_lock=2, svc_unlock=1, svc_testlock=1,
                               svc_share=3),
            "blocked": _hcap13_run(svc_lock=2, svc_unlock=1, clnt_grant=1,
                                   svc_grant_blocked=4,
                                   svc_grant_callback=2),
        },
    })
    return value


def test_hcap13_evidence_accepts_the_validated_campaign_shape():
    evidence = Hcap13KvmEvidence.model_validate(
        _hcap13_evidence(EVIDENCE_IDENTITY, "8" * 64))
    assert evidence.runs.blocked.probe_hits.clnt_grant == (1, 1, 1)


@pytest.mark.parametrize(("path", "value", "message"), [
    (("runs", "control", "probe_hits", "svc_lock"), [0, 1, 0],
     "control run reached a lockd probe"),
    (("runs", "lock", "probe_hits", "svc_unlock"), [1, 0, 1],
     "lock run missed svc_unlock"),
    (("runs", "lock", "probe_hits", "clnt_grant"), [0, 1, 0],
     "lock run reached a grant callback"),
    (("runs", "rpc", "probe_hits", "svc_share"), [1, 1, 0],
     "rpc run missed svc_share"),
    (("runs", "rpc", "probe_hits", "svc_testlock"), [0, 1, 1],
     "rpc run missed svc_testlock"),
    (("runs", "blocked", "probe_hits", "clnt_grant"), [1, 0, 1],
     "blocked run missed clnt_grant"),
    (("runs", "blocked", "probe_hits", "svc_grant_blocked"), [4, 4, 0],
     "blocked run missed svc_grant_blocked"),
    (("runs", "blocked", "probe_hits", "svc_grant_callback"), [0, 2, 2],
     "blocked run missed svc_grant_callback"),
    (("runs", "lock", "probe_hits", "svc_grant_blocked"), [0, 0, 1],
     "lock run reached a grant callback"),
    (("runs", "blocked", "attributed_generations"), 2,
     "lacks one attributed generation"),
    (("runs", "rpc", "status_checks_passed"), 2,
     "left the lane fixture unhealthy"),
    (("runs", "rpc", "completed"), 2, "greater than or equal to 3"),
    (("probe_mapping_sha256",), {"svc_lock": "1" * 64},
     "probe mappings differ"),
    (("raw_artifact_error_count",), 1, "crash or artifact error"),
    (("shareable_result_contains_target_metadata_or_addresses",), True,
     "private target data"),
    (("scenario",), "v41-cld-lifecycle", "v3-nlm-lock"),
])
def test_hcap13_evidence_rejects_unvalidated_campaigns(path, value, message):
    evidence = _hcap13_evidence(EVIDENCE_IDENTITY, "8" * 64)
    target = evidence
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError, match=message):
        Hcap13KvmEvidence.model_validate(evidence)


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

def _inputs(tmp: Path, config: Stage1Config, harness_selection,
            approval: int = 0) -> Path:
    """An engine-shaped input directory for one lease."""
    from agent_pipeline.materializer import ExecutionHarnessApproval
    store = ArtifactStore(config.artifact_root)
    approval = load_record(store, config.execution_harness_approvals[approval],
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


def _collect(host, tmp, approval=0, **fake):
    result = generate(host.spec)
    config = Stage1Config.load(result.stage1_config)
    collector = CollectorConfig.load(result.collector_config)
    inp = _inputs(tmp, config, host.selection, approval)
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
    # A fixture of another mode is not the selection's fixture.
    run = _collect(host, tmp_path / "d", pcs=["0x401000"],
                   fixture_mode="nlm-knfsd")
    assert "fixture_not_ready" in run.observation.runtime_errors
    run = _collect(host, tmp_path / "c", boot_error="no ssh")
    assert not run.observation.boot_ok
    assert run.observation.generation.generation_begin is None


def _crash(run):
    entries = {a["identity"]: a for a in run.capture["artifacts"]}
    if "crash-report" not in entries:
        return None
    assert entries["crash-report"]["type"] == CRASH_REPORT_TYPE
    return CrashReport.model_validate_json(
        (run.out / entries["crash-report"]["path"]).read_bytes())


@needs_gcc
def test_collector_seals_a_crash_of_a_completed_run(host, tmp_path):
    """#81 §3: the crash is a sealed report, not a runtime error; the run
    stays complete and judgeable."""
    run = _collect(host, tmp_path / "a", pcs=["0x401000"],
                   console="[   9.1] WARNING: CPU: 0 PID: 1 at x.c:1\n")
    obs = run.observation
    assert obs.runtime_errors == ()
    assert obs.runner_completed and obs.generation_attributed
    crash = _crash(run)
    assert (crash.source, crash.kind) == ("console", CrashKind.WARNING)
    assert crash.title == "WARNING: CPU: 0 PID: 1 at x.c:1"
    assert not crash.panicked
    assert b"WARNING: CPU: 0" in (run.out / "console.log").read_bytes()
    # The console is the primary evidence; dmesg is the fallback.
    run = _collect(host, tmp_path / "b", pcs=["0x401000"],
                   dmesg="BUG: KASAN: slab-out-of-bounds in nfsd4_open\n")
    assert run.observation.runtime_errors == ()
    assert (_crash(run).source, _crash(run).kind) == ("dmesg",
                                                      CrashKind.KASAN)
    assert _crash(_collect(host, tmp_path / "c", pcs=["0x401000"])) is None


@needs_gcc
def test_collector_seals_a_panic_of_an_incomplete_run(host, tmp_path):
    run = _collect(host, tmp_path / "a", pcs=["0x401000"], panic=True,
                   console="BUG: KASAN: use-after-free in nfsd4_bind\n"
                           "Kernel panic - not syncing: KASAN: panic_on_warn"
                           "\n")
    obs = run.observation
    assert not obs.runner_completed and obs.runtime_errors
    crash = _crash(run)
    assert crash.kind is CrashKind.KASAN and crash.panicked
    assert crash.source == "console"


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


def test_guest_cmdline_selects_the_nlm_fixture_by_name():
    d = SimpleNamespace(guest_kernel_command_line="root=/dev/sda nokaslr")
    cmdline = guest_cmdline(d, runtime(
        profile="knfsd-v3", nfs_version="3", fixture_mode="nlm-knfsd"),
        "0" * 64).split()
    assert "koov.nfs_fixture=nlm-knfsd" in cmdline
    assert not any(t.startswith("koov.nfs_version=") for t in cmdline)


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
@pytest.mark.parametrize("warning", (False, True))
def test_generated_host_runs_a_candidate_to_reached(host, tmp_path, warning):
    """stage1.json from generate, the collector (scripted guest) as the
    engine command, and a mapping from target-pcs on the gcc binary.  A
    WARNING while the program runs is a crash finding; the job still
    reaches s1_reached on its coverage (#81 §3)."""
    result = generate(host.spec)
    config = Stage1Config.load(result.stage1_config)
    pcs_file = tmp_path / "cover-pcs.txt"
    console = tmp_path / "console.txt"
    console.write_text("[  7.5] WARNING: CPU: 0 PID: 9 at fs/nfsd/x.c:3\n"
                       if warning else "")
    config = config.model_copy(update={"engine": EngineConfig(
        argv=(sys.executable, "-I", "-c", COMMAND.format(repo=str(REPO)),
              str(result.collector_config), "{input}", "{output}"),
        cwd=tmp_path, resource_key="test-lane",
        env={"LANG": "C.UTF-8", "TEST_COVER_PCS": str(pcs_file),
             "TEST_CONSOLE": str(console)},
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
        if warning:
            (finding,) = job.crash_findings
            assert finding.kind == "warning"
            assert finding.title.startswith("WARNING: CPU: 0 PID: 9")
            assert finding.bundle_ref == job.last_verdict.bundle_ref
            assert finding.q1_verdict_id == verdict.verdict_id
        else:
            assert job.crash_findings == ()
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


def _load_bootstrap():
    spec = importlib.util.spec_from_file_location(
        "bootstrap_kcov_env", REPO / "tools" / "bootstrap-kcov-env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _patched_kernel_env(tmp_path, bootstrap, *, legacy=False):
    """A target with a committed patched tree, recorded variant images and
    the passing manifest of the bootstrap that built them.  ``legacy``
    writes records in the pre-#66 four-field form, without kconfig_sha256."""
    linux = tmp_path / "linux"
    (linux / "include/linux/sunrpc").mkdir(parents=True)
    (linux / "include/linux/sunrpc/fuzz.h").write_text(
        "sunrpc_fuzz_svc_remote_grant\n")
    git = ["git", "-C", str(linux)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "-c", "user.name=t", "-c", "user.email=t@t",
                    "commit", "-q", "-m", "patched"], check=True)
    head = bootstrap.git_head(linux)
    base = {"series_sha256": bootstrap.series_fingerprint("kernel"),
            "base": bootstrap.KERNEL_COMMIT, "head": head, "commits": 5}
    variants = {}
    for variant in bootstrap.VARIANTS:
        images = tmp_path / "images" / variant
        images.mkdir(parents=True)
        (images / "bzImage").write_bytes(b"bz-" + variant.encode())
        (images / "vmlinux").write_bytes(b"vmlinux-" + variant.encode())
        (images / ".config").write_text("CONFIG_KCOV=y\n")
        record = dict(base)
        if not legacy:
            record["kconfig_sha256"] = bootstrap.sha256(
                bootstrap.KCONFIGS[variant])
        (images / bootstrap.BUILD_RECORD).write_text(json.dumps(record))
        variants[variant] = {
            "config_sha256": bootstrap.sha256(bootstrap.KCONFIGS[variant]),
            "bzImage_sha256": bootstrap.sha256(images / "bzImage"),
            "vmlinux_sha256": bootstrap.sha256(images / "vmlinux"),
        }
    (tmp_path / "manifest.json").write_text(json.dumps({
        "status": "pass", "kernel": {
            "ref": bootstrap.KERNEL_TAG, **base, "variants": variants}}))
    return SimpleNamespace(
        target=tmp_path, variants=list(bootstrap.VARIANTS), update=True,
        skip_build=False, kernel_ref=bootstrap.KERNEL_TAG,
        kernel_repo="unused"), head


def _no_rebuild(*_args, **_kwargs):
    raise AssertionError("an unchanged kernel must not be re-applied")


@pytest.mark.parametrize("legacy", (False, True))
def test_bootstrap_update_keeps_an_unchanged_kernel_commit(
        tmp_path, monkeypatch, legacy):
    bootstrap = _load_bootstrap()
    args, head = _patched_kernel_env(tmp_path, bootstrap, legacy=legacy)
    monkeypatch.setattr(bootstrap, "run", _no_rebuild)
    manifest = {}
    _, rebuilt = bootstrap.stage_kernel(args, manifest, False)
    assert rebuilt is False
    assert manifest["kernel"]["head"] == head
    assert bootstrap.git_head(tmp_path / "linux") == head
    for variant in bootstrap.VARIANTS:
        record = json.loads(
            (tmp_path / "images" / variant / "build.json").read_text())
        # A legacy record is backfilled once, from the verified manifest.
        assert record["kconfig_sha256"] == bootstrap.sha256(
            bootstrap.KCONFIGS[variant])
        assert record["head"] == head
    # The backfilled record is then reused as is.
    assert bootstrap.stage_kernel(args, {}, False)[1] is False


@pytest.mark.parametrize("break_", (
    "no_manifest", "failed_manifest", "kconfig", "bzImage", "vmlinux",
    "head", "series"))
def test_bootstrap_update_refuses_an_unverifiable_legacy_record(
        tmp_path, monkeypatch, break_):
    bootstrap = _load_bootstrap()
    args, head = _patched_kernel_env(tmp_path, bootstrap, legacy=True)
    manifest_path = tmp_path / "manifest.json"
    previous = json.loads(manifest_path.read_text())
    kasan = previous["kernel"]["variants"]["kasan"]
    images = tmp_path / "images" / "kasan"
    if break_ == "no_manifest":
        manifest_path.unlink()
    elif break_ == "failed_manifest":
        previous["status"] = "fail"
    elif break_ == "kconfig":
        kasan["config_sha256"] = "0" * 64
    elif break_ == "bzImage":
        (images / "bzImage").write_bytes(b"other image")
    elif break_ == "vmlinux":
        (images / "vmlinux").unlink()
    elif break_ == "head":
        previous["kernel"]["head"] = "0" * 40
    elif break_ == "series":
        previous["kernel"]["series_sha256"] = "0" * 64
    if manifest_path.exists():
        manifest_path.write_text(json.dumps(previous))
    record_before = (images / "build.json").read_text()
    monkeypatch.setattr(bootstrap, "run", _no_rebuild)
    with pytest.raises(RuntimeError, match="cannot migrate the kasan"):
        bootstrap.stage_kernel(args, {}, False)
    # Fail closed: nothing was rebuilt, removed or rewritten.
    assert bootstrap.git_head(tmp_path / "linux") == head
    assert (images / "build.json").read_text() == record_before


@pytest.mark.parametrize("also", ("nothing", "series", "base", "images"))
def test_bootstrap_update_refuses_a_dirty_kernel_tree(
        tmp_path, monkeypatch, also):
    """Local work is kept even when the inputs also call for a rebuild."""
    bootstrap = _load_bootstrap()
    args, head = _patched_kernel_env(tmp_path, bootstrap, legacy=True)
    stray = tmp_path / "linux" / "local-change"
    stray.write_text("x\n")
    if also == "series":
        monkeypatch.setattr(bootstrap, "series_fingerprint",
                            lambda kind: "0" * 64)
    elif also == "base":
        args.kernel_ref = "v0.0"
    elif also == "images":
        (tmp_path / "images" / "kasan" / "bzImage").unlink()
    monkeypatch.setattr(bootstrap, "run", _no_rebuild)
    with pytest.raises(RuntimeError, match="local changes"):
        bootstrap.stage_kernel(args, {}, False)
    assert stray.read_text() == "x\n"
    assert bootstrap.git_head(tmp_path / "linux") == head


@pytest.mark.parametrize("change", ("kconfig", "series", "base"))
def test_bootstrap_update_rebuilds_a_changed_kernel(
        tmp_path, monkeypatch, change):
    bootstrap = _load_bootstrap()
    args, _ = _patched_kernel_env(tmp_path, bootstrap)
    if change == "kconfig":
        # The checked-in kconfig no longer matches the one recorded.
        for variant in bootstrap.VARIANTS:
            path = tmp_path / "images" / variant / "build.json"
            record = json.loads(path.read_text())
            record["kconfig_sha256"] = "0" * 64
            path.write_text(json.dumps(record))
    elif change == "series":
        monkeypatch.setattr(bootstrap, "series_fingerprint",
                            lambda kind: "0" * 64)
    elif change == "base":
        args.kernel_ref = "v0.0"

    class Rebuild(Exception):
        pass

    def clone(argv, **_kwargs):
        raise Rebuild(argv)
    monkeypatch.setattr(bootstrap, "run", clone)
    with pytest.raises(Rebuild, match="clone"):
        bootstrap.stage_kernel(args, {}, False)


def test_kernel_series_apply_is_deterministic(tmp_path):
    """fport-apply reproduces the same commits from the same base and series."""
    base = tmp_path / "base"
    base.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run([*git, "-C", str(base), "init", "-q"], check=True)
    subprocess.run([*git, "-C", str(base), "commit", "-q", "--allow-empty",
                    "-m", "base"], check=True)
    commit = subprocess.run(["git", "-C", str(base), "rev-parse", "HEAD"],
                            capture_output=True, text=True,
                            check=True).stdout.strip()
    (base / "f").write_text("patched\n")
    subprocess.run(["git", "-C", str(base), "add", "f"], check=True)
    subprocess.run([*git, "-C", str(base), "commit", "-q", "-m", "patch"],
                   check=True,
                   env={**os.environ,
                        "GIT_AUTHOR_DATE": "2026-10-01T00:00:00+0900"})
    patches = tmp_path / "patches"
    (patches / "kernel").mkdir(parents=True)
    subprocess.run(["git", "-C", str(base), "format-patch", "-q", "-1",
                    "-o", str(patches / "kernel")], check=True)
    (patches / "BASE").write_text("kernel_commit=%s\n" % commit)
    heads = []
    for index, date in enumerate(("2026-10-02T00:00:00+0000",
                                  "2027-01-01T00:00:00+0000")):
        tree = tmp_path / ("tree%d" % index)
        subprocess.run(["git", "clone", "-q", str(base), str(tree)],
                       check=True)
        subprocess.run(["git", "-C", str(tree), "checkout", "-q", commit],
                       check=True)
        # The applying host's clock and git identity must not matter.
        subprocess.run([str(REPO / "tools" / "fport-apply.sh"), "kernel",
                        str(tree)], check=True, capture_output=True,
                       env={**os.environ, "KOOV_BUNDLE": str(patches),
                            "GIT_COMMITTER_DATE": date,
                            "GIT_COMMITTER_NAME": "host%d" % index})
        heads.append(subprocess.run(
            ["git", "-C", str(tree), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip())
    assert heads[0] == heads[1] != commit


# ------------------------------------------------------------ KCSAN variant

def _two_variants(host, **variant_kw):
    """The host's KASAN build plus a KCSAN build of the same tree, one spec
    for both (#81 D10)."""
    images = host.env / "images" / "kcsan"
    images.mkdir()
    _compile_vmlinux(host.env / "linux", images / "vmlinux")
    (images / "bzImage").write_bytes(b"synthetic kcsan bzImage")
    (images / ".config").write_text("CONFIG_KCOV=y\nCONFIG_KCSAN=y\n")
    (images / "build.json").write_text(json.dumps({
        "head": host.kernel_commit,
        "series_sha256": series_fingerprint("kernel")}))
    spec = json.loads(host.spec.read_text())
    del spec["variant"]
    spec["variants"] = [{"sanitizer": "kasan", **variant_kw.get("kasan", {})},
                        {"sanitizer": "kcsan", **variant_kw.get("kcsan", {})}]
    spec["policies"].append(policy("p-kcsan", sanitizer="kcsan").model_dump(
        mode="json"))
    host.spec.write_text(json.dumps(spec, indent=1))


@needs_gcc
def test_one_spec_generates_a_harness_per_variant(host):
    _two_variants(host)
    result = generate(host.spec)
    config = Stage1Config.load(result.stage1_config)
    store = ArtifactStore(config.artifact_root)
    from agent_pipeline.hcap import ArtifactHcapChecker
    from agent_pipeline.materializer import ExecutionHarnessApproval
    from agent_pipeline.registry import ArtifactHarnessRegistry
    descriptors = [load_record(store, ref, ExecutionHarnessApproval).descriptor
                   for ref in config.execution_harness_approvals]
    assert [d.sanitizer.value for d in descriptors] == ["kasan", "kcsan"]
    kasan, kcsan = descriptors
    builds = [{a.name: a.artifact_ref for a in d.build_artifacts}
              for d in descriptors]
    # The kernel build is the variant's own; the rest is shared.
    for name in ("bzimage", "instrumentation"):
        assert builds[0][name] != builds[1][name]
    for name in ("lane-script", "syz-executor", "vm-image"):
        assert builds[0][name] == builds[1][name]
    assert kasan.syzkaller_identity == kcsan.syzkaller_identity
    assert set(result.variants) == {"kasan", "kcsan"}
    assert result.execution_harness_id == \
        result.variants["kasan"].execution_harness_id
    ids = {v.execution_harness_id for v in result.variants.values()}
    hcaps = {v.hcap_revision for v in result.variants.values()}
    assert len(ids) == len(hcaps) == 2
    # The policy's sanitizer selects the binding.
    registry = ArtifactHarnessRegistry(store, config.harness_catalog_ref)
    for name, variant in result.variants.items():
        b = registry.lookup(host.kernel_commit, Sanitizer(name))
        assert (b.execution_harness_id, b.hcap_revision) == (
            variant.execution_harness_id, variant.hcap_revision)
    # Each HCAP names its own support boundary (its instrumentation).
    checker = ArtifactHcapChecker(store)
    versions = [checker.judge_versions(v.hcap_revision)
                for v in result.variants.values()]
    assert versions[0].judge_profile_id == versions[1].judge_profile_id
    assert versions[0].support_boundary_id != versions[1].support_boundary_id
    assert config.judge_versions == versions[0]
    collector = CollectorConfig.load(result.collector_config)
    assert "bzimage" not in collector.files
    assert collector.files_for(Sanitizer.KCSAN)["bzimage"] == \
        (host.env / "images" / "kcsan" / "bzImage").resolve()
    assert result.digests["kcsan:hcap"] == \
        result.variants["kcsan"].hcap_revision


@needs_gcc
def test_capability_evidence_belongs_to_its_variant(host):
    evidence = host.root / "kcsan-evidence.json"
    evidence.write_text('{"schema_version":"test-evidence.v1"}\n')
    _two_variants(host, kcsan={"capability_evidence": {
        "CAP-lane": ["kcsan-evidence.json"]}})
    result = generate(host.spec)
    from agent_pipeline.hcap import ArtifactHcapChecker
    checker = ArtifactHcapChecker(ArtifactStore(host.root / "cas"))

    def refs(name):
        catalog = checker.load_catalog(result.variants[name].hcap_revision)
        return next(c for c in catalog.capabilities
                    if c.id == "CAP-lane").evidence_refs
    assert refs("kasan") == ()
    assert len(refs("kcsan")) == 1


@pytest.mark.parametrize(("change", "message"), [
    ({"variant": "kasan"}, "variant or variants"),
    ({"capability_evidence": {"CAP-lane": ["x.json"]}},
     "belongs to each variant"),
    ({"variants": [{"sanitizer": "kcsan"}, {"sanitizer": "kcsan"}]},
     "listed twice"),
])
def test_variant_spec_errors(host, change, message):
    from agent_pipeline.stage1.host.generate import HostSpec
    spec = json.loads(host.spec.read_text())
    del spec["variant"]
    spec["variants"] = [{"sanitizer": "kasan"}]
    spec.update(change)
    with pytest.raises(ValidationError, match=message):
        HostSpec.model_validate_json(json.dumps(spec))


def test_a_policy_needs_a_generated_variant(host):
    spec = json.loads(host.spec.read_text())
    spec["policies"].append(policy("p-kcsan", sanitizer="kcsan").model_dump(
        mode="json"))
    host.spec.write_text(json.dumps(spec, indent=1))
    with pytest.raises(GenerationError, match="another sanitizer"):
        generate(host.spec)


KCSAN_REPORT = ("[   4.2] BUG: KCSAN: data-race in nfsd4_bind_conn / "
                "nfsd4_destroy_session\n")


@needs_gcc
def test_a_kcsan_harness_seals_a_kcsan_report(host, tmp_path):
    _two_variants(host)
    run = _collect(host, tmp_path / "kcsan", approval=1, pcs=["0x401000"],
                   console=KCSAN_REPORT)
    crash = _crash(run)
    assert crash.kind is CrashKind.KCSAN and crash.sanitizer is \
        Sanitizer.KCSAN
    assert crash.title.startswith("BUG: KCSAN: data-race in nfsd4_bind_conn")
    assert run.observation.runtime_errors == ()
    assert run.guest.config.bzimage == \
        (host.env / "images" / "kcsan" / "bzImage").resolve()
    # The same report on the KASAN harness is not a crash of its own.
    run = _collect(host, tmp_path / "kasan", approval=0, pcs=["0x401000"],
                   console=KCSAN_REPORT)
    assert _crash(run) is None


# ------------------------------------------------------------ Stage 2 manager

def _with_stage2(host, **stage2):
    spec = json.loads(host.spec.read_text())
    spec["stage2"] = stage2
    host.spec.write_text(json.dumps(spec, indent=1))


def _preflight_manager(host, result, path: Path) -> str:
    """The Stage 2 preflight's manager check on a generated config, against
    every generated harness."""
    from agent_pipeline.materializer import (ExecutionHarnessApproval,
                                             descriptor_id)
    from agent_pipeline.stage2.host import _approved_harness, _check_manager
    config = Stage1Config.load(result.stage1_config)
    store = ArtifactStore(config.artifact_root)
    descriptors = [load_record(store, ref, ExecutionHarnessApproval).descriptor
                   for ref in config.execution_harness_approvals]
    harnesses = tuple(_approved_harness(store, descriptor_id(d), d)
                      for d in descriptors)
    (host.env / "syzkaller" / "bin" / "syz-manager").chmod(0o755)
    command = SimpleNamespace(
        argv=("/bin/true", "--manager", str(path), "{input}", "{output}"),
        cwd=host.root)
    return _check_manager(
        path, 4, command=command,
        collector=CollectorConfig.load(result.collector_config),
        harnesses=harnesses, expected_target=config.syzkaller_identity.target,
        which=lambda _: "/bin/true")


@needs_gcc
def test_generate_writes_a_stage2_manager_the_preflight_accepts(host):
    # #81 D17: the manager is pinned to the Stage 1 collector's descriptor.
    _with_stage2(host, procs=2, nfs_proxy_window=6)
    result = generate(host.spec)
    path = result.stage2_managers["kasan"]
    assert path == host.root / "state" / "stage2-manager.json"
    manager = json.loads(path.read_text())
    # Every admitted call and every call the selection enables.
    assert manager["enable_syscalls"] == ["close", "openat$lane", "read$extra"]
    assert manager["procs"] == 2
    assert manager["experimental"] == {"remote_cover": True,
                                       "nfs_proxy_window": 6}
    collector = CollectorConfig.load(result.collector_config)
    assert manager["vm"]["kernel"] == str(collector.files["bzimage"])
    assert Path(manager["kernel_obj"]) / "vmlinux" == collector.files["kernel"]
    assert manager["image"] == str(collector.files["vm-image"])
    assert manager["sshkey"] == str(collector.ssh_key)
    lane = Path(manager["workdir_template"]) / "lane.sh"
    assert lane.read_bytes() == collector.files["lane-script"].read_bytes()
    cmdline = manager["vm"]["cmdline"].split()
    assert cmdline[:4] == ["root=/dev/sda", "console=ttyS0", "nokaslr",
                           "nfs.localio_enabled=N"]
    assert {"koov.nfs_version=4.1", "koov.nfs_trace=0",
            "koov.nfs_target=1"} <= set(cmdline)
    assert result.digests["stage2_manager"] == hashlib.sha256(
        path.read_bytes()).hexdigest()
    assert "2 proc(s)" in _preflight_manager(host, result, path)
    # Generating again keeps the frozen lane template.
    assert generate(host.spec).stage2_managers["kasan"].read_bytes() == \
        path.read_bytes()


@needs_gcc
def test_stage2_manager_calls_include_the_approved_calls(host):
    _with_stage2(host, enable_syscalls=["close", "write$known"])
    with pytest.raises(GenerationError,
                       match=r"lacks approved calls: openat\$lane, read\$extra"):
        generate(host.spec)
    _with_stage2(host, enable_syscalls=[
        "close", "openat$lane", "read$extra", "write$nope"])
    with pytest.raises(GenerationError, match=r"lacks: write\$nope"):
        generate(host.spec)
    _with_stage2(host, enable_syscalls=[
        "close", "openat$lane", "read$extra", "write$known"])
    manager = json.loads(generate(host.spec).stage2_managers["kasan"]
                         .read_text())
    assert manager["enable_syscalls"][-1] == "write$known"


@needs_gcc
def test_stage2_manager_boots_a_spec_runtime_selection(host):
    other = host.selection.model_copy(update={"nfs_version": "4.2",
                                              "profile": "knfsd-v42"})
    _with_stage2(host, runtime_selection=other.model_dump(mode="json"))
    with pytest.raises(GenerationError, match="not one of runtime_selections"):
        generate(host.spec)


@needs_gcc
def test_each_variant_gets_its_own_stage2_manager(host):
    _two_variants(host)
    _with_stage2(host)
    result = generate(host.spec)
    assert set(result.stage2_managers) == {"kasan", "kcsan"}
    kernels = set()
    for name, path in result.stage2_managers.items():
        assert path.name == f"stage2-manager-{name}.json"
        manager = json.loads(path.read_text())
        kernels.add(manager["vm"]["kernel"])
        # The preflight matches the manager to its own variant.
        assert "approved assets" in _preflight_manager(host, result, path)
        assert result.digests[f"{name}:stage2_manager"]
    assert len(kernels) == 2


def test_live_spec_manager_enables_the_live_bind_calls():
    # The live BIND path is the HCAP-14 syzlang calls (patch 0031); the
    # manager enables them as approved calls.
    from agent_pipeline.stage1.host.generate import HostSpec, _approved_calls
    spec = HostSpec.model_validate_json(
        (REPO / "stage1-host-live/host-spec.json").read_bytes())
    assert spec.stage2 is not None
    bind = next(c for c in spec.capabilities if c.id == "HCAP-14")
    (selection,) = spec.runtime_selections
    calls = {e.call for e in spec.admission_source.entries} | {
        i for i in selection.enabled_interfaces if i != "remote_cover"}
    table = SimpleNamespace(calls=tuple(sorted(calls)))
    approved = _approved_calls(spec.admission_source, table, selection)
    assert set(bind.interface.syz_calls) <= approved
    assert "write$nfs41_bind_conn_to_session" in approved
    assert "remote_cover" not in approved
