"""Identity and failure-evidence checks for the NFS lifecycle campaign."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import Sanitizer
from agent_pipeline.data import canonical_json, put_record
from agent_pipeline.hcap import RuntimeSelection
from agent_pipeline.materializer import (
    ExecutionHarnessDescriptor,
    HarnessBuildArtifact,
    descriptor_id,
)
from agent_pipeline.q1 import CandidateTarget, KernelIdentity, TargetPcMapping
from agent_pipeline.stage1.host.collector import CollectorConfig
from agent_pipeline.stage1.host.pins import pin_file


REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "tools/nfs-lifecycle/run.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("nfs_lifecycle_run", RUNNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_identity_inputs(tmp_path):
    runner = load_runner()
    store = ArtifactStore(tmp_path / "cas")
    file_names = (
        "bzimage", "kernel", "lane-script", "syz-execprog",
        "syz-executor", "vm-image",
    )
    files = {}
    artifacts = []
    lane_dir = tmp_path / "lane"
    lane_dir.mkdir()
    for name in file_names:
        path = (lane_dir / "lane.sh" if name == "lane-script"
                else tmp_path / name)
        path.write_bytes((name + " pinned bytes\n").encode())
        files[name] = path
        artifacts.append(HarnessBuildArtifact(
            name=name, artifact_ref=put_record(store, pin_file(name, path))))
    instrumentation_ref = store.put(b"instrumentation manifest")
    artifacts.append(HarnessBuildArtifact(
        name="instrumentation", artifact_ref=instrumentation_ref))
    artifacts.sort(key=lambda item: item.name)

    identity = SyzkallerTargetIdentity(
        syzkaller_commit="b" * 40,
        patch_series_sha256="1" * 64,
        build_manifest_sha256="2" * 64,
        call_table_sha256="3" * 64,
        target="linux/amd64")
    selection = RuntimeSelection(
        profile="knfsd-v41", nfs_version="4.1", fixture_mode="single",
        route="direct", topology="one-lane",
        enabled_interfaces=tuple(sorted(runner.ADMIN_REQUIRED_INTERFACES)),
        trace_mode="off")
    descriptor = ExecutionHarnessDescriptor(
        kernel_commit="a" * 40, sanitizer=Sanitizer.KASAN,
        syzkaller_identity=identity, build_artifacts=tuple(artifacts),
        guest_kernel_command_line=(
            "root=/dev/sda console=ttyS0 nokaslr nfs.localio_enabled=N"),
        allowed_runtime_selections=(selection,))
    descriptor_path = tmp_path / "descriptor.json"
    descriptor_path.write_text(descriptor.model_dump_json(indent=2))

    ssh_key = tmp_path / "ssh-key"
    ssh_key.write_text("private test key\n")
    config = CollectorConfig(
        artifact_root=store.root, files=files, ssh_key=ssh_key)
    config_path = tmp_path / "collector.json"
    config_path.write_text(config.model_dump_json(indent=2))

    builds = {item.name: item.artifact_ref
              for item in descriptor.build_artifacts}
    mapping_identity = KernelIdentity(
        execution_harness_id=descriptor_id(descriptor),
        kernel_commit=descriptor.kernel_commit,
        instrumentation_sha256=builds["instrumentation"],
        vmlinux_sha256=builds["kernel"],
        kaslr_enabled=False, kaslr_offset=0)
    mapping = TargetPcMapping(
        mapping_method="synthetic verified fixture", verified=True,
        target=CandidateTarget(
            candidate_id="private-candidate", kernel_commit="a" * 40,
            kind="function", path="fs/nfsd/private.c",
            symbol="private_symbol", start_line=10, end_line=20),
        identity=mapping_identity,
        target_pcs=(0xffffffff81001234,))
    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(mapping.model_dump_json(indent=2))
    return runner, config_path, descriptor_path, mapping_path, mapping


def test_admin_context_binds_mapping_to_verified_harness_without_leaking_target(
        tmp_path):
    runner, config, descriptor, mapping_path, _ = write_identity_inputs(
        tmp_path)
    context = runner.load_admin_context(config, descriptor, mapping_path)
    assert context.target_pcs == frozenset((0xffffffff81001234,))
    shareable = json.dumps(context.evidence_identity, sort_keys=True)
    for private in (
            "private-candidate", "fs/nfsd/private.c", "private_symbol",
            "0xffffffff81001234"):
        assert private not in shareable


def test_admin_context_refuses_mapping_from_another_harness(tmp_path):
    runner, config, descriptor, mapping_path, mapping = write_identity_inputs(
        tmp_path)
    bad = mapping.model_copy(update={
        "identity": mapping.identity.model_copy(update={
            "execution_harness_id": "e" * 64})})
    mapping_path.write_text(bad.model_dump_json(indent=2))
    with pytest.raises(RuntimeError, match="exact execution harness"):
        runner.load_admin_context(config, descriptor, mapping_path)


@pytest.mark.parametrize("raw", (
    "private-coverage-sentinel\n",
    "0x10000000000000000\n",
))
def test_coverage_parse_errors_do_not_reflect_private_input(raw):
    runner = load_runner()
    with pytest.raises(RuntimeError) as caught:
        runner.parse_cover(raw)
    assert raw.strip() not in str(caught.value)


def test_shareable_error_redacts_hex_addresses():
    runner = load_runner()
    rendered = runner.shareable_error(
        RuntimeError("coverage failed at 0xffffffff81001234"))
    assert "0xffffffff81001234" not in rendered
    assert rendered == "RuntimeError: coverage failed at <redacted-hex>"


class FailedExecGuest:
    def __init__(self, runner):
        self.runner = runner
        self.released = False

    def guest(self, command, timeout=60):
        if command.startswith("if test -f "):
            return "exited\n" if self.released else "ready\n"
        if command == self.runner.STATE_COMMAND:
            return ("owner 1 state COMMITTED outstanding_tokens 0 "
                    "active_roots 0\n")
        if command == self.runner.STATS_COMMAND:
            return "raw generation counters\n"
        if command.startswith("wc -l < "):
            return "4\n"
        if command == "touch %s.go" % self.runner.ADMIN_GATE:
            self.released = True
            return ""
        if command == "cat %s" % self.runner.ADMIN_RC:
            return "7\n"
        if command == "cat %s" % self.runner.ADMIN_LOG:
            return "executor failed after gate\n"
        if command.startswith("cat ") and command.endswith("/trace"):
            return "trace retained\n"
        if command.startswith("tail -n +"):
            return "lifecycle retained\n"
        if command.startswith("find /tmp/cov "):
            return "cover.0\ncover.extra\ncover.meta\n"
        if command == "cat /tmp/cov/cover.extra":
            return "0xffffffff81001234\n"
        if command == "cat /tmp/cov/cover.meta":
            return "completed_unix_nano 1\n"
        if command == "cat /tmp/cov/cover.0":
            return "0x1\n"
        return ""


def test_admin_exec_failure_retains_all_available_raw_artifacts(tmp_path):
    runner = load_runner()
    guest = FailedExecGuest(runner)
    with pytest.raises(RuntimeError, match="rc=7"):
        runner.run_admin_program(
            guest, tmp_path, "stimulus", 1, "/sys/kernel/tracing",
            {0xffffffff81001234})
    stem = "stimulus-001."
    expected = (
        "executor.log", "stats-before.txt", "stats-after.txt",
        "state-before.txt", "state-after.txt", "trace.txt",
        "lifecycle.log", "coverage-files.txt", "coverage.extra",
        "coverage.meta", "coverage.raw.cover.0",
        "coverage.raw.cover.extra", "coverage.raw.cover.meta",
    )
    for suffix in expected:
        assert (tmp_path / (stem + suffix)).is_file(), suffix
    assert "executor failed" in (
        tmp_path / (stem + "executor.log")).read_text()


class CompletedExecGuest(FailedExecGuest):
    """A program that exited cleanly and left ``cover`` in /tmp/cov."""

    def __init__(self, runner, cover):
        super().__init__(runner)
        self.cover = cover
        self.started = []

    def guest(self, command, timeout=60):
        if command.startswith("rm -rf /tmp/cov "):
            self.started.append(command)
            return ""
        if command == "cat %s" % self.runner.ADMIN_RC:
            return "0\n"
        if command.startswith("find /tmp/cov "):
            return "".join(name + "\n" for name in sorted(self.cover))
        if command.startswith("cat /tmp/cov/"):
            return self.cover[command[len("cat /tmp/cov/"):]]
        return super().guest(command, timeout)


def run_cover_program(runner, tmp_path, cover, **kwargs):
    guest = CompletedExecGuest(runner, cover)
    result = runner.run_program(
        guest, tmp_path, "stimulus", 1, "/sys/kernel/tracing",
        lambda artifacts, pcs: {"pcs": len(pcs)}, **kwargs)
    return guest, result


def test_run_program_exports_remote_cover_artifacts(tmp_path, monkeypatch):
    runner = load_runner()
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)
    cover = {"cover_prog1.extra": "0xffffffff81001234\n",
             "cover_prog1.meta": "unfinished_calls 0\n"}
    guest, result = run_cover_program(runner, tmp_path, cover)
    assert "-program-timeout" not in guest.started[0]
    assert result["pcs"] == 1
    assert result["coverage_files"] == sorted(cover)
    exported = sorted(path.name for path in tmp_path.iterdir()
                      if path.name.endswith((".extra", ".meta")))
    assert exported == ["stimulus-001.coverage.extra",
                        "stimulus-001.coverage.meta",
                        "stimulus-001.coverage.raw.cover_prog1.extra",
                        "stimulus-001.coverage.raw.cover_prog1.meta"]


@pytest.mark.parametrize(("meta", "message"), (
    ("unfinished_calls 4\n",
     "^execution: program stopped at its budget with 4 unfinished calls"),
    ("unfinished_calls 0\n",
     "^execution: remote-KCOV generation not published$"),
    ("completed_unix_nano 1\n", "^execution: .* predates 0029$"),
))
def test_unpublished_generation_is_a_typed_execution_failure(
        tmp_path, monkeypatch, meta, message):
    runner = load_runner()
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)
    cover = {"cover_prog1.0": "0x1\n", "cover_prog1.meta": meta}
    with pytest.raises(RuntimeError, match=message):
        run_cover_program(runner, tmp_path, cover)
    # The .meta is still retained as raw evidence.
    assert (tmp_path / "stimulus-001.coverage.meta").read_text() == meta
    assert not (tmp_path / "stimulus-001.coverage.extra").exists()


def test_admin_context_refuses_two_matching_runtime_selections(tmp_path):
    runner, config, descriptor_path, _, _ = write_identity_inputs(tmp_path)
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        descriptor_path.read_text())
    admin = descriptor.allowed_runtime_selections[0]
    extra = admin.model_copy(update={"enabled_interfaces": tuple(sorted(
        (*admin.enabled_interfaces, "syz_nfsd_cld_ctl$reconnect")))})
    descriptor = descriptor.model_copy(update={
        "allowed_runtime_selections": tuple(sorted(
            (admin, extra), key=lambda item: canonical_json(item)))})
    descriptor_path.write_text(descriptor.model_dump_json(indent=2))
    with pytest.raises(RuntimeError, match="must expose one exact"):
        runner.load_admin_context(config, descriptor_path, None)


RECOVER_SOURCE = """\
static void
nfsd4_cld_create(struct nfs4_client *clp)
{
\tint ret;

\tret = cld_pipe_upcall(cn->cn_pipe, &cup->cu_u.cu_msg, nn);
}
"""


@pytest.mark.parametrize(("source", "function", "part", "message"), [
    (RECOVER_SOURCE + RECOVER_SOURCE, "nfsd4_cld_create", "function",
     "definitions=2"),
    (RECOVER_SOURCE, "nfsd4_cld_create_v2", "function", "definitions=0"),
    (RECOVER_SOURCE.replace("}\n", ""), "nfsd4_cld_create", "function",
     "has no end"),
])
def test_probe_ranges_fail_closed(source, function, part, message):
    runner = load_runner()
    with pytest.raises(RuntimeError, match=message):
        runner.probe_range(source, function, part)
    with pytest.raises(ValueError, match="unknown probe part"):
        runner.probe_range(RECOVER_SOURCE, "nfsd4_cld_create", "error_report")


def test_probe_pcs_require_function_path_and_line():
    runner = load_runner()
    from agent_pipeline.stage1.host.target_pcs import Frame
    ranges = {"pipe_upcall": [{
        "path": "net/sunrpc/rpc_pipe.c", "function": "rpc_queue_upcall",
        "start_line": 145, "end_line": 153}]}
    frames = [
        (1, [Frame("rpc_queue_upcall", "/b/net/sunrpc/rpc_pipe.c", 146)]),
        (2, [Frame("rpc_queue_upcall", "/b/net/sunrpc/rpc_pipe.c", 142)]),
        (3, [Frame("other", "/b/net/sunrpc/rpc_pipe.c", 146)]),
        (4, [Frame("inner", "/b/include/x.h", 9),
             Frame("rpc_queue_upcall", "/b/net/sunrpc/rpc_pipe.c", 150)]),
        (5, [Frame("rpc_queue_upcall", "/b/net/sunrpc/other.c", 146)]),
    ]
    assert runner.select_probe_pcs(frames, ranges) == {"pipe_upcall": {1, 4}}


GRANT_SOURCE = """\
__be32 nlmclnt_grant(const struct sockaddr *addr, const struct lockd_lock *lock);

__be32 nlmclnt_grant(const struct sockaddr *addr, const struct lockd_lock *lock)
{
\tint res = 0;

\ttrace_nlmclnt_grant(lock, addr, svc_addr_len(addr), res);
\treturn res;
}
"""


def test_probe_range_accepts_a_return_type_before_the_name():
    runner = load_runner()
    assert runner.probe_range(GRANT_SOURCE, "nlmclnt_grant", "function") == (
        3, 9)
    ranges = runner.probe_ranges(
        {"fs/lockd/clntlock.c": GRANT_SOURCE}.__getitem__,
        {"clnt_grant": runner.NLM_PROBES["clnt_grant"]})
    assert [(item["function"], item["start_line"], item["end_line"])
            for item in ranges["clnt_grant"]] == [("nlmclnt_grant", 3, 9)]


def nlm_run(**hits):
    probes = dict.fromkeys(load_runner().NLM_PROBES, 0)
    probes.update(hits)
    return {"probe_hits": probes, "status_check": "pass",
            "generation": {"remote_start_ok": 2}}


NLM_GOOD = {
    "control": nlm_run(),
    "lock": nlm_run(svc_lock=1, svc_unlock=1),
    "rpc": nlm_run(svc_lock=1, svc_unlock=1, svc_testlock=1, svc_share=1),
    "blocked": nlm_run(svc_lock=1, svc_unlock=1, clnt_grant=1,
                       svc_grant_blocked=1, svc_grant_callback=1),
}


@pytest.mark.parametrize(("phase", "run", "message"), [
    ("control", nlm_run(svc_testlock=1), "control reached lockd probe"),
    ("lock", nlm_run(svc_lock=1), "lock run missed svc_unlock"),
    ("lock", nlm_run(svc_lock=1, svc_unlock=1, clnt_grant=1),
     "grant callback"),
    ("rpc", nlm_run(svc_lock=1, svc_unlock=1, svc_testlock=1),
     "rpc run missed svc_share"),
    ("lock", nlm_run(svc_lock=1, svc_unlock=1, svc_grant_blocked=1),
     "grant callback"),
    ("blocked", nlm_run(svc_lock=1, svc_unlock=1, svc_grant_blocked=1,
                        svc_grant_callback=1), "missed clnt_grant"),
    ("blocked", nlm_run(svc_lock=1, svc_unlock=1, clnt_grant=1,
                        svc_grant_callback=1), "missed svc_grant_blocked"),
    ("blocked", nlm_run(svc_lock=1, svc_unlock=1, clnt_grant=1,
                        svc_grant_blocked=1), "missed svc_grant_callback"),
])
def test_nlm_runs_fail_closed(phase, run, message):
    runner = load_runner()
    with pytest.raises(RuntimeError, match=message):
        runner.check_nlm_run(phase, run)


def test_nlm_campaign_uses_the_nlm_selection_and_types_its_evidence(
        tmp_path):
    runner, config, descriptor_path, _, _ = write_identity_inputs(tmp_path)
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        descriptor_path.read_text())
    admin = descriptor.allowed_runtime_selections[0]
    nlm = RuntimeSelection(
        profile="knfsd-v3", nfs_version="3", fixture_mode="nlm-knfsd",
        route="direct", topology="one-lane",
        enabled_interfaces=tuple(sorted(runner.NLM_REQUIRED_INTERFACES)),
        trace_mode="off")
    descriptor = descriptor.model_copy(update={
        "allowed_runtime_selections": tuple(sorted(
            (admin, nlm), key=lambda item: canonical_json(item)))})
    descriptor_path.write_text(descriptor.model_dump_json(indent=2))
    context = runner.load_admin_context(
        config, descriptor_path, None,
        required=runner.NLM_REQUIRED_INTERFACES, profile="knfsd-v3",
        nfs_version="3", fixture_mode=runner.NLM_FIXTURE)
    assert context.selection == nlm
    with pytest.raises(RuntimeError, match="knfsd-v3 single"):
        runner.load_admin_context(
            config, descriptor_path, None,
            required=runner.NLM_REQUIRED_INTERFACES, profile="knfsd-v3",
            nfs_version="3")
    for phase, run in NLM_GOOD.items():
        runner.check_nlm_run(phase, run)
    cycles = {phase: [run] * 3 for phase, run in NLM_GOOD.items()}
    guest = {"guest_lane_script_sha256": "4" * 64,
             "guest_nfs_proxy_sha256": "5" * 64}
    digests = {name: "6" * 64 for name in runner.NLM_PROBES}
    evidence = runner.hcap13_evidence(
        context, guest, digests, cycles, b'{"status": "pass"}\n', 0, 0)
    assert evidence.capability_id == "HCAP-13"
    assert evidence.runs.blocked.probe_hits.clnt_grant == (1, 1, 1)
    assert evidence.generation_contract.minimum_remote_start_ok == 2
    with pytest.raises(ValueError, match="private target data"):
        runner.hcap13_evidence(
            context, guest, digests, cycles,
            b'{"pc": "0xffffffff81001234"}\n', 0, 0)


def test_nlm_programs_use_only_lane_profile_and_nlm_calls():
    runner = load_runner()
    allowed = {"close", "fcntl$lock", "getdents64", "nanosleep",
               *runner.NLM_REQUIRED_INTERFACES} - {"remote_cover"}
    for phase, path in runner.NLM_PROGRAMS.items():
        calls = [line.split("(", 1)[0].split("= ")[-1]
                 for line in path.read_text().splitlines()]
        calls = [call.replace("recvfrom$inet_nlm_tcp", "close")
                 for call in calls]
        assert set(calls) <= allowed, phase
        assert "0x7, " not in path.read_text(), "F_SETLKW in %s" % phase
