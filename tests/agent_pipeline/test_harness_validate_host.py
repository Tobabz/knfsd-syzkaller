"""07 §5.2: the host validation command, on a bootstrap-shaped env.

Real: the patch application and path checks, the build step under a
launcher, staged generation (``generate`` with ``StagedBase``), the copy of
the staged host files, the collector's run of each program, and the
``CommandValidator`` that takes the report into the CAS.  Scripted: the
guests (``host_fakes``), the build script (it copies the base env) and the
boundary PCs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import GapClass, GapRef, Sanitizer
from agent_pipeline.controller.generation import ValidationInput
from agent_pipeline.data import load_record, put_record
from agent_pipeline.hcap import HcapCatalog
from agent_pipeline.materializer import (ExecutionHarnessApproval,
                                         StaticExecutionHarnessAuthority)
from agent_pipeline.stage1.config import Stage1Config
from agent_pipeline.stage1.host.collector import (CollectorConfig,
                                                  verify_pins)
from agent_pipeline.stage1.host.generate import generate
from agent_pipeline.stage1.host.validate import ValidateConfig, validate
from agent_pipeline.stage1.validation import (CommandValidator,
                                              CommandValidatorConfig,
                                              StagedExecutionHarnessAuthority,
                                              ValidationStore)

from .host_fakes import FakeGuest
from .test_stage1_host import _git, _mark_legacy, host, needs_gcc  # noqa: F401

pytestmark = [needs_gcc, pytest.mark.skipif(sys.platform != "linux",
                                            reason="Linux")]

REPO = Path(__file__).resolve().parents[2]
GAP_ID = "fixture.nfs4.lock_owner"
GAP = GapRef(gap_class=GapClass.FIXTURE_OR_TOOL, missing_capability_id=GAP_ID)
CONTRACT = {"entry_points": [{"kind": "fixture_action",
                              "name": "lock_owner"}],
            "boundary_functions": ["target"]}
BOUNDARY_PC = 0x4242
SMOKE = b"synthetic lock owner smoke\n"

# The operator's build script: the patch set changes no build input here,
# so it reuses the base env and parser bundle.
BUILD = r'''
import shutil, sys
from pathlib import Path
tree, env, base_env, bundle = map(Path, sys.argv[1:5])
assert (tree / "stage1-host" / "host-spec.json").is_file()
for name in ("linux", "images", "syzkaller"):
    shutil.copytree(base_env / name, env / name, symlinks=True)
shutil.copytree(bundle, env / "syz-bridge")
# The patch set's kernel: a new image, the rest as the base built it.
(env / "images" / "kasan" / "bzImage").write_bytes(b"rebuilt bzImage")
print("built", env)
'''


def _capability(**change) -> dict:
    return {"id": "CAP-lock-owner", "name": "Lock owner fixture",
            "purpose": "Hold a lock owner across clients",
            "usable_stage": ["stage1"], "usable_by": ["agent_stage1"],
            "interface": {"runtime_features": ["lock_owner"]},
            "status": "experimental", "scope": ["lock_owner"],
            "fills_gap": GAP_ID, "contract": CONTRACT, **change}


class World:
    def __init__(self, host, tmp_path, monkeypatch) -> None:
        self.host = host
        spec = json.loads(host.spec.read_text())
        spec["missing_capability_ids"] = [GAP_ID]
        spec["gap_contracts"] = [{"missing_capability_id": GAP_ID,
                                  "contract": CONTRACT}]
        host.spec.write_text(json.dumps(spec, indent=1))
        _mark_legacy(monkeypatch, spec)
        self.spec = spec
        # The host's generated harness: the base binding.
        self.base = generate(host.spec)
        self.config = Stage1Config.load(self.base.stage1_config)
        self.store = ArtifactStore(self.config.artifact_root)
        self.collector = CollectorConfig.load(self.base.collector_config)
        approval = load_record(self.store,
                               self.config.execution_harness_approvals[0],
                               ExecutionHarnessApproval)
        self.approval = approval
        # The host's clone: the data a patch set starts from.
        self.repo = tmp_path / "clone"
        for part in ("bundle/patches", "bundle/lane"):
            shutil.copytree(REPO / part, self.repo / part)
        tree_spec = dict(spec, neutral_controls=[
            dict(spec["neutral_controls"][0], program="neutral.syz")])
        (self.repo / "stage1-host").mkdir()
        (self.repo / "stage1-host" / "host-spec.json").write_text(
            json.dumps(tree_spec, indent=1))
        shutil.copy(host.root / "neutral.syz",
                    self.repo / "stage1-host" / "neutral.syz")
        _git(self.repo, "init", "-q")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-qm", "base")
        self.commit = _git(self.repo, "rev-parse", "HEAD")
        (tmp_path / "build.py").write_text(BUILD)
        self.tmp = tmp_path
        self.validate_config = ValidateConfig(
            repo=self.repo, work_root=tmp_path / "validation-work",
            base_spec=host.spec, collector=self.base.collector_config,
            build_argv=(sys.executable, "-I", str(tmp_path / "build.py"),
                        "{tree}", "{env}", "{base_env}",
                        str(host.root / "syz-build")),
            launcher=("/usr/bin/env",), keep_work=True)
        self.guests: list[FakeGuest] = []

    def patch(self, *, capability=None, smoke=SMOKE, extra=None,
              links=None) -> bytes:
        """The diff a generation worktree would give."""
        work = self.tmp / f"worktree-{len(list(self.tmp.glob('worktree-*')))}"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(work)],
                       check=True)
        spec_path = work / "stage1-host" / "host-spec.json"
        spec = json.loads(spec_path.read_text())
        if capability is not False:
            spec["capabilities"].append(capability or _capability())
        spec_path.write_text(json.dumps(spec, indent=1))
        if smoke is not None:
            path = work / "stage1-host" / "generation" / GAP_ID / "smoke.syz"
            path.parent.mkdir(parents=True)
            path.write_bytes(smoke)
        for name, data in (extra or {}).items():
            (work / name).parent.mkdir(parents=True, exist_ok=True)
            (work / name).write_bytes(data)
        for name, target in (links or {}).items():
            (work / name).symlink_to(target)
        _git(work, "add", "-A")
        return subprocess.run(["git", "-C", str(work), "diff", "--cached",
                               "--binary"], check=True,
                              capture_output=True).stdout

    def inputs(self, diff: bytes, name="in", gap: GapRef = GAP) -> Path:
        inp = self.tmp / name
        inp.mkdir()
        files = sorted({line.split(" b/", 1)[1] for line in
                        diff.decode().splitlines()
                        if line.startswith("diff --git ")})
        b = self.approval.descriptor
        task = {"task_id": "gen-1.a1.v1", "generation_id": "gen-1",
                "gap": gap.model_dump(mode="json"),
                "kernel_commit": b.kernel_commit, "sanitizer": "kasan",
                "base_binding": {
                    "kernel_commit": b.kernel_commit, "sanitizer": "kasan",
                    "execution_harness_id": self.base.execution_harness_id,
                    "hcap_revision": self.base.hcap_revision},
                "patch_set_ref": "0" * 64}
        (inp / "validation.json").write_text(json.dumps(task))
        (inp / "patch_set.json").write_text(json.dumps({
            "generation_id": "gen-1", "task_id": "gen-1.a1", "attempt": 1,
            "gap": gap.model_dump(mode="json"), "base_commit": self.commit,
            "patch_ref": "1" * 64, "files": files, "summary": "lock owner"}))
        (inp / "patch.diff").write_bytes(diff)
        (inp / "base_hcap.json").write_bytes(
            self.store.get(self.base.hcap_revision))
        return inp

    def factory(self, smoke_pcs=(BOUNDARY_PC,), neutral_pcs=(), **fake):
        def make(vm):
            label = Path(vm.console_log).parent.name
            pcs = smoke_pcs if label.startswith("smoke") else neutral_pcs
            guest = FakeGuest(vm, pcs=[f"0x{pc:x}" for pc in pcs], **fake)
            self.guests.append(guest)
            return guest
        return make

    def run(self, diff, *, out="out", gap: GapRef = GAP,
            **kw) -> tuple[dict, Path]:
        inp = self.inputs(diff, name=f"{out}-in", gap=gap)
        outdir = self.tmp / out
        outdir.mkdir()
        report = validate(self.validate_config, inp, outdir,
                          guest_factory=self.factory(**kw),
                          sleep=lambda s: None,
                          boundary_pcs=lambda vmlinux, fns, sha:
                          (BOUNDARY_PC,) if "target" in fns else ())
        return report, outdir


@pytest.fixture
def world(host, tmp_path):
    return World(host, tmp_path, host.monkeypatch)


def test_a_patch_set_is_staged_on_the_new_build(world):
    report, out = world.run(world.patch())
    assert report["result"] == "passed", (report, (out / "end.log").read_text()
                                          if (out / "end.log").exists()
                                          else None)
    hcap = HcapCatalog.model_validate_json((out / "hcap.json").read_bytes())
    by_id = {c.id: c for c in hcap.capabilities}
    assert by_id["CAP-lock-owner"].status == "experimental"
    # The capabilities the patch set kept are the base HCAP's entries.
    base = HcapCatalog.model_validate_json(
        world.store.get(world.base.hcap_revision))
    for c in base.capabilities:
        assert by_id[c.id] == c
    runs = json.loads((out / "runs.json").read_text())
    assert [r["label"] for r in runs] == ["smoke-0", "neutral"]
    assert runs[0]["boundary_hits"] == 1 and runs[1]["boundary_hits"] == 0
    labels = {a["identity"] for a in report["artifacts"]}
    assert {"build-log", "runs", "staged-object",
            "smoke-0-console"} <= labels
    # The staged files are where the service's collector finds them.
    from agent_pipeline.materializer import ExecutionHarnessDescriptor
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        (out / "descriptor.json").read_bytes())
    files = verify_pins(world.collector.model_copy(update={
        "artifact_root": world.tmp / "validation-work" / "gen-1.a1.v1"
        / "cas"}), descriptor)
    assert all(p.is_file() for p in files.values())
    staged = world.collector.staged_files
    assert files["bzimage"].is_relative_to(staged)
    assert files["bzimage"].read_bytes() == b"rebuilt bzImage"
    # Unchanged files boot from where the service has them.
    configured = world.collector.files_for(Sanitizer.KASAN)
    assert files["vm-image"] == configured["vm-image"]
    assert [p.name for p in staged.iterdir()] == [
        descriptor_pin(world, out, "bzimage")]


def descriptor_pin(world, out, name) -> str:
    from agent_pipeline.materializer import ExecutionHarnessDescriptor
    from agent_pipeline.stage1.host.pins import HostFilePin
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        (out / "descriptor.json").read_bytes())
    ref = next(a.artifact_ref for a in descriptor.build_artifacts
               if a.name == name)
    return HostFilePin.model_validate_json((out / f"cas-{ref}").read_bytes()
                                           ).sha256


def test_the_validator_takes_the_report_into_the_cas(world):
    """The whole command under CommandValidator: a pass stages the HCAP
    and the build in the service's CAS, and the staged authority approves
    it."""
    diff = world.patch()
    store = world.store
    patch_ref = store.put(diff)
    from agent_pipeline.agent_tasks.generation import HarnessPatchSet
    patch_set = HarnessPatchSet(
        generation_id="gen-1", task_id="gen-1.a1", attempt=1, gap=GAP,
        base_commit=world.commit, patch_ref=patch_ref,
        files=("stage1-host/generation/fixture.nfs4.lock_owner/smoke.syz",
               "stage1-host/host-spec.json"), summary="lock owner")
    b = world.approval.descriptor
    from agent_pipeline.contracts import HarnessBinding
    base_binding = HarnessBinding(
        kernel_commit=b.kernel_commit, sanitizer=Sanitizer.KASAN,
        execution_harness_id=world.base.execution_harness_id,
        hcap_revision=world.base.hcap_revision)
    task_input = ValidationInput(
        generation_id="gen-1", gap=GAP, kernel_commit=b.kernel_commit,
        sanitizer=Sanitizer.KASAN, base_binding=base_binding,
        patch_set_ref=put_record(store, patch_set))
    config_path = world.tmp / "validate.json"
    config_path.write_text(world.validate_config.model_dump_json())
    # The fake guest and boundary PCs come from a wrapper module.
    wrapper = world.tmp / "run_validate.py"
    wrapper.write_text(WRAPPER.format(repo=str(REPO),
                                      tests=str(Path(__file__).parent),
                                      pc=BOUNDARY_PC))
    state = world.tmp / "service-state"
    state.mkdir()
    vstore = ValidationStore(state / "validations.sqlite")
    validator = CommandValidator(CommandValidatorConfig(
        argv=(sys.executable, "-I", str(wrapper), str(config_path),
              "{input}", "{output}"),
        cwd=world.tmp, work_root=state / "validation-runs",
        resource_key="validate"), vstore, store, state / "validation.lock")
    try:
        validator.submit("gen-1.a1.v1", task_input)
        assert validator.wait(120)
        st = validator.status("gen-1.a1.v1")
        assert st.state == "passed", (st, (state / "validation-runs" /
                                           "gen-1.a1.v1" / "process.log")
                                      .read_text())
        authority = StagedExecutionHarnessAuthority(
            StaticExecutionHarnessAuthority((world.approval,)), vstore, store)
        approval = authority.resolve(st.binding)
        assert approval is not None
        assert st.binding.hcap_revision in approval.approved_hcap_revisions
    finally:
        validator.close()
        vstore.close()


WRAPPER = r'''
import sys
sys.path.insert(0, {repo!r})
from pathlib import Path
from agent_pipeline.stage1.host.validate import ValidateConfig, validate
sys.path.insert(0, {tests!r})
from host_fakes import FakeGuest

def factory(vm):
    smoke = Path(vm.console_log).parent.name.startswith("smoke")
    return FakeGuest(vm, pcs=["0x{pc:x}"] if smoke else [])

config, inp, out = sys.argv[1:4]
report = validate(ValidateConfig.load(Path(config)), Path(inp), Path(out),
                  guest_factory=factory, sleep=lambda s: None,
                  boundary_pcs=lambda v, f, s: ({pc},))
print(report["result"], report.get("reason"))
'''


@pytest.mark.parametrize("change,reason", [
    ({"smoke": None}, "smoke_missing"),
    ({"capability": False}, "generate_refused"),
    ({"capability": _capability(status="validated")}, "generate_refused"),
    ({"capability": _capability(fills_gap=None)}, "generate_refused"),
    ({"extra": {"agent_pipeline/judge.py": b"x = 1\n"}},
     "patch_outside_allowed_paths"),
    ({"extra": {"bundle/lane/boot-fixture.sh": b"#!/bin/sh\n"}},
     "unpinned_lane_file"),
])
def test_what_a_patch_set_is_rejected_for(world, change, reason):
    report, out = world.run(world.patch(**change))
    assert (report["result"], report["reason"]) == ("rejected", reason)


def test_a_link_in_the_patch_set_is_rejected(world):
    report, _ = world.run(world.patch(
        links={"stage1-host/secret.syz": "/etc/hostname"}))
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "symlink_in_patch")


def test_a_build_file_linked_out_of_the_env_is_rejected(world):
    """The generation user writes the env; a host file it links to outside
    the validation's work directory is not copied to the staged files."""
    (world.tmp / "build.py").write_text(BUILD + r'''
image = env / "images" / "kasan" / "bzImage"
image.unlink()
elsewhere = env.parent.parent.parent / "service-only"
elsewhere.write_bytes(b"a file of the service")
image.symlink_to(elsewhere)
''')
    report, _ = world.run(world.patch())
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "build_file_outside_env")


def test_a_smoke_that_misses_the_boundary_is_rejected(world):
    report, _ = world.run(world.patch(), smoke_pcs=())
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "smoke_unreached")


def test_a_neutral_control_that_reaches_the_boundary_is_rejected(world):
    report, _ = world.run(world.patch(), neutral_pcs=(BOUNDARY_PC,))
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "neutral_reached")


def test_a_broken_fixture_is_the_patch_sets(world):
    report, _ = world.run(world.patch(), fixture="failed")
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "bootstrap_failed")


def test_a_guest_that_does_not_boot_is_inconclusive(world):
    report, _ = world.run(world.patch(), boot_error="qemu: no kvm")
    assert (report["result"], report["reason"]) == ("inconclusive",
                                                    "vm_boot_failed")


def test_a_failed_build_is_rejected_with_its_log(world):
    (world.tmp / "build.py").write_text("raise SystemExit('cc: error')\n")
    report, out = world.run(world.patch())
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "build_failed")
    assert b"cc: error" in (out / "build.log").read_bytes()


def test_a_patch_that_does_not_apply_is_rejected(world):
    report, _ = world.run(b"diff --git a/stage1-host/x b/stage1-host/x\n"
                          b"--- a/stage1-host/x\n+++ b/stage1-host/x\n"
                          b"@@ -1 +1 @@\n-old\n+new\n")
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "patch_does_not_apply")


def test_a_gap_without_a_vocabulary_contract_is_inconclusive(world):
    hcap = HcapCatalog.model_validate_json(
        world.store.get(world.base.hcap_revision))
    diff = world.patch()
    inp = world.inputs(diff, name="nocontract-in")
    (inp / "base_hcap.json").write_bytes(json.dumps(hcap.model_copy(update={
        "gap_contracts": ()}).model_dump(mode="json")).encode())
    out = world.tmp / "nocontract"
    out.mkdir()
    report = validate(world.validate_config, inp, out,
                      guest_factory=world.factory())
    assert (report["result"], report["reason"]) == ("inconclusive",
                                                    "gap_contract_missing")


def test_the_collector_boots_a_staged_file_by_its_pin(world, tmp_path):
    """A descriptor whose pin the configured file does not match boots the
    staged copy of that digest; without one, the pin check still fails."""
    from agent_pipeline.stage1.host.collector import staged_path
    from agent_pipeline.stage1.host.pins import HostFilePin, pin_file
    from agent_pipeline.stage1.host.pins import PinError
    descriptor = world.approval.descriptor
    image = tmp_path / "new-bzImage"
    image.write_bytes(b"staged bzImage")
    pin = pin_file("bzimage", image)
    builds = tuple(a if a.name != "bzimage" else a.model_copy(update={
        "artifact_ref": put_record(world.store, pin)})
        for a in descriptor.build_artifacts)
    staged = descriptor.model_copy(update={"build_artifacts": builds})
    with pytest.raises(PinError):
        verify_pins(world.collector, staged)
    configured = world.collector.files_for(Sanitizer.KASAN)["bzimage"]
    dest = staged_path(world.collector.staged_files, pin, configured)
    dest.parent.mkdir(parents=True)
    shutil.copy(image, dest)
    files = verify_pins(world.collector, staged)
    assert files["bzimage"] == dest
    assert load_record(world.store, builds[[a.name for a in builds]
                                           .index("bzimage")].artifact_ref,
                       HostFilePin) == pin
    # The base descriptor still boots the configured files.
    assert verify_pins(world.collector, descriptor)["bzimage"] == configured


def test_the_build_script_must_be_an_absolute_path():
    with pytest.raises(ValueError):
        ValidateConfig(repo="/r", work_root="/w", base_spec="/s",
                       collector="/c", build_argv=("build",),
                       launcher=("/usr/bin/env",))


# -- generate's generation section and the build step ------------------------

def _with_generation(host, monkeypatch, **generation) -> None:
    import agent_pipeline.stage1.host.generate as generate_module
    spec = json.loads(host.spec.read_text())
    spec["generation"] = generation
    host.spec.write_text(json.dumps(spec, indent=1))
    _mark_legacy(monkeypatch, spec)
    # The spec must be inside the clone; here the clone is the fixture.
    monkeypatch.setattr(generate_module, "REPO", host.root)


def test_generate_writes_the_generation_configs(host, monkeypatch):
    _with_generation(host, monkeypatch, launcher=["/usr/bin/env"],
                     build_args=["--go", "/opt/go/bin/go"])
    out = generate(host.spec)
    config = Stage1Config.load(out.stage1_config)
    g = config.generation
    state = out.stage1_config.parent
    assert (g.repo, g.worktree_root, g.launcher) == (
        host.root, state / "generation-worktrees", ("/usr/bin/env",))
    argv = g.validation.argv
    assert argv[1:5] == ("-m", "agent_pipeline.stage1.host", "validate",
                         "--config")
    v = ValidateConfig.model_validate_json(Path(argv[5]).read_bytes())
    assert v.repo == host.root and v.base_spec == host.spec
    assert v.spec == str(host.spec.relative_to(host.root))
    assert v.collector == out.collector_config
    assert v.work_root == state / "validation-work"
    assert v.launcher == ("/usr/bin/env",)
    assert v.build_argv[1].endswith("tools/harness-generation-build.py")
    assert v.build_argv[2:5] == ("{tree}", "{env}", "{base_env}")
    assert "{sanitizer}" in v.build_argv
    assert v.build_argv[-2:] == ("--go", "/opt/go/bin/go")
    # The promotion probe campaign reads this stage1.json and collector.
    c = g.campaign
    assert c.argv[1:5] == ("-m", "agent_pipeline.stage1.host",
                           "probe-campaign", "--config")
    assert c.argv[5:] == ("{input}/campaign.json", "{output}")
    assert (c.stage1, c.collector, c.cwd) == (
        out.stage1_config, out.collector_config, host.root)


def test_the_default_launcher_needs_the_setup_script(host, monkeypatch):
    from agent_pipeline.stage1.host.generate import GenerationError
    _with_generation(host, monkeypatch, user="no-such-gen-user")
    with pytest.raises(GenerationError, match="setup-generation-user.sh"):
        generate(host.spec)


def test_a_generation_spec_outside_the_clone_is_refused(host, monkeypatch):
    import agent_pipeline.stage1.host.generate as generate_module
    from agent_pipeline.stage1.host.generate import GenerationError
    _with_generation(host, monkeypatch, launcher=["/usr/bin/env"])
    monkeypatch.setattr(generate_module, "REPO", host.root / "elsewhere")
    with pytest.raises(GenerationError, match="in this repository"):
        generate(host.spec)


def _build_tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "harness_generation_build",
        REPO / "tools" / "harness-generation-build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_build_step_reuses_the_base_env_when_no_input_changed(tmp_path):
    tool = _build_tool()
    host, tree = tmp_path / "host", tmp_path / "tree"
    for root in (host, tree):
        (root / "bundle" / "patches" / "kernel").mkdir(parents=True)
        (root / "bundle" / "patches" / "kernel" / "0001.patch").write_text(
            "kernel\n")
        (root / "bundle" / "lane").mkdir(parents=True)
        (root / "bundle" / "lane" / "lane.sh").write_text("lane\n")
        (root / "stage1-host").mkdir()
    (tree / "stage1-host" / "host-spec.json").write_text("{}")
    assert tool.changed(tree, host) == []
    (tree / "bundle" / "lane" / "lane.sh").write_text("new lane\n")
    assert tool.changed(tree, host) == ["image"]
    (tree / "bundle" / "patches" / "kernel" / "0002.patch").write_text("x\n")
    assert tool.changed(tree, host) == ["kernel", "image"]

    (tree / "bundle" / "lane" / "lane.sh").write_text("lane\n")
    (tree / "bundle" / "patches" / "kernel" / "0002.patch").unlink()
    base_env, bundle = tmp_path / "base-env", tmp_path / "syz-bridge" / "bundle"
    for name in ("linux", "images", "syzkaller"):
        (base_env / name).mkdir(parents=True)
    bundle.mkdir(parents=True)
    env = tmp_path / "env"
    env.mkdir()
    tool.HOST = host
    tool.changed.__defaults__ = (host,)
    assert tool.main([str(tree), str(env), str(base_env),
                      "--base-bundle", str(bundle)]) == 0
    assert (env / "linux").resolve() == base_env / "linux"
    assert (env / "syz-bridge" / "bundle").resolve() == bundle


# ---------------------------------------------------------------- mutation_engine

SEMANTIC_GAP = GapRef(gap_class=GapClass.MUTATION_ENGINE,
                      missing_capability_id="mutation_engine.unlisted")
SEMANTIC_DIR = f"stage1-host/generation/{SEMANTIC_GAP.missing_capability_id}"


def _semantic_patch(world, **over):
    files = {f"{SEMANTIC_DIR}/subset.json": b"{}",
             f"{SEMANTIC_DIR}/rules.nfsprul1": b"NFSPRUL1",
             f"{SEMANTIC_DIR}/production.syz": b"getpid()\n",
             "bundle/src/nfs-proxy-lane": b"the patch set's guest Proxy\n"}
    files.update(over)
    return world.patch(capability=False, smoke=None,
                       extra={k: v for k, v in files.items() if v is not None})


def test_a_mutation_engine_patch_set_is_pinned_in_hcap10(world, monkeypatch):
    """M7 stage 1 (03-nfs-proxy/06 §30): no smoke, the regression, then the
    staged pin, whose registry the staged HCAP-10 references."""
    import agent_pipeline.stage1.host.semantic as semantic
    from .test_stage2_host import _build
    _, promoted = _build()
    pinned = promoted.model_copy(update={"subsets": tuple(
        p.model_copy(update={"crash_survival": "pending"})
        for p in promoted.subsets)})
    seen = {}

    def fake_pin(store, proxy, inputs, guest, work, **kw):
        seen.update(proxy=proxy.read_bytes(), program=inputs.program.name,
                    guest=guest, **kw)
        return pinned, "e" * 64

    monkeypatch.setattr(semantic, "read_inputs", lambda d: SimpleNamespace(
        subset=pinned.subsets[0].subset, program=d / "production.syz"))
    monkeypatch.setattr(semantic, "staged_pin", fake_pin)
    report, out = world.run(_semantic_patch(world), gap=SEMANTIC_GAP)
    assert report["result"] == "passed", report
    assert seen["proxy"] == b"the patch set's guest Proxy\n"
    assert seen["launcher"] == world.validate_config.launcher
    assert "koov.nfs_target=1" in seen["guest"].cmdline
    hcap = HcapCatalog.model_validate_json((out / "hcap.json").read_bytes())
    entry = next(c for c in hcap.capabilities if c.id == "HCAP-10")
    assert any("Crash survival pending" in c for c in entry.constraints)
    runs = json.loads((out / "runs.json").read_text())
    assert [r["label"] for r in runs][-1] == "semantic"
    assert not any(r["label"].startswith("smoke") for r in runs)


@pytest.mark.parametrize("over,reason", [
    ({"bundle/src/nfs-proxy-lane": None}, "proxy_missing"),
    ({f"{SEMANTIC_DIR}/subset.json": None}, "semantic_input_missing"),
])
def test_what_a_mutation_engine_patch_set_is_rejected_for(world, over, reason):
    report, _ = world.run(_semantic_patch(world, **over), gap=SEMANTIC_GAP)
    assert (report["result"], report["reason"]) == ("rejected", reason)


def test_a_mutation_engine_patch_set_adds_no_spec_capability(world):
    diff = world.patch(smoke=None, capability=_capability(
        fills_gap=SEMANTIC_GAP.missing_capability_id, contract=None))
    report, _ = world.run(diff, gap=SEMANTIC_GAP)
    assert (report["result"], report["reason"]) == ("rejected",
                                                    "generate_refused")


def test_a_changed_proxy_is_built_and_baked_into_the_guest_deps(tmp_path):
    import io
    import tarfile
    tool = _build_tool()
    host, tree = tmp_path / "host", tmp_path / "tree"
    for root in (host, tree):
        (root / "tools" / "nfs-proxy" / "src").mkdir(parents=True)
        (root / "tools" / "nfs-proxy" / "src" / "rule.c").write_text("old\n")
    assert tool.changed(tree, host) == []
    (tree / "tools" / "nfs-proxy" / "src" / "rule.c").write_text("new\n")
    assert tool.changed(tree, host) == ["proxy"]

    deps = tmp_path / "deps.tar.gz"
    with tarfile.open(deps, "w:gz") as tar:
        for name, body in (("./usr/sbin/nfs-proxy", b"old proxy"),
                           ("./usr/sbin/rpc.nfsd", b"nfsd")):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(body), 0o755
            tar.addfile(info, io.BytesIO(body))
    proxy = tmp_path / "nfs-proxy-lane"
    proxy.write_bytes(b"new proxy")
    out = tool.with_proxy(deps, proxy, tmp_path / "out.tar.gz")
    with tarfile.open(out) as tar:
        members = {m.name: m for m in tar.getmembers()}
        assert tar.extractfile(members["./usr/sbin/nfs-proxy"]).read() == \
            b"new proxy"
        assert members["./usr/sbin/nfs-proxy"].mode == 0o755
        assert tar.extractfile(members["./usr/sbin/rpc.nfsd"]).read() == b"nfsd"
    with tarfile.open(deps, "w:gz") as tar:
        pass
    with pytest.raises(SystemExit, match="has no ./usr/sbin/nfs-proxy"):
        tool.with_proxy(deps, proxy, tmp_path / "none.tar.gz")
