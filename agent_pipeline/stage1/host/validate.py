"""The host command of a Harness Generation validation (07 §5.2).

``python -m agent_pipeline.stage1.host validate --config validate.json IN
OUT`` is ``generation.validation.argv`` of ``stage1.json``.  It reads the
``CommandValidator`` input directory and writes ``OUT/report.json`` (the
contract is in ``agent_pipeline/stage1/validation.py``).  This code is the
host's; the patch set's tree supplies only data (spec, bundle, lane), and
the patch set's own build runs under the generation launcher.

1. **Tree.** The base commit of the patch set is exported from the host
   clone and the patch applied there.  A patch set outside the allowed
   paths, or one that changes an unpinned lane file, is rejected.
2. **Build.** The operator's build script runs under the launcher (the
   generation OS user, no network) with ``{tree}``, ``{env}`` and
   ``{base_env}`` replaced.  It writes a ``tools/bootstrap-kcov-env.py``
   env in ``{env}`` and the parser bundle in ``{env}/syz-bridge/bundle``,
   reusing ``{base_env}`` for what the patch set did not change.
3. **Generate.** ``generate`` runs on the tree's spec with the
   Controller's gap contract, the host's base spec and the base binding's
   HCAP (``StagedBase``): only the policy's sanitizer, the patch set's
   capabilities experimental, the others kept from the base HCAP.
4. **Staged files.** The new build's host files are copied to the
   service collector's ``staged_files``, so the Runner can boot them.
5. **Runs**, each a fresh guest as ``collect`` boots it:
   - every ``stage1-host/generation/<gap id>/smoke*.syz`` of the tree
     must boot, pass the fixture and lane checks, run, and reach one of
     the gap contract's boundary functions, without a crash;
   - the neutral control of the smoke selection must reach none of them;
   - every neutral control of the base spec must still run clean on the
     new build (the regression of the existing capabilities).
6. **Report.** ``passed`` lists the descriptor, the staged HCAP and every
   object ``generate`` stored; any end lists the logs.

A guest that does not boot is ``inconclusive`` (the host or the build may
be at fault; the Controller retries within its limit), and so is any
host-side error.  Everything after a boot is the patch set's.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ...agent_tasks.generation import DEFAULT_ALLOWED_PATHS, allowed
from ...artifacts import ArtifactStore
from ...contracts import Sanitizer
from ...data import canonical_json, load_record
from ...hcap import GapContract, HcapCatalog, RuntimeSelection
from ...materializer import ExecutionHarnessDescriptor, _runtime_key
from .collector import (CollectorConfig, CollectorError, crash_report,
                        guest_cmdline, run_lane, staged_path, verify_pins)
from .generate import GenerationError, HostSpec, StagedBase, generate
from .pins import HostFilePin, PinCache, PinError, verify_file
from .target_pcs import function_callsites
from .vm import QemuGuest, VmConfig

#: Lane files the guest loads but no pin covers: a staged build keeps the
#: host's, so a patch set may not change them.
UNPINNED_LANE_FILES = ("bundle/lane/boot-fixture.sh",
                       "bundle/lane/fixture.service")
GENERATION_DIR = "stage1-host/generation"
LOG_TYPE = "text/plain"
RUNS_TYPE = "application/vnd.knfsd.validation-runs+json"
CAS_TYPE = "application/octet-stream"
LOG_LIMIT = 1 << 20


class ValidateConfig(BaseModel):
    """``validate.json``: host configuration only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("stage1-validate.v1",
                                pattern=r"^stage1-validate\.v1$")
    #: The host's clone; patch sets name a commit of it.
    repo: Path
    #: Scratch: ``<task>/tree``, ``env``, ``state``, ``cas``.
    work_root: Path
    #: The host spec inside the tree.
    spec: str = "stage1-host/host-spec.json"
    #: The host's own spec, the base of every patch set (never the tree's).
    base_spec: Path
    #: The service's collector.json: its staged_files, key and timings.
    collector: Path
    build_argv: tuple[str, ...] = Field(min_length=1)
    #: The generation OS user, no network (07 §5.1).
    launcher: tuple[str, ...] = Field(min_length=1)
    build_env: dict[str, str] = Field(
        default_factory=lambda: {"LANG": "C.UTF-8"})
    build_timeout_s: float = Field(default=21_600, gt=0)
    allowed_paths: tuple[str, ...] = DEFAULT_ALLOWED_PATHS
    #: Keep the tree and env after the run (debugging).
    keep_work: bool = False

    @field_validator("build_argv", "launcher")
    @classmethod
    def _absolute(cls, argv: tuple[str, ...]) -> tuple[str, ...]:
        if not Path(argv[0]).is_absolute():
            raise ValueError("argv[0] must be an absolute path")
        return argv

    @classmethod
    def load(cls, path: Path) -> ValidateConfig:
        return cls.model_validate_json(Path(path).read_bytes())


class End(Exception):
    """The validation's result, before every step ran."""

    def __init__(self, result: str, reason: str, detail: str = "") -> None:
        super().__init__(f"{result}:{reason}")
        self.result, self.reason, self.detail = result, reason, detail


def _reject(reason: str, detail: str = "") -> End:
    return End("rejected", reason, detail)


def _inconclusive(reason: str, detail: str = "") -> End:
    return End("inconclusive", reason, detail)


def _write_log(path: Path, text: str | bytes) -> None:
    data = text.encode("utf-8", "replace") if isinstance(text, str) else text
    if len(data) > LOG_LIMIT:
        data = b"[truncated]\n" + data[-LOG_LIMIT:]
    path.write_bytes(data)


class Validation:
    def __init__(self, config: ValidateConfig, inp: Path, out: Path, *,
                 guest_factory: Callable[[VmConfig], object] = QemuGuest,
                 sleep: Callable[[float], None] = time.sleep,
                 boundary_pcs: Callable[..., tuple[int, ...]] | None = None
                 ) -> None:
        self.config = config
        self.inp, self.out = Path(inp), Path(out)
        self.guest_factory = guest_factory
        self.sleep = sleep
        self.boundary_pcs = boundary_pcs or self._boundary_pcs
        self.task = json.loads((self.inp / "validation.json").read_text())
        self.task_id = self.task["task_id"]
        self.sanitizer = Sanitizer(self.task["sanitizer"])
        self.gap_id = self.task["gap"]["missing_capability_id"]
        self.work = config.work_root / self.task_id
        self.artifacts: list[dict] = []
        self.runs: list[dict] = []

    # ------------------------------------------------------------ steps

    def run(self) -> dict:
        try:
            self.work.mkdir(parents=True, exist_ok=False)
            report = self._validate()
        except End as end:
            report = {"result": end.result, "reason": end.reason}
            if end.detail:
                _write_log(self.out / "end.log", end.detail)
                self._evidence("end", LOG_TYPE, "end.log")
        except Exception as exc:          # a host-side error, not a verdict
            report = {"result": "inconclusive",
                      "reason": f"host_error:{type(exc).__name__}".lower()}
            _write_log(self.out / "end.log", f"{type(exc).__name__}: {exc}")
            self._evidence("end", LOG_TYPE, "end.log")
        finally:
            if not self.config.keep_work:
                for name in ("tree", "env", "state"):
                    shutil.rmtree(self.work / name, ignore_errors=True)
        if self.runs:
            (self.out / "runs.json").write_bytes(canonical_json(self.runs))
            self._evidence("runs", RUNS_TYPE, "runs.json")
        report["artifacts"] = [*report.get("artifacts", ()), *self.artifacts]
        (self.out / "report.json").write_text(json.dumps(report, indent=1))
        return report

    def _validate(self) -> dict:
        service = CollectorConfig.load(self.config.collector)
        if service.staged_files is None:
            raise _inconclusive("collector_has_no_staged_files")
        if not (self.inp / "base_hcap.json").is_file():
            raise _inconclusive("no_base_binding")
        base_hcap = HcapCatalog.model_validate_json(
            (self.inp / "base_hcap.json").read_bytes())
        gap = next((g for g in base_hcap.gap_contracts
                    if g.missing_capability_id == self.gap_id), None)
        if gap is None:
            raise _inconclusive("gap_contract_missing")
        tree = self._tree()
        env = self._build(tree)
        result, store = self._generate(tree, env, gap, base_hcap)
        variant = result.variants.get(self.sanitizer.value)
        harness_id = variant.execution_harness_id if variant else \
            result.execution_harness_id
        hcap_ref = variant.hcap_revision if variant else result.hcap_revision
        descriptor = load_record(store, harness_id,
                                 ExecutionHarnessDescriptor)
        if descriptor.kernel_commit != self.task["kernel_commit"]:
            raise _inconclusive(
                "build_key_mismatch", f"the build is of "
                f"{descriptor.kernel_commit}, the task of "
                f"{self.task['kernel_commit']}")
        built = CollectorConfig.load(result.collector_config)
        files = verify_pins(built, descriptor)
        self._stage(tree, store, descriptor, built, service)
        self._runs(tree, store, descriptor, built, files, gap,
                   HcapCatalog.model_validate_json(store.get(hcap_ref)))
        (self.out / "descriptor.json").write_bytes(canonical_json(descriptor))
        (self.out / "hcap.json").write_bytes(store.get(hcap_ref))
        objects = []
        for shard in sorted(Path(store.root).iterdir()):
            for item in sorted(shard.iterdir()):
                name = f"cas-{item.name}"
                (self.out / name).write_bytes(store.get(item.name))
                objects.append({"identity": "staged-object", "type": CAS_TYPE,
                                "path": name})
        return {"result": "passed", "descriptor": "descriptor.json",
                "hcap": "hcap.json", "artifacts": objects}

    def _evidence(self, identity: str, kind: str, path: str) -> None:
        self.artifacts.append({"identity": identity, "type": kind,
                               "path": path})

    def _tree(self) -> Path:
        patch_set = json.loads((self.inp / "patch_set.json").read_text())
        patch = self.inp / "patch.diff"
        files = list(patch_set["files"])
        tree = self.work / "tree"
        tree.mkdir()
        exported = subprocess.run(
            ["git", "-C", str(self.config.repo), "archive", "--format=tar",
             patch_set["base_commit"]], capture_output=True)
        if exported.returncode:
            raise _inconclusive("base_commit_unknown",
                                exported.stderr.decode("utf-8", "replace"))
        subprocess.run(["tar", "-x", "-C", str(tree)], input=exported.stdout,
                       check=True)
        git = ["git", "-C", str(tree)]
        subprocess.run([*git, "init", "-q"], check=True)
        stat = subprocess.run([*git, "apply", "--numstat", str(patch)],
                              capture_output=True, text=True)
        if stat.returncode:
            raise _reject("patch_does_not_apply", stat.stderr)
        files += [line.split("\t", 2)[2] for line in stat.stdout.splitlines()
                  if line.count("\t") >= 2]
        outside = sorted({f for f in files
                          if not allowed(f, self.config.allowed_paths)
                          or "=>" in f})
        if outside:
            raise _reject("patch_outside_allowed_paths", "\n".join(outside))
        unpinned = sorted(set(files) & set(UNPINNED_LANE_FILES))
        if unpinned:
            raise _reject("unpinned_lane_file", "\n".join(unpinned))
        applied = subprocess.run([*git, "apply", "--binary", str(patch)],
                                 capture_output=True, text=True)
        if applied.returncode:
            raise _reject("patch_does_not_apply", applied.stderr)
        # This process reads the tree with the service's rights: a link
        # could point it at a file the generation user cannot read.
        links = sorted(f for f in files if (tree / f).is_symlink())
        if links:
            raise _reject("symlink_in_patch", "\n".join(links))
        return tree

    def _base_spec(self) -> HostSpec:
        return HostSpec.model_validate_json(self.config.base_spec.read_bytes())

    def _resolve_base(self, path: Path) -> Path:
        base = self.config.base_spec.resolve().parent
        return path if path.is_absolute() else (base / path).resolve()

    def _build(self, tree: Path) -> Path:
        env = self.work / "env"
        env.mkdir()
        env.chmod(0o2775)         # the generation user writes the build
        base_env = self._resolve_base(self._base_spec().env_dir)
        argv = [*self.config.launcher, *(
            a.replace("{tree}", str(tree)).replace("{env}", str(env))
            .replace("{base_env}", str(base_env))
            .replace("{sanitizer}", self.sanitizer.value)
            for a in self.config.build_argv)]
        log = self.out / "build.log"
        try:
            with open(log, "wb") as sink:
                done = subprocess.run(
                    argv, cwd=tree, env=dict(self.config.build_env),
                    stdin=subprocess.DEVNULL, stdout=sink,
                    stderr=subprocess.STDOUT,
                    timeout=self.config.build_timeout_s)
        except subprocess.TimeoutExpired:
            raise _inconclusive("build_timeout") from None
        finally:
            _write_log(log, log.read_bytes() if log.exists() else b"")
            self._evidence("build-log", LOG_TYPE, "build.log")
        if done.returncode:
            raise _reject("build_failed")
        return env

    def _generate(self, tree: Path, env: Path, gap: GapContract,
                  base_hcap: HcapCatalog):
        spec_path = tree / self.config.spec
        if not spec_path.is_file():
            raise _reject("spec_missing", self.config.spec)
        service = CollectorConfig.load(self.config.collector)
        spec = json.loads(spec_path.read_text())
        spec.update(state_dir=str(self.work / "state"),
                    artifact_root=str(self.work / "cas"), env_dir=str(env),
                    syzkaller_bundle=str(env / "syz-bridge" / "bundle"),
                    ssh_key=str(service.ssh_key))
        validation_spec = spec_path.parent / ".validation-spec.json"
        validation_spec.write_text(json.dumps(spec, indent=1))
        try:
            result = generate(validation_spec, gap=gap,
                              base_spec=self.config.base_spec, repo=tree,
                              staged=StagedBase(sanitizer=self.sanitizer,
                                                hcap=base_hcap))
        except (GenerationError, ValueError) as exc:
            # A spec the patch set made that generation refuses.
            raise _reject("generate_refused", str(exc)) from exc
        return result, ArtifactStore(self.work / "cas")

    def _stage(self, tree: Path, store: ArtifactStore,
               descriptor: ExecutionHarnessDescriptor,
               built: CollectorConfig, service: CollectorConfig) -> None:
        """Copy the new build's host files where the service's collector
        finds them by pin (``staged_path``)."""
        built_files = built.files_for(descriptor.sanitizer)
        service_files = service.files_for(descriptor.sanitizer)
        cache = PinCache(None)
        for artifact in descriptor.build_artifacts:
            if artifact.name not in service_files:
                continue
            pin = load_record(store, artifact.artifact_ref, HostFilePin)
            try:
                # Unchanged: the service boots its configured file.
                verify_file(pin, service_files[artifact.name], cache)
                continue
            except PinError:
                pass
            source = built_files[artifact.name]
            if not source.resolve().is_relative_to(self.work.resolve()):
                # The generation user wrote the env; a link out of it
                # would publish a file of the service's.
                raise _reject("build_file_outside_env", str(source))
            verify_file(pin, source, cache)
            dest = staged_path(service.staged_files, pin,
                               service_files[artifact.name])
            if dest.is_file():
                verify_file(pin, dest, cache)
                continue
            tmp = dest.parent.with_name(dest.parent.name + f".{os.getpid()}")
            shutil.rmtree(tmp, ignore_errors=True)
            if artifact.name == "lane-script":
                # The guest mounts the lane script's directory.
                shutil.copytree(source.parent, tmp)
                if source.name != dest.name:
                    (tmp / source.name).rename(tmp / dest.name)
            else:
                tmp.mkdir(parents=True)
                shutil.copyfile(source, tmp / dest.name)
            for item in tmp.iterdir():
                item.chmod(0o444)
            try:
                tmp.rename(dest.parent)
            except OSError:
                shutil.rmtree(tmp, ignore_errors=True)
                if not dest.is_file():
                    raise
            verify_file(pin, dest, cache)

    # ------------------------------------------------------------ runs

    def _boundary_pcs(self, vmlinux: Path, functions, sha256: str
                      ) -> tuple[int, ...]:
        return function_callsites(vmlinux, functions,
                                  cache=self.work / "pcs-cache",
                                  vmlinux_file_sha256=sha256)

    def _runs(self, tree: Path, store: ArtifactStore,
              descriptor: ExecutionHarnessDescriptor,
              built: CollectorConfig, files: dict[str, Path],
              gap: GapContract, hcap: HcapCatalog) -> None:
        builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
        kernel = load_record(store, builds[built.vmlinux_artifact_name],
                             HostFilePin)
        probes = set(self.boundary_pcs(files[built.vmlinux_artifact_name],
                                       gap.contract.boundary_functions,
                                       kernel.sha256))
        if not probes:
            raise _reject("boundary_not_instrumented", ", ".join(
                gap.contract.boundary_functions))
        directory = tree / GENERATION_DIR / self.gap_id
        smokes = sorted(directory.glob("smoke*.syz"))
        if not smokes:
            raise _reject("smoke_missing", f"{GENERATION_DIR}/{self.gap_id}/"
                          "smoke*.syz")
        selection = descriptor.allowed_runtime_selections[0]
        if (directory / "selection.json").is_file():
            selection = RuntimeSelection.model_validate_json(
                (directory / "selection.json").read_bytes())
        allowed_keys = {_runtime_key(s)
                        for s in descriptor.allowed_runtime_selections}
        if _runtime_key(selection) not in allowed_keys:
            raise _reject("smoke_selection_not_allowed")
        for i, program in enumerate(smokes):
            run = self._run(f"smoke-{i}", program, selection, descriptor,
                            built, files, probes)
            if run["crash"] is not None:
                raise _reject("smoke_crashed")
            self._clean(run)
            if not run["boundary_hits"]:
                raise _reject("smoke_unreached", program.name)
        neutral = self._neutral(store, hcap, selection)
        run = self._run("neutral", neutral, selection, descriptor, built,
                        files, probes)
        self._clean(run)
        if run["boundary_hits"]:
            raise _reject("neutral_reached")
        if run["crash"] is not None:
            raise _reject("neutral_crashed")
        seen = {(neutral.read_bytes(), _runtime_key(selection))}
        for i, item in enumerate(self._base_spec().neutral_controls):
            program = self._resolve_base(item.program)
            key = (program.read_bytes(), _runtime_key(item.runtime_selection))
            if key in seen:
                continue
            seen.add(key)
            run = self._run(f"regression-{i}", program,
                            item.runtime_selection, descriptor, built, files,
                            probes)
            if run["runtime_errors"] or run["crash"] is not None:
                raise _reject("regression", f"base neutral control "
                              f"{item.program}: {run['runtime_errors']}")
            self._clean(run)

    def _neutral(self, store: ArtifactStore, hcap: HcapCatalog,
                 selection: RuntimeSelection) -> Path:
        from ...admission import NeutralControlCatalog
        ref = next(r.artifact_ref for r in hcap.authority_refs
                   if r.kind == "NeutralControlCatalog")
        catalog = load_record(store, ref, NeutralControlCatalog)
        entry = next((e for e in catalog.entries
                      if _runtime_key(e.runtime_selection)
                      == _runtime_key(selection)), None)
        if entry is None:
            raise _reject("neutral_control_missing")
        path = self.work / "neutral.syz"
        path.write_bytes(store.get(entry.program_ref))
        return path

    @staticmethod
    def _clean(run: dict) -> None:
        """Booted: the rest of the run is the patch set's."""
        facts = run["facts"]
        if not all(facts[k] for k in ("fixture_ok", "lane_ok",
                                      "runner_completed",
                                      "collection_completed")):
            raise _reject("bootstrap_failed",
                          f"{run['label']}: {run['runtime_errors']}")

    def _run(self, label: str, program: Path, selection: RuntimeSelection,
             descriptor: ExecutionHarnessDescriptor, built: CollectorConfig,
             files: dict[str, Path], probes: set[int]) -> dict:
        out = self.work / "runs" / label
        out.mkdir(parents=True)
        builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
        lane = load_record(ArtifactStore(built.artifact_root),
                           builds["lane-script"], HostFilePin)
        try:
            cmdline = guest_cmdline(descriptor, selection, lane.sha256)
        except CollectorError as exc:
            raise _reject("guest_cmdline", str(exc)) from exc
        console = out / "console.log"
        guest = self.guest_factory(VmConfig(
            qemu=built.qemu, bzimage=files["bzimage"],
            image=files["vm-image"], lane_dir=files["lane-script"].parent,
            ssh_key=built.ssh_key, cmdline=cmdline, console_log=console,
            memory_mb=built.memory_mb, cpus=built.cpus,
            boot_timeout_s=built.boot_timeout_s, accel=built.accel))
        result: dict = {}
        try:
            lane_run = run_lane(guest, files, program, selection,
                                lane.sha256, built, out, result, self.sleep,
                                exec_slowdown=built.exec_slowdown)
        finally:
            guest.stop()
        crash = crash_report(out, console, descriptor)
        run = {"label": label, "program": program.name,
               "selection": selection.model_dump(mode="json"),
               "facts": {k: getattr(lane_run, k) for k in (
                   "boot_ok", "fixture_ok", "lane_ok", "runner_completed",
                   "collection_started", "collection_completed",
                   "extra_present")},
               "runtime_errors": lane_run.runtime_errors,
               "published_pcs": len(lane_run.pcs),
               "boundary_hits": len(lane_run.pcs & probes),
               "crash": None if crash is None
               else crash.model_dump(mode="json")}
        self.runs.append(run)
        if console.is_file():
            _write_log(self.out / f"{label}.console.log", console.read_bytes())
            self._evidence(f"{label}-console", LOG_TYPE,
                           f"{label}.console.log")
        if not lane_run.boot_ok:
            raise _inconclusive("vm_boot_failed",
                                f"{label}: {lane_run.runtime_errors}")
        return run


def validate(config: ValidateConfig, inp: Path, out: Path, **kw) -> dict:
    return Validation(config, inp, out, **kw).run()
