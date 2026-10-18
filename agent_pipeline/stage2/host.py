"""Read-only readiness checks for a real Stage 2 KVM deployment.

The Stage 2 engine deliberately treats its host command as trusted
configuration.  This module checks that configuration and its immutable
authority before an operator starts a job; it does not boot a guest, run a
candidate or write pipeline state.

Run it with::

    python -m agent_pipeline.stage2.host preflight --stage1 stage1.json
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Callable, Literal

from pydantic import Field

from ..artifacts import ArtifactStore
from ..contracts import JobPolicy, Record
from ..data import load_record, parse_json
from ..hcap import ArtifactHcapChecker
from ..m1 import M1JudgeProfile
from ..materializer import ExecutionHarnessApproval, descriptor_id
from ..q2 import Q2JudgeProfile
from ..registry import HarnessCatalog
from ..semantic_promotion import (BuildRegistry,
                                  PromotedSemanticCapabilityRegistry,
                                  check_runtime, promoted_registry,
                                  read_build_registry)
from ..semantic_replay import ReplayJudgeProfile
from ..stage1.config import Stage1Config
from ..stage1.host.collector import CollectorConfig, verify_pins
from ..stage1.host.pins import file_sha256


class PreflightCheck(Record):
    name: str = Field(min_length=1, max_length=128)
    status: Literal["pass", "warning", "error"]
    detail: str = Field(min_length=1, max_length=1024)


class PreflightReport(Record):
    schema_version: Literal["stage2-kvm-preflight.v1"] = \
        "stage2-kvm-preflight.v1"
    ready: bool
    checks: tuple[PreflightCheck, ...]


class PreflightError(RuntimeError):
    """One readiness invariant is not met."""


class _Checks:
    def __init__(self) -> None:
        self.items: list[PreflightCheck] = []

    def add(self, name: str, status: Literal["pass", "warning", "error"],
            detail: str) -> None:
        self.items.append(PreflightCheck(
            name=name, status=status, detail=detail[:1024]))

    def attempt(self, name: str, operation: Callable[[], str]) -> bool:
        try:
            detail = operation()
        except (OSError, ValueError, TypeError, RuntimeError,
                subprocess.SubprocessError) as exc:
            self.add(name, "error", f"{type(exc).__name__}: {exc}")
            return False
        self.add(name, "pass", detail)
        return True


def _executable(path: Path | str, *, which: Callable[[str], str | None]
                ) -> Path:
    value = str(path)
    found = Path(value) if Path(value).is_absolute() else None
    if found is None:
        resolved = which(value)
        if resolved is None:
            raise PreflightError(f"executable is not on PATH: {value}")
        found = Path(resolved)
    if not found.is_file() or not os.access(found, os.X_OK):
        raise PreflightError(f"not an executable file: {found}")
    return found


def _check_kvm(path: Path) -> str:
    info = path.stat()
    if not stat.S_ISCHR(info.st_mode):
        raise PreflightError(f"not a character device: {path}")
    if not os.access(path, os.R_OK | os.W_OK):
        raise PreflightError(f"current user cannot read and write {path}")
    return f"{path} is accessible"


def _check_command(config, *, which: Callable[[str], str | None]) -> str:
    binary = _executable(config.argv[0], which=which)
    if not config.cwd.is_dir():
        raise PreflightError(f"command cwd is not a directory: {config.cwd}")
    if not os.access(config.cwd, os.X_OK):
        raise PreflightError(f"command cwd is not searchable: {config.cwd}")
    joined = "\0".join(config.argv)
    missing = [value for value in ("{input}", "{output}")
               if value not in joined]
    if missing:
        raise PreflightError("command argv lacks " + ", ".join(missing))
    return f"command={binary} cwd={config.cwd}"


def _check_profiles(store: ArtifactStore, config) -> str:
    load_record(store, config.m1_profile_ref, M1JudgeProfile)
    load_record(store, config.q2_profile_ref, Q2JudgeProfile)
    load_record(store, config.replay_profile_ref, ReplayJudgeProfile)
    return "M1, Q2 and replay profiles are canonical and present"


def _verify_pins_read_only(collector: CollectorConfig, descriptor) -> None:
    # PinCache writes on a miss.  Preflight must leave the collector's
    # persistent cache and all pipeline state untouched.
    verify_pins(collector.model_copy(update={"pin_cache": None}), descriptor)


def _check_harnesses(
    store: ArtifactStore, config: Stage1Config, collector: CollectorConfig,
) -> tuple[PromotedSemanticCapabilityRegistry, ...]:
    approvals = [load_record(store, ref, ExecutionHarnessApproval)
                 for ref in config.execution_harness_approvals]
    by_descriptor = {descriptor_id(item.descriptor): item
                     for item in approvals}
    if len(by_descriptor) != len(approvals):
        raise PreflightError("duplicate execution harness approval")
    catalog = load_record(store, config.harness_catalog_ref, HarnessCatalog)
    if not catalog.registrations:
        raise PreflightError("harness catalog has no registrations")
    checker = ArtifactHcapChecker(store)
    promoted: list[PromotedSemanticCapabilityRegistry] = []
    checked_descriptors: set[str] = set()
    for registration in catalog.registrations:
        binding = registration.binding
        approval = by_descriptor.get(binding.execution_harness_id)
        if approval is None:
            raise PreflightError(
                f"{binding.execution_harness_id[:12]} has no configured approval")
        descriptor = approval.descriptor
        if (descriptor.kernel_commit != binding.kernel_commit
                or descriptor.sanitizer != binding.sanitizer):
            raise PreflightError("harness binding differs from its descriptor")
        if binding.hcap_revision not in approval.approved_hcap_revisions:
            raise PreflightError("harness binding uses an unapproved HCAP")
        hcap = checker.load_catalog(binding.hcap_revision)
        registry = promoted_registry(store, hcap)
        if registry is None:
            raise PreflightError(
                f"HCAP {binding.hcap_revision[:12]} has no promoted semantic subset")
        promoted.append(registry)
        if binding.execution_harness_id not in checked_descriptors:
            _verify_pins_read_only(collector, descriptor)
            checked_descriptors.add(binding.execution_harness_id)
        tokens = descriptor.guest_kernel_command_line.split()
        if "nokaslr" not in tokens or "nfs.localio_enabled=N" not in tokens:
            raise PreflightError(
                "Stage 2 harness requires nokaslr and nfs.localio_enabled=N")
    return tuple(promoted)


def _check_runtime(
    path: Path, promoted: tuple[PromotedSemanticCapabilityRegistry, ...],
    *, reader: Callable[[Path], BuildRegistry],
) -> BuildRegistry:
    build = reader(path)
    mismatched = [item.proxy_sha256[:12] for item in promoted
                  if not check_runtime(item, build)]
    if mismatched:
        raise PreflightError(
            "runtime is not the promoted Proxy build for: "
            + ", ".join(mismatched))
    return build


def _check_kernel_repo(config: Stage1Config) -> str:
    if not config.kernel_repo.is_dir():
        raise PreflightError(f"kernel repository is absent: {config.kernel_repo}")
    run = subprocess.run(
        ["git", "-C", str(config.kernel_repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30)
    if run.returncode != 0:
        raise PreflightError("kernel repository has no readable HEAD")
    head = run.stdout.strip()
    if not config.artifact_root.is_dir():
        raise PreflightError(f"artifact root is absent: {config.artifact_root}")
    store = ArtifactStore(config.artifact_root)
    catalog = load_record(store, config.harness_catalog_ref, HarnessCatalog)
    commits = {item.binding.kernel_commit for item in catalog.registrations}
    if head not in commits:
        raise PreflightError(
            f"kernel HEAD {head[:12]} is not registered in the harness catalog")
    return f"kernel HEAD {head[:12]} is registered"


_POLICY_DEFAULTS = (1, 1000, 10000, 100, 100000)


def _policy_values(policy: JobPolicy) -> tuple[int, ...]:
    return (policy.gate_repetitions,
            policy.campaign_not_applied_generations,
            policy.campaign_no_signal_generations,
            policy.campaign_inconclusive_generations,
            policy.fuzz_budget_executions)


def _check_policies(policies: tuple[JobPolicy, ...], checks: _Checks) -> None:
    enabled = [p.policy_id for p in policies if p.run_stage2]
    if enabled:
        checks.add("stage2_policy", "pass",
                   "automatic Stage 2 enabled for: " + ", ".join(enabled))
    else:
        checks.add("stage2_policy", "warning",
                   "run_stage2 is false for every policy; use operator start_stage2")
    defaults = [p.policy_id for p in policies
                if _policy_values(p) == _POLICY_DEFAULTS]
    if defaults:
        checks.add("campaign_policy", "warning",
                   "placeholder Stage 2 thresholds remain for: "
                   + ", ".join(defaults))
    else:
        checks.add("campaign_policy", "pass",
                   "Stage 2 thresholds differ from repository placeholders")


def _check_manager(path: Path, crash_window_bound: int) -> str:
    raw = path.read_bytes()
    value = parse_json(raw)
    if not isinstance(value, dict):
        raise PreflightError("manager config is not a JSON object")
    if value.get("type") != "qemu":
        raise PreflightError("manager config type must be qemu")
    experimental = value.get("experimental")
    if not isinstance(experimental, dict):
        raise PreflightError("manager config lacks experimental settings")
    if experimental.get("remote_cover") is not True:
        raise PreflightError("experimental.remote_cover must be true")
    window = experimental.get("nfs_proxy_window")
    if type(window) is not int or window < crash_window_bound:
        raise PreflightError(
            f"experimental.nfs_proxy_window must be at least {crash_window_bound}")
    vm = value.get("vm")
    if not isinstance(vm, dict) or vm.get("count", 1) != 1:
        raise PreflightError("target-mode campaign requires vm.count 1")
    cmdline = str(vm.get("cmdline", "")).split()
    if "nfs.localio_enabled=N" not in cmdline:
        raise PreflightError("manager VM cmdline lacks nfs.localio_enabled=N")
    if "koov.nfs_target=1" not in cmdline:
        raise PreflightError("manager VM cmdline lacks koov.nfs_target=1")
    template_value = value.get("workdir_template")
    if not isinstance(template_value, str) or not template_value:
        raise PreflightError("manager config lacks workdir_template")
    template = Path(template_value)
    lane_script = template / "lane.sh"
    if not lane_script.is_file():
        raise PreflightError(f"manager lane script is absent: {lane_script}")
    lane_digest = file_sha256(lane_script)
    lane_tokens = [token.removeprefix("koov.lane_sha256=")
                   for token in cmdline
                   if token.startswith("koov.lane_sha256=")]
    if lane_tokens != [lane_digest]:
        raise PreflightError("manager lane script differs from koov.lane_sha256")
    qemu_args = str(vm.get("qemu_args", ""))
    if "-enable-kvm" not in qemu_args.split():
        raise PreflightError("manager QEMU args lack -enable-kvm")
    if "nfsp-journal-0" not in qemu_args:
        raise PreflightError("manager QEMU args lack journal channels")
    return f"manager window={window}, target mode and journal channels enabled"


def preflight(
    stage1_path: Path, *, collector_path: Path | None = None,
    manager_path: Path | None = None, kvm_path: Path = Path("/dev/kvm"),
    which: Callable[[str], str | None] = shutil.which,
    runtime_reader: Callable[[Path], BuildRegistry] = read_build_registry,
) -> PreflightReport:
    """Check one deployment without running a candidate or changing state."""
    checks = _Checks()
    try:
        config = Stage1Config.load(stage1_path)
    except (OSError, ValueError, TypeError) as exc:
        checks.add("stage1_config", "error", f"{type(exc).__name__}: {exc}")
        return PreflightReport(ready=False, checks=tuple(checks.items))
    checks.add("stage1_config", "pass", f"loaded {stage1_path}")
    stage2 = config.stage2
    if stage2 is None:
        checks.add("stage2_config", "error", "Stage1Config.stage2 is unset")
        return PreflightReport(ready=False, checks=tuple(checks.items))
    checks.add("stage2_config", "pass", "Stage 2 backend is configured")

    collector_file = collector_path or Path(config.state_dir) / "collector.json"
    try:
        collector = CollectorConfig.load(collector_file)
    except (OSError, ValueError, TypeError) as exc:
        checks.add("collector_config", "error", f"{type(exc).__name__}: {exc}")
        return PreflightReport(ready=False, checks=tuple(checks.items))
    checks.add("collector_config", "pass", f"loaded {collector_file}")

    checks.attempt("kvm", lambda: _check_kvm(kvm_path))
    checks.attempt("stage2_command",
                   lambda: _check_command(stage2, which=which))
    checks.attempt("qemu", lambda: f"qemu={_executable(collector.qemu, which=which)}")
    checks.attempt("ssh", lambda: f"ssh={_executable('ssh', which=which)}")
    checks.attempt("scp", lambda: f"scp={_executable('scp', which=which)}")
    checks.attempt("kernel_repo", lambda: _check_kernel_repo(config))

    promoted: tuple[PromotedSemanticCapabilityRegistry, ...] = ()
    try:
        if not config.artifact_root.is_dir():
            raise PreflightError(f"artifact root is absent: {config.artifact_root}")
        if not collector.artifact_root.is_dir():
            raise PreflightError(
                f"collector artifact root is absent: {collector.artifact_root}")
        store = ArtifactStore(config.artifact_root)
        _check_profiles(store, stage2)
        promoted = _check_harnesses(store, config, collector)
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        checks.add("authority", "error", f"{type(exc).__name__}: {exc}")
    else:
        checks.add("authority", "pass",
                   f"{len(promoted)} harness binding(s), profiles and pins verified")

    compiler_build: BuildRegistry | None = None
    replay_build: BuildRegistry | None = None
    if config.nfs_proxy is None:
        checks.add("compiler_proxy", "error", "Stage1Config.nfs_proxy is unset")
    elif promoted:
        try:
            _executable(config.nfs_proxy, which=which)
            compiler_build = _check_runtime(config.nfs_proxy, promoted,
                                            reader=runtime_reader)
        except (OSError, ValueError, TypeError, RuntimeError,
                subprocess.SubprocessError) as exc:
            checks.add("compiler_proxy", "error",
                       f"{type(exc).__name__}: {exc}")
        else:
            checks.add("compiler_proxy", "pass",
                       f"promoted build {compiler_build.proxy_sha256[:12]}")
    if promoted:
        try:
            _executable(stage2.replay_proxy, which=which)
            replay_build = _check_runtime(stage2.replay_proxy, promoted,
                                          reader=runtime_reader)
        except (OSError, ValueError, TypeError, RuntimeError,
                subprocess.SubprocessError) as exc:
            checks.add("replay_proxy", "error",
                       f"{type(exc).__name__}: {exc}")
        else:
            checks.add("replay_proxy", "pass",
                       f"promoted build {replay_build.proxy_sha256[:12]}")
    if compiler_build is not None and replay_build is not None:
        if compiler_build != replay_build:
            checks.add("proxy_identity", "error",
                       "compiler and replay Proxy registries differ")
        else:
            checks.add("proxy_identity", "pass",
                       "compiler and replay use the same promoted build")

    if stage2.resource_key == config.engine.resource_key:
        checks.add("resource_key", "pass",
                   "Stage 1 and Stage 2 share one KVM resource fence")
    else:
        checks.add("resource_key", "warning",
                   "Stage 1 and Stage 2 use different resource keys")
    _check_policies(config.policies, checks)
    if manager_path is None:
        checks.add("manager_config", "warning",
                   "manager config not supplied; campaign window and target mode unchecked")
    else:
        checks.attempt("manager_config",
                       lambda: _check_manager(manager_path,
                                              stage2.crash_window_bound))
    ready = not any(item.status == "error" for item in checks.items)
    return PreflightReport(ready=ready, checks=tuple(checks.items))


def _print(report: PreflightReport) -> None:
    for item in report.checks:
        marker = {"pass": "PASS", "warning": "WARN", "error": "FAIL"}[
            item.status]
        print(f"[{marker}] {item.name}: {item.detail}")
    print("READY" if report.ready else "NOT READY")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agent_pipeline.stage2.host",
        description="Read-only checks for a Stage 2 KVM deployment")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("preflight")
    check.add_argument("--stage1", type=Path, required=True)
    check.add_argument("--collector", type=Path)
    check.add_argument("--manager", type=Path)
    check.add_argument("--kvm", type=Path, default=Path("/dev/kvm"))
    check.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = preflight(args.stage1, collector_path=args.collector,
                       manager_path=args.manager, kvm_path=args.kvm)
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        _print(report)
    return 0 if report.ready else 2


if __name__ == "__main__":
    sys.exit(main())
