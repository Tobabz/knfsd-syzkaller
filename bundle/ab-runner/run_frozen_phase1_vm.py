#!/usr/bin/env python3
"""Boot a disposable VM and execute the Frozen Baseline Phase 1 gate.

The base disk is always attached as a raw snapshot.  All guest mutations,
including dependency extraction and namespace setup, therefore disappear with
the QEMU process.  The runner never starts a fuzzer and never writes an input
kernel, image, dependency archive, or SSH key.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time


SCHEMA_VERSION = 1
LANE_ROOT_TEMPLATE = "/tmp/frozen-nfs.XXXXXX"
REMOTE_DRIVER = "/opt/frozen-phase1"
REMOTE_PYTHON = "/opt/frozen-python/usr/bin/python3.10"
REMOTE_PYTHON_LOADER = "/opt/frozen-python/lib64/ld-linux-x86-64.so.2"
REMOTE_PYTHON_LIBS = "/opt/frozen-python/lib/x86_64-linux-gnu"
FATAL_KERNEL_RE = re.compile(
    r"(?:^|\n).*(?:BUG:|WARNING:|KASAN:|kernel BUG|Kernel panic|Oops:)",
    re.IGNORECASE,
)


class GateFailure(RuntimeError):
    """A failure that prevents Gate 1 from passing."""


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def json_result(output):
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise GateFailure("command did not emit one JSON value: %s" % error) from error
    if not isinstance(value, dict):
        raise GateFailure("command JSON result is not an object")
    return value


def safe_stage(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "command"


class FrozenPhase1VM:
    def __init__(self, args, evidence):
        self.args = args
        self.evidence = evidence
        self.output = args.output
        self.command_index = 0
        self.process = None
        self.serial = None
        self.ready = False
        self.lane_root = None

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.ssh_port = reservation.getsockname()[1]

        common = [
            "-F", "/dev/null",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=5",
            "-i", str(args.ssh_key),
        ]
        self.ssh = [
            "ssh", *common, "-p", str(self.ssh_port), "root@127.0.0.1"
        ]
        self.scp = ["scp", "-O", *common, "-P", str(self.ssh_port)]
        self.qemu = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-cpu", "host",
            "-m", str(args.memory),
            "-smp", str(args.cpus),
            "-display", "none",
            "-serial", "stdio",
            "-no-reboot",
            "-snapshot",
            "-drive", "file=%s,format=raw,if=ide" % args.image,
            "-kernel", str(args.kernel),
            "-append", "root=/dev/sda console=ttyS0 nokaslr nfs.localio_enabled=N",
            "-device", "e1000,netdev=net0",
            "-netdev",
            "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:%d-:22"
            % self.ssh_port,
        ]
        evidence["runtime"] = {
            "qemu": self.qemu,
            "ssh_port": self.ssh_port,
        }

    def _record(self, stage, command, result, duration):
        self.command_index += 1
        stem = "%03d-%s" % (self.command_index, safe_stage(stage))
        stdout_path = self.output / "commands" / (stem + ".stdout")
        stderr_path = self.output / "commands" / (stem + ".stderr")
        stdout_path.write_text(result.stdout, encoding="utf-8", errors="replace")
        stderr_path.write_text(result.stderr, encoding="utf-8", errors="replace")
        entry = {
            "stage": stage,
            "command": command,
            "returncode": result.returncode,
            "duration_seconds": round(duration, 6),
            "stdout": str(stdout_path.relative_to(self.output)),
            "stderr": str(stderr_path.relative_to(self.output)),
        }
        self.evidence["commands"].append(entry)
        write_evidence(self.output, self.evidence)
        return entry

    def guest(self, stage, command, timeout=60, check=True):
        started = time.monotonic()
        try:
            result = subprocess.run(
                [*self.ssh, command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or ""
            stderr = error.stderr or "guest command timed out"
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            result = subprocess.CompletedProcess(
                [*self.ssh, command],
                124,
                stdout,
                stderr,
            )
        self._record(stage, command, result, time.monotonic() - started)
        if check and result.returncode:
            raise GateFailure(
                "%s failed with rc=%d; see command logs" % (stage, result.returncode)
            )
        return result

    def guest_parallel(self, stage, commands, timeout=90):
        processes = []
        started = time.monotonic()
        for command in commands:
            processes.append(
                (
                    command,
                    subprocess.Popen(
                        [*self.ssh, command],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    ),
                )
            )
        results = []
        deadline = started + timeout
        try:
            for command, process in processes:
                remaining = max(0.1, deadline - time.monotonic())
                try:
                    stdout, stderr = process.communicate(timeout=remaining)
                    result = subprocess.CompletedProcess(
                        [*self.ssh, command], process.returncode, stdout, stderr
                    )
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    result = subprocess.CompletedProcess(
                        [*self.ssh, command], 124, stdout, stderr + "parallel command timed out\n"
                    )
                results.append(result)
        finally:
            for _command, process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

        duration = time.monotonic() - started
        for index, (command, _process) in enumerate(processes):
            self._record("%s-role%d" % (stage, index), command, results[index], duration)
        failures = [result.returncode for result in results if result.returncode]
        if failures:
            raise GateFailure("%s failed; return codes=%s" % (stage, failures))
        return results

    def put(self, stage, source, destination):
        command = [*self.scp, str(source), "root@127.0.0.1:" + destination]
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        # Do not copy the full local SSH invocation into evidence; it contains
        # no secret bytes, but the concise transfer mapping is more useful.
        self._record(
            stage,
            "scp %s %s" % (source, destination),
            result,
            time.monotonic() - started,
        )
        if result.returncode:
            raise GateFailure("%s failed; see command logs" % stage)

    def start(self):
        self.serial = (self.output / "serial.log").open("wb")
        self.process = subprocess.Popen(
            self.qemu,
            stdin=subprocess.DEVNULL,
            stdout=self.serial,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + self.args.boot_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise GateFailure("QEMU exited before SSH became ready")
            result = subprocess.run(
                [*self.ssh, "true"], capture_output=True, text=True, timeout=8
            )
            if result.returncode == 0:
                self.ready = True
                self.evidence["runtime"]["qemu_pid"] = self.process.pid
                self.evidence["runtime"]["ssh_ready_at"] = utc_timestamp()
                write_evidence(self.output, self.evidence)
                return
            time.sleep(2)
        raise GateFailure("timed out waiting for guest SSH")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if self.serial is not None:
            self.serial.close()

    def workload_command(self, client, command, run_id, sync=False):
        mount = "%s/client%d/mnt" % (self.lane_root, client)
        pid_file = "%s/client%d.pid" % (self.lane_root, client)
        arguments = [
            "timeout", "75s",
            "nsenter", "-t", "PID", "-m", "-n", "--",
            "env", "PYTHONHOME=/opt/frozen-python/usr",
            REMOTE_PYTHON_LOADER, "--library-path", REMOTE_PYTHON_LIBS,
            REMOTE_PYTHON, REMOTE_DRIVER + "/workload.py", command,
            mount,
        ]
        if sync:
            arguments.append(self.lane_root + "/sync")
        arguments.extend([
            "--client", "client%d" % client,
            "--run-id", run_id,
        ])
        if sync:
            arguments.extend(
                [
                    "--timeout", "60",
                ]
            )
            if command.startswith("rename-"):
                arguments.extend(["--iterations", str(self.args.rename_iterations)])
        rendered = shlex.join(arguments).replace("PID", '"$client_pid"', 1)
        return "set -eu; client_pid=$(cat %s); exec %s" % (
            shlex.quote(pid_file), rendered
        )


def write_evidence(output, evidence):
    temporary = output / ".phase1-evidence.json.tmp"
    final = output / "phase1-evidence.json"
    temporary.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, final)


def validate_inputs(args, evidence):
    inputs = {}
    for label in ("kernel", "image", "ssh_key", "deps_tar", "lane_script", "workload"):
        path = getattr(args, label)
        if not path.is_file() or path.stat().st_size == 0:
            raise GateFailure("missing or empty --%s: %s" % (label.replace("_", "-"), path))
        inputs[label] = {
            "path": str(path),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
    image_info = subprocess.run(
        ["qemu-img", "info", "--output=json", str(args.image)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if image_info.returncode:
        raise GateFailure("qemu-img could not inspect the base image")
    try:
        image_metadata = json.loads(image_info.stdout)
    except json.JSONDecodeError as error:
        raise GateFailure("invalid qemu-img JSON: %s" % error) from error
    if image_metadata.get("format") != "raw":
        raise GateFailure("--image must be raw, got %r" % image_metadata.get("format"))
    inputs["image"]["qemu_img"] = image_metadata

    source = args.lane_script.read_text(encoding="utf-8")
    identifier_write = source.find("/sys/fs/nfs/net/nfs_client/identifier")
    first_mount = source.find("mount.nfs4")
    if identifier_write < 0 or first_mount < 0 or identifier_write >= first_mount:
        raise GateFailure(
            "lane script does not set the NFS client identifier before its first mount"
        )
    evidence["inputs"] = inputs
    evidence["source_contract"] = {
        "identifier_before_first_mount": True,
        "lane_script_identifier_offset": identifier_write,
        "lane_script_mount_offset": first_mount,
    }


def build_python_runtime(args, evidence):
    if not args.python_bin.is_file():
        raise GateFailure("missing host validation Python: %s" % args.python_bin)
    if not args.python_stdlib.is_dir():
        raise GateFailure("missing host validation Python stdlib: %s" % args.python_stdlib)
    archive = args.output / "python-validation-runtime.tar.gz"
    members = [
        str(args.python_bin.relative_to("/")),
        str(args.python_stdlib.relative_to("/")),
        "lib/x86_64-linux-gnu/libm.so.6",
        "lib/x86_64-linux-gnu/libexpat.so.1",
        "lib/x86_64-linux-gnu/libz.so.1",
        "lib/x86_64-linux-gnu/libc.so.6",
        "lib64/ld-linux-x86-64.so.2",
    ]
    result = subprocess.run(
        ["tar", "--dereference", "-C", "/", "-czf", str(archive), *members],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode:
        raise GateFailure("could not package validation Python: " + result.stderr)
    evidence["inputs"]["python_runtime"] = {
        "archive": str(archive),
        "bytes": archive.stat().st_size,
        "sha256": sha256(archive),
        "python_bin": str(args.python_bin),
        "python_stdlib": str(args.python_stdlib),
    }
    return archive


def validate_status(value):
    if value.get("localio") != "N":
        raise GateFailure("LOCALIO is not disabled")
    if int(value.get("server_threads", 0)) < 2:
        raise GateFailure("knfsd has fewer than two worker threads")
    if int(value.get("tcp_connections", 0)) < 2:
        raise GateFailure("fewer than two TCP client connections reach knfsd")
    first = value.get("client0_identifier")
    second = value.get("client1_identifier")
    if not first or not second or first == second:
        raise GateFailure("NFS client identifiers are missing or not distinct")


def validate_basic(value, client):
    if value.get("status") != "pass" or value.get("client") != client:
        raise GateFailure("basic workload result identity/status mismatch for " + client)
    required = {
        "CREATE", "OPEN", "READ", "WRITE", "FSYNC", "LOCK", "LOCKU",
        "RENAME", "REMOVE", "CLOSE",
    }
    if not required.issubset(set(value.get("operations", []))):
        raise GateFailure("basic workload omitted required operations for " + client)


def validate_cross(values, workload, roles):
    actual_roles = set()
    for value in values:
        if value.get("status") != "pass" or value.get("workload") != workload:
            raise GateFailure("cross-client workload did not report PASS: " + workload)
        actual_roles.add(value.get("role"))
    if actual_roles != set(roles):
        raise GateFailure("cross-client workload role mismatch: " + workload)


def topology_evidence(vm, cycle):
    root = shlex.quote(vm.lane_root)
    script = """set -eu
root=%s
for ns in fnfs-l0-s fnfs-l0-c0 fnfs-l0-c1; do
    printf 'NETNS %%s\\n' "$ns"
    ip -n "$ns" -o -4 addr show
    ip -n "$ns" route show
done
server_pid=$(cat "$root/server.pid")
backing_type=$(nsenter -t "$server_pid" -m -n -- findmnt -n -o FSTYPE -- "$root/server/export")
backing_source=$(nsenter -t "$server_pid" -m -n -- findmnt -n -o SOURCE -- "$root/server/export")
printf 'BACKING %%s %%s\n' "$backing_type" "$backing_source"
printf 'CLIENTS_BEGIN\\n'
nsenter -t "$server_pid" -m -n -- sh -c 'for f in /proc/fs/nfsd/clients/*/info; do test -r "$f" && cat "$f"; done'
printf 'CLIENTS_END\\n'
for index in 0 1; do
    client_pid=$(cat "$root/client$index.pid")
    printf 'IDENTIFIER%%s ' "$index"
    cat "$root/client$index.identifier"
    printf 'IDENTIFIER_POSTMOUNT%%s ' "$index"
    nsenter -t "$client_pid" -n -- cat /sys/fs/nfs/net/nfs_client/identifier
    printf 'MOUNT%%s ' "$index"
    nsenter -t "$client_pid" -m -n -- findmnt -n -o FSTYPE,OPTIONS -- "$root/client$index/mnt"
done
""" % root
    result = vm.guest("cycle%d-topology" % cycle, script, timeout=45)
    text = result.stdout
    requirements = (
        "NETNS fnfs-l0-s",
        "NETNS fnfs-l0-c0",
        "NETNS fnfs-l0-c1",
        "10.77.0.1/30",
        "10.77.0.2/30",
        "10.77.0.5/30",
        "10.77.0.6/30",
        "BACKING tmpfs frozen-lane0",
        "IDENTIFIER0 frozen-lane0-client0",
        "IDENTIFIER1 frozen-lane0-client1",
        "MOUNT0 nfs4",
        "MOUNT1 nfs4",
        "vers=4.1",
        "proto=tcp",
        'address: "10.77.0.2:',
        'address: "10.77.0.6:',
    )
    missing = [item for item in requirements if item not in text]
    if missing:
        raise GateFailure("topology/server-state evidence missing: " + ", ".join(missing))
    if text.count("minor version: 1") < 2:
        raise GateFailure("server did not report two NFSv4.1 clients")
    return {
        "command_log": vm.evidence["commands"][-1]["stdout"],
        "direct_veth_addresses": True,
        "dedicated_tmpfs": True,
        "nfs_version": "4.1",
        "transport": "tcp",
        "same_server_netns_clients": ["10.77.0.2", "10.77.0.6"],
    }


def cleanup_and_validate(vm, cycle, strict=True):
    if vm.lane_root is None:
        return None
    lane = REMOTE_DRIVER + "/lane.sh"
    cleanup = vm.guest(
        "cycle%d-cleanup" % cycle,
        shlex.join([lane, "cleanup", vm.lane_root]),
        timeout=60,
        check=strict,
    )
    root = shlex.quote(vm.lane_root)
    checks = """set -eu
root=%s
test ! -e "$root"
for ns in fnfs-l0-s fnfs-l0-c0 fnfs-l0-c1; do
    ! ip netns list | awk '{print $1}' | grep -Fx "$ns"
done
for link in fz0c0 fz0s0 fz0c1 fz0s1; do
    ! ip link show "$link" >/dev/null 2>&1
done
! findmnt -rn | grep -F "$root"
! ps -eo comm= | grep -Ex '(rpcbind|rpc.mountd|nfsdcld|nfsd)'
printf '{"mount_leaks":0,"namespace_leaks":0,"nfsd_resource_leaks":0,"veth_leaks":0}\n'
""" % root
    validation = vm.guest(
        "cycle%d-cleanup-validation" % cycle,
        checks,
        timeout=30,
        check=strict,
    )
    if strict:
        return json_result(validation.stdout)
    return {
        "cleanup_returncode": cleanup.returncode,
        "validation_returncode": validation.returncode,
    }


def run_cycle(vm, cycle):
    lane = REMOTE_DRIVER + "/lane.sh"
    cycle_result = {"cycle": cycle, "started_at": utc_timestamp()}
    vm.evidence["cycles"].append(cycle_result)
    write_evidence(vm.output, vm.evidence)

    setup = vm.guest(
        "cycle%d-setup" % cycle,
        shlex.join([lane, "setup", vm.lane_root]),
        timeout=150,
    )
    setup_value = json_result(setup.stdout)
    validate_status(setup_value)
    cycle_result["setup"] = setup_value

    # The configured grace period is ten seconds.  Let it expire before OPEN
    # and LOCK validation so grace denial cannot masquerade as a workload bug.
    vm.guest("cycle%d-grace" % cycle, "sleep 11", timeout=20)
    status = vm.guest(
        "cycle%d-status" % cycle,
        shlex.join([lane, "status", vm.lane_root]),
        timeout=30,
    )
    status_value = json_result(status.stdout)
    validate_status(status_value)
    cycle_result["status"] = status_value

    basics = []
    for client in (0, 1):
        result = vm.guest(
            "cycle%d-basic-client%d" % (cycle, client),
            vm.workload_command(
                client, "basic", "cycle%d-basic-client%d" % (cycle, client)
            ),
            timeout=90,
        )
        value = json_result(result.stdout)
        validate_basic(value, "client%d" % client)
        basics.append(value)
    cycle_result["basic_workloads"] = basics

    lock_run = "cycle%d-cross-lock" % cycle
    lock_results = vm.guest_parallel(
        "cycle%d-cross-lock" % cycle,
        [
            vm.workload_command(0, "lock-holder", lock_run, sync=True),
            vm.workload_command(1, "lock-contender", lock_run, sync=True),
        ],
    )
    lock_values = [json_result(item.stdout) for item in lock_results]
    validate_cross(lock_values, "cross_lock", ("holder", "contender"))
    cycle_result["cross_lock"] = lock_values

    rename_run = "cycle%d-cross-rename" % cycle
    rename_results = vm.guest_parallel(
        "cycle%d-cross-rename" % cycle,
        [
            vm.workload_command(0, "rename-reader", rename_run, sync=True),
            vm.workload_command(1, "rename-renamer", rename_run, sync=True),
        ],
    )
    rename_values = [json_result(item.stdout) for item in rename_results]
    validate_cross(rename_values, "cross_rename_read", ("reader", "renamer"))
    for value in rename_values:
        if value.get("role") == "reader" and value.get("reads_ok") != vm.args.rename_iterations:
            raise GateFailure("rename reader did not complete every iteration")
    cycle_result["cross_rename_read"] = rename_values
    cycle_result["topology"] = topology_evidence(vm, cycle)

    vm.guest(
        "cycle%d-lane-diagnostics" % cycle,
        "set +e; root=%s; for f in \"$root\"/*.log \"$root\"/*.mount; do "
        "test -f \"$f\" || continue; printf 'FILE %%s\\n' \"$f\"; sed -n '1,240p' \"$f\"; done"
        % shlex.quote(vm.lane_root),
        timeout=30,
        check=False,
    )
    cycle_result["lane_diagnostics"] = vm.evidence["commands"][-1]["stdout"]
    cycle_result["cleanup"] = cleanup_and_validate(vm, cycle)
    cycle_result["status_result"] = "pass"
    cycle_result["completed_at"] = utc_timestamp()
    write_evidence(vm.output, vm.evidence)
    return cycle_result


def gate_checks(evidence, cycles):
    checks = {
        "server_netns_works": True,
        "two_client_netns_work": True,
        "client_identifiers_distinct": True,
        "identifier_set_before_first_mount": evidence["source_contract"][
            "identifier_before_first_mount"
        ],
        "nfsv4_1_confirmed": True,
        "tcp_confirmed": True,
        "localio_disabled": True,
        "both_clients_same_knfsd_lane": True,
        "dedicated_backing_filesystem": True,
        "crud_workload_succeeds": True,
        "lock_locku_succeeds": True,
        "cross_client_workloads_succeed": True,
        "repeated_setup_cleanup_stable": len(cycles) >= 2,
        "no_leaked_mounts_netns_nfsd_resources": all(
            item.get("cleanup", {}).get("mount_leaks") == 0
            and item.get("cleanup", {}).get("namespace_leaks") == 0
            and item.get("cleanup", {}).get("nfsd_resource_leaks") == 0
            and item.get("cleanup", {}).get("veth_leaks") == 0
            for item in cycles
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise GateFailure("Gate 1 checks failed: " + ", ".join(failed))
    evidence["gate"] = {"name": "Gate 1", "status": "pass", "checks": checks}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True, help="supplied bzImage")
    parser.add_argument("--image", type=Path, required=True, help="clean raw base image")
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    scripts = Path(__file__).resolve().parent
    parser.add_argument(
        "--lane-script", type=Path, default=scripts / "frozen_phase1_lane.sh"
    )
    parser.add_argument(
        "--workload", type=Path, default=scripts / "frozen_phase1_workload.py"
    )
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--rename-iterations", type=int, default=32)
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory", type=int, default=4096, help="guest MiB")
    parser.add_argument("--boot-timeout", type=int, default=180)
    parser.add_argument("--python-bin", type=Path, default=Path("/usr/bin/python3.10"))
    parser.add_argument("--python-stdlib", type=Path, default=Path("/usr/lib/python3.10"))
    args = parser.parse_args(argv)
    for field in ("kernel", "image", "ssh_key", "deps_tar", "lane_script", "workload"):
        setattr(args, field, getattr(args, field).resolve())
    args.python_bin = args.python_bin.resolve()
    args.python_stdlib = args.python_stdlib.resolve()
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new path; refusing to overwrite evidence")
    if args.cycles < 2:
        parser.error("--cycles must be at least 2 for the repeated cleanup gate")
    if not 1 <= args.rename_iterations <= 1000:
        parser.error("--rename-iterations must be 1..1000")
    if not 2 <= args.cpus <= 32:
        parser.error("--cpus must be 2..32")
    if not 2048 <= args.memory <= 32768:
        parser.error("--memory must be 2048..32768 MiB")
    if not 30 <= args.boot_timeout <= 600:
        parser.error("--boot-timeout must be 30..600 seconds")
    return args


def main(argv=None):
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "commands").mkdir()
    evidence = {
        "schema": SCHEMA_VERSION,
        "phase": 1,
        "status": "running",
        "started_at": utc_timestamp(),
        "commands": [],
        "cycles": [],
    }
    write_evidence(args.output, evidence)
    vm = None
    exit_code = 1
    base_hash = None
    try:
        validate_inputs(args, evidence)
        python_runtime = build_python_runtime(args, evidence)
        base_hash = evidence["inputs"]["image"]["sha256"]
        write_evidence(args.output, evidence)
        vm = FrozenPhase1VM(args, evidence)
        vm.start()

        inventory = vm.guest(
            "guest-inventory",
            "set -eu; uname -a; test \"$(cat /sys/module/nfs/parameters/localio_enabled)\" = N; "
            "command -v ip unshare nsenter mountpoint mount ping findmnt timeout tar",
            timeout=30,
        )
        evidence["runtime"]["inventory"] = inventory.stdout.splitlines()
        evidence["runtime"]["uname"] = inventory.stdout.splitlines()[0]

        vm.put("copy-dependencies", args.deps_tar, "/tmp/frozen-phase1-deps.tar.gz")
        vm.put("copy-python-runtime", python_runtime, "/tmp/frozen-python-runtime.tar.gz")
        vm.put("copy-lane-script", args.lane_script, "/tmp/frozen-phase1-lane.sh")
        vm.put("copy-workload", args.workload, "/tmp/frozen-phase1-workload.py")
        install = """set -eu
test ! -e /opt/kcov-nfs/deps
test ! -e /opt/frozen-phase1
test ! -e /opt/frozen-python
install -d /opt/kcov-nfs/deps /opt/frozen-phase1 /opt/frozen-python
tar -xzf /tmp/frozen-phase1-deps.tar.gz -C /opt/kcov-nfs/deps
tar -xzf /tmp/frozen-python-runtime.tar.gz -C /opt/frozen-python
install -m 0755 /tmp/frozen-phase1-lane.sh /opt/frozen-phase1/lane.sh
install -m 0755 /tmp/frozen-phase1-workload.py /opt/frozen-phase1/workload.py
PATH=/opt/kcov-nfs/deps/usr/sbin:/opt/kcov-nfs/deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin
LD_LIBRARY_PATH=/opt/kcov-nfs/deps/usr/lib/x86_64-linux-gnu:/opt/kcov-nfs/deps/lib/x86_64-linux-gnu
export PATH LD_LIBRARY_PATH
command -v mount.nfs4 exportfs rpcbind rpc.mountd rpc.nfsd nfsdcld
PYTHONHOME=/opt/frozen-python/usr \
/opt/frozen-python/lib64/ld-linux-x86-64.so.2 \
    --library-path /opt/frozen-python/lib/x86_64-linux-gnu \
    /opt/frozen-python/usr/bin/python3.10 \
    -m py_compile /opt/frozen-phase1/workload.py
"""
        installed = vm.guest("install-guest-inputs", install, timeout=90)
        evidence["runtime"]["installed_tools"] = installed.stdout.splitlines()
        root_result = vm.guest(
            "allocate-lane-root", "mktemp -d " + LANE_ROOT_TEMPLATE, timeout=15
        )
        vm.lane_root = root_result.stdout.strip()
        if not re.fullmatch(r"/tmp/frozen-nfs\.[A-Za-z0-9]+", vm.lane_root):
            raise GateFailure("guest returned unsafe lane root: %r" % vm.lane_root)
        evidence["runtime"]["lane_root"] = vm.lane_root

        for cycle in range(1, args.cycles + 1):
            run_cycle(vm, cycle)
        gate_checks(evidence, evidence["cycles"])

        dmesg = vm.guest("final-dmesg", "dmesg", timeout=30, check=False)
        (args.output / "dmesg.txt").write_text(
            dmesg.stdout + dmesg.stderr, encoding="utf-8", errors="replace"
        )
        evidence["runtime"]["dmesg"] = "dmesg.txt"
        if dmesg.returncode:
            raise GateFailure("could not collect final dmesg")
        if FATAL_KERNEL_RE.search(dmesg.stdout):
            raise GateFailure("fatal kernel diagnostic found; see dmesg.txt")

        evidence["status"] = "pass"
        evidence["completed_at"] = utc_timestamp()
        exit_code = 0
    except Exception as error:
        evidence["status"] = "fail"
        evidence["failure"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        evidence["completed_at"] = utc_timestamp()
        evidence.setdefault("gate", {"name": "Gate 1"})["status"] = "fail"
    finally:
        if vm is not None and vm.ready:
            if vm.lane_root is not None:
                try:
                    evidence["final_cleanup"] = cleanup_and_validate(
                        vm, args.cycles + 1, strict=False
                    )
                    final_cleanup_failed = any(
                        evidence["final_cleanup"].get(field) != 0
                        for field in ("cleanup_returncode", "validation_returncode")
                    )
                    if final_cleanup_failed and exit_code == 0:
                        evidence["status"] = "fail"
                        evidence["gate"]["status"] = "fail"
                        evidence["failure"] = {
                            "type": "GateFailure",
                            "message": "final idempotent cleanup validation failed",
                        }
                        exit_code = 1
                except Exception as cleanup_error:
                    evidence["final_cleanup"] = {
                        "error": str(cleanup_error),
                        "type": type(cleanup_error).__name__,
                    }
                    if exit_code == 0:
                        evidence["status"] = "fail"
                        evidence["failure"] = {
                            "type": type(cleanup_error).__name__,
                            "message": "final cleanup failed: %s" % cleanup_error,
                        }
                        evidence["gate"]["status"] = "fail"
                        exit_code = 1
            try:
                result = vm.guest("failure-dmesg", "dmesg", timeout=30, check=False)
                if not (args.output / "dmesg.txt").exists():
                    (args.output / "dmesg.txt").write_text(
                        result.stdout + result.stderr,
                        encoding="utf-8",
                        errors="replace",
                    )
                    evidence.setdefault("runtime", {})["dmesg"] = "dmesg.txt"
            except Exception as dmesg_error:
                evidence.setdefault("collection_errors", []).append(str(dmesg_error))
        if vm is not None:
            vm.stop()
        if base_hash is not None:
            try:
                final_hash = sha256(args.image)
                evidence["inputs"]["image"]["sha256_after"] = final_hash
                evidence["inputs"]["image"]["unchanged"] = final_hash == base_hash
                if final_hash != base_hash:
                    evidence["status"] = "fail"
                    evidence["failure"] = {
                        "type": "GateFailure",
                        "message": "raw base image changed despite snapshot mode",
                    }
                    exit_code = 1
            except OSError as hash_error:
                evidence.setdefault("collection_errors", []).append(str(hash_error))
                evidence["status"] = "fail"
                exit_code = 1
        write_evidence(args.output, evidence)

    print(json.dumps({
        "status": evidence["status"],
        "evidence": str(args.output / "phase1-evidence.json"),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
