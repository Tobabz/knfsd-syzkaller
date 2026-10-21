"""A scripted guest for the Stage 1 host collector tests.

It answers the collector's commands the way a healthy fixture does, so the
collector's parsing and record building run unchanged without KVM.  Its
counters move the way the guest's do: execprog's machine check opens one
generation before the gate, and the program opens one after it.  The
remote coverage it returns is read from ``TEST_COVER_PCS`` (a file of hex
PCs, one per line) when the coverage is fetched.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path

STATS_BOOT = """== /sys/kernel/debug/sunrpc_fuzz/lane_stats
lane_owner_failed 0
lane_attribution 1
== /sys/kernel/debug/sunrpc_fuzz/phase4_stats
generation_begin 4
generation_aborted 0
outstanding_tokens 0
object_refs 0
== /sys/kernel/debug/sunrpc_fuzz/phase5_stats
remote_start_ok 3
remote_refs 0
== /sys/kernel/debug/sunrpc_fuzz/phase6_stats
aggregate_published 1
scratch_overflow 0
aggregate_merge_truncated 0
remote_refs 0
"""

#: After the machine check: its extra-coverage request opened and
#: published one generation of its own.
STATS_BEFORE = STATS_BOOT.replace("generation_begin 4", "generation_begin 5") \
    .replace("aggregate_published 1", "aggregate_published 2")

STATS_AFTER = STATS_BEFORE.replace("generation_begin 5", "generation_begin 6") \
    .replace("remote_start_ok 3", "remote_start_ok 5") \
    .replace("aggregate_published 2", "aggregate_published 3")


GENERATIONS = ("owner 1 state COMMITTED outstanding_tokens 0 object_refs 1 "
               "active_roots 0 retry_deadline_active 0 generation 5\n")


class FakeGuest:
    def __init__(self, config, *, pcs=None, fixture="active", lane_sha=None,
                 nfs_version="4.1", gate="ready", exec_rc="0", dmesg="",
                 generations=GENERATIONS, boot_error=None,
                 fixture_mode="single"):
        self.config = config
        self.pcs = pcs
        self.fixture = fixture
        self.lane_sha = lane_sha
        self.nfs_version = nfs_version
        self.fixture_mode = fixture_mode
        self.gate = gate
        self.exec_rc = exec_rc
        self.generations = generations
        #: boot -> started -> checked (at the gate) -> released -> done
        self.phase = "boot"
        self.dmesg = dmesg
        self.boot_error = boot_error
        self.commands: list[str] = []
        self.puts: list[tuple[Path, str]] = []
        self.stopped = False

    def start(self):
        if self.boot_error:
            raise RuntimeError(self.boot_error)
        Path(self.config.console_log).write_text("Linux version fake\n")

    def _lane_sha(self):
        if self.lane_sha is not None:
            return self.lane_sha
        return self.config.cmdline.split("koov.lane_sha256=")[1].split()[0]

    def run(self, command, *, timeout=60):
        self.commands.append(command)
        if command.startswith("systemctl is-active"):
            return 0, self.fixture + "\n"
        if "lane.sh status" in command:
            return 0, json.dumps({"lane_count": 4,
                                  "fixture_mode": self.fixture_mode,
                                  "nfs_version": self.nfs_version,
                                  "nfs_minor": 1, "nfs_trace": 0})
        if command.startswith("sha256sum"):
            return 0, f"{self._lane_sha()}  /run/frozen-phase9/lane.sh\n"
        if command.startswith("ip netns exec"):
            return 0, "lane_id 0 lane_epoch 1 valid 1 unhealthy 0 owner 1\n"
        if "sunrpc_fuzz/*_stats" in command:
            return 0, {"boot": STATS_BOOT, "started": STATS_BOOT,
                       "done": STATS_AFTER}.get(self.phase, STATS_BEFORE)
        if command.endswith("phase4_state"):
            return 0, self.generations
        if command.startswith("rm -rf /tmp/cov"):
            assert "-gate=/tmp/stage1/gate" in command
            self.phase = "started"
            return 0, ""
        if command.startswith("if [ -e /tmp/stage1/exec.rc ]"):
            if self.phase == "started":
                self.phase = "checked" if self.gate == "ready" else "done"
                return 0, ("ready" if self.gate == "ready" else "exited") + "\n"
            if self.phase == "released":
                self.phase = "done"
            return 0, "exited\n" if self.phase == "done" else ""
        if command == "touch /tmp/stage1/gate.go":
            assert self.phase == "checked"
            self.phase = "released"
            return 0, ""
        if command.startswith("cat /tmp/stage1/exec.rc"):
            return 0, self.exec_rc + "\n"
        if command.startswith("cat /tmp/stage1/exec.log"):
            return 0, "CALL 0: signal 3, coverage 9 errno 0\n"
        if command == "dmesg":
            return 0, self.dmesg
        return 0, ""

    def put(self, source, destination):
        self.puts.append((Path(source), destination))

    def get(self, source, destination):
        pcs = self.pcs
        if pcs is None:
            pcs = Path(os.environ["TEST_COVER_PCS"]).read_text().split()
        files = {"cover_prog0.meta": b"completed_unix_nano 1\nelapsed_nano 1\n",
                 "cover_prog0.0": b"0x1\n"}
        if pcs:
            files["cover_prog0.extra"] = "".join(
                f"{p}\n" for p in pcs).encode()
        with tarfile.open(destination, "w") as tf:
            for name, data in files.items():
                info = tarfile.TarInfo("./" + name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

    def stop(self):
        self.stopped = True
