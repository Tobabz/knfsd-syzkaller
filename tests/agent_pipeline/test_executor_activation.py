"""S1a on the host: the syzkaller executor's activation barrier against the real Proxy.

The barrier code is `executor/nfs_proxy_activation.h`, which the checked-in
syzkaller patch adds.  This test takes that header out of the patch, compiles
it into a small driver (a program-process thread asking the fork server's
broker over a socket pair, as in the executor), and runs it against the built Proxy in
target mode with the real host sink -- the same pieces as
`test_journal_live.py`, with the executor's client instead of the test's own
activation requests.  How the executor places the barrier around a program
(skip the program without an ACK, close the window before KCOV FINISH, the
fork server's orphan path, the runner refusing an uncleared lane) is covered
by the patch's own executor tests; booting a guest is the KVM step.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from agent_pipeline.journal_sink import parse_request

from .test_journal_live import (  # noqa: F401  (proxy_binary is a fixture)
    SESSION, SLOTID_OFFSET, HostJournal, Live, _journal, compound_call, proxy_binary,
)

ROOT = Path(__file__).resolve().parents[2]
PATCHES = ROOT / "bundle" / "patches" / "syzkaller"
HEADER = "executor/nfs_proxy_activation.h"

# NFSP_ACT_BARRIER_* and NFSP_ACT_LEASE_*.
ACKED, REFUSED, NO_ANSWER = 1, 2, 3
CLEAR, HELD, UNCLEARED = 0, 1, 2
QUARANTINE = 31

DRIVER = r"""
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "nfs_proxy_activation.h"

/* The executor's two sides: the program process (a thread here) asks over
 * its pair, the fork server (main) brokers the barrier on the endpoint.
 *
 * argv: SOCKET RULE_SET_ID TIMEOUT_MS.  stdin, one command per line:
 *   activate GEN PROGRAM_HEX   the program asks for its window
 *   release                    DONE if it ran, then the program process ends */
struct ask {
	int fd;
	unsigned op;
	unsigned long long generation;
	int answer;
	volatile int finished;
};

static void* program_process(void* arg)
{
	struct ask* a = arg;
	a->answer = nfsp_broker_call(a->fd, a->op, a->generation);
	a->finished = 1;
	return NULL;
}

static int ask_broker(struct nfsp_act_endpoint* ep, struct nfsp_broker* k, int fd, unsigned op,
		      unsigned long long generation)
{
	struct ask a = {fd, op, generation, -1, 0};
	pthread_t th;
	pthread_create(&th, NULL, program_process, &a);
	while (!a.finished)
		nfsp_broker_serve(ep, k, 10);
	pthread_join(th, NULL);
	return a.answer;
}

int main(int argc, char **argv)
{
	struct nfsp_act_endpoint ep;
	struct nfsp_broker k;
	struct sockaddr_un addr = {0};
	char line[8192], hex[4096];
	static unsigned char prog[2048];
	unsigned long long gen;
	int pair[2] = {-1, -1};
	int ran = 0;

	if (argc != 4)
		return 2;
	ep.fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);
	if (ep.fd < 0 || connect(ep.fd, (struct sockaddr *)&addr, sizeof(addr)))
		return 3;
	if (!nfsp_act_valid_rule_set_id(argv[2], strlen(argv[2])))
		return 5;
	memcpy(ep.rule_set_id, argv[2], NFSP_ACT_RULE_SET_ID_LEN);
	ep.timeout_ms = strtoull(argv[3], NULL, 10);
	while (fgets(line, sizeof(line), stdin)) {
		if (sscanf(line, "activate %llu %4095s", &gen, hex) == 2) {
			size_t n = strlen(hex) / 2;
			for (size_t i = 0; i < n; i++)
				sscanf(hex + 2 * i, "%2hhx", &prog[i]);
			if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair))
				return 6;
			nfsp_broker_start(&k, pair[0], prog, n);
			ran = ask_broker(&ep, &k, pair[1], NFSP_BROKER_ACTIVATE, gen) == 1;
			printf("ok=%d activation=%u/%u lease=%u executed=%u digest=", ran,
			       k.b.activation, k.b.activation_status, k.b.lease, k.b.executed);
			for (int i = 0; i < 32; i++)
				printf("%02x", k.b.digest[i]);
			printf("\n");
		} else if (strncmp(line, "release", 7) == 0) {
			if (ran && ask_broker(&ep, &k, pair[1], NFSP_BROKER_DONE, 0) != 1)
				return 7;
			close(pair[1]);
			nfsp_broker_finish(&ep, &k);
			printf("deactivation=%u/%u lease=%u\n", k.b.deactivation,
			       k.b.deactivation_status, k.b.lease);
		} else {
			return 4;
		}
		fflush(stdout);
	}
	return 0;
}
"""


def executor_header() -> str:
    """The new file `HEADER` exactly as the syzkaller patch series adds it."""
    found = []
    for patch in sorted(PATCHES.glob("*.patch")):
        lines = patch.read_text().splitlines()
        for i, line in enumerate(lines):
            if line == f"+++ b/{HEADER}" and lines[i - 1] == "--- /dev/null":
                body = []
                for added in lines[i + 2:]:
                    if added.startswith("diff --git ") or added == "-- ":
                        break
                    assert added.startswith("+"), added
                    body.append(added[1:])
                found.append("\n".join(body) + "\n")
    assert len(found) == 1, f"{HEADER} added by {len(found)} patches"
    return found[0]


@pytest.fixture(scope="module")
def driver(tmp_path_factory) -> Path:
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.fail("a C compiler is required to build the activation driver")
    work = tmp_path_factory.mktemp("activation-driver")
    (work / "nfs_proxy_activation.h").write_text(executor_header())
    (work / "driver.c").write_text(DRIVER)
    out = work / "driver"
    subprocess.run([cc, "-std=c11", "-D_GNU_SOURCE", "-O1", "-g", "-Wall", "-Werror", "-pthread",
                    f"-I{work}", "-o", str(out), str(work / "driver.c")], check=True)
    return out


class Executor:
    """The driver, connected to `live`'s activation endpoint like an executor."""

    def __init__(self, binary: Path, live: Live, timeout_ms: int = 2000) -> None:
        self.proc = subprocess.Popen(
            [str(binary), str(live.activation_path), live.rule_set_id, str(timeout_ms)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def run(self, command: str) -> dict[str, str]:
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, f"driver exited on {command!r}: {self.proc.wait()}"
        return dict(field.split("=", 1) for field in line.split())

    def activate(self, generation: int, program: bytes) -> dict[str, str]:
        return self.run(f"activate {generation} {program.hex()}")

    def release(self) -> dict[str, str]:
        return self.run("release")

    def close(self) -> None:
        self.proc.stdin.close()
        assert self.proc.wait(timeout=10) == 0


def _stop(live: Live) -> str:
    try:
        return live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()


def test_header_is_the_patch_copy():
    header = executor_header()
    assert '"NFSPACT1"' in header and '"NFSPACK1"' in header
    assert "nfsp_act_activate" in header and "nfsp_act_release" in header


def test_window_brackets_mutation_with_the_program_digest(proxy_binary, driver, tmp_path):
    journal = _journal(tmp_path)
    live = Live(proxy_binary, tmp_path, journal)
    executor = Executor(driver, live)
    program = b"\x01exec-encoded program\x00" * 3
    digest = hashlib.sha256(program).hexdigest()
    try:
        live.call(10, 5)  # before the window: untouched
        assert live.backend.received[-1][0] == compound_call(10, 5)

        got = executor.activate(7, program)
        assert got == {"ok": "1", "activation": f"{ACKED}/0", "lease": str(HELD),
                       "executed": "1", "digest": digest}
        live.call(11, 5)
        record = live.backend.received[-1][0]
        assert record[SLOTID_OFFSET:SLOTID_OFFSET + 4] == (7).to_bytes(4, "big")

        assert executor.release() == {"deactivation": f"{ACKED}/0", "lease": str(CLEAR)}
        live.wait_event("GENERATION_COMPLETE")
        live.call(12, 5)  # after the window: untouched again
        assert live.backend.received[-1][0] == compound_call(12, 5)
        executor.close()
        out = _stop(live)
    finally:
        if executor.proc.poll() is None:
            executor.proc.kill()
        if live.proc.poll() is None:
            live.proc.kill()
    events = journal.events(SESSION)
    assert [e.request.event_type for e in events] == [
        "RULESET", "GENERATION_OPEN", "EXPOSURE_INTENT", "FORWARD_COMPLETE",
        "GENERATION_DRAINING", "GENERATION_COMPLETE", "RUN_COMPLETE"]
    opened = events[1].request.payload.correlation
    assert (opened.kcov_generation, opened.program_digest) == (7, digest)
    assert opened.rule_set_id == live.rule_set_id
    assert journal.rejections() == []
    assert "run_complete=acked" in out


def test_refused_open_keeps_the_program_out_and_the_lease_clear(proxy_binary, driver, tmp_path):
    journal = _journal(tmp_path, lane=3)  # the host bound another lane
    live = Live(proxy_binary, tmp_path, journal)
    executor = Executor(driver, live)
    try:
        got = executor.activate(7, b"program")
        # Not executed; the refused generation is closed, so nothing is held.
        assert got["ok"] == "0" and got["executed"] == "0"
        assert got["activation"].startswith(f"{REFUSED}/")
        assert got["lease"] == str(CLEAR)
        live.call(21, 5)
        assert live.backend.received[-1][0] == compound_call(21, 5)
        executor.close()
        _stop(live)
    finally:
        if executor.proc.poll() is None:
            executor.proc.kill()
        if live.proc.poll() is None:
            live.proc.kill()
    # The host refused to bind G (and so also G's summary after the abort).
    rejected = [(r.event_type, r.reason) for r in journal.rejections()]
    assert rejected[0] == ("GENERATION_OPEN", "wrong_lane"), rejected
    assert {reason for _, reason in rejected} == {"wrong_lane"}
    assert live.types() == ["RULESET"]


class _StallsOpen(HostJournal):
    """A sink that answers GENERATION_OPEN only once `release` is set."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.release = threading.Event()

    def submit(self, channel, raw):  # type: ignore[override]
        if parse_request(raw).event_type == "GENERATION_OPEN":
            self.release.wait(20)
        return super().submit(channel, raw)


def test_lost_activation_ack_ends_in_an_uncleared_lane(proxy_binary, driver, tmp_path):
    """No ACK is not "not active": the executor aborts, the Proxy quarantines
    the session, and the next program finds the lane unusable -- the runner's
    cue to recreate it instead of running programs outside their window."""
    journal = _journal(tmp_path, cls=_StallsOpen)
    live = Live(proxy_binary, tmp_path, journal)
    executor = Executor(driver, live, timeout_ms=300)
    try:
        got = executor.activate(7, b"program")
        assert got["ok"] == "0" and got["activation"] == f"{NO_ANSWER}/{0xffffffff}"
        assert got["lease"] == str(CLEAR)  # the ABORT was ACKed
        live.call(31, 5)  # no window: untouched
        assert live.backend.received[-1][0] == compound_call(31, 5)

        journal.release.set()  # the late OPEN ACK must not open anything
        time.sleep(0.3)
        got = executor.activate(8, b"next program")
        assert got["ok"] == "0" and got["activation"] == f"{REFUSED}/{QUARANTINE}"
        assert got["lease"] == str(UNCLEARED)
        live.call(32, 5)
        assert live.backend.received[-1][0] == compound_call(32, 5)
        executor.close()
        out = _stop(live)
    finally:
        journal.release.set()
        if executor.proc.poll() is None:
            executor.proc.kill()
        if live.proc.poll() is None:
            live.proc.kill()
    assert "exposures=0" in out
