"""Machine-contract and semantic tests for attribution hook emission."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from tools.attr_hooks import HOOKS, SCHEMA, hook_result, verify_retry_trace

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "attr_hooks.py"

EXPECTED_COMMAND_SHA256 = {
    "v4.abort-next-async": [
        ("arm", "9dcaaaf3538d5df188f941dcc89463d45d99a62c22503f37b5634902b91de383")],
    "v4.abort-next-deferred": [
        ("arm", "8079a5e0fcd2ffe511db0ab7699ca2bf51c56681c4975815445197b08145018b")],
    "v4.generation-abort-ioctl": [
        ("abort", "d3d8bfd154ad904fe02cbeedb7d1a503ed270b6cddbf98f88a50866e0737e069")],
    "v4.pause-release-async-after-grant": [
        ("arm", "dee4bafb3c0174f6d04f788d16fa62481a70af0fd2cf84d2930c6346dff9d849"),
        ("observe-entered", "b079625172c95ceb9ceed255a29f7b88d0aa968f70e56930fefe67710caaeba6"),
        ("release", "d674f8a5a855a495c332401574ad5100a1f47a8b4675fbe36da1a0f789e82e18")],
    "v4.pause-release-deferred-after-grant": [
        ("arm", "d1fb6b1da4f0dfae6b7dda6407143b7d2e98875e4238fa98c5b0ea366f53f371"),
        ("observe-entered", "b079625172c95ceb9ceed255a29f7b88d0aa968f70e56930fefe67710caaeba6"),
        ("release", "0178170b0884df84a5d8235f06de2292c3a6619d22c895c0c875889b9d96caf2")],
    "v5.cancel-saved-work": [],
    "v5.redefer-cache-revisit": [
        ("hold-initial-cache", "82580d4aca08e0b8ac077fa5619377e11827854dcdc714f67207d1f60ae26db5"),
        ("arm-replay-pause", "d1fb6b1da4f0dfae6b7dda6407143b7d2e98875e4238fa98c5b0ea366f53f371"),
        ("resume-first-cache", "2e209ca9ef6a949dd2572c79659eb489de7f9f82ceba81e4dcf6daa25c83787f"),
        ("observe-replay-pause", "b079625172c95ceb9ceed255a29f7b88d0aa968f70e56930fefe67710caaeba6"),
        ("invalidate-at-replay", "068e615c15e72464da0e40ad2a6ba72f59af275b9467ea354c19d432f1b92fda"),
        ("release-replay", "0178170b0884df84a5d8235f06de2292c3a6619d22c895c0c875889b9d96caf2"),
        ("observe-redefer", "b079625172c95ceb9ceed255a29f7b88d0aa968f70e56930fefe67710caaeba6"),
        ("resume-second-cache-cleanup", "2e209ca9ef6a949dd2572c79659eb489de7f9f82ceba81e4dcf6daa25c83787f")],
    "v6.retry-same-cookie-same-socket": [
        ("run", "23fcb5cf9911ff608dc29b5cc0554e66f5b9b40320e950e2a138800c5aca798d"),
        ("verify-socket-identity", "13799c05c29b70b2b092de23bd584714aa34b7680c5be69755dc6d10e626ba0e")],
    "v7.concurrent-cross-lane": [
        ("snapshot-before", "4392c0a4c35339915871364807eea842e60d2906901571cfd2cf91b1a3da237d"),
        ("interleave", "2aad5d7bf4d56091990576a5b9790206c5eca3cff5111ade964315faf4c2d1bb"),
        ("snapshot-after", "4392c0a4c35339915871364807eea842e60d2906901571cfd2cf91b1a3da237d")],
}


def _command_contract(hook_id: str) -> list[tuple[str, str]]:
    return [(item["stage"], hashlib.sha256(item["command"].encode()).hexdigest())
            for item in hook_result(hook_id, dry_run=True)["commands"]]


@pytest.mark.parametrize("hook_id", sorted(EXPECTED_COMMAND_SHA256))
def test_each_hook_emits_exact_machine_commands(hook_id: str) -> None:
    assert _command_contract(hook_id) == EXPECTED_COMMAND_SHA256[hook_id]


def test_abort_and_pause_controls_use_exact_phase8_path_and_payloads() -> None:
    assert hook_result("v4.abort-next-deferred")["commands"] == [{
        "stage": "arm",
        "command": "printf '%s\\n' 'abort-next-deferred' > "
                   "/sys/kernel/debug/sunrpc_fuzz/phase8_control",
    }]
    assert hook_result("v4.pause-release-async-after-grant")["commands"] == [
        {"stage": "arm", "command": "printf '%s\\n' "
         "'fault-arm pause-next-async-after-grant' > "
         "/sys/kernel/debug/sunrpc_fuzz/phase8_control"},
        {"stage": "observe-entered", "command":
         "cat /sys/kernel/debug/sunrpc_fuzz/phase8_stats"},
        {"stage": "release", "command": "printf '%s\\n' "
         "'fault-release pause-async-after-grant' > "
         "/sys/kernel/debug/sunrpc_fuzz/phase8_control"},
    ]


def test_generation_abort_emits_guest_c_helper_with_write_ioctl() -> None:
    command = hook_result("v4.generation-abort-ioctl")["commands"][0]["command"]
    assert "python3" not in command
    assert "#define KCOV_REMOTE_GENERATION_ABORT _IOW('c', 112" in command
    assert '"$out/generation-abort" "${KCOV_FD:?}" "${KCOV_GENERATION:?}"' in command


def test_retry_trace_accepts_one_socket_one_connect_three_sends() -> None:
    trace = """SOCKET fd=4 domain=2 type=524289 protocol=6
CONNECT fd=4
SENDMSG fd=4
SENDMSG fd=4
SENDMSG fd=4
"""
    result = json.dumps({"status": "pass", "scenario": "retry-final",
                         "sends": 3, "replies": 3})
    assert verify_retry_trace(trace, result) == {
        "status": "pass", "socket_fd": 4, "connects": 1,
        "sendmsg_calls": 3, "reconnected": False,
    }


def test_real_emitter_to_verifier_uses_one_socket_and_three_sends(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        f"#!{sys.executable}\n"
        "import json, os, socket, sys\n"
        "assert sys.argv[1] == 'retry-final'\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)\n"
        "s.connect(('127.0.0.1',int(os.environ['ATTR_TEST_PORT'])))\n"
        "[s.sendmsg([b'x']) for _ in range(3)]\n"
        "s.close()\n"
        "print(json.dumps({'status':'pass','scenario':'retry-final','sends':3,'replies':3},separators=(',',':')))\n",
        encoding="utf-8")
    probe.chmod(0o755)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        env = dict(os.environ, ATTR_HOOK_DIR=str(tmp_path),
                   ATTR_PHASE7_PROBE=str(probe),
                   ATTR_TEST_PORT=str(listener.getsockname()[1]))
        run = subprocess.run(["sh", "-c", hook_result(
            "v6.retry-same-cookie-same-socket")["commands"][0]["command"]],
            env=env, text=True, capture_output=True, check=False)
    assert run.returncode == 0, run.stderr
    trace = (tmp_path / "retry-same-socket.audit").read_text(encoding="utf-8")
    assert trace.count("\n") == 5
    result_text = (tmp_path / "retry-same-socket.json").read_text(encoding="utf-8")
    assert verify_retry_trace(trace, result_text)["reconnected"] is False
    verify = subprocess.run(["sh", "-c", hook_result(
        "v6.retry-same-cookie-same-socket")["commands"][1]["command"]],
        env=env, text=True, capture_output=True, check=False)
    assert verify.returncode == 0, verify.stderr
    assert json.loads(verify.stdout)["sendmsg_calls"] == 3


def test_retry_trace_rejects_reconnect_even_if_fd_is_reused() -> None:
    trace = """SOCKET fd=4 domain=2 type=524289 protocol=6
CONNECT fd=4
SENDMSG fd=4
SOCKET fd=4 domain=2 type=524289 protocol=6
CONNECT fd=4
SENDMSG fd=4
SENDMSG fd=4
"""
    with pytest.raises(ValueError, match="expected one TCP socket"):
        verify_retry_trace(trace, json.dumps({
            "status": "pass", "scenario": "retry-final", "sends": 3, "replies": 3}))


@pytest.mark.parametrize("extra", ["CONNECT fd=99", "SENDMSG fd=99"])
def test_both_retry_verifiers_reject_records_on_another_fd(
        tmp_path: Path, extra: str) -> None:
    trace = ("SOCKET fd=4 domain=2 type=524289 protocol=6\n"
             "CONNECT fd=4\nSENDMSG fd=4\nSENDMSG fd=4\nSENDMSG fd=4\n" + extra + "\n")
    result = '{"status":"pass","scenario":"retry-final","sends":3,"replies":3}\n'
    with pytest.raises(ValueError, match="expected only one socket"):
        verify_retry_trace(trace, result)
    (tmp_path / "retry-same-socket.audit").write_text(trace, encoding="utf-8")
    (tmp_path / "retry-same-socket.json").write_text(result, encoding="utf-8")
    completed = subprocess.run(
        ["sh", "-c", hook_result(
            "v6.retry-same-cookie-same-socket")["commands"][1]["command"]],
        env=dict(os.environ, ATTR_HOOK_DIR=str(tmp_path)),
        text=True, capture_output=True, check=False)
    assert completed.returncode != 0


def test_retry_hook_does_not_emit_disconnect_fault_control() -> None:
    commands = hook_result("v6.retry-same-cookie-same-socket")["commands"]
    joined = "\n".join(item["command"] for item in commands)
    assert "fault-arm sunrpc-retry" not in joined
    assert '"$probe" retry-final' in commands[0]["command"]
    assert "LD_PRELOAD" in commands[0]["command"]
    assert 'sockets != 1 || connects != 1 || sends != 3' in commands[1]["command"]


def test_redefer_uses_after_grant_barrier_and_two_cache_invalidations() -> None:
    commands = hook_result("v5.redefer-cache-revisit")["commands"]
    assert [item["stage"] for item in commands] == [
        "hold-initial-cache", "arm-replay-pause", "resume-first-cache",
        "observe-replay-pause", "invalidate-at-replay", "release-replay",
        "observe-redefer", "resume-second-cache-cleanup",
    ]
    joined = "\n".join(item["command"] for item in commands)
    assert joined.count("/proc/net/rpc/nfsd.export/flush") == 2
    assert "pause-next-deferred-after-grant" in joined
    assert "pause-deferred-after-grant" in joined


def test_cancel_is_typed_unforceable_after_runtime_attempts() -> None:
    completed = subprocess.run(
        [sys.executable, str(TOOL), "--dry-run", "v5.cancel-saved-work"],
        cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 2
    value = json.loads(completed.stdout)
    assert value["commands"] == [] and value["proof"] == []
    assert value["failure"]["type"] == "UNFORCEABLE"


def test_cross_lane_is_fifo_handshaked_without_timing_delay() -> None:
    command = hook_result("v7.concurrent-cross-lane")["commands"][1]["command"]
    assert "mkfifo" in command
    assert command.count("READY") == 3
    assert command.count("GO1") == 3
    assert command.count("GO2") == 3
    assert command.count("DONE1") == 3
    assert command.count("DONE2") == 3
    assert "sleep" not in command and "nanosleep" not in command


def test_all_emitted_shell_commands_parse_and_have_no_fixed_sleep() -> None:
    for hook in HOOKS.values():
        for item in hook.commands:
            completed = subprocess.run(
                ["sh", "-n", "-c", item["command"]], text=True,
                capture_output=True, check=False)
            assert completed.returncode == 0, (hook.hook_id, item, completed.stderr)
            assert "sleep " not in item["command"]


def test_schema_args_render_deterministic_exact_commands() -> None:
    generation = hook_result(
        "v4.generation-abort-ioctl",
        args={"hook_dir": "/tmp/h", "kcov_fd": 3, "generation": 7})
    assert hashlib.sha256(
        generation["commands"][0]["command"].encode()).hexdigest() == (
            "21564d8fc37584964f544d82c52ff1940c7dcc36250008e708dc01b74fdb7867")
    cross_lane = hook_result("v7.concurrent-cross-lane", args={
        "hook_dir": "/tmp/h", "phase9_root": "/tmp/frozen-phase9.x",
        "lane0_workload": "/opt/l0", "lane1_workload": "/opt/l1"})
    assert [(item["stage"], hashlib.sha256(item["command"].encode()).hexdigest())
            for item in cross_lane["commands"]] == [
        ("snapshot-before", "4a919e21488c94850a0e614d9e46721899156b635798f47327bd2c7bc8799a65"),
        ("interleave", "6392b67c3a790f4e733d89aec2ee93ba5e383a0db6274b4e4ea785152d14eb6f"),
        ("snapshot-after", "4a919e21488c94850a0e614d9e46721899156b635798f47327bd2c7bc8799a65")]


def test_task5_accepts_v7_positive_delta_ge_without_exact_one_narrowing() -> None:
    path = ROOT / "tools" / "attr-scenario-assert.py"
    spec = importlib.util.spec_from_file_location("attr_scenario_assert", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    hook_id = "v7.concurrent-cross-lane"
    hook_args: dict[str, object] = {}
    manifest = {
        "id": "B11-V7", "mode": "on", "procs": 2, "executions": 2,
        "hooks": [{"id": hook_id, "args": hook_args}],
        "counter_expect": [
            {"file": "phase9_stats", "name": "owner_lane_match",
             "op": "delta_ge", "value": 1},
            {"file": "phase9_stats", "name": "cross_lane_attribution",
             "op": "delta_eq", "value": 0}],
    }
    run = {
        "id": "B11-V7", "mode": "on", "procs": 2, "executions": 2,
        "hooks": [{"id": hook_id, "args": hook_args,
                   "manifest": hook_result(hook_id)}],
        "inputs": {},
    }
    assert module._run_contract(manifest, run) == (True, ["FORCEABLE"])


def test_invalid_schema_args_are_machine_rejected() -> None:
    completed = subprocess.run(
        [sys.executable, str(TOOL), "--dry-run", "v4.abort-next-deferred",
         "--args-json", '{"server_pid":1}'],
        cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 66
    assert completed.stdout == ""
    assert json.loads(completed.stderr)["status"] == "INVALID_ARGS"


def test_unknown_hook_is_rejected_in_machine_format() -> None:
    completed = subprocess.run(
        [sys.executable, str(TOOL), "--dry-run", "v9.impossible"],
        cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 64
    assert completed.stdout == ""
    assert json.loads(completed.stderr)["failure"] == {
        "hook_id": "v9.impossible", "type": "INVALID_HOOK"}


def test_hook_ids_remain_manifest_compatible() -> None:
    schema = json.loads((ROOT / "bundle/corpus/attr-scenarios/schema.json").read_text())
    assert set(schema["properties"]["hooks"]["items"]["enum"]) == set(HOOKS)
    assert set(schema["$defs"]["hook"]["properties"]["id"]["enum"]) == set(HOOKS)
    assert all(hook_result(name)["schema"] == SCHEMA for name in HOOKS)
