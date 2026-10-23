"""The diagnostic must never assign an ambiguous or late grant."""

import importlib.util
import struct
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "nlm_callback_attribution",
    Path(__file__).resolve().parents[2] / "tools/nlm_callback_attribution.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def u32(value):
    return struct.pack(">I", value)


def opaque(value):
    return u32(len(value)) + value + b"\0" * (-len(value) % 4)


def call(procedure, xid=7, *, cookie=b"cookie", status=0):
    body = b"".join((u32(xid), u32(0), u32(2), u32(100021), u32(4),
                     u32(procedure), u32(0), opaque(b""), u32(0), opaque(b""),
                     opaque(cookie)))
    if procedure == 15:
        return body + u32(status)
    if procedure == 2:
        body += u32(1)
    body += u32(1) + opaque(b"host") + opaque(b"fh") + opaque(b"owner")
    body += u32(123) + struct.pack(">QQ", 1, 10)
    if procedure == 2:
        body += u32(0) + u32(1)
    return body


def test_nlm_lock_grant_identity_ignores_cookie_and_xid():
    lock = module.nlm_call(call(2))
    grant = module.nlm_call(call(10, xid=8))
    assert lock["key_digest"] == grant["key_digest"]
    assert lock["xid"] != grant["xid"]
    assert module.nlm_call(call(2).replace(b"owner", b"other"))["key_digest"] != lock["key_digest"]
    assert module.nlm_call(call(5)) is None


def test_granted_res_decodes_only_cookie_digest_and_typed_status():
    response = module.nlm_call(call(15, cookie=b"private", status=1))
    callback = module.nlm_call(call(10, cookie=b"private"))
    assert response == {
        "xid": 7, "procedure": 15,
        "cookie_digest": callback["cookie_digest"],
        "status": 1, "status_name": "LCK_DENIED",
    }
    assert b"private" not in repr(response).encode()
    assert module.nlm_call(call(15, status=99))["status_name"] == "UNKNOWN"
    with __import__("pytest").raises(module.Incomplete):
        module.nlm_call(call(15) + u32(0))


def test_granted_res_requires_one_earlier_reverse_path_callback():
    callback = {**module.nlm_call(call(10, cookie=b"same")),
                "src": "server", "dst": "client", "timestamp": 2}
    response = {**module.nlm_call(call(15, cookie=b"same", status=1)),
                "src": "client", "dst": "server", "timestamp": 3,
                "framed_sha256": "a" * 64}
    matched = module.granted_responses([callback, response])[0]
    assert (matched["status_name"], matched["correlation"]) == (
        "LCK_DENIED", "matched_callback")
    assert matched["observation_count"] == 1
    assert module.granted_responses([response])[0]["correlation"] == (
        "ambiguous_or_unmatched_callback")
    assert module.granted_responses([callback, callback, response])[0]["correlation"] == (
        "ambiguous_or_unmatched_callback")
    duplicate = {**response, "sport": 999, "dport": 4050}
    collapsed = module.granted_responses([callback, response, duplicate])
    assert len(collapsed) == 1 and collapsed[0]["observation_count"] == 2


def test_trace_parser_retains_status_only():
    trace = """
 task: nlmclnt_grant: addr=private oh=0x1 fh=0x2 status=LCK_DENIED
 task: nlmclnt_grant: addr=private status=LCK_GRANTED
 task: nlmclnt_lock: addr=private status=LCK_DENIED
 task: nlmclnt_grant: addr=private status=MADE_UP
 task: nlmclnt_grant: addr=private status=LCK_DENIED suffix
"""
    assert module.grant_trace_statuses(trace) == [
        "LCK_DENIED", "LCK_GRANTED", "LCK_DENIED"]


def test_unique_ambiguous_and_late_callbacks():
    framed = u32(0x80000000 | len(call(2))) + call(2)
    digest = module.hashlib.sha256(framed).hexdigest()
    exposure = {"record_context": {"route": "nlm", "program": 100021,
                                   "procedure": 2, "client": 1, "xid": 7},
                "correlation": {"lane_id": 0, "kcov_generation": 1},
                "output": {"output_sha256": digest}}
    key = module.nlm_call(call(2))["key_digest"]
    lock = {"procedure": 2, "xid": 7, "framed_sha256": digest,
            "key_digest": key, "src": "10.89.0.6", "dst": "10.89.0.5",
            "dport": 4050, "timestamp": 2}
    callback = {"procedure": 10, "key_digest": key, "src": "10.89.0.5",
                "dst": "10.89.0.6", "timestamp": 3}
    assert module.attribute([exposure], [lock, callback], 1, 4)[0]["generation"] == 1
    second = {**exposure, "correlation": {"lane_id": 0, "kcov_generation": 2}}
    assert module.attribute([exposure, second], [lock, callback], 1, 4)[0]["status"] == "ambiguous_or_unmatched_lock"
    late = module.attribute([exposure], [lock, callback], 1, 2.5)[0]
    assert late["status"] == "outside_activation_window"
    assert late["generation"] is None
    early = module.attribute([exposure], [lock, callback], 3.5, 4)[0]
    assert early["status"] == "outside_activation_window"
    assert early["generation"] is None
    assert module.attribute([exposure], [callback], 1, 4)[0]["status"] == "ambiguous_or_unmatched_lock"
    other_client = {**callback, "dst": "10.89.0.2"}
    assert module.attribute([exposure], [lock, other_client], 1, 4)[0]["status"] == "ambiguous_or_unmatched_lock"
    wrong_source = {**callback, "src": "10.89.0.9"}
    assert module.attribute([exposure], [lock, wrong_source], 1, 4)[0]["status"] == "unexpected_callback_source"
    other_server = {**callback, "src": "10.89.0.1"}
    assert module.attribute([exposure], [lock, other_server], 1, 4)[0]["status"] == "ambiguous_or_unmatched_lock"


def test_classic_pcap_parses_one_complete_rpc_and_rejects_truncation(tmp_path):
    rpc = call(2)
    body = u32(0x80000000 | len(rpc)) + rpc
    tcp = struct.pack(">HHIIHHHH", 885, 4050, 42, 0, 5 << 12, 0, 0, 0) + body
    ip = (bytes.fromhex("4500") + struct.pack(">H", 20 + len(tcp)) +
          bytes.fromhex("0000000040060000") + bytes((10, 89, 0, 6, 10, 89, 0, 1)))
    packet = bytes.fromhex("0000000000000000000000000800") + ip + tcp
    header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(header + struct.pack("<IIII", 3, 500000, len(packet), len(packet)) + packet)
    decoded = list(module.calls(pcap))
    assert len(decoded) == 1
    assert decoded[0]["framed_sha256"] == module.hashlib.sha256(body).hexdigest()
    assert decoded[0]["timestamp"] == 3.5
    assert (decoded[0]["tcp_sequence"], decoded[0]["framed_length"]) == (42, len(body))
    pcap.write_bytes(pcap.read_bytes()[:-1])
    try:
        list(module.calls(pcap))
    except module.Incomplete:
        pass
    else:
        raise AssertionError("truncated capture was accepted")
