#!/usr/bin/env python3
"""Non-promoting offline NLMv4 LOCK/GRANTED correlation from a VM pcap."""

import hashlib
import ipaddress
import re
import struct
from collections import defaultdict


NLM4_STATUS = {
    0: "LCK_GRANTED",
    1: "LCK_DENIED",
    2: "LCK_DENIED_NOLOCKS",
    3: "LCK_BLOCKED",
    4: "LCK_DENIED_GRACE_PERIOD",
    5: "DEADLCK",
    6: "ROFS",
    7: "STALE_FH",
    8: "FBIG",
    9: "FAILED",
}
TRACE_STATUS = frozenset(NLM4_STATUS.values())


class Incomplete(ValueError):
    pass


def word(data, offset):
    if offset + 4 > len(data):
        raise Incomplete("short XDR word")
    return struct.unpack_from(">I", data, offset)[0], offset + 4


def opaque(data, offset):
    size, offset = word(data, offset)
    padded = (size + 3) // 4 * 4
    if size > 1024 or offset + padded > len(data):
        raise Incomplete("invalid XDR opaque")
    return data[offset:offset + size], offset + padded


def opaque_digest(domain, value):
    return hashlib.sha256(domain + struct.pack(">I", len(value)) + value).hexdigest()


def grant_trace_statuses(trace):
    """Extract only the non-sensitive result from nlmclnt_grant events."""
    result = []
    for line in trace.splitlines():
        if "nlmclnt_grant:" not in line:
            continue
        match = re.search(r"(?:^|\s)status=([A-Z_]+)(?:\s|$)", line)
        if match and match.group(1) in TRACE_STATUS:
            result.append(match.group(1))
    return result


def nlm_call(record):
    offset = 0
    xid, offset = word(record, offset)
    direction, offset = word(record, offset)
    rpc_version, offset = word(record, offset)
    program, offset = word(record, offset)
    version, offset = word(record, offset)
    procedure, offset = word(record, offset)
    if (direction, rpc_version, program, version) != (0, 2, 100021, 4):
        return None
    for _ in range(2):
        _, offset = word(record, offset)
        _, offset = opaque(record, offset)
    if procedure not in (2, 10, 15):
        return None
    cookie, offset = opaque(record, offset)
    cookie_digest = opaque_digest(b"nlm4-cookie-v1\0", cookie)
    if procedure == 15:
        status, offset = word(record, offset)
        if offset != len(record):
            raise Incomplete("trailing NLM GRANTED_RES data")
        return {"xid": xid, "procedure": procedure,
                "cookie_digest": cookie_digest, "status": status,
                "status_name": NLM4_STATUS.get(status, "UNKNOWN")}
    if procedure == 2:
        _, offset = word(record, offset)  # block
    _, offset = word(record, offset)  # exclusive
    _, offset = opaque(record, offset)  # caller_name
    fh, offset = opaque(record, offset)
    oh, offset = opaque(record, offset)
    svid, offset = word(record, offset)
    if offset + 16 > len(record):
        raise Incomplete("short NLM range")
    start, length = struct.unpack_from(">QQ", record, offset)
    key = hashlib.sha256(b"nlm4-lock-key-v1\0" + struct.pack(">I", len(fh)) + fh +
                         struct.pack(">I", len(oh)) + oh +
                         struct.pack(">IQQ", svid, start, length)).hexdigest()
    return {"xid": xid, "procedure": procedure, "key_digest": key,
            "cookie_digest": cookie_digest}


def packets(path):
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in (
                b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise Incomplete("requires classic pcap")
        endian = "<" if header[0] == 0xd4 else ">"
        _, _, _, _, snaplen, linktype = struct.unpack(endian + "HHiIII", header[4:])
        if linktype != 1 or snaplen < 256:
            raise Incomplete("requires full Ethernet pcap")
        while packet_header := stream.read(16):
            if len(packet_header) != 16:
                raise Incomplete("short packet header")
            seconds, micros, included, original = struct.unpack(endian + "IIII", packet_header)
            if included != original or included > snaplen:
                raise Incomplete("truncated packet")
            frame = stream.read(included)
            if len(frame) != included:
                raise Incomplete("short packet")
            if len(frame) < 54 or frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
            ihl = (ip[0] & 15) * 4
            if ip[0] >> 4 != 4 or ihl < 20 or ip[9] != 6 or len(ip) < ihl + 20:
                continue
            if int.from_bytes(ip[6:8], "big") & 0x3fff:
                raise Incomplete("fragmented IPv4 packet")
            total = int.from_bytes(ip[2:4], "big")
            if total < ihl + 20 or total > len(ip):
                raise Incomplete("truncated IPv4 packet")
            tcp = ip[ihl:total]
            thl = (tcp[12] >> 4) * 4
            if thl < 20 or len(tcp) < thl:
                raise Incomplete("short TCP header")
            body = tcp[thl:]
            if body:
                yield (seconds + micros / 1_000_000,
                       str(ipaddress.IPv4Address(ip[12:16])),
                       str(ipaddress.IPv4Address(ip[16:20])),
                       int.from_bytes(tcp[:2], "big"),
                       int.from_bytes(tcp[2:4], "big"),
                       int.from_bytes(tcp[4:8], "big"), body)


def calls(path, *, deduplicate=True):
    seen = set()
    for timestamp, src, dst, sport, dport, seq, body in packets(path):
        identity = (src, dst, sport, dport, seq, hashlib.sha256(body).digest())
        if deduplicate and identity in seen:
            continue
        seen.add(identity)
        # Multi-segment RPC needs reassembly; never guess its identity.
        if len(body) < 4:
            continue
        marker = int.from_bytes(body[:4], "big")
        if marker >> 31 != 1 or marker & 0x7fffffff != len(body) - 4:
            continue
        try:
            decoded = nlm_call(body[4:])
        except Incomplete:
            continue
        if decoded:
            decoded.update(timestamp=timestamp, src=src, dst=dst,
                           sport=sport, dport=dport, tcp_sequence=seq,
                           framed_length=len(body),
                           framed_sha256=hashlib.sha256(body).hexdigest())
            yield decoded


def attribute(exposures, observed, activation_time, closure_time):
    """Require an exact forwarded message and unique live lock identity."""
    locks = defaultdict(list)
    callbacks = []
    for call in observed:
        if call["procedure"] == 2:
            locks[(call["xid"], call["framed_sha256"])].append(call)
        elif call["procedure"] == 10:
            callbacks.append(call)
    matched = []
    for exposure in exposures:
        ctx = exposure["record_context"]
        if (ctx.get("route"), ctx.get("program"), ctx.get("procedure")) != ("nlm", 100021, 2):
            continue
        lane = exposure["correlation"]["lane_id"]
        client_ip = f"10.89.{lane}.{2 if ctx['client'] == 0 else 6}"
        for call in locks[(ctx["xid"], exposure["output"]["output_sha256"])]:
            if call["dport"] != 4050 or call["src"] != client_ip:
                continue
            matched.append((exposure["correlation"]["kcov_generation"],
                            call["src"], call["dst"], call["key_digest"], call["timestamp"]))
    result = []
    for cb in callbacks:
        candidates = {(gen, client, timestamp)
                      for gen, client, server, key, timestamp in matched
                      if key == cb["key_digest"] and client == cb["dst"]
                      and server == cb["src"] and timestamp <= cb["timestamp"]}
        if not re.fullmatch(r"10\.89\.\d+\.[15]", cb["src"]):
            status = "unexpected_callback_source"
        elif not activation_time <= cb["timestamp"] <= closure_time:
            status = "outside_activation_window"
        elif len(candidates) != 1:
            status = "ambiguous_or_unmatched_lock"
        else:
            status = "matched_diagnostic"
        result.append({"procedure": cb["procedure"], "key_digest": cb["key_digest"],
                       "status": status,
                       "generation": next(iter(candidates))[0] if status == "matched_diagnostic" else None})
    return result


def granted_responses(observed):
    """Correlate GRANTED_RES to GRANTED_MSG without exposing their cookie."""
    callbacks = [call for call in observed if call["procedure"] == 10]
    grouped = {}
    for response in (call for call in observed if call["procedure"] == 15):
        candidates = [callback for callback in callbacks
                      if callback["cookie_digest"] == response["cookie_digest"]
                      and callback["src"] == response["dst"]
                      and callback["dst"] == response["src"]
                      and callback["timestamp"] <= response["timestamp"]]
        correlation = ("matched_callback" if len(candidates) == 1
                       else "ambiguous_or_unmatched_callback")
        # The relay experiment can expose the same RPC before and after the
        # transparent listener. Collapse that observation without claiming it
        # was not instead a retransmission.
        identity = (response["xid"], response["cookie_digest"],
                    response["status"], response["framed_sha256"])
        entry = grouped.setdefault(identity, {
            "cookie_digest": response["cookie_digest"],
            "status": response["status"],
            "status_name": response["status_name"],
            "correlation": correlation,
            "observation_count": 0,
        })
        entry["observation_count"] += 1
        if entry["correlation"] != correlation:
            entry["correlation"] = "ambiguous_or_unmatched_callback"
    return list(grouped.values())


def diagnostic(exposures, pcap, activation_time, closure_time):
    observed = list(calls(pcap))
    result = attribute(exposures, observed, activation_time, closure_time)
    responses = granted_responses(observed)
    return {"status": "diagnostic_only", "lock_calls": sum(
        call["procedure"] == 2 for call in observed),
        "callback_calls": len(result), "granted_res_calls": len(responses),
        "granted_responses": responses, "attribution": result}
