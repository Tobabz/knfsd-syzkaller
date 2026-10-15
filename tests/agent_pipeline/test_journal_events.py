"""Wire-contract oracles, not semantic approval of fixture rules/records."""

import copy
import hashlib
import json
import struct

import pytest
from pydantic import ValidationError

from agent_pipeline.data import canonical_json
from agent_pipeline.journal_events import (
    MAX_APPLICATIONS, MAX_RECORD_BYTES, MAX_RULESET_BYTES, Application,
    BoolValue, EnumValue, HyperValue, IntValue, JournalEventError, ResolverCounts,
    UHyperValue, UIntValue, UnsupportedRuleProfile, decode_event, encode_event,
    parse_ruleset, scalar_bytes,
)
from agent_pipeline.journal_framing import MAX_PAYLOAD_BYTES


def word(value):
    return struct.pack(">I", value)


def name(value):
    raw = value.encode("ascii")
    return word(len(raw)) + raw + b"\0" * (-len(raw) % 4)


def rule_bytes(rule_id="call", message_type=0, **changes):
    """Independent XDR builder following design 04 §35, without a compiler."""
    values = dict(direction=message_type, backend=1, client=2, program=100003,
                  version=4, procedure=1, family="nfs4", nfs_version=4, minor_version=1,
                  operation=None, target_kind=0, part=0, predicates=0, mutation=0,
                  has_transform=1, transform=0, literal_kind=1 if not message_type else 5,
                  literal=2 if not message_type else 10001, policy=0, application=0,
                  path="nfs4.request.COMPOUND.args.minorversion" if not message_type
                  else "nfs4.response.COMPOUND.res.status", forwarded_rpc=message_type,
                  forwarded_operations=0, forwarded_fields=0, original_rpc=0,
                  original_operations=0, original_fields=0)
    values.update(changes)
    v = values

    def optional(value):
        return word(0) if value is None else word(1) + word(value)

    literal = int(v["literal"]).to_bytes(8 if v["literal_kind"] in (2, 3) else 4,
                                      "big", signed=v["literal_kind"] in (0, 2))
    return b"".join((
        name(rule_id), name("intent-1"), word(v["direction"]), word(v["backend"]),
        word(v["client"]), word(message_type), word(v["program"]), word(v["version"]),
        optional(v["procedure"]), name(v["family"]), optional(v["nfs_version"]),
        optional(v["minor_version"]), word(0) if v["operation"] is None else word(1) + name(v["operation"]),
        word(v["target_kind"]), name(v["path"]), word(v["part"]), word(v["predicates"]),
        word(v["mutation"]), word(v["has_transform"]), word(v["transform"]),
        word(v["literal_kind"]), literal, word(v["policy"]),
        word(v["forwarded_rpc"]), word(v["forwarded_operations"]), word(v["forwarded_fields"]),
        word(v["original_rpc"]), word(v["original_operations"]), word(v["original_fields"]),
        word(v["application"]),
    ))


def snapshot(*rules, schema_id="nfs4.1/test", candidate_id="candidate-1", version=1):
    if not rules:
        rules = (rule_bytes(), rule_bytes("reply", 1))
    return b"NFSPRUL1" + word(version) + name(schema_id) + name(candidate_id) + word(len(rules)) + b"".join(rules)


def binding(raw=None):
    return dict(vm_instance_id="vm-1", channel_id="channel-1", proxy_session_id="session-1",
                rule_set_id=hashlib.sha256(snapshot() if raw is None else raw).hexdigest())


def correlation(generation=1, lane=0, raw=None):
    return dict(vm_instance_id="vm-1", lane_id=lane, proc_id=lane,
                kcov_generation=generation, rule_set_id=binding(raw)["rule_set_id"],
                program_digest=f"{generation:064x}")


def context(reply=False):
    return dict(direction="S2C" if reply else "C2S", backend=1, client=2,
                connection_id=1, rpc_message_type="reply" if reply else "call",
                rpc_program=100003, rpc_version=4, rpc_procedure=1,
                protocol_family="nfs4", nfs_version=4, minor_version=1)


def exposure(batch="batch-1", reply=False):
    # RPC payload coordinates: CALL's minorversion at 44; REPLY status at 24.
    words = ([1, 1, 0, 0, 0, 0, 0, 0, 0] if reply
             else [1, 0, 2, 100003, 4, 1, 0, 0, 0, 0, 0, 1, 0])
    original = b"".join(word(w) for w in words)
    offset, old, new = (24, 0, 10001) if reply else (44, 1, 2)
    kind, rule_id = ("enum", "reply") if reply else ("uint", "call")
    path = "nfs4.response.COMPOUND.res.status" if reply else "nfs4.request.COMPOUND.args.minorversion"
    application = dict(
        rule_id=rule_id, semantic_target=dict(kind="field", semantic_path=path, part="value",
                                            field_index=0, operation_index=None, operation=None,
                                            wire_span=dict(offset=offset, length=4)),
        mutation_kind="replace", structure_policy="preserve", predicate_values=[],
        transform_source_values=[], original_value_snapshot=dict(kind=kind, value=old),
        mutated_value_snapshot=dict(kind=kind, value=new),
        concrete_edits=[dict(offset=offset, remove_length=4, original_hex=word(old).hex(),
                            replacement_hex=word(new).hex())])
    result = original[:offset] + word(new) + original[offset + 4:]
    framed = word(0x80000000 | len(result)) + result
    return dict(batch_id=batch, record_context=context(reply),
                semantic_signature=[dict(rule_id=rule_id, semantic_path=path, part="value", mutation_kind="replace")],
                applications=[application], original_record_hex=original.hex(),
                output=dict(final_record_length=len(framed), framed_record_hex=framed.hex()))


def counts(**changes):
    result = {name: 0 for name in ResolverCounts.model_fields}
    result.update(changes)
    return result


def summaries(call=None, reply=None):
    return [dict(rule_id="call", counts=counts(**(call or {}))),
            dict(rule_id="reply", counts=counts(**(reply or {})))]


def summary(batches=0, call=None, reply=None, reason="drained", unresolved=0):
    return dict(records_seen=batches, exposure_batch_count=batches, outside_activation_window=0,
                evidence_path_failures=0, resolver_summary=summaries(call, reply),
                closure=dict(reason=reason, drain_bound=1000, reply_unresolved_count=unresolved))


def event(kind="RULESET", seq=0, *, corr=None, payload=None, raw=None):
    raw = snapshot() if raw is None else raw
    if payload is None:
        payload = {
            "RULESET": dict(profile="scalar-literal-v1", semantic_runtime_version=1,
                            schema_id="nfs4.1/test", candidate_id="candidate-1",
                            rule_set_id=binding(raw)["rule_set_id"], snapshot_hex=raw.hex()),
            "GENERATION_OPEN": dict(draining_generations=[]),
            "GENERATION_DRAINING": {},
            "EXPOSURE_INTENT": exposure(),
            "APPLY_REFUSAL": dict(rule_id="call", refusal="conflict", record_context=context()),
            "FORWARD_COMPLETE": dict(batch_id="batch-1", forwarded_length=56),
            "FORWARD_FAILED": dict(batch_id="batch-1", reason="connection_closed", bytes_written=0),
            "GENERATION_COMPLETE": summary(),
            "RUN_COMPLETE": dict(rule_summaries=summaries(), batch_count=0,
                                 forward_complete_count=0, forward_failed_count=0),
        }[kind]
    result = dict(schema_version="nfs-proxy-journal-event.v1", session_binding=binding(raw),
                  event_seq=seq, event_type=kind, payload=payload)
    if kind not in ("RULESET", "RUN_COMPLETE"):
        result["program_generation_correlation"] = correlation(raw=raw) if corr is None else corr
    return result


@pytest.mark.parametrize("kind", ["RULESET", "GENERATION_OPEN", "GENERATION_DRAINING",
                                 "EXPOSURE_INTENT", "APPLY_REFUSAL", "FORWARD_COMPLETE",
                                 "FORWARD_FAILED", "GENERATION_COMPLETE", "RUN_COMPLETE"])
def test_all_nine_event_schemas_roundtrip_exact_bytes(kind):
    raw = canonical_json(event(kind))
    assert encode_event(decode_event(raw)) == raw
    assert decode_event(raw).event_type == kind


# Produced independently with the existing C test builder and accepted by
# production nfsp_ruleset_load in an independent cross-language check. Embedding
# bytes keeps these tests independent of /tmp artifacts and of our builder.
C_CALL = bytes.fromhex(
    "4e46535052554c31000000010000004e6e6673342e312f7368613235363a653137623764"
    "6463363531623434326435383565306265353537343730316439353662306538393533"
    "626135303965376235313732613937383932383463316400000000000456432d3100"
    "000001000000027231000000000002693100000000000000000001000000020000"
    "0000000186a3000000040000000100000001000000046e6673340000000100000004"
    "0000000100000001000000010000000853455155454e434500000000000000246e66"
    "73342e726571756573742e53455155454e43452e617267732e73615f736c6f746964"
    "000000000000000000000000000000010000000000000001000000070000000000"
    "000000000000000000000000000000000000000000000000000000")
C_REPLY = bytes.fromhex(
    "4e46535052554c31000000010000004e6e6673342e312f7368613235363a653137623764"
    "6463363531623434326435383565306265353537343730316439353662306538393533"
    "626135303965376235313732613937383932383463316400000000000456432d3100"
    "00000100000006722d6f70656e000000000012666f7267652d6f70656e2d7374617465"
    "6964000000000001000000000000000000000001000186a300000004000000010000"
    "0001000000046e66733400000000000000010000000100000001000000044f50454e"
    "00000000000000206e6673342e726573706f6e73652e4f50454e2e726573756c742e"
    "73746174757300000000000000000000000000000001000000000000000500002711"
    "0000000100000001000000000000000000000000000000000000000000000000")


@pytest.mark.parametrize("raw,message,path,kind,value,policy", [
    (C_CALL, "call", "nfs4.request.SEQUENCE.args.sa_slotid", "uint", 7, "preserve"),
    (C_REPLY, "reply", "nfs4.response.OPEN.result.status", "enum", 10001, "raw"),
])
def test_independent_c_load_validated_vectors(raw, message, path, kind, value, policy):
    parsed = parse_ruleset(raw)
    assert parsed.raw == raw
    assert parsed.rule_set_id == hashlib.sha256(raw).hexdigest()
    assert parsed.candidate_id == "VC-1"
    rule, = parsed.rules
    assert (rule.message_type, rule.target_path, rule.literal.kind, rule.literal.value,
            rule.structure_policy) == (message, path, kind, value, policy)


def test_snapshot_prefixes_and_trailing_bytes_are_not_accepted():
    raw = snapshot(rule_bytes())
    for end in range(len(raw)):
        with pytest.raises(JournalEventError):
            parse_ruleset(raw[:end])
    with pytest.raises(JournalEventError, match="trailing"):
        parse_ruleset(raw + b"\0\0\0\0")
    with pytest.raises(JournalEventError, match="byte bound"):
        parse_ruleset(b"x" * (MAX_RULESET_BYTES + 1))


@pytest.mark.parametrize("changes", [
    {"predicates": 1}, {"transform": 1}, {"transform": 2}, {"part": 1},
    {"part": 2}, {"target_kind": 1}, {"mutation": 1}, {"mutation": 2},
    {"mutation": 3}, {"mutation": 4}, {"has_transform": 0},
    {"literal_kind": 6}, {"literal_kind": 7}, {"forwarded_operations": 1},
    {"forwarded_fields": 1}, {"original_fields": 1},
])
def test_unsupported_profile_never_drops_rule_semantics(changes):
    with pytest.raises(UnsupportedRuleProfile):
        parse_ruleset(snapshot(rule_bytes(**changes)))


@pytest.mark.parametrize("changes", [
    {"direction": 2}, {"part": 6}, {"predicates": 17}, {"policy": 2},
    {"literal_kind": 8}, {"literal_kind": 4, "literal": 2},
    {"forwarded_rpc": 1}, {"original_rpc": 1}, {"application": 1},
])
def test_malformed_binary_words_and_dependencies(changes):
    with pytest.raises(JournalEventError):
        parse_ruleset(snapshot(rule_bytes(**changes)))


def test_binary_names_padding_order_and_runtime_are_strict():
    for raw in (snapshot(rule_bytes("x"), rule_bytes("x")),
                snapshot(rule_bytes("z"), rule_bytes("a")),
                snapshot(rule_bytes("")), snapshot(rule_bytes("bad name")),
                snapshot(rule_bytes("x" * 129)), snapshot(version=2),
                snapshot().replace(b"NFSPRUL1", b"NFSPRUL2", 1)):
        with pytest.raises(JournalEventError):
            parse_ruleset(raw)
    raw = snapshot(rule_bytes("x"))
    # XDR string padding is mandatory zero, even though its hash would differ.
    raw = raw.replace(name("x"), word(1) + b"x\x01\0\0", 1)
    with pytest.raises(JournalEventError, match="padding"):
        parse_ruleset(raw)


@pytest.mark.parametrize("model,kind,value,expected", [
    (IntValue, "int", -(2**31), "80000000"),
    (UIntValue, "uint", 2**32 - 1, "ffffffff"),
    (HyperValue, "hyper", -(2**63), "8000000000000000"),
    (UHyperValue, "uhyper", 2**64 - 1, "ffffffffffffffff"),
    (BoolValue, "bool", True, "00000001"), (BoolValue, "bool", False, "00000000"),
    (EnumValue, "enum", 10001, "00002711"),
])
def test_typed_scalar_xdr_boundaries(model, kind, value, expected):
    assert scalar_bytes(model(kind=kind, value=value)).hex() == expected


@pytest.mark.parametrize("model,kind,value", [
    (IntValue, "int", 2**31), (UIntValue, "uint", -1),
    (HyperValue, "hyper", -(2**63) - 1), (UHyperValue, "uhyper", 2**64),
    (UIntValue, "uint", True), (UIntValue, "uint", 1.0),
    (BoolValue, "bool", 1), (EnumValue, "enum", "1"),
])
def test_scalar_types_never_coerce(model, kind, value):
    with pytest.raises(ValidationError):
        model(kind=kind, value=value)


@pytest.mark.parametrize("wire", [
    b"", b"null", b"[]", b"{}", b"\xff", b"{", b'{"a":NaN}', b'{"a":1e999}',
    b'{"event_type":"RULESET","event_type":"RUN_COMPLETE"}',
    b"[" * 1100 + b"]" * 1100, b" " * (MAX_PAYLOAD_BYTES + 1),
])
def test_malformed_json_and_payload_bounds(wire):
    with pytest.raises(JournalEventError):
        decode_event(wire)


def test_noncanonical_json_escapes_whitespace_numbers_and_duplicate_nested_keys():
    canonical = canonical_json(event())
    cases = [canonical + b"\n", b" " + canonical,
             json.dumps(event(), indent=2).encode(),
             canonical.replace(b'"event_seq":0', b'"event_seq":0.0'),
             canonical.replace(b'"event_seq":0', b'"event_seq":-0'),
             canonical.replace(b'"RULESET"', b'"RULE\\u0053ET"'),
             canonical.replace(b'"channel_id":"channel-1"',
                               b'"channel_id":"channel-1","channel_id":"channel-1"')]
    for wire in cases:
        with pytest.raises(JournalEventError):
            decode_event(wire)


@pytest.mark.parametrize("field,value", [("event_seq", True), ("event_seq", -1),
                                          ("event_seq", 2**64), ("event_seq", "0"),
                                          ("event_type", "UNKNOWN"),
                                          ("schema_version", "v2"), ("durable", True)])
def test_strict_envelope(field, value):
    data = event()
    data[field] = value
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(data))


def test_scope_and_exact_snapshot_metadata():
    for field, value in (("candidate_id", "other"), ("schema_id", "other"),
                         ("rule_set_id", "a" * 64), ("semantic_runtime_version", True),
                         ("snapshot_hex", snapshot().hex().upper()),
                         ("profile", "generic")):
        data = event()
        data["payload"][field] = value
        with pytest.raises(JournalEventError):
            decode_event(canonical_json(data))
    for kind in ("RULESET", "RUN_COMPLETE"):
        data = event(kind)
        data["program_generation_correlation"] = correlation()
        with pytest.raises(JournalEventError):
            decode_event(canonical_json(data))
    data = event("GENERATION_OPEN")
    del data["program_generation_correlation"]
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(data))


@pytest.mark.parametrize("path,value", [
    (("applications", 0, "original_value_snapshot", "value"), 9),
    (("applications", 0, "mutated_value_snapshot", "kind"), "enum"),
    (("applications", 0, "concrete_edits", 0, "remove_length"), 8),
    (("applications", 0, "concrete_edits", 0, "offset"), 40),
    (("applications", 0, "semantic_target", "wire_span", "offset"), 43),
    (("applications", 0, "semantic_target", "wire_span", "offset"), MAX_RECORD_BYTES),
    (("applications", 0, "predicate_values"), [{"kind": "uint", "value": 1}]),
    (("applications", 0, "transform_source_values"), [{"kind": "uint", "value": 1}]),
    (("applications", 0, "semantic_target", "operation"), "OPEN"),
    (("semantic_signature", 0, "rule_id"), "other"),
    (("output", "final_record_length"), 52),
    (("output", "framed_record_hex"), "8000000400000000"),
    (("original_record_hex",), "00000000"),
])
def test_semantic_and_concrete_evidence_must_agree(path, value):
    data = event("EXPOSURE_INTENT")
    node = data["payload"]
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(data))


def test_signature_multiplicity_and_overlap_cannot_be_hidden():
    data = event("EXPOSURE_INTENT")
    payload = data["payload"]
    second = copy.deepcopy(payload["applications"][0])
    second["semantic_target"]["field_index"] = 1
    payload["applications"].append(second)
    payload["semantic_signature"] *= 2
    with pytest.raises(JournalEventError, match="overlapping"):
        decode_event(canonical_json(data))
    second["semantic_target"]["wire_span"]["offset"] = 48
    second["concrete_edits"][0]["offset"] = 48
    second["original_value_snapshot"]["value"] = 0
    second["concrete_edits"][0]["original_hex"] = "00000000"
    framed = bytes.fromhex(payload["output"]["framed_record_hex"])
    payload["output"]["framed_record_hex"] = (framed[:-4] + word(2)).hex()
    decoded = decode_event(canonical_json(data))
    assert len(decoded.payload.semantic_signature) == 2
    assert decoded.payload.semantic_signature[0] == decoded.payload.semantic_signature[1]
    payload["semantic_signature"].pop()
    with pytest.raises(JournalEventError, match="multiset"):
        decode_event(canonical_json(data))


def test_exact_record_limit_and_application_limit():
    data = event("EXPOSURE_INTENT")
    payload = data["payload"]
    original = bytes.fromhex(payload["original_record_hex"])
    original += b"\0" * (MAX_RECORD_BYTES - len(original))
    payload["original_record_hex"] = original.hex()
    output = original[:44] + word(2) + original[48:]
    payload["output"] = dict(final_record_length=len(output) + 4,
                             framed_record_hex=(word(0x80000000 | len(output)) + output).hex())
    assert decode_event(canonical_json(data)).payload.output.final_record_length == MAX_RECORD_BYTES + 4
    payload["original_record_hex"] += "00"
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(data))
    data = event("EXPOSURE_INTENT")
    data["payload"]["applications"] *= MAX_APPLICATIONS + 1
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(data))


def test_nested_extras_missing_fields_and_invalid_model_copy_are_rejected():
    data = event("EXPOSURE_INTENT")
    data["payload"]["applications"][0]["opaque_evidence"] = {"anything": []}
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(data))
    data = event("GENERATION_COMPLETE")
    del data["payload"]["resolver_summary"][0]["counts"]["resolved"]
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(data))
    parsed = decode_event(canonical_json(event()))
    with pytest.raises(JournalEventError):
        encode_event(parsed.model_copy(update={"event_seq": -1}))
    application = Application.model_validate_json(canonical_json(exposure()["applications"][0]))
    with pytest.raises(ValidationError):
        application.semantic_target.wire_span.offset = 0


@pytest.mark.parametrize("payload", [
    {"draining_generations": [2, 1]}, {"draining_generations": [1, 1]},
    {"draining_generations": [0]}, {"draining_generations": list(range(1, 66))},
])
def test_draining_set_is_bounded_sorted_unique_and_nonzero(payload):
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(event("GENERATION_OPEN", payload=payload)))


@pytest.mark.parametrize("reason,count", [("drained", 1), ("reply_unresolved", 0)])
def test_closure_reason_counts_are_consistent(reason, count):
    with pytest.raises(JournalEventError):
        decode_event(canonical_json(event("GENERATION_COMPLETE", payload=summary(reason=reason, unresolved=count))))
