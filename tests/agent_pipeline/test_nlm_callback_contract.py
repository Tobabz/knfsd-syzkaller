"""NLM callback attribution stays diagnostic and fails closed."""

import pytest
from pydantic import ValidationError

from agent_pipeline.stage2.nlm_callback_contract import (
    Activation, Attribution, Callback, Capture, Lock, attribute,
)


def sample():
    digest = "a" * 64
    capture = Capture(vm_instance_id="vm-1", capture_sha256=digest,
                      first_sequence=0, last_sequence=100,
                      ordered_observations_complete=True)
    activation = Activation(vm_instance_id="vm-1", session_id="session-1",
                            lane_id=0, generation=1,
                            open_sequence=10, close_sequence=60)
    lock = Lock(vm_instance_id="vm-1", session_id="session-1", lane_id=0,
                generation=1, batch_id=7,
                journal_request_sha256="b" * 64, output_sha256=digest,
                forwarded_sha256=digest, forward_complete=True,
                key_digest="c" * 64, client_ip="10.89.0.6",
                server_ip="10.89.0.1", first_sequence=20, last_sequence=22)
    callback = Callback(vm_instance_id="vm-1", key_digest=lock.key_digest,
                        client_ip=lock.client_ip,
                        server_ip=lock.server_ip, first_sequence=30, last_sequence=32)
    return capture, activation, lock, callback


def decision(*, capture=None, activations=None, locks=None, callbacks=None):
    base_capture, activation, lock, callback = sample()
    return attribute(capture or base_capture,
                     (activation,) if activations is None else activations,
                     (lock,) if locks is None else locks,
                     (callback,) if callbacks is None else callbacks)


def test_unique_live_lock_is_only_diagnostic():
    result, = decision()
    assert (result.status, result.reason, result.generation, result.batch_id) == (
        "diagnostic_only", "matched", 1, 7)


@pytest.mark.parametrize("change", [
    {"ordered_observations_complete": False}, {"first_sequence": 31},
    {"last_sequence": 31},
])
def test_capture_gaps_and_cutoffs_refuse_attribution(change):
    capture, _, _, _ = sample()
    assert decision(capture=capture.model_copy(update=change))[0].reason == (
        "capture_incomplete")


def test_retransmission_and_new_generation_remain_ambiguous():
    _, activation, lock, callback = sample()
    retry = lock.model_copy(update={"batch_id": 8, "first_sequence": 23,
                                    "last_sequence": 24})
    assert decision(locks=(lock, retry))[0].reason == "ambiguous_or_unmatched_lock"
    failed_retry = retry.model_copy(update={"forward_complete": False})
    assert decision(locks=(lock, failed_retry))[0].reason == (
        "ambiguous_or_unmatched_lock")
    next_gen = retry.model_copy(update={"generation": 2})
    assert decision(locks=(lock, next_gen))[0].reason == "ambiguous_or_unmatched_lock"
    assert decision(callbacks=(callback, callback))[0].reason == "duplicate_callback"


def test_wrong_route_incomplete_forward_and_missing_lock_fail_closed():
    _, _, lock, callback = sample()
    assert decision(callbacks=(callback.model_copy(update={"server_ip": "10.89.0.5"}),)
                    )[0].reason == "ambiguous_or_unmatched_lock"
    for changed in ({"forward_complete": False},
                    {"forwarded_sha256": "d" * 64}):
        assert decision(locks=(lock.model_copy(update=changed),)
                        )[0].reason == "ambiguous_or_unmatched_lock"
    assert decision(locks=())[0].reason == "ambiguous_or_unmatched_lock"
    other_vm = lock.model_copy(update={"vm_instance_id": "vm-2"})
    assert decision(locks=(other_vm,))[0].reason == "ambiguous_or_unmatched_lock"
    callback_other_vm = callback.model_copy(update={"vm_instance_id": "vm-2"})
    assert decision(callbacks=(callback_other_vm,))[0].reason == "capture_incomplete"


def test_activation_boundary_and_missing_owner_fail_closed():
    _, activation, lock, callback = sample()
    assert decision(callbacks=(callback.model_copy(update={"first_sequence": 61,
                                                            "last_sequence": 62}),)
                    )[0].reason == "outside_activation_window"
    assert decision(activations=())[0].reason == "outside_activation_window"
    assert decision(activations=(activation, activation)
                    )[0].reason == "outside_activation_window"
    capture, _, _, _ = sample()
    short = capture.model_copy(update={"last_sequence": 50})
    assert decision(capture=short)[0].reason == "capture_incomplete"


def test_schema_rejects_invalid_bounds_and_digests():
    capture, activation, lock, _ = sample()
    with pytest.raises(ValidationError):
        Capture.model_validate({**capture.model_dump(), "last_sequence": -1})
    with pytest.raises(ValidationError):
        Activation.model_validate({**activation.model_dump(), "close_sequence": 10})
    with pytest.raises(ValidationError):
        Lock.model_validate({**lock.model_dump(), "output_sha256": "bad"})
    with pytest.raises(ValidationError):
        Attribution(reason="capture_incomplete", generation=1)
    with pytest.raises(ValidationError):
        Attribution(reason="matched", generation=1)
