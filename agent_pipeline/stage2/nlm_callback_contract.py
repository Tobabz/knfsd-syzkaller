"""Fail-closed, non-authoritative NLM callback attribution prototype.

The caller supplies normalized observations. This module does not authenticate
capture completeness or journal anchors and must not feed a Stage 2 verdict.
"""

from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Hex64 = str


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Capture(_Record):
    """A diagnostic interval with complete ordered observations."""

    vm_instance_id: str = Field(min_length=1)
    capture_sha256: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    first_sequence: int = Field(ge=0)
    last_sequence: int = Field(ge=0)
    ordered_observations_complete: bool
    capture_complete: Literal[False] = False

    @model_validator(mode="after")
    def _interval(self) -> Capture:
        if self.first_sequence > self.last_sequence:
            raise ValueError("capture interval is reversed")
        return self


class Activation(_Record):
    """Host-observed open/close boundaries, not Proxy wall-clock guesses."""

    vm_instance_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    lane_id: int = Field(ge=0)
    generation: int = Field(ge=1)
    open_sequence: int = Field(ge=0)
    close_sequence: int = Field(ge=0)

    @model_validator(mode="after")
    def _ordered(self) -> Activation:
        if self.open_sequence >= self.close_sequence:
            raise ValueError("activation interval is empty or reversed")
        return self


class Lock(_Record):
    """One forwarded LOCK and its purported, independently checked journal anchor."""

    vm_instance_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    lane_id: int = Field(ge=0)
    generation: int = Field(ge=1)
    batch_id: int = Field(ge=0)
    journal_request_sha256: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    output_sha256: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    forwarded_sha256: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    forward_complete: bool
    key_digest: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    client_ip: str = Field(min_length=1)
    server_ip: str = Field(min_length=1)
    first_sequence: int = Field(ge=0)
    last_sequence: int = Field(ge=0)

    @model_validator(mode="after")
    def _interval(self) -> Lock:
        if self.first_sequence > self.last_sequence:
            raise ValueError("LOCK sequence interval is reversed")
        return self


class Callback(_Record):
    """One complete GRANTED_MSG RPC record on the separate client path."""

    vm_instance_id: str = Field(min_length=1)
    key_digest: Hex64 = Field(pattern=r"^[0-9a-f]{64}$")
    client_ip: str = Field(min_length=1)
    server_ip: str = Field(min_length=1)
    first_sequence: int = Field(ge=0)
    last_sequence: int = Field(ge=0)

    @model_validator(mode="after")
    def _interval(self) -> Callback:
        if self.first_sequence > self.last_sequence:
            raise ValueError("callback sequence interval is reversed")
        return self


class Attribution(_Record):
    schema_version: Literal["nlm-callback-diagnostic.v1"] = (
        "nlm-callback-diagnostic.v1")
    status: Literal["diagnostic_only"] = "diagnostic_only"
    reason: Literal["matched", "capture_incomplete", "outside_activation_window",
                    "ambiguous_or_unmatched_lock", "duplicate_callback"]
    session_id: str | None = None
    lane_id: int | None = None
    generation: int | None = None
    batch_id: int | None = None

    @model_validator(mode="after")
    def _ownership(self) -> Attribution:
        owners = (self.session_id, self.lane_id, self.generation, self.batch_id)
        if self.reason == "matched" and any(value is None for value in owners):
            raise ValueError("matched callback needs complete diagnostic owner")
        if self.reason != "matched" and any(value is not None for value in owners):
            raise ValueError("unmatched callback must not name an owner")
        return self


def attribute(capture: Capture, activations: tuple[Activation, ...],
              locks: tuple[Lock, ...], callbacks: tuple[Callback, ...]
              ) -> tuple[Attribution, ...]:
    """Never assign on incomplete capture, duplicate identity, or closed owner.

    The input contract requires a separate verifier to bind journal_request_sha256
    to a re-admitted EXPOSURE_INTENT and FORWARD_COMPLETE in a sealed journal,
    and to attest complete ordered observations. The disposable diagnostic
    verifier provides that normalization; production Stage 2 does not call it.
    """
    identities = Counter((cb.key_digest, cb.client_ip, cb.server_ip)
                         for cb in callbacks)
    result = []
    for callback in callbacks:
        identity = (callback.key_digest, callback.client_ip,
                    callback.server_ip)
        if not capture.ordered_observations_complete or not (
                capture.first_sequence <= callback.first_sequence <=
                callback.last_sequence <= capture.last_sequence) or (
                callback.vm_instance_id != capture.vm_instance_id):
            result.append(Attribution(reason="capture_incomplete"))
            continue
        if identities[identity] != 1:
            result.append(Attribution(reason="duplicate_callback"))
            continue
        matching = [lock for lock in locks
                    if lock.vm_instance_id == callback.vm_instance_id
                    and lock.key_digest == callback.key_digest
                    and lock.client_ip == callback.client_ip
                    and lock.server_ip == callback.server_ip
                    and lock.last_sequence < callback.first_sequence]
        if any(not (capture.first_sequence <= lock.first_sequence <=
                    lock.last_sequence <= capture.last_sequence)
               for lock in matching):
            result.append(Attribution(reason="capture_incomplete"))
            continue
        # Do not collapse retransmissions or identical locks across generations:
        # either case needs stronger kernel ownership evidence.
        if len(matching) != 1:
            result.append(Attribution(reason="ambiguous_or_unmatched_lock"))
            continue
        lock = matching[0]
        if not lock.forward_complete or lock.output_sha256 != lock.forwarded_sha256:
            result.append(Attribution(reason="ambiguous_or_unmatched_lock"))
            continue
        windows = [a for a in activations
                   if a.vm_instance_id == capture.vm_instance_id
                   and (a.session_id, a.lane_id, a.generation) ==
                   (lock.session_id, lock.lane_id, lock.generation)]
        if any(not (capture.first_sequence <= a.open_sequence and
                    a.close_sequence <= capture.last_sequence) for a in windows):
            result.append(Attribution(reason="capture_incomplete"))
            continue
        if len(windows) != 1 or not (
                windows[0].open_sequence < lock.first_sequence <=
                lock.last_sequence < callback.first_sequence <=
                callback.last_sequence < windows[0].close_sequence):
            result.append(Attribution(reason="outside_activation_window"))
            continue
        result.append(Attribution(reason="matched", session_id=lock.session_id,
                                  lane_id=lock.lane_id,
                                  generation=lock.generation,
                                  batch_id=lock.batch_id))
    return tuple(result)
