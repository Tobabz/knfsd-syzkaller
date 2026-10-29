"""Delta durability of a Proxy build: the write-ahead order and the prefixes
of its journal, checked on the host without a guest crash."""

from __future__ import annotations

import hashlib
import sys

import pytest
from pydantic import ValidationError

from agent_pipeline.delta_durability import (
    DeltaDurabilityCheck, ProbeError, probe,
)
from agent_pipeline.semantic_promotion import read_build_registry

from agent_pipeline.journal_sink import JournalSinkError, parse_request

from .test_journal_live import (  # noqa: F401  (proxy_binary is a fixture)
    HostJournal, _schema_id, proxy_binary,
)

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="127.0.0.x aliases and SOCK_SEQPACKET are Linux")


class _FailsExposure(HostJournal):
    """A sink that cannot store EXPOSURE_INTENT: the Proxy forwards the
    original and loses its channel."""

    def submit(self, channel, raw):  # type: ignore[override]
        if parse_request(raw).event_type == "EXPOSURE_INTENT":
            raise JournalSinkError("append failed")
        return super().submit(channel, raw)


@pytest.fixture(scope="module")
def build(proxy_binary):
    return read_build_registry(proxy_binary)


def _probe(proxy_binary, build, tmp_path, **extra):
    return probe(proxy_binary, proxy_sha256=build.proxy_sha256,
                 registry_digest=build.registry_digest,
                 schema_id=_schema_id(), workdir=tmp_path, **extra)


def test_a_build_keeps_its_exposure_before_the_peer_and_at_every_cut(
        proxy_binary, build, tmp_path):
    check = _probe(proxy_binary, build, tmp_path)
    assert check.passed, check.problems()
    assert (check.proxy_sha256, check.registry_digest) == (
        build.proxy_sha256, build.registry_digest)
    assert check.exposures == check.mutated_forwards == 1
    assert check.cuts_checked > 20


def test_a_sink_that_cannot_store_the_intent_is_no_evidence(
        proxy_binary, build, tmp_path):
    with pytest.raises(ProbeError, match="did not follow the probe"):
        _probe(proxy_binary, build, tmp_path, journal_cls=_FailsExposure)


def test_another_binary_is_not_probed(proxy_binary, build, tmp_path):
    with pytest.raises(ProbeError, match="not the build"):
        probe(proxy_binary, proxy_sha256=hashlib.sha256(b"x").hexdigest(),
              registry_digest=build.registry_digest, schema_id=_schema_id(),
              workdir=tmp_path)


@pytest.mark.parametrize("change", [
    {"intent_before_forward": False},
    {"prefix_keeps_exposure": False},
    {"cuts_checked": 0},
    {"exposures": 0},
    {"mutated_forwards": 0},
])
def test_each_failed_fact_fails_the_check(change):
    good = dict(proxy_sha256="a" * 64, registry_digest="b" * 64, exposures=1,
                mutated_forwards=1, intent_before_forward=True,
                cuts_checked=30, prefix_keeps_exposure=True)
    assert DeltaDurabilityCheck(**good).passed
    bad = DeltaDurabilityCheck(**{**good, **change})
    assert not bad.passed and bad.problems()


def test_the_record_refuses_extra_fields():
    with pytest.raises(ValidationError):
        DeltaDurabilityCheck(
            proxy_sha256="a" * 64, registry_digest="b" * 64, exposures=1,
            mutated_forwards=1, intent_before_forward=True, cuts_checked=1,
            prefix_keeps_exposure=True, passed=True)
