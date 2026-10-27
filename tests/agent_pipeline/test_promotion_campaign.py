"""07 §5.3: the promotion probe campaign, on a bootstrap-shaped env.

Real: the binding, pin checks and staged files, the admission of every
program through the HCAP's profile, the withheld programs, the collector's
run of each program, the evidence model and its use by ``generate``.
Scripted: the parser bridge (programs, parse facts, argument shapes), the
guests (``host_fakes``) and the probe call sites.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from agent_pipeline.admission import CallResourceFacts, ProgramResourceUsage
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import load_record, put_record
from agent_pipeline.hcap import CapabilityContract, HcapCatalog
from agent_pipeline.materializer import (ExecutionHarnessApproval,
                                         ParsedCall, ParsedProgram)
from agent_pipeline.promotion import (CallShape, CallShapes, ArgumentLeaf,
                                      GeneratedProgram, GeneratedPrograms,
                                      PromotionProbeEvidence)
from agent_pipeline.stage1.config import Stage1Config
from agent_pipeline.stage1.host.campaign import CampaignConfig, probe_campaign
from agent_pipeline.stage1.host.generate import generate

from .host_fakes import FakeGuest
from .test_stage1_host import _mark_legacy, host, needs_gcc  # noqa: F401

pytestmark = [needs_gcc, pytest.mark.skipif(sys.platform != "linux",
                                            reason="Linux")]

PROBE = "nfsd_read"
PROBE_PC = 0x4242
CONTRACT = {"entry_points": [{"kind": "syz_call", "name": "read$extra"}],
            "boundary_functions": [PROBE]}


def _contract(value: dict) -> CapabilityContract:
    return CapabilityContract.model_validate_json(json.dumps(value))


def _catalog(value: dict) -> HcapCatalog:
    return HcapCatalog.model_validate_json(json.dumps(value))


def _program(text: str, entry: str | None = None) -> GeneratedProgram:
    return GeneratedProgram(entry_call=entry, text=text,
                            sha256=hashlib.sha256(text.encode()).hexdigest())


class Bridge:
    """The parser bridge: ``generate`` as asked, ``parse`` with no
    resource facts, ``describe`` with open arguments."""

    #: Programs before these are an unverified lane open (refused by the
    #: profile's resource constraint).
    refused = 3
    generated = [_program(f"r0 = openat$lane(0x{i:x})\n") for i in range(refused)] \
        + [_program(f"read$extra(0x{i:x})\nclose(0x0)\n") for i in range(80)]
    requests: list[dict] = []

    def __init__(self, bundle, *, identity):
        self.identity = identity

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def generate(self, **request):
        self.requests.append(request)
        return GeneratedPrograms(
            schema_version="syz-generated-programs.v1",
            syzkaller_commit=self.identity.syzkaller_commit,
            seed=request["seed"],
            minimal=(_program("read$extra(0x0)\n", "read$extra"),),
            generated=tuple(self.generated[:request["generated"]]),
            dropped_without_entry_call=2)

    def parse(self, program, *, identity):
        calls = [line.split("(")[0].split("= ")[-1]
                 for line in program.decode().splitlines()]
        return ParsedProgram(
            identity=identity,
            program_sha256=hashlib.sha256(program).hexdigest(),
            calls=tuple(ParsedCall(index=i, call=c, availability="available",
                                   resource_facts=CallResourceFacts())
                        for i, c in enumerate(calls)),
            usage=ProgramResourceUsage(program_bytes=len(program),
                                       call_count=len(calls),
                                       resource_count=0),
            nfs_acquisitions=())

    def describe(self, calls):
        return CallShapes(
            syzkaller_commit=self.identity.syzkaller_commit,
            calls=tuple(CallShape(call=c, leaves=(
                ArgumentLeaf(path="fd", literal=False),)) for c in calls))


class World:
    def __init__(self, host, monkeypatch) -> None:
        import agent_pipeline.syzkaller.adapter as adapter
        monkeypatch.setattr(adapter, "PinnedSyzParser", Bridge)
        Bridge.requests = []
        self.host = host
        self.spec = json.loads(host.spec.read_text())
        self.base = generate(host.spec)
        self.config = Stage1Config.load(self.base.stage1_config)
        self.store = ArtifactStore(self.config.artifact_root)
        approval = load_record(self.store,
                               self.config.execution_harness_approvals[0],
                               ExecutionHarnessApproval)
        self.harness_id = self.base.execution_harness_id
        assert approval.descriptor.kernel_commit
        # The binding the campaign runs on: CAP-extra with its contract.
        catalog = load_record(self.store, self.base.hcap_revision,
                              HcapCatalog)
        capabilities = tuple(
            c.model_copy(update={"contract": _contract(CONTRACT)})
            if c.id == "CAP-extra" else c
            for c in catalog.capabilities)
        catalog = _catalog(catalog.model_copy(
            update={"capabilities": capabilities}).model_dump(mode="json"))
        self.hcap_revision = put_record(self.store, catalog)
        self.guests: list[FakeGuest] = []

    def campaign(self, out="campaign", hits=None, **change):
        hits = hits or {}
        fake = change.pop("fake", {})

        def make(vm):
            label = Path(vm.console_log).parent.name
            kind, index = label.rsplit("-", 1)
            reach = hits.get(kind, kind != "neutral")
            if callable(reach):
                reach = reach(int(index))
            guest = FakeGuest(vm, pcs=[f"0x{PROBE_PC:x}"] if reach else [],
                              **fake)
            self.guests.append(guest)
            return guest
        config = CampaignConfig(**{
            "stage1": self.base.stage1_config,
            "execution_harness_id": self.harness_id,
            "hcap_revision": self.hcap_revision,
            "capability_id": "CAP-extra", **change})
        report = probe_campaign(
            config, self.host.root / out, guest_factory=make,
            sleep=lambda s: None, today=lambda: "2026-10-27",
            callsite_map=lambda vmlinux, fns, sha:
            {f: (PROBE_PC,) if f == PROBE else () for f in fns})
        return report, self.host.root / out


@pytest.fixture
def world(host):
    return World(host, host.monkeypatch)


def test_a_campaign_writes_evidence_generate_promotes_on(world):
    withheld = Bridge.generated[Bridge.refused].sha256
    report, out = world.campaign(withheld_program_sha256s=[withheld])
    assert (report["result"], report["reason"]) == ("evidence",
                                                    "criteria_met")
    assert (report["withheld"], report["admission_refused"]) == (1, 3)
    evidence = PromotionProbeEvidence.model_validate_json(
        (out / "evidence.json").read_bytes())
    assert evidence.probes == (PROBE,)
    assert (evidence.minimal.runs, evidence.minimal.runs_hitting) == (3, 3)
    assert evidence.generated.runs == 32
    assert len(evidence.generated.program_sha256s) == 16
    assert withheld not in evidence.generated.program_sha256s
    assert (evidence.neutral.runs, evidence.neutral.runs_hitting) == (3, 0)
    assert evidence.withheld_program_sha256s == (withheld,)
    collector = json.loads((world.base.collector_config).read_bytes())
    assert evidence.accelerator == collector["accel"]
    assert evidence.execution_harness_id == world.harness_id
    # The bridge was asked over the admission profile, for the entry call.
    request = Bridge.requests[0]
    assert request["entry"] == ["read$extra"]
    assert request["enabled"] == ["close", "openat$lane", "read$extra"]
    assert request["generated"] == 64
    assert len(world.guests) == 3 + 32 + 3
    record = json.loads((out / f"probe-{PROBE}.json").read_bytes())
    assert record["pcs"] == [f"{PROBE_PC:#x}"]
    assert evidence.probe_mapping_sha256[PROBE] == hashlib.sha256(
        (out / f"probe-{PROBE}.json").read_bytes()).hexdigest()

    # A host spec that gives CAP-extra the contract promotes it on this
    # evidence: the campaign is bound to the harness generate builds.
    spec = dict(world.spec)
    spec["capabilities"] = [dict(c, contract=CONTRACT)
                            if c["id"] == "CAP-extra" else c
                            for c in spec["capabilities"]]
    spec["capability_evidence"] = {"CAP-extra": [str(out / "evidence.json")]}
    world.host.spec.write_text(json.dumps(spec, indent=1))
    result = generate(world.host.spec)
    catalog = load_record(world.store, result.hcap_revision, HcapCatalog)
    extra = next(c for c in catalog.capabilities if c.id == "CAP-extra")
    assert extra.contract is not None and extra.evidence_refs


@pytest.mark.parametrize("hits, change, reason", [
    ({"neutral": True}, {}, "criteria_not_met"),
    ({"generated": lambda i: i % 8 == 0}, {}, "criteria_not_met"),
    ({"minimal": lambda i: i != 1}, {}, "criteria_not_met"),
    ({}, {"generated_programs": 8}, "criteria_not_met"),
    ({}, {"capability_id": "CAP-lane"}, "contract_missing"),
    ({}, {"capability_id": "CAP-nope"}, "capability_missing"),
])
def test_what_a_campaign_is_refused_for(world, hits, change, reason):
    report, out = world.campaign(hits=hits, **change)
    assert (report["result"], report["reason"]) == ("refused", reason)
    assert not (out / "evidence.json").exists()


def test_a_contract_without_an_entry_syz_call_is_refused(world):
    catalog = load_record(world.store, world.hcap_revision, HcapCatalog)
    target = next(c for c in catalog.capabilities
                  if not c.interface.syz_calls)
    contract = {"entry_points": [{"kind": "fixture_action",
                                  "name": "lane_partition"}],
                "boundary_functions": [PROBE]}
    world.hcap_revision = put_record(world.store, _catalog(
        catalog.model_copy(update={"capabilities": tuple(
            c.model_copy(update={"contract": _contract(contract)})
            if c.id == target.id else c for c in catalog.capabilities)})
        .model_dump(mode="json")))
    report, _ = world.campaign(capability_id=target.id)
    assert (report["result"], report["reason"]) == (
        "refused", "entry_points_without_syz_call")
    assert world.guests == []


def test_a_withheld_minimal_program_refuses_the_campaign(world):
    minimal = _program("read$extra(0x0)\n").sha256
    report, _ = world.campaign(withheld_program_sha256s=[minimal])
    assert (report["result"], report["reason"]) == (
        "refused", "minimal_programs_not_admitted")


def test_a_probe_without_call_sites_is_refused(world):
    catalog = load_record(world.store, world.hcap_revision, HcapCatalog)
    world.hcap_revision = put_record(world.store, _catalog(
        catalog.model_copy(update={"capabilities": tuple(
            c.model_copy(update={"contract": _contract(
                dict(CONTRACT, boundary_functions=[PROBE, "nfsd_write"]))})
            if c.id == "CAP-extra" else c for c in catalog.capabilities)})
        .model_dump(mode="json")))
    report, _ = world.campaign()
    assert (report["result"], report["reason"], report["detail"]) == (
        "refused", "probe_not_instrumented", "nfsd_write")


def test_a_guest_that_does_not_boot_is_inconclusive(world):
    report, _ = world.campaign(fake={"boot_error": "no kvm"})
    assert (report["result"], report["reason"]) == ("inconclusive",
                                                    "vm_boot_failed")


def test_a_crash_refuses_the_campaign(world):
    report, out = world.campaign(fake={
        "dmesg": "BUG: KASAN: slab-out-of-bounds in nfsd_read\n"})
    assert (report["result"], report["reason"]) == ("refused",
                                                    "criteria_not_met")
    assert "crash" in report["detail"]
