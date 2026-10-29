"""A target-PC mapping is keyed by the kernel it was built from (#136)."""

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.q1 import CandidateTarget, KernelIdentity, TargetPcMapping
from agent_pipeline.stage1.authority import MappingCatalog

from .fakes import sha


def _identity(**changes) -> KernelIdentity:
    fields = dict(execution_harness_id=sha("harness"),
                  kernel_commit="a" * 40, instrumentation_sha256=sha("patches"),
                  vmlinux_sha256=sha("vmlinux"), kaslr_enabled=False,
                  kaslr_offset=0)
    return KernelIdentity(**{**fields, **changes})


def _target() -> CandidateTarget:
    return CandidateTarget(candidate_id="c1", kernel_commit="a" * 40,
                           kind="source_range", path="fs/nfsd/nfs4state.c",
                           start_line=10, end_line=10)


def test_lookup_ignores_the_execution_harness_but_not_the_kernel(tmp_path):
    catalog = MappingCatalog(ArtifactStore(tmp_path / "cas"),
                             tmp_path / "index")
    ref = catalog.add(TargetPcMapping(
        mapping_method="test", verified=True, target=_target(),
        identity=_identity(), target_pcs=(4096,)))
    assert catalog.lookup(_target(), _identity()) == ref
    # A rebuilt image, lane script or executor: another harness, same kernel.
    assert catalog.lookup(
        _target(), _identity(execution_harness_id=sha("rebuilt"))) == ref
    for change in (dict(vmlinux_sha256=sha("other-vmlinux")),
                   dict(instrumentation_sha256=sha("other-patches")),
                   dict(kernel_commit="b" * 40),
                   dict(kaslr_enabled=True, kaslr_offset=0x100000)):
        assert catalog.lookup(_target(), _identity(**change)) is None


def test_same_kernel_compares_the_mapping_fields_only():
    base = _identity()
    assert base.same_kernel(_identity(execution_harness_id=sha("rebuilt")))
    assert not base.same_kernel(_identity(vmlinux_sha256=sha("other")))
