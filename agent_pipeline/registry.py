"""Read-only registry of host-approved execution harness bindings.

The catalog digest is trusted configuration, never supplied by an Agent or
guest. This reader checks the bindings and their referenced bytes; it does
not infer runtime validation from an evidence file or promote capabilities.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .artifacts import ArtifactStore
from .contracts import Commit, HarnessBinding, Record, Sanitizer, Sha256
from .data import load_record
from .hcap import ArtifactHcapChecker


class HarnessRegistration(Record):
    binding: HarnessBinding
    evidence_refs: tuple[Sha256, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def _unique_refs(self) -> HarnessRegistration:
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("duplicate validation evidence reference")
        return self


class HarnessCatalog(Record):
    schema_version: Literal[1] = 1
    registrations: tuple[HarnessRegistration, ...] = Field(max_length=4096)

    @model_validator(mode="after")
    def _unique_keys(self) -> HarnessCatalog:
        keys = [(r.binding.kernel_commit, r.binding.sanitizer)
                for r in self.registrations]
        if len(keys) != len(set(keys)):
            raise ValueError("multiple bindings for one commit and sanitizer")
        return self


class _Lookup(Record):
    kernel_commit: Commit
    sanitizer: Sanitizer


class ArtifactHarnessRegistry:
    """Implements components.HarnessRegistry over one immutable catalog.

    Switching to a new catalog requires constructing a new registry and
    delivering the existing Controller registry-changed event. A missing,
    corrupt, ambiguous or incomplete registration has no usable binding.
    """

    def __init__(self, artifacts: ArtifactStore, catalog_ref: str) -> None:
        self.artifacts = artifacts
        self.catalog_ref = catalog_ref

    def lookup(self, kernel_commit: str,
               sanitizer: Sanitizer) -> HarnessBinding | None:
        try:
            query = _Lookup(kernel_commit=kernel_commit, sanitizer=sanitizer)
            catalog = load_record(self.artifacts, self.catalog_ref,
                                  HarnessCatalog)
            for registration in catalog.registrations:
                binding = registration.binding
                if (binding.kernel_commit, binding.sanitizer) != (
                        query.kernel_commit, query.sanitizer):
                    continue
                # A binding is not usable when its host-selected HCAP or
                # approval evidence is absent or has a different digest.
                ArtifactHcapChecker(self.artifacts).load_catalog(binding.hcap_revision)
                for ref in registration.evidence_refs:
                    self.artifacts.get(ref)
                return binding
        except (OSError, ValueError, TypeError, RecursionError):
            return None
        return None
