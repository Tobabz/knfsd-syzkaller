"""Encode one accepted function candidate for the existing kernel loader."""

from __future__ import annotations

import re

from agent_pipeline.contracts import LocationKind, VulnerabilityCandidate

SCHEMA_VERSION = 5
SCOPES = ("fs/nfs", "fs/nfs_common", "fs/lockd", "net/sunrpc", "fs/nfsd")
POLICY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,127}\Z")
SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def prepare_program_policy(candidate: VulnerabilityCandidate) -> bytes:
    """Build a Policy whose identity is the accepted candidate ID."""
    location = candidate.location
    if location.kind is not LocationKind.FUNCTION or location.symbol is None:
        raise ValueError("KCSAN requires a function candidate")
    if candidate.candidate_id in (".", "..") or not POLICY_NAME.fullmatch(candidate.candidate_id):
        raise ValueError("candidate ID is not a kernel policy name")
    if not SYMBOL.fullmatch(location.symbol) or len(location.symbol) >= 512:
        raise ValueError("candidate has no usable kernel function symbol")
    scope = next((name for name in SCOPES
                  if location.path.startswith(name + "/")), None)
    if scope is None:
        raise ValueError("candidate is outside the NFS/RPC KCSAN scope")

    payload = (
        f"policy {candidate.candidate_id} {SCHEMA_VERSION} 1 80 20 1\n"
        f"rule {location.symbol} {scope} 8 3000\n"
    ).encode("ascii")
    if len(payload) > 4096:
        raise ValueError("KCSAN payload exceeds the kernel limit")
    return payload
