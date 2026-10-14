"""Explicit dependency gate for the pending PydanticAI runtime binding.

Decision 2026-10-13 selects ``pydantic-ai-slim==2.55.0``.  The package was
not present locally and network resolution was forbidden for this change, so
``pyproject.toml`` and ``uv.lock`` are deliberately untouched.  This module
makes that deployment gap fail clearly; it does not substitute a home-grown
provider loop for PydanticAI.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

PYDANTIC_AI_DISTRIBUTION = "pydantic-ai-slim"
PYDANTIC_AI_VERSION = "2.55.0"


class PydanticAIDependencyUnavailable(RuntimeError):
    pass


def require_pydantic_ai() -> None:
    """Require the reviewed version before constructing a production driver."""

    try:
        installed = version(PYDANTIC_AI_DISTRIBUTION)
    except PackageNotFoundError as exc:
        raise PydanticAIDependencyUnavailable(
            f"{PYDANTIC_AI_DISTRIBUTION}=={PYDANTIC_AI_VERSION} is not "
            "installed; inject an AgentRuntime or install the reviewed lock"
        ) from exc
    if installed != PYDANTIC_AI_VERSION:
        raise PydanticAIDependencyUnavailable(
            f"expected {PYDANTIC_AI_DISTRIBUTION}=={PYDANTIC_AI_VERSION}, "
            f"found {installed}")
