"""Exact-version gate for the optional concrete PydanticAI runtime.

The base Stage 1 package does not import the driver. Install the locked
``agent-runtime`` extra for injected models, or ``agent-openai`` for the
default OpenAI Responses driver. The dev group includes both for CI.
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
            "installed; run uv sync --locked --extra agent-runtime "
            "(or --extra agent-openai for the default provider)"
        ) from exc
    if installed != PYDANTIC_AI_VERSION:
        raise PydanticAIDependencyUnavailable(
            f"expected {PYDANTIC_AI_DISTRIBUTION}=={PYDANTIC_AI_VERSION}, "
            f"found {installed}")
