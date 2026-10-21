"""Injectable structured-output runtime boundary for PydanticAI.

The selected runtime must use Pydantic models as its output schema, expose
only the supplied ``Stage1Toolbox``, and call ``validate_output`` as an
output validator.  Schema or validator failures may be shown to the model
for at most ``model_policy.output_retries`` repairs.  Exhaustion is returned
as one failed Agent execution; the runtime never retries Controller tasks or
changes job state.

The concrete PydanticAI package is intentionally not imported here.  It was
not available in the implementation environment, so callers inject this
small protocol rather than receiving an untested provider loop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from pydantic import BaseModel

from ..contracts import AgentModelPolicy, AgentTask, AgentUsage
from .tools import Stage1Toolbox

class OutputRejected(ValueError):
    """A schema-valid output conflicts with trusted task inputs."""


@dataclass(frozen=True)
class RuntimeRequest:
    task: AgentTask
    model_policy: AgentModelPolicy
    instructions: str
    prompt: str
    output_type: type[BaseModel]
    tools: Stage1Toolbox
    validate_output: Callable[[BaseModel], BaseModel]


@dataclass(frozen=True)
class RuntimeResult:
    output: BaseModel
    # Required response metadata from the provider.  It must not be filled
    # from model_policy when the provider omits it.
    model_id: str
    #: What the run used, when the runtime counts it.
    usage: AgentUsage | None = None


class AgentRuntime(Protocol):
    def run(self, request: RuntimeRequest) -> RuntimeResult:
        """Run once, including bounded structured-output repair."""
