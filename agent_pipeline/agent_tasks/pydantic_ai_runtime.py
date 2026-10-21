"""Concrete, bounded PydanticAI 2.55.0 Stage 1 runtime.

Import this optional adapter explicitly; importing ``agent_tasks`` does not
require PydanticAI or a provider SDK. One run owns one Agent, message history
and pinned toolbox. Exceptions propagate once to Stage1AgentExecutor.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import math
import re
from typing import Callable

from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from .pydantic_ai_dependency import require_pydantic_ai

require_pydantic_ai()

from pydantic_ai import Agent, ModelRetry, Tool, ToolOutput  # noqa: E402
from pydantic_ai.exceptions import UsageLimitExceeded  # noqa: E402
from pydantic_ai.messages import (ModelRequest, ModelResponse,  # noqa: E402
                                  RetryPromptPart, ToolCallPart)
from pydantic_ai.models import Model  # noqa: E402
from pydantic_ai.models.wrapper import WrapperModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from ..contracts import AgentModelPolicy, AgentUsage
from .runtime import OutputRejected, RuntimeRequest, RuntimeResult
from .tools import (BackendBoundaryError, Stage1Toolbox, ToolBoundaryError,
                    known_tool_set)

OUTPUT_TOOL = "stage1_result"
ModelFactory = Callable[[AgentModelPolicy], Model]


class PydanticAIRuntimeError(RuntimeError):
    """A model response violates the runtime boundary."""


@dataclass(frozen=True)
class RuntimeLimits:
    """Trusted host limits, independent of the Controller task retry budget."""

    # Sized for a Planning run that reads source and syzlang, then checks
    # its draft with validate_program more than once (#75).
    max_requests: int = 32
    max_tool_calls: int = 96
    request_timeout_seconds: float = 180
    run_timeout_seconds: float = 1200

    def __post_init__(self) -> None:
        for name in ("max_requests", "max_tool_calls"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("request_timeout_seconds", "run_timeout_seconds"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value <= 0):
                raise ValueError(f"{name} must be finite and positive")


def _response_identity(response: ModelResponse) -> str:
    # Neither field may be reconstructed from the requested policy/model.
    provider, model = response.provider_name, response.model_name
    if (not isinstance(provider, str)
            or re.fullmatch(r"[^\s:]+", provider) is None
            or not isinstance(model, str)
            or re.fullmatch(r"\S+", model) is None):
        raise PydanticAIRuntimeError(
            "response is missing a valid actual provider/model identity")
    return f"{provider}:{model}"


class _ResponseGuard(WrapperModel):
    """Guard responses before the Agent can dispatch tools or accept output."""

    def __init__(self, model: Model, request: RuntimeRequest,
                 limits: RuntimeLimits) -> None:
        super().__init__(model)
        self.policy = request.model_policy
        self.allowed_tools = frozenset(request.tools.names) | {OUTPUT_TOOL}
        self.limits = limits
        self.requests = 0

    async def request(self, messages, model_settings, model_request_parameters):
        # PydanticAI has separate text-path and output-tool retry counters.
        # Count repair turns across both paths, without implementing a loop.
        repair_turns = sum(
            any(isinstance(part, RetryPromptPart)
                and part.tool_name in (None, OUTPUT_TOOL)
                for part in message.parts)
            for message in messages if isinstance(message, ModelRequest))
        if repair_turns > self.policy.output_retries:
            raise PydanticAIRuntimeError("output repair budget exhausted")
        if self.requests >= self.limits.max_requests:
            raise UsageLimitExceeded("model request limit exhausted")
        self.requests += 1
        async with asyncio.timeout(self.limits.request_timeout_seconds):
            response = await self.wrapped.request(
                messages, model_settings, model_request_parameters)
        _response_identity(response)
        if response.usage.output_tokens > self.policy.max_output_tokens:
            raise UsageLimitExceeded("response exceeds max_output_tokens")
        for part in response.parts:
            if isinstance(part, ToolCallPart) and part.tool_name not in self.allowed_tools:
                raise PydanticAIRuntimeError(
                    f"tool is not registered: {part.tool_name}")
        return response


#: Retries of one tool after a call mistake the model can correct.
TOOL_RETRIES = 2


def _tool_function(toolbox: Stage1Toolbox, name: str):
    def invoke(**arguments):
        # Tool.from_schema advertises JSON schema but skips argument validation.
        # The pinned dispatcher performs actual validation before any backend IO.
        try:
            return toolbox.invoke(name, arguments)
        except BackendBoundaryError:
            raise
        except (ToolBoundaryError, ValidationError) as exc:
            # A call mistake (bad arguments, a path outside the roots, too
            # many lines, a missing file) goes back to the model to correct.
            # Backend and source-index failures still end the run.
            raise ModelRetry(f"{name}: {exc}") from exc
    return invoke


class PydanticAIRuntime:
    """Synchronous AgentRuntime; run from a worker without an active event loop.

    With no factory, supports trusted ``provider='openai'`` via Responses.
    Injected factories receive only trusted policy and return an actual
    PydanticAI Model. They own their clients and must disable transport/SDK
    retries, fallback and continuation loops; this adapter never adds them.
    """

    def __init__(self, model_factory: ModelFactory | None = None, *,
                 limits: RuntimeLimits = RuntimeLimits()) -> None:
        self.model_factory = model_factory
        self.limits = limits

    def run(self, request: RuntimeRequest) -> RuntimeResult:
        require_pydantic_ai()
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise PydanticAIRuntimeError(
                "run is synchronous; call it in a worker outside the event loop")
        return asyncio.run(self._run(request))

    async def _run(self, request: RuntimeRequest) -> RuntimeResult:
        if not known_tool_set(request.tools.definitions):
            raise PydanticAIRuntimeError("unexpected Stage 1 tool definitions")
        if not isinstance(request.output_type, type) or not issubclass(
                request.output_type, BaseModel):
            raise TypeError("output_type must be a Pydantic model class")
        client = None
        try:
            if self.model_factory is not None:
                model = self.model_factory(request.model_policy)
            else:
                model, client = self._openai_model(request.model_policy)
            if not isinstance(model, Model):
                raise TypeError("model_factory must return a PydanticAI Model")
            tools = [Tool.from_schema(
                _tool_function(request.tools, definition.name),
                name=definition.name, description=definition.description,
                json_schema=definition.arguments.model_json_schema(),
                sequential=True,
            ) for definition in request.tools.definitions]
            # Tool schemas must be objects. Planning is a RootModel whose
            # schema is a top-level discriminated union; keep that real typed
            # model inside an object envelope instead of weakening its schema.
            envelope = create_model(
                "Stage1Response", result=(request.output_type, ...),
                __config__=ConfigDict(extra="forbid"))
            agent = Agent(
                _ResponseGuard(model, request, self.limits),
                output_type=ToolOutput(envelope, name=OUTPUT_TOOL),
                instructions=request.instructions, tools=tools,
                retries={"tools": TOOL_RETRIES,
                         "output": request.model_policy.output_retries},
                tool_timeout=self.limits.request_timeout_seconds,
                # Explicitly disable global Agent.instrument_all() defaults.
            )
            agent.instrument = False

            @agent.output_validator
            def validate(value: BaseModel) -> BaseModel:
                try:
                    checked = request.validate_output(value.result)
                    if not isinstance(checked, request.output_type):
                        raise OutputRejected("output validator returned the wrong type")
                    return value.model_copy(update={"result": checked})
                except (OutputRejected, ValidationError) as exc:
                    raise ModelRetry(str(exc)) from exc

            settings = {
                "max_tokens": request.model_policy.max_output_tokens,
                "timeout": self.limits.request_timeout_seconds,
                "parallel_tool_calls": False,
            }
            if request.model_policy.reasoning_effort is not None and \
                    request.model_policy.provider == "openai":
                settings["openai_reasoning_effort"] = \
                    request.model_policy.reasoning_effort
            async with asyncio.timeout(self.limits.run_timeout_seconds):
                result = await agent.run(
                    request.prompt,
                    model_settings=settings,
                    usage_limits=UsageLimits(
                        request_limit=self.limits.max_requests,
                        tool_calls_limit=self.limits.max_tool_calls,
                        output_tokens_limit=(self.limits.max_requests
                                             * request.model_policy.max_output_tokens),
                    ),
                    infer_name=False,
                )
            usage = result.usage
            return RuntimeResult(
                output=result.output.result,
                model_id=_response_identity(result.response),
                usage=AgentUsage(
                    requests=usage.requests, tool_calls=usage.tool_calls,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens))
        finally:
            if client is not None:
                await client.close()

    @staticmethod
    def _openai_model(policy: AgentModelPolicy):
        if policy.provider != "openai":
            raise PydanticAIRuntimeError(
                "default driver supports only openai; inject a reviewed model factory")
        from openai import AsyncOpenAI
        from pydantic_ai.models.openai import OpenAIResponsesModel
        from pydantic_ai.providers.openai import OpenAIProvider

        # Credentials use the SDK's standard host configuration. Pin the API
        # origin explicitly instead of accepting OPENAI_BASE_URL implicitly.
        client = AsyncOpenAI(max_retries=0, base_url="https://api.openai.com/v1")
        model = OpenAIResponsesModel(
            policy.model, provider=OpenAIProvider(openai_client=client),
            settings={"openai_store": False, "openai_background": False})
        return model, client
