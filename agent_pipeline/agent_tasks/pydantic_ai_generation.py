"""PydanticAI 2.55.0 runtime of the Harness Generation Agent Task.

Like the Stage 1 runtime: one run owns one Agent and one toolbox, every
response is guarded (actual model identity, registered tools only, the
output repair budget), and exceptions propagate once to the executor.  The
tools are the worktree's file and command tools (``GenerationToolbox``);
the output validator takes the worktree's diff (``validate_output``).
"""

from __future__ import annotations

import asyncio

from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from .pydantic_ai_dependency import require_pydantic_ai

require_pydantic_ai()

from pydantic_ai import Agent, ModelRetry, Tool, ToolOutput  # noqa: E402
from pydantic_ai.usage import RunUsage, UsageLimits  # noqa: E402

from .generation import (GenerationAnswer, GenerationResult,  # noqa: E402
                         GenerationRun, GenerationToolbox)
from .pydantic_ai_runtime import (ModelFactory,  # noqa: E402
                                  PydanticAIRuntime, PydanticAIRuntimeError,
                                  RuntimeLimits, _agent_usage,
                                  _response_identity, _ResponseGuard)
from .runtime import OutputRejected, attach_usage  # noqa: E402
from .tools import ToolBoundaryError  # noqa: E402

OUTPUT_TOOL = "generation_result"

#: A generation reads, edits and builds: more turns and longer commands
#: than a Stage 1 run.  Placeholders until a host measures real runs.
GENERATION_LIMITS = RuntimeLimits(max_requests=160, max_tool_calls=640,
                                  request_timeout_seconds=960,
                                  run_timeout_seconds=4 * 3600)


def _tool_function(toolbox: GenerationToolbox, name: str):
    async def invoke(**arguments):
        try:
            return await toolbox.invoke(name, arguments)
        except (ToolBoundaryError, ValidationError) as exc:
            raise ModelRetry(f"{name}: {exc}") from exc
    return invoke


class PydanticAIGenerationRuntime:
    """Synchronous GenerationRuntime; run it from a worker thread."""

    def __init__(self, model_factory: ModelFactory | None = None, *,
                 limits: RuntimeLimits = GENERATION_LIMITS) -> None:
        self.model_factory = model_factory
        self.limits = limits

    def run(self, run: GenerationRun) -> GenerationResult:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise PydanticAIRuntimeError(
                "run is synchronous; call it in a worker outside the event loop")
        return asyncio.run(self._run(run))

    async def _run(self, run: GenerationRun) -> GenerationResult:
        client = None
        try:
            if self.model_factory is not None:
                model = self.model_factory(run.model_policy)
            else:
                model, client = PydanticAIRuntime._openai_model(
                    run.model_policy)
            # The toolbox validates arguments before any command runs.
            tools = [Tool.from_schema(
                _tool_function(run.tools, d.name), name=d.name,
                description=d.description,
                json_schema=d.arguments.model_json_schema(),
                sequential=True) for d in run.tools.definitions]
            envelope = create_model(
                "GenerationResponse", result=(GenerationAnswer, ...),
                __config__=ConfigDict(extra="forbid"))
            guard = _ResponseGuard(model, run, self.limits,
                                   output_tool=OUTPUT_TOOL)
            agent = Agent(
                guard, output_type=ToolOutput(envelope, name=OUTPUT_TOOL),
                instructions=run.instructions, tools=tools,
                retries={"tools": 2,
                         "output": run.model_policy.output_retries},
                tool_timeout=self.limits.request_timeout_seconds)
            agent.instrument = False

            @agent.output_validator
            def validate(value: BaseModel) -> BaseModel:
                try:
                    checked = run.validate_output(value.result)
                    return value.model_copy(update={"result": checked})
                except (OutputRejected, ValidationError) as exc:
                    raise ModelRetry(str(exc)) from exc

            settings = {"max_tokens": run.model_policy.max_output_tokens,
                        "timeout": self.limits.request_timeout_seconds,
                        "parallel_tool_calls": False}
            if run.model_policy.reasoning_effort is not None and \
                    run.model_policy.provider == "openai":
                settings["openai_reasoning_effort"] = \
                    run.model_policy.reasoning_effort
            run_usage = RunUsage()
            try:
                async with asyncio.timeout(self.limits.run_timeout_seconds):
                    result = await agent.run(
                        run.prompt, model_settings=settings,
                        usage_limits=UsageLimits(
                            request_limit=self.limits.max_requests,
                            tool_calls_limit=self.limits.max_tool_calls,
                            output_tokens_limit=(
                                self.limits.max_requests
                                * run.model_policy.max_output_tokens)),
                        usage=run_usage, infer_name=False)
            except Exception as exc:
                attach_usage(exc, _agent_usage(run_usage, guard.rejected))
                raise
            return GenerationResult(
                answer=result.output.result,
                model_id=_response_identity(result.response),
                usage=_agent_usage(result.usage))
        finally:
            if client is not None:
                await client.close()
