# Concrete Stage 1 PydanticAI runtime

`pydantic_ai_runtime.PydanticAIRuntime` implements the existing synchronous
`AgentRuntime.run(RuntimeRequest) -> RuntimeResult` protocol using the real
PydanticAI Agent graph. It is pinned to **pydantic-ai-slim 2.55.0**. The base
`agent_pipeline.agent_tasks` import does not load this optional adapter.

## Install and test

```sh
# Production with a host-supplied PydanticAI model factory:
uv sync --locked --no-dev --extra agent-runtime

# Production using the built-in OpenAI Responses factory:
uv sync --locked --no-dev --extra agent-openai

# CI / development (includes slim and the OpenAI SDK, no extra required):
uv sync --locked
uv run pytest -q tests/agent_pipeline/test_pydantic_ai_runtime.py \
    tests/agent_pipeline/test_agent_tasks.py
```

The dev group includes `pydantic-ai-slim[openai]==2.55.0`, so the existing
`uv sync --locked` / `uv run pytest -q` gate executes all adapter tests.
There are no optional-import skips. The lock fixes the transitive provider
SDK too (OpenAI 3.31.0). No workflow change is required.

## Integration

```python
from agent_pipeline.agent_tasks.pydantic_ai_runtime import (
    PydanticAIRuntime, RuntimeLimits,
)
from agent_pipeline.agent_tasks.executor import Stage1AgentExecutor

runtime = PydanticAIRuntime(limits=RuntimeLimits(
    max_requests=16,
    max_tool_calls=32,
    request_timeout_seconds=60,
    run_timeout_seconds=300,
))
executor = Stage1AgentExecutor(runtime, artifacts, pinned_toolbox_factory, sink)
```

The default factory accepts only trusted `provider="openai"` policy and
passes its model name to `OpenAIResponsesModel`. It uses the SDK's host
credentials, the explicit `https://api.openai.com/v1` origin, SDK
`max_retries=0`, `store=False` and `background=False`. `OPENAI_BASE_URL`
does not silently redirect this default adapter. Each run closes its SDK
client on success or failure. Provider errors propagate once to the
executor; the Controller owns task retry decisions.

Call the synchronous runtime from a worker without an active asyncio event
loop. A host may inject `model_factory: Callable[[AgentModelPolicy], Model]`
to use another reviewed PydanticAI model/provider or local test model. The
factory receives only trusted Controller policy. It owns injected client
lifetimes and must disable SDK/transport retries, fallback models and
internal continuation loops. The runtime cannot bound requests hidden
inside an arbitrary injected model implementation.

## Output and tool boundary

Each execution constructs a fresh Agent, message history and tool bindings.
Its only function tools are the five registered `Stage1Toolbox` definitions;
the pinned dispatcher validates all arguments before source/HCAP access.
Tools execute sequentially. Unknown tool names fail before any tool runs,
including unknown calls accompanying otherwise valid final output. Invalid
arguments, scope violations and source/backend failures terminate the run;
tool retries are zero.

The sole output tool is `stage1_result`. Its JSON object is
`{"result": <requested typed output>}`. This envelope lets the Planning
`RootModel` discriminated union retain its schema inside an object, as
required for tool outputs. `agent.output_validator` invokes the executor's
semantic validator on the original typed value. `OutputRejected` and
Pydantic validation errors request repair. A wrong validator result type
also rejects the output. The caller receives the original typed value,
without the envelope.

`output_retries=N` allows at most N additional repair turns after the first
invalid response. A guard counts repair turns across both invalid text and
output-tool paths, because PydanticAI maintains distinct counters for them.
Exhaustion is one runtime failure. The adapter does not implement a provider
or tool loop of its own.

Every response must carry nonempty `provider_name` and `model_name` metadata
before tools run. `RuntimeResult.model_id` is the final response's
`provider_name:model_name`, never the requested model policy. An alias may
therefore resolve to a different actual model snapshot. Missing metadata
fails closed. Provider adapters, including injected models, are responsible
for accurately preserving response metadata.

## Execution bounds and side effects

`max_output_tokens` becomes the provider's per-response `max_tokens` setting.
The guard also rejects provider-reported output usage above that bound.
PydanticAI enforces at most 16 requests and 32 successful tool calls by
default, plus a cumulative output cap of
`max_requests * max_output_tokens`. Token accounting uses provider-reported
usage; request counts remain bounded independently. Individual model
requests and tool executions have a 60-second deadline, and the async run
has a 300-second deadline. Hosts can lower these finite positive limits.
Blocking synchronous backends must also enforce their own I/O limits:
Python cancellation cannot forcibly stop an already running worker thread.

The adapter does not alter environment variables, configure logging,
install telemetry exporters or enable background price updates. Agent
instrumentation is explicitly disabled even if `Agent.instrument_all()`
was enabled globally. Injected models/clients remain trusted host code.
PydanticAI itself may print its startup banner in terminals/coding-agent
environments; hosts wanting silent stderr can set `PYDANTIC_AI_NO_BANNER=1`
before startup. SDK logging settings remain under host control.

Tests use real `FunctionModel`/`TestModel` and mock HTTP transport through
the real Responses adapter. Model network access is disabled except inside
the local HTTP-mock tests; no paid/live API calls are made. Coverage includes
schema and semantic repair/exhaustion at 0 and 2, mixed output paths, typed
Planning handoff, unknown/invalid tools, request/token/tool limits, deadlines,
missing response identity, provider failures, concurrent binding isolation,
client cleanup, base imports, and executor success/failure delivery.

## API verification references

The installed 2.55.0 package source was checked against the official
[PyPI release](https://pypi.org/project/pydantic-ai-slim/2.55.0/),
[Agent API](https://pydantic.dev/docs/ai/api/pydantic-ai/agent/),
[output validators](https://pydantic.dev/docs/ai/core-concepts/output/), and
[function tools](https://pydantic.dev/docs/ai/tools-toolsets/tools/).
In this version `Agent(retries={"tools": 0, "output": N})` selects separate
budgets; `Tool.from_schema` advertises but does not validate arguments, hence
the explicit pinned dispatcher validation above.
