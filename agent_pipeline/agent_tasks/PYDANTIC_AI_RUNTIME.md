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
from agent_pipeline.agent_tasks.queued import QueuedAgentExecutor

runtime = PydanticAIRuntime(limits=RuntimeLimits(
    max_requests=32,
    max_tool_calls=96,
    request_timeout_seconds=180,
    run_timeout_seconds=1200,
))
agents = QueuedAgentExecutor(runtime, artifacts, pinned_toolbox_factory, sink)
controller = Controller(..., agents=agents, ...)
agents.sink = controller

while running:                       # the Controller thread
    agents.deliver(block=True, timeout=1.0)
    controller.poll()
```

Give the Controller a `QueuedAgentExecutor`, not `Stage1AgentExecutor`.
`Stage1AgentExecutor.start` runs the whole task inline: as the Controller's
`agents` it would block `submit`/`poll` for up to the run timeout and nest
each retry inside the previous failure's callback. Its sink also must not be
called from a worker thread, because the Controller's SQLite Store belongs
to the Controller thread. `QueuedAgentExecutor.start` hands the task to a
worker pool and returns; `deliver()` passes finished results to the
Controller on the thread that calls it.

These are the defaults; the Stage 1 service takes them from
`Stage1Config.agent_runtime`. A run's request, tool-call and token counts
come back as `RuntimeResult.usage` and are kept on its `AgentAttempt`
record, so the limits can be tuned from real runs. A run that fails (a
request, tool-call or token limit, a deadline, a provider error) keeps what
it used on its exception (`runtime.failure_usage`); the executor passes it
to `on_agent_failure`, and the failed attempt keeps it too.

`AgentModelPolicy.reasoning_effort`, when set, is sent to an OpenAI model as
`openai_reasoning_effort`; unset leaves the provider default and is left out
of the policy's encoding, so stored task digests do not change. The host
template uses `gpt-5.6-sol` for `kasan-default` and `kasan-agent-effort`. The
effort policy uses 32768 output tokens, medium effort for Analysis and high
effort for Planning.

The default factory accepts only trusted `provider="openai"` policy and
passes its model name to `OpenAIResponsesModel`. It uses the SDK's host
credentials and defaults to the explicit `https://api.openai.com/v1` origin.
An operator may select a reviewed endpoint with `KNFSD_OPENAI_BASE_URL`; it
must use HTTPS, loopback HTTP, or an IP in Tailscale's `100.64.0.0/10` range.
An empty value uses the default. Generic `OPENAI_BASE_URL` does not silently
redirect this adapter. The SDK uses `max_retries=0`, `store=False` and
`background=False`. Each run closes its client on success or failure. Provider
errors propagate once to the executor; the Controller owns task retry
decisions.

Call the synchronous runtime from a worker without an active asyncio event
loop. A host may inject `model_factory: Callable[[AgentModelPolicy], Model]`
to use another reviewed PydanticAI model/provider or local test model. The
factory receives only trusted Controller policy. It owns injected client
lifetimes and must disable SDK/transport retries, fallback models and
internal continuation loops. The runtime cannot bound requests hidden
inside an arbitrary injected model implementation.

## Output and tool boundary

Each execution constructs a fresh Agent, message history and tool bindings.
Its only function tools are the seven registered `Stage1Toolbox` read-only
definitions, plus the four harness knowledge tools for Stage 1 tasks when
the factory binds a knowledge source (`search_syzlang`, `read_syzlang`,
`read_harness_patch`, `lookup_reference_programs`; see `knowledge.py`: all
of them read only artifacts the pinned HCAP revision selects), plus
`validate_program` when the toolbox factory binds a draft checker (a Reachability Planning task whose job has a binding, with the host
Materializer). `validate_program` runs the Materializer's checks (HCAP plan
check, pinned parser, call admission) on a draft without storing anything
and answers accepted or the refusing check, with the parser's own message;
it costs no Controller repair. The pinned dispatcher validates all arguments
before source/HCAP access.
Tools execute sequentially. Unknown tool names fail before any tool runs,
including unknown calls accompanying otherwise valid final output. Call
mistakes the model can correct (invalid arguments, a path outside the
allowed roots, a read over 400 lines, a file missing at the pinned commit)
are returned to the model as `ModelRetry`, with at most `TOOL_RETRIES` (2)
retries per tool. Source-index and backend failures terminate the run. The
tool descriptions state the line limit and the allowed roots.

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
In this version `Agent(retries={"tools": 2, "output": N})` selects separate
budgets; `Tool.from_schema` advertises but does not validate arguments, hence
the explicit pinned dispatcher validation above.
