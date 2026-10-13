# agent_pipeline

The Agent pipeline Controller, Stage 1. It owns the candidate job: intake,
harness binding, the job state machine, and the record of every transition.
The design is [09-job-state-graph.md](../docs/design/02-llm-agent/09-job-state-graph.md).
Its contracts come from `docs/design/02-llm-agent/01`–`07`.

```sh
uv sync --locked
uv run pytest            # tests/agent_pipeline: oracles 1-5 of 09, intake
```

| Module | What |
|---|---|
| `contracts.py` | Pydantic forms of the data contracts (candidate, JobPolicy, binding, Q1Result, Agent output variants) |
| `intake.py` | candidate intake validation (02 §3) over git plumbing |
| `components.py` | interfaces of the HCAP checker, Materializer, Q1 Judge, harness registry, issue tracker |
| `artifacts.py` | SHA-256 content-addressed artifact store |
| `controller/machine.py` | the state machine: `handle(job, event)`, no I/O |
| `controller/store.py` | SQLite: one transaction per transition |
| `controller/service.py` | events in, tasks out after commit; `recover()` after a restart; `replay()` |
| `controller/tasks.py` | the Runner and Agent executor task contracts (09 §8) |

Not here yet: the Agent Tasks themselves (PydanticAI, decision record decision
2), the real HCAP checker, Harness Materializer, Q1 Judge and Runner, and
Stage 2. The tests use fakes for all of them, so they prove the routing, the
budgets and the restart rules, not the components' verdicts.
