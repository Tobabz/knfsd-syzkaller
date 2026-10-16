"""Agent pipeline Stage 1 Controller and deterministic validation components.

Design: docs/design/02-llm-agent/09-job-state-graph.md (job states and
transitions), 01 §11 (Controller / Runner responsibilities), 02 §3 (intake).
Implementation stack: docs/design/decisions/2026-10-13-agent-implementation-stack.md.

Candidate Analysis and Reachability Planning live in ``agent_tasks`` behind
an injectable PydanticAI runtime boundary. The deterministic Materializer core
and durable Runner use injected parser and execution backends. This package
owns the job state machine, its SQLite store, intake and harness binding. M1's
pure kernel and Q2's kernel/sealed-evidence adapter are implemented independently
of the not-yet-enabled Stage 2 Controller path.
"""
