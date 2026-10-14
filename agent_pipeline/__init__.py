"""Agent pipeline Controller, Stage 1.

Design: docs/design/02-llm-agent/09-job-state-graph.md (job states and
transitions), 01 §11 (Controller / Runner responsibilities), 02 §3 (intake).
Implementation stack: docs/design/decisions/2026-10-13-agent-implementation-stack.md.

Agent Tasks, the HCAP checker, the Harness Materializer, the Q1 Judge and
the Runner are interfaces here (components.py, controller/tasks.py). This
package owns the job state machine, its SQLite store, intake and harness
binding.
"""
