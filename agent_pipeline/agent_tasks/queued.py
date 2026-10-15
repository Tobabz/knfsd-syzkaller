"""Run Stage 1 Agent Tasks off the Controller thread (09 §8).

``Stage1AgentExecutor.start`` runs a whole Agent Task synchronously.  Used
directly as the Controller's ``agents`` it would block ``submit``/``poll``
for the run and nest every retry inside the previous failure's callback.
Calling the Controller from a worker thread is not an option either: its
SQLite Store belongs to the Controller thread.

``QueuedAgentExecutor.start`` hands the task to a worker pool and returns.
Workers put each result on a queue; the Controller's own loop calls
``deliver()`` to pass them to the Controller on its thread.
"""

from __future__ import annotations

import queue
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..artifacts import ArtifactStore
from ..contracts import AgentOutput
from ..controller.tasks import AgentRequest
from .executor import (MAX_FAILURE_CHARS, AgentResultSink, Stage1AgentExecutor,
                       ToolboxFactory)
from .runtime import AgentRuntime


@dataclass(frozen=True)
class _Result:
    task_id: str
    attempt: int
    output: AgentOutput | None = None
    model_id: str | None = None
    failure: str | None = None


class _QueueSink:
    def __init__(self, results: queue.SimpleQueue) -> None:
        self._results = results

    def on_agent_result(self, task_id: str, attempt: int,
                        output: AgentOutput, model_id: str) -> None:
        self._results.put(_Result(task_id, attempt, output=output,
                                  model_id=model_id))

    def on_agent_failure(self, task_id: str, attempt: int,
                         failure: str) -> None:
        self._results.put(_Result(task_id, attempt, failure=failure))


class QueuedAgentExecutor:
    """An ``AgentExecutor`` whose ``start`` never runs the task inline."""

    def __init__(self, runtime: AgentRuntime, artifacts: ArtifactStore,
                 tools: ToolboxFactory, sink: AgentResultSink, *,
                 max_workers: int = 2) -> None:
        self._results: queue.SimpleQueue = queue.SimpleQueue()
        self._inner = Stage1AgentExecutor(runtime, artifacts, tools,
                                          _QueueSink(self._results))
        self._pool = ThreadPoolExecutor(max_workers=max_workers,
                                        thread_name_prefix="stage1-agent")
        self.sink = sink

    def start(self, request: AgentRequest) -> None:
        self._pool.submit(self._run, request)

    def _run(self, request: AgentRequest) -> None:
        try:
            self._inner.start(request)
        except BaseException as exc:      # never lose a task silently
            self._results.put(_Result(
                request.task_id, request.attempt,
                failure=f"{type(exc).__name__}: {exc}"[:MAX_FAILURE_CHARS]))

    def deliver(self, *, block: bool = False,
                timeout: float | None = None) -> int:
        """Pass queued results to the sink on the calling (Controller)
        thread.  With ``block``, wait for at least one.  Returns how many
        were delivered."""

        delivered = 0
        while True:
            try:
                item = self._results.get(block=block and delivered == 0,
                                         timeout=timeout)
            except queue.Empty:
                return delivered
            if item.failure is None:
                self.sink.on_agent_result(item.task_id, item.attempt,
                                          item.output, item.model_id)
            else:
                self.sink.on_agent_failure(item.task_id, item.attempt,
                                           item.failure)
            delivered += 1

    def close(self, *, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)
