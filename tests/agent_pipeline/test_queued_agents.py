"""QueuedAgentExecutor: Agent Tasks never run on the Controller thread."""

from __future__ import annotations

import threading

from agent_pipeline.agent_tasks.queued import QueuedAgentExecutor
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import AgentTask

from .test_agent_tasks import (DeterministicFunctionRuntime, Sink,
                               analysis_data, request, toolbox)


class _ThreadSink(Sink):
    def __init__(self) -> None:
        super().__init__()
        self.threads = []

    def on_agent_result(self, *args, **kwargs):
        self.threads.append(threading.get_ident())
        super().on_agent_result(*args, **kwargs)

    def on_agent_failure(self, *args, **kwargs):
        self.threads.append(threading.get_ident())
        super().on_agent_failure(*args, **kwargs)


class _GatedRuntime:
    def __init__(self, inner) -> None:
        self.inner = inner
        self.entered = threading.Event()
        self.release = threading.Event()

    def run(self, req):
        self.entered.set()
        assert self.release.wait(5)
        return self.inner.run(req)


def test_start_returns_before_the_run_and_results_arrive_on_deliver(tmp_path):
    runtime = _GatedRuntime(DeterministicFunctionRuntime([analysis_data()]))
    sink = _ThreadSink()
    executor = QueuedAgentExecutor(runtime, ArtifactStore(tmp_path / "a"),
                                   lambda req: toolbox(), sink)
    try:
        executor.start(request(AgentTask.CANDIDATE_ANALYSIS))
        assert runtime.entered.wait(5)          # running on a worker
        assert executor.deliver() == 0
        runtime.release.set()
        assert executor.deliver(block=True, timeout=5) == 1
    finally:
        executor.close()
    assert len(sink.results) == 1 and not sink.failures
    assert sink.threads == [threading.get_ident()]


def test_failure_is_delivered_once_and_a_retry_does_not_nest(tmp_path):
    class Failing:
        calls = 0

        def run(self, req):
            type(self).calls += 1
            raise RuntimeError("provider unavailable")

    sink = Sink()
    executor = QueuedAgentExecutor(Failing(), ArtifactStore(tmp_path / "a"),
                                   lambda req: toolbox(), sink)

    def on_failure(task_id, attempt, failure):
        Sink.on_agent_failure(sink, task_id, attempt, failure)
        if attempt < 3:                    # the Controller retries inline
            executor.start(request(AgentTask.CANDIDATE_ANALYSIS).model_copy(
                update={"attempt": attempt + 1}))

    sink.on_agent_failure = on_failure
    try:
        executor.start(request(AgentTask.CANDIDATE_ANALYSIS))
        for _ in range(3):
            assert executor.deliver(block=True, timeout=5) == 1
    finally:
        executor.close()
    assert [f[1] for f in sink.failures] == [1, 2, 3]
    assert all(f[2].startswith("RuntimeError") for f in sink.failures)


def test_result_is_redelivered_after_the_sink_fails_to_store_it(tmp_path):
    import pytest
    import sqlite3

    sink = Sink()
    calls = []

    def flaky(*args):
        calls.append(args)
        if len(calls) == 1:              # e.g. a transient SQLite write lock
            raise sqlite3.OperationalError("database is locked")
        Sink.on_agent_result(sink, *args)

    sink.on_agent_result = flaky
    executor = QueuedAgentExecutor(DeterministicFunctionRuntime([analysis_data()]),
                                   ArtifactStore(tmp_path / "a"),
                                   lambda req: toolbox(), sink)
    try:
        executor.start(request(AgentTask.CANDIDATE_ANALYSIS))
        with pytest.raises(sqlite3.OperationalError):
            executor.deliver(block=True, timeout=5)
        assert executor.deliver() == 1
        assert executor.deliver() == 0
    finally:
        executor.close()
    assert len(calls) == 2 and calls[0] == calls[1]
    assert len(sink.results) == 1
