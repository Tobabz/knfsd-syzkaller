"""Read-only Stage 1 reasoning tasks.

The Controller remains authoritative for retries, repairs, materialization
and verdicts.  This package turns one ``AgentRequest`` into one of the
existing Agent output variants through an injectable structured-output
runtime.
"""

from .analysis import CandidateAnalysis
from .executor import Stage1AgentExecutor
from .planning import ReachabilityPlanningOutput
from .queued import QueuedAgentExecutor
from .runtime import AgentRuntime, RuntimeResult
from .source_index import GitKernelSourceIndex
from .tools import Stage1Toolbox

__all__ = [
    "AgentRuntime",
    "CandidateAnalysis",
    "GitKernelSourceIndex",
    "QueuedAgentExecutor",
    "ReachabilityPlanningOutput",
    "RuntimeResult",
    "Stage1AgentExecutor",
    "Stage1Toolbox",
]
