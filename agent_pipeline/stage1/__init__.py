"""The wired service (Controller + Agent Tasks + Runner + Q1, and Stage 2
when configured).

See ``README.md`` in this directory.  Importing this package does not
import the optional PydanticAI driver or the syzkaller parser.
"""

from .authority import (DescriptorKernelIdentity, MappingCatalog,
                        PublishedQ1Judge, Q1AuthorityPublisher)
from .engine import CommandEngineConfig, CommandExecutionEngine
from .service import Stage1Parts, Stage1Service, Stage2Parts, StepReport

__all__ = [
    "CommandEngineConfig",
    "CommandExecutionEngine",
    "DescriptorKernelIdentity",
    "MappingCatalog",
    "PublishedQ1Judge",
    "Q1AuthorityPublisher",
    "Stage1Parts",
    "Stage1Service",
    "Stage2Parts",
    "StepReport",
]
