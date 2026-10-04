"""Account-free local client; safe to export independently of the managed API."""

from .app import create_local_app, run_local
from .lifecycle import (
    LaunchContext,
    LifecycleCoordinator,
    ProcessAdapter,
    ProcessHandle,
    ProcessStatus,
    UnavailableProcessAdapter,
)
from .store import WorkspaceError, WorkspaceStore

__all__ = [
    "LaunchContext",
    "LifecycleCoordinator",
    "ProcessAdapter",
    "ProcessHandle",
    "ProcessStatus",
    "UnavailableProcessAdapter",
    "WorkspaceError",
    "WorkspaceStore",
    "create_local_app",
    "run_local",
]
