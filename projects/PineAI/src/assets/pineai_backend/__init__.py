"""PineAI backend with lazy public service imports.

The Mark VII starts a module backend on its first request and expects the
Unix-domain socket to become available quickly. Importing every analysis
service here makes that cold start too slow on its MIPS processor, so the
public service classes are resolved only when an action needs them.
"""

__all__ = ["AssuranceService", "BackendError"]
__version__ = "0.6.3"


def __getattr__(name):
    if name == "AssuranceService":
        from .assurance_service import AssuranceService

        return AssuranceService
    if name == "BackendError":
        from .errors import BackendError

        return BackendError
    raise AttributeError("module {0!r} has no attribute {1!r}".format(__name__, name))
