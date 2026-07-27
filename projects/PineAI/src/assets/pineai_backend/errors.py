"""Shared safe backend errors."""


class BackendError(ValueError):
    """A validation or storage error safe to return to a module caller."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.safe_message = message
