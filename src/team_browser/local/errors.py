"""Local-client failures, deliberately free of secret values."""


class LocalClientError(RuntimeError):
    """An operation could not be performed safely."""


class UnsafePathError(LocalClientError):
    """A local path is unsafe or has unexpected permissions."""


class ProfileInUseError(LocalClientError):
    """Another process already holds the profile lease."""


class SecretStoreUnavailable(LocalClientError):
    """An approved operating-system secret store is not configured."""


class RuntimeVerificationError(LocalClientError):
    """The installed engine did not satisfy its pinned trust policy."""


class EngineExecutionUnavailable(LocalClientError):
    """This scaffold does not execute browsers."""
