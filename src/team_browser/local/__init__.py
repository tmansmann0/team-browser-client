"""Mac-first local client safety contracts. All launch plans remain dry runs."""

from .engines import CamoufoxAdapter, EngineAdapter, LaunchPlan, NormalBrowserAdapter
from .errors import (
    EngineExecutionUnavailable,
    LocalClientError,
    ProfileInUseError,
    RuntimeVerificationError,
    SecretStoreUnavailable,
    UnsafePathError,
)
from .proxy import (
    PreflightResult,
    ProxyConfiguration,
    ProxyExpectations,
    ProxyProbe,
    ProxyProbeEvidence,
    validate_proxy_preflight,
)
from .runtime import (
    MacOSSignatureVerifier,
    RuntimeGate,
    RuntimePolicy,
    SignatureEvidence,
    SignatureVerifier,
    VerifiedRuntime,
)
from .secrets import MacOSKeychainStore, SecretRef, SecretStore
from .storage import (
    ProfileLease,
    ProfilePaths,
    ProfileStore,
    default_profile_root,
    validate_identifier,
)

__all__ = [
    "CamoufoxAdapter",
    "EngineAdapter",
    "EngineExecutionUnavailable",
    "LaunchPlan",
    "LocalClientError",
    "MacOSKeychainStore",
    "MacOSSignatureVerifier",
    "NormalBrowserAdapter",
    "PreflightResult",
    "ProfileInUseError",
    "ProfileLease",
    "ProfilePaths",
    "ProfileStore",
    "ProxyConfiguration",
    "ProxyExpectations",
    "ProxyProbe",
    "ProxyProbeEvidence",
    "RuntimeGate",
    "RuntimePolicy",
    "RuntimeVerificationError",
    "SecretRef",
    "SecretStore",
    "SecretStoreUnavailable",
    "SignatureEvidence",
    "SignatureVerifier",
    "UnsafePathError",
    "VerifiedRuntime",
    "default_profile_root",
    "validate_identifier",
    "validate_proxy_preflight",
]
