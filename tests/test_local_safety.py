"""Synthetic safety-gate evidence. No tests use real browser binaries or secrets."""

import hashlib
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from team_browser.local import (
    CamoufoxAdapter,
    EngineExecutionUnavailable,
    MacOSKeychainStore,
    NormalBrowserAdapter,
    ProfileStore,
    ProxyConfiguration,
    ProxyExpectations,
    ProxyProbeEvidence,
    RuntimeGate,
    RuntimePolicy,
    RuntimeVerificationError,
    SecretRef,
    SecretStoreUnavailable,
    SignatureEvidence,
    validate_proxy_preflight,
)


NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
SYNTHETIC_BYTES = b"NOT EXECUTABLE: synthetic runtime fixture for hash tests only\n"
DIGEST = hashlib.sha256(SYNTHETIC_BYTES).hexdigest()


class SyntheticSignatureVerifier:
    """A test double, never a production source of signature evidence."""

    def __init__(self, evidence: SignatureEvidence | None = None):
        self.evidence = evidence or SignatureEvidence(
            DIGEST, "SYNTHETIC-TEST-SIGNER", True, True, NOW
        )

    def verify(self, executable: Path, expected_sha256: str) -> SignatureEvidence:
        return self.evidence


def proxy_fixture() -> tuple[ProxyConfiguration, ProxyExpectations, ProxyProbeEvidence]:
    proxy = ProxyConfiguration("proxy-1", "socks5", "proxy.example.invalid", 1080)
    expectations = ProxyExpectations("profile-1", DIGEST, ("198.51.100.0/24",), ("192.0.2.10",))
    evidence = ProxyProbeEvidence(
        "profile-1",
        DIGEST,
        proxy.fingerprint,
        NOW,
        ("198.51.100.7",),
        route_verified=True,
        dns_via_proxy=True,
        webrtc_udp_blocked=True,
        ipv6_routed_or_blocked=True,
        direct_fallback_blocked=True,
        tls_verified=True,
    )
    return proxy, expectations, evidence


class ProxySafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proxy, self.expectations, self.evidence = proxy_fixture()

    def check(self, evidence: ProxyProbeEvidence | None):
        return validate_proxy_preflight(self.proxy, self.expectations, evidence, now=NOW)

    def test_complete_synthetic_evidence_passes_validation(self) -> None:
        result = self.check(self.evidence)
        self.assertTrue(result.passed)
        self.assertEqual(result.blockers, ())
        self.assertEqual(result.valid_until, NOW + timedelta(seconds=60))

    def test_missing_evidence_fails(self) -> None:
        self.assertFalse(self.check(None).passed)

    def test_each_missing_routing_check_blocks(self) -> None:
        for field in (
            "route_verified",
            "dns_via_proxy",
            "webrtc_udp_blocked",
            "ipv6_routed_or_blocked",
            "direct_fallback_blocked",
            "tls_verified",
        ):
            with self.subTest(field=field):
                result = self.check(replace(self.evidence, **{field: False}))
                self.assertFalse(result.passed)
                self.assertIsNone(result.valid_until)

    def test_probe_context_is_bound_to_profile_runtime_and_proxy(self) -> None:
        for field, value in (
            ("profile_id", "other"),
            ("runtime_sha256", "0" * 64),
            ("proxy_fingerprint", "1" * 64),
            ("probe_scope", "http-echo-only"),
        ):
            with self.subTest(field=field):
                self.assertFalse(self.check(replace(self.evidence, **{field: value})).passed)

    def test_stale_future_and_naive_evidence_block(self) -> None:
        for timestamp in (
            NOW - timedelta(seconds=61),
            NOW + timedelta(seconds=1),
            NOW.replace(tzinfo=None),
        ):
            with self.subTest(timestamp=timestamp):
                self.assertFalse(self.check(replace(self.evidence, observed_at=timestamp)).passed)

    def test_wrong_direct_empty_and_invalid_exit_addresses_block(self) -> None:
        for ips in (
            ("203.0.113.1",),
            ("192.0.2.10",),
            (),
            ("not-an-ip",),
            ("198.51.100.7", "192.0.2.10"),
        ):
            with self.subTest(ips=ips):
                self.assertFalse(self.check(replace(self.evidence, observed_exit_ips=ips)).passed)

    def test_proxy_host_cannot_embed_credentials_paths_or_options(self) -> None:
        for host in (
            "user:synthetic@host",
            "https://proxy.invalid",
            "proxy.invalid/path",
            "-flag",
            "host\n",
            "localhost:1080",
            "fe80::1%en0",
            "",
        ):
            with self.subTest(host=host), self.assertRaises(ValueError):
                ProxyConfiguration("proxy-1", "socks5", host, 1080)

    def test_proxy_port_and_protocol_are_validated(self) -> None:
        for port in (0, -1, 65536, True, 1.5):
            with self.subTest(port=port), self.assertRaises(ValueError):
                ProxyConfiguration("proxy-1", "socks5", "proxy.invalid", port)
        with self.assertRaises(ValueError):
            ProxyConfiguration("proxy-1", "file", "proxy.invalid", 1080)

    def test_ipv6_proxy_endpoint_is_bracketed(self) -> None:
        proxy = ProxyConfiguration("proxy-1", "socks5", "2001:db8::1", 1080)
        self.assertEqual(proxy.endpoint, "socks5://[2001:db8::1]:1080")

    def test_unbounded_exit_expectations_are_rejected(self) -> None:
        for networks, baseline in (
            ((), ("192.0.2.1",)),
            (("0.0.0.0/0",), ("192.0.2.1",)),
            (("198.51.100.0/24",), ()),
        ):
            with self.subTest(networks=networks), self.assertRaises(ValueError):
                ProxyExpectations("profile-1", DIGEST, networks, baseline)

    def test_changed_proxy_reference_invalidates_evidence(self) -> None:
        changed = replace(self.proxy, credentials=SecretRef("rotated-reference"))
        self.assertFalse(
            validate_proxy_preflight(changed, self.expectations, self.evidence, now=NOW).passed
        )

    def test_naive_clock_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_proxy_preflight(
                self.proxy, self.expectations, self.evidence, now=NOW.replace(tzinfo=None)
            )


class RuntimeSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "synthetic-runtime.txt"
        self.path.write_bytes(SYNTHETIC_BYTES)
        self.path.chmod(0o600)
        self.policy = RuntimePolicy("chromium", "0.0.0-test", DIGEST, "SYNTHETIC-TEST-SIGNER")
        self.verifier = SyntheticSignatureVerifier()
        self.gate = RuntimeGate(self.verifier)

    def verify(self, gate: RuntimeGate | None = None, **kwargs):
        return (gate or self.gate).verify(
            self.path,
            observed_version=kwargs.pop("observed_version", "0.0.0-test"),
            policy=kwargs.pop("policy", self.policy),
            now=NOW,
            **kwargs,
        )

    def test_matching_synthetic_evidence_produces_identity(self) -> None:
        runtime = self.verify()
        self.assertEqual(runtime.sha256, DIGEST)
        self.assertTrue(RuntimeGate.is_unchanged(runtime))

    def test_default_signature_verifier_fails_closed(self) -> None:
        with self.assertRaises(RuntimeVerificationError):
            self.verify(RuntimeGate())

    def test_version_mismatch_blocks_before_signature_check(self) -> None:
        with self.assertRaises(RuntimeVerificationError):
            self.verify(observed_version="wrong")

    def test_hash_mismatch_blocks(self) -> None:
        self.path.write_bytes(b"altered synthetic data")
        with self.assertRaises(RuntimeVerificationError):
            self.verify()

    def test_signature_digest_signer_and_notarization_are_required(self) -> None:
        for field, value in (
            ("artifact_sha256", "0" * 64),
            ("signer_identity", "WRONG-SIGNER"),
            ("signature_valid", False),
            ("signature_valid", "true"),
            ("notarized", False),
            ("notarized", "true"),
        ):
            with self.subTest(field=field):
                verifier = SyntheticSignatureVerifier(
                    replace(self.verifier.evidence, **{field: value})
                )
                with self.assertRaises(RuntimeVerificationError):
                    self.verify(RuntimeGate(verifier))

    def test_stale_or_naive_signature_evidence_blocks(self) -> None:
        for timestamp in (
            NOW - timedelta(minutes=6),
            NOW + timedelta(minutes=1),
            NOW.replace(tzinfo=None),
        ):
            verifier = SyntheticSignatureVerifier(
                replace(self.verifier.evidence, checked_at=timestamp)
            )
            with self.subTest(timestamp=timestamp), self.assertRaises(RuntimeVerificationError):
                self.verify(RuntimeGate(verifier))

    def test_runtime_symlink_is_rejected(self) -> None:
        link = Path(self.temp.name).resolve() / "link"
        link.symlink_to(self.path)
        with self.assertRaises(RuntimeVerificationError):
            self.gate.verify(link, observed_version="0.0.0-test", policy=self.policy, now=NOW)

    def test_runtime_group_writable_file_is_rejected(self) -> None:
        self.path.chmod(0o660)
        with self.assertRaises(RuntimeVerificationError):
            self.verify()

    def test_runtime_fifo_is_rejected_without_blocking(self) -> None:
        self.path.unlink()
        os.mkfifo(self.path, mode=0o600)
        with self.assertRaises(RuntimeVerificationError):
            self.verify()

    def test_mutation_after_verification_invalidates_identity(self) -> None:
        runtime = self.verify()
        self.path.write_bytes(b"changed")
        self.assertFalse(RuntimeGate.is_unchanged(runtime))

    def test_mutation_during_signature_check_blocks(self) -> None:
        evidence = self.verifier.evidence

        class MutatingVerifier:
            def verify(self, executable: Path, expected_sha256: str) -> SignatureEvidence:
                executable.write_bytes(b"modified while verifying")
                return evidence

        with self.assertRaises(RuntimeVerificationError):
            self.verify(RuntimeGate(MutatingVerifier()))

    def test_signature_provider_error_blocks(self) -> None:
        class FailingVerifier:
            def verify(self, executable: Path, expected_sha256: str) -> SignatureEvidence:
                raise OSError("synthetic failure")

        with self.assertRaises(RuntimeVerificationError):
            self.verify(RuntimeGate(FailingVerifier()))


class KeychainTests(unittest.TestCase):
    def test_unconfigured_keychain_never_falls_back(self) -> None:
        store = MacOSKeychainStore()
        reference = SecretRef("synthetic-reference")
        for operation in (
            lambda: store.put(reference, b"synthetic-not-a-password"),
            lambda: store.get(reference),
            lambda: store.delete(reference),
        ):
            with self.assertRaises(SecretStoreUnavailable):
                operation()

    def test_secret_reference_rejects_path_or_url(self) -> None:
        with self.assertRaises(ValueError):
            SecretRef("../escape")


class EnginePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        executable = root / "synthetic-runtime.txt"
        executable.write_bytes(SYNTHETIC_BYTES)
        executable.chmod(0o600)
        policy = RuntimePolicy("chromium", "0.0.0-test", DIGEST, "SYNTHETIC-TEST-SIGNER")
        self.runtime = RuntimeGate(SyntheticSignatureVerifier()).verify(
            executable,
            observed_version="0.0.0-test",
            policy=policy,
            now=NOW,
        )
        self.lease = ProfileStore(root / "profiles").acquire("profile-1")
        self.addCleanup(self.lease.release)
        self.proxy, expectations, evidence = proxy_fixture()
        self.preflight = validate_proxy_preflight(self.proxy, expectations, evidence, now=NOW)

    def test_normal_plan_is_always_a_dry_run_even_when_checks_pass(self) -> None:
        adapter = NormalBrowserAdapter()
        plan = adapter.plan(
            self.lease, runtime=self.runtime, proxy=self.proxy, preflight=self.preflight, now=NOW
        )
        self.assertTrue(plan.dry_run)
        self.assertFalse(plan.can_launch)
        self.assertEqual(plan.blockers, ("Browser execution is disabled in this scaffold",))
        self.assertIn(f"--user-data-dir={self.lease.paths.browser_data}", plan.argv)
        self.assertEqual(plan.argv[-1], "about:blank")
        with self.assertRaises(EngineExecutionUnavailable):
            adapter.launch(plan)

    def test_missing_runtime_and_preflight_block(self) -> None:
        plan = NormalBrowserAdapter().plan(self.lease, runtime=None, proxy=self.proxy, now=NOW)
        self.assertEqual(plan.argv, ())
        self.assertEqual(len(plan.blockers), 3)

    def test_expired_preflight_blocks(self) -> None:
        plan = NormalBrowserAdapter().plan(
            self.lease,
            runtime=self.runtime,
            proxy=self.proxy,
            preflight=self.preflight,
            now=NOW + timedelta(seconds=61),
        )
        self.assertIn("Proxy preflight evidence is no longer current", plan.blockers)

    def test_wrong_profile_preflight_blocks(self) -> None:
        result = replace(self.preflight, profile_id="other")
        plan = NormalBrowserAdapter().plan(
            self.lease, runtime=self.runtime, proxy=self.proxy, preflight=result, now=NOW
        )
        self.assertIn("Proxy preflight does not match this launch context", plan.blockers)

    def test_released_lease_blocks(self) -> None:
        self.lease.release()
        plan = NormalBrowserAdapter().plan(
            self.lease, runtime=self.runtime, proxy=self.proxy, preflight=self.preflight, now=NOW
        )
        self.assertIn("An active profile lease is required", plan.blockers)

    def test_proxy_auth_is_not_rendered_in_argv(self) -> None:
        proxy = replace(self.proxy, credentials=SecretRef("synthetic-reference"))
        plan = NormalBrowserAdapter().plan(
            self.lease, runtime=self.runtime, proxy=proxy, preflight=self.preflight, now=NOW
        )
        self.assertNotIn("synthetic-reference", str(plan.argv))
        self.assertIn(
            "A vetted in-memory proxy authentication bridge is not configured", plan.blockers
        )

    def test_camoufox_is_not_imported_or_runnable(self) -> None:
        adapter = CamoufoxAdapter()
        plan = adapter.plan(self.lease, runtime=None, proxy=self.proxy, now=NOW)
        self.assertEqual(plan.argv, ())
        self.assertFalse(plan.can_launch)
        with self.assertRaises(EngineExecutionUnavailable):
            adapter.launch(plan)
