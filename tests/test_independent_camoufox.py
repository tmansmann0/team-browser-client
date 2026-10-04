"""Independent synthetic runtime/localhost relay regressions; no engine execution."""

import asyncio
import hashlib
import json
import os
import ssl
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from team_browser.client.camoufox_runtime import (
    CAMOUFOX_VERSION,
    PLAYWRIGHT_VERSION,
    ROUTE_PREFS_SHA256,
    CamoufoxAcceptance,
    CamoufoxAdapter,
    CamoufoxProfilePolicy,
    CamoufoxProxyRoute,
    CamoufoxRuntimeMetadata,
    CamoufoxSupervisor,
    profile_policy_binding,
)
from team_browser.client.lifecycle import GMAIL_INBOX_URL, LaunchContext
from team_browser.client.proxy_relay import (
    HTTPSConnectTransport,
    ProxyRelay,
    RelayError,
    RelayLimits,
    _target,
)
from team_browser.client.store import WorkspaceError
from team_browser.local.proxy import ProxyConfiguration, ProxyExpectations, ProxyProbeEvidence
from team_browser.local.runtime import RuntimeGate, RuntimePolicy, SignatureEvidence
from team_browser.local.storage import ProfileStore


class _Policies:
    def __init__(self, value):
        self.value = value

    def for_profile(self, _):
        return self.value


class _Verifier:
    def verify(self, _, digest):
        return SignatureEvidence(digest, "synthetic", True, True, datetime.now(timezone.utc))


class _Page:
    def __init__(self):
        self.targets = []

    def is_closed(self):
        return False

    async def goto(self, target, **_):
        self.targets.append(target)

    async def bring_to_front(self):
        pass


class _Context:
    def __init__(self):
        self.pages, self.closed, self.close_calls = [_Page()], False, 0
        self.callbacks = {}

    def on(self, name, callback):
        self.callbacks[name] = callback

    def is_closed(self):
        return self.closed

    async def close(self):
        self.close_calls += 1
        if self.closed:
            return
        self.closed = True
        self.callbacks["close"]()


class _Driver:
    def __init__(self):
        self.started = threading.Event()
        self.continue_start = threading.Event()
        self.continue_start.set()
        self.calls = []
        self.context = _Context()

    async def start(self):
        self.started.set()
        while not self.continue_start.is_set():
            await asyncio.sleep(0.005)
        return self

    async def stop(self):
        pass

    async def launch(self, _, **options):
        self.calls.append(options)
        return self.context


class _Probe:
    def __init__(self):
        self.started = threading.Event()
        self.continue_probe = threading.Event()
        self.continue_probe.set()
        self.calls = 0
        self.pass_count = 100

    async def collect(self, context, config, expected):
        self.started.set()
        self.calls += 1
        while not self.continue_probe.is_set():
            await asyncio.sleep(0.005)
        return ProxyProbeEvidence(
            expected.profile_id,
            expected.runtime_sha256,
            config.fingerprint,
            datetime.now(timezone.utc),
            ("203.0.113.20",),
            route_verified=self.calls <= self.pass_count,
            dns_via_proxy=True,
            webrtc_udp_blocked=True,
            ipv6_routed_or_blocked=True,
            direct_fallback_blocked=True,
            tls_verified=True,
        )


class _NoTraffic:
    async def connect(self, *_):
        raise AssertionError("Synthetic runtime tests never contact a provider")


class IndependentCamoufoxRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "never-execute-fixture"
        self.binary.write_bytes(b"synthetic non-executable inventory")
        self.inventory = self.root / "synthetic-inventory.json"
        self.inventory.write_text('{"version":"fixture-1"}')
        self.policy = RuntimePolicy(
            "camoufox",
            "fixture-1",
            hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "synthetic",
        )
        self.acceptance = CamoufoxAcceptance(
            self.policy.sha256,
            self.policy.version,
            sys.platform,
            "SYNTHETIC-NOT-NATIVE-ACCEPTANCE",
            datetime.now(timezone.utc) + timedelta(minutes=10),
            proxy_preferences_sha256=ROUTE_PREFS_SHA256,
            trusted_single_user_host=True,
        )
        self.profile = dict(
            id="independent-profile",
            engine_id="camoufox",
            preset_id="isolated",
            revision=1,
            origin="local",
            network_policy="local_direct",
        )
        self.policies = _Policies(
            CamoufoxProfilePolicy(
                self.profile["id"], profile_policy_binding(self.profile), "isolated", "en-US", "UTC"
            )
        )
        self.driver = _Driver()
        self.supervisor = CamoufoxSupervisor(
            acceptance=self.acceptance,
            factory=lambda: self.driver,
            launcher=self.driver.launch,
            dependencies=lambda: (CAMOUFOX_VERSION, PLAYWRIGHT_VERSION),
            transport_factory=lambda _: _NoTraffic(),
        )
        self.store = ProfileStore(self.root / "profiles")
        self.lease = self.store.acquire(self.profile["id"])
        self.context = LaunchContext(
            self.profile["id"], "camoufox", self.lease.paths.browser_data, 1, lease=self.lease
        )
        self.adapter = CamoufoxAdapter(
            profile_store=self.store,
            executable=self.binary,
            observed_version=self.policy.version,
            policy=self.policy,
            runtime_gate=RuntimeGate(_Verifier()),
            supervisor=self.supervisor,
            profile_policies=self.policies,
            metadata_observer=self.observe,
        )

    def observe(self, _):
        raw = self.inventory.read_bytes()
        stat = self.inventory.stat()
        return CamoufoxRuntimeMetadata(
            json.loads(raw)["version"],
            self.inventory,
            (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns),
            hashlib.sha256(raw).hexdigest(),
        )

    def wait(self, predicate, seconds=2):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(0.005)
        self.fail("Synthetic state change timed out")

    def tearDown(self):
        self.driver.continue_start.set()
        if hasattr(self, "probe"):
            self.probe.continue_probe.set()
        for handle in self.supervisor._handles:
            if handle.launch_future:
                handle.launch_future.result(timeout=3)
            if handle.ownership_uncertain:
                # No real processes exist: fixture-only cleanup after asserted uncertainty.
                handle.ownership_uncertain = False
                self.driver.context.closed = False
            handle.stop()
            self.wait(lambda: handle.phase == "stopped")
        self.supervisor.shutdown()
        self.lease.release()
        self.temp.cleanup()

    def start(self):
        self.assertEqual(self.adapter.blockers(self.profile), ())
        return self.adapter.start(self.context)

    def proxy(self, age=60):
        self.profile.update(origin="managed", network_policy="verified_proxy")
        config = ProxyConfiguration("proxy-fixture", "https", "proxy.example.test", 443)
        self.policies.value = replace(
            self.policies.value,
            profile_binding_sha256=profile_policy_binding(self.profile),
            proxy_fingerprint=config.fingerprint,
        )
        self.probe = _Probe()
        self.route = CamoufoxProxyRoute(
            config,
            ProxyExpectations(
                self.profile["id"],
                self.policy.sha256,
                ("203.0.113.0/24",),
                ("198.51.100.20",),
                timedelta(seconds=age),
            ),
            self.probe,
            (("diagnostic.example.test", 443),),
        )
        self.routes = _Policies(self.route)
        self.adapter.proxy_routes = self.routes

    def test_asserted_version_without_observer_never_admits(self):
        self.adapter.metadata_observer = None
        self.assertTrue(self.adapter.blockers(self.profile))
        with self.assertRaises(WorkspaceError):
            self.adapter.start(self.context)
        self.assertEqual(self.driver.calls, [])

    def test_metadata_change_across_signature_review_fails_closed(self):
        original = self.adapter.gate.verify

        def mutate(*args, **kwargs):
            runtime = original(*args, **kwargs)
            self.inventory.write_text('{"version":"fixture-1","changed":true}')
            return runtime

        with patch.object(self.adapter.gate, "verify", side_effect=mutate):
            self.assertTrue(self.adapter.blockers(self.profile))
        self.assertEqual(self.driver.calls, [])

    def test_metadata_changed_during_driver_start_prevents_spawn(self):
        self.driver.continue_start.clear()
        handle = self.start()
        self.assertTrue(self.driver.started.wait(1))
        self.inventory.write_text('{"version":"fixture-1","changed":true}')
        self.driver.continue_start.set()
        self.wait(lambda: handle.phase == "stopped")
        self.assertEqual(self.driver.calls, [])

    def test_unsolicited_close_during_startup_never_becomes_ready(self):
        original = self.driver.context.on

        def close_after_listener(name, callback):
            original(name, callback)
            self.driver.context.closed = True
            callback()

        self.driver.context.on = close_after_listener
        handle = self.start()
        handle.launch_future.result(timeout=2)
        self.assertTrue(handle.ownership_uncertain)
        self.assertEqual(handle.phase, "unknown")
        with self.assertRaises(WorkspaceError):
            handle.status()

    def test_released_lease_cannot_be_used_for_admission(self):
        self.assertEqual(self.adapter.blockers(self.profile), ())
        self.lease.release()
        with self.assertRaises(WorkspaceError) as raised:
            self.adapter.start(self.context)
        self.assertEqual(raised.exception.code, "profile_lease_required")
        self.assertEqual(self.driver.calls, [])

    def test_existing_identity_prevents_silent_locale_change(self):
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        handle.stop()
        self.wait(lambda: handle.phase == "stopped")
        self.policies.value = replace(self.policies.value, locale="fr-FR")
        self.assertEqual(self.adapter.blockers(self.profile), ())
        with self.assertRaises(WorkspaceError) as raised:
            self.adapter.start(self.context)
        self.assertEqual(raised.exception.code, "profile_identity_changed")
        self.assertEqual(len(self.driver.calls), 1)

    def test_missed_close_event_never_confirms_noop_close(self):
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.driver.context.closed = True  # Deliberately no callback: event already missed.
        handle.stop()
        self.wait(lambda: handle.phase == "unknown")
        self.assertTrue(handle.ownership_uncertain)
        self.assertEqual(self.driver.context.close_calls, 0)
        with self.assertRaises(WorkspaceError):
            handle.status()
        self.assertTrue(self.lease.active)

    def test_revoked_route_during_driver_start_does_not_spawn(self):
        self.proxy()
        self.driver.continue_start.clear()
        handle = self.start()
        self.assertTrue(self.driver.started.wait(1))
        self.policies.value = replace(self.policies.value, proxy_fingerprint="0" * 64)
        self.driver.continue_start.set()
        self.wait(lambda: handle.phase == "stopped")
        self.assertEqual(self.driver.calls, [])

    def test_revocation_during_probe_never_releases_quarantine_or_opens_gmail(self):
        self.proxy()
        self.probe.continue_probe.clear()
        self.context = replace(self.context, initial_url=GMAIL_INBOX_URL)
        handle = self.start()
        self.assertTrue(self.probe.started.wait(1))
        self.assertTrue(handle.relay.quarantined)
        self.policies.value = replace(self.policies.value, proxy_fingerprint="0" * 64)
        self.probe.continue_probe.set()
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.relay.quarantined)
        self.assertFalse(handle.relay.healthy)
        self.assertEqual(self.driver.context.pages[0].targets, [])

    def test_runtime_mutation_during_final_authority_check_does_not_spawn(self):
        self.proxy()
        original = self.routes.for_profile
        calls = []

        def mutate_on_final_guard(profile_id):
            calls.append(profile_id)
            if len(calls) == 3:  # blockers, admission, then async pre-spawn authority.
                self.binary.write_bytes(b"changed synthetic bits must never be launched")
            return original(profile_id)

        self.routes.for_profile = mutate_on_final_guard
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertEqual(self.driver.calls, [])

    def test_evidence_expiring_during_post_probe_authority_stays_quarantined(self):
        self.proxy(age=0.1)
        original = self.routes.for_profile

        def slow_after_probe(profile_id):
            if self.probe.calls:
                time.sleep(0.2)
            return original(profile_id)

        self.routes.for_profile = slow_after_probe
        handle = self.start()
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.relay.quarantined)
        self.assertFalse(handle.relay.healthy)

    def test_expired_ongoing_evidence_closes_route_and_context(self):
        self.proxy(age=0.3)
        self.probe.pass_count = 1
        handle = self.start()
        self.wait(lambda: handle.phase == "ready")
        self.assertFalse(handle.relay.quarantined)
        self.wait(lambda: handle.phase == "stopped")
        self.assertTrue(handle.relay.failed)
        self.assertTrue(self.driver.context.closed)


class IndependentRelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relays, self.servers, self.writers = [], [], []
        self.calls = []
        self.failures = []

    async def asyncTearDown(self):
        for writer in self.writers:
            writer.close()
            await writer.wait_closed()
        for relay in self.relays:
            await relay.stop()
        for server in self.servers:
            server.close()
            await server.wait_closed()

    async def create(self, *, diagnostic_targets=None, idle=0.1, stream=False):
        async def upstream(reader, writer):
            try:
                if stream:
                    for _ in range(20):
                        writer.write(b"x")
                        await writer.drain()
                        await asyncio.sleep(0.025)
                    await reader.read()  # Stay open until the relay's idle timeout.
                else:
                    while data := await reader.read(1024):
                        writer.write(data)
                        await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        self.servers.append(server)
        upstream_port = server.sockets[0].getsockname()[1]
        calls = self.calls

        class LocalOnlyTransport:
            async def connect(self, host, port):
                calls.append((host, port))
                return await asyncio.open_connection("127.0.0.1", upstream_port)

        relay = ProxyRelay(
            LocalOnlyTransport(),
            on_failure=lambda: self.failures.append(True),
            diagnostic_targets=diagnostic_targets,
            limits=RelayLimits(idle_seconds=idle),
        )
        await relay.start()
        self.relays.append(relay)
        return relay

    async def socks(self, relay, host, port=443):
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.port)
        self.writers.append(writer)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        hostname = host.encode("ascii")
        writer.write(
            b"\x05\x01\x00\x03" + bytes([len(hostname)]) + hostname + port.to_bytes(2, "big")
        )
        await writer.drain()
        return reader, writer, await reader.readexactly(10)

    async def test_numeric_private_aliases_are_not_dns_destinations(self):
        for host in (
            "127.1",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f.1",
            "2130706433",
            "0xa.1",
            "0300.0250.0.1",
            "127.0.1",
            "0.0.0.0",
            "::ffff:127.0.0.1",
        ):
            with self.subTest(host=host), self.assertRaises(RelayError):
                _target(host, 443)
        self.assertEqual(_target("127.example.test", 443), "127.example.test:443")

    async def test_quarantine_refuses_exact_mismatch_without_global_failure(self):
        relay = await self.create(diagnostic_targets=(("diagnostic.example.test", 443),))
        for host, port in (
            ("ordinary.example.test", 443),
            ("diagnostic.example.test", 80),
            ("diagnostic.example.test.attacker.test", 443),
        ):
            _, _, reply = await self.socks(relay, host, port)
            self.assertEqual(reply[1], 2)
        self.assertTrue(relay.healthy)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.failures, [])
        _, _, reply = await self.socks(relay, "DIAGNOSTIC.example.test")
        self.assertEqual(reply[1], 0)
        relay.release_quarantine()
        _, _, reply = await self.socks(relay, "ordinary.example.test")
        self.assertEqual(reply[1], 0)
        with self.assertRaises(RelayError):
            relay.release_quarantine()

    async def test_failed_relay_cannot_be_widened_or_restarted(self):
        relay = await self.create(diagnostic_targets=(("diagnostic.example.test", 443),))
        relay.fail_closed()
        with self.assertRaises(RelayError):
            relay.release_quarantine()
        with self.assertRaises(RelayError):
            await relay.start()
        self.assertEqual(self.failures, [True])

    async def test_shared_idle_clock_preserves_active_one_way_stream(self):
        relay = await self.create(idle=0.15, stream=True)
        reader, _, reply = await self.socks(relay, "ordinary.example.test")
        self.assertEqual(reply[1], 0)
        # Upstream sends for >3x idle while the client sends no tunnel bytes at all.
        self.assertEqual(await asyncio.wait_for(reader.readexactly(20), 1.5), b"x" * 20)
        self.assertTrue(relay.healthy)
        self.assertEqual(await asyncio.wait_for(reader.read(), 0.8), b"")
        self.assertFalse(relay.failed)

    async def test_partial_request_cannot_wait_for_quarantine_release(self):
        relay = await self.create(diagnostic_targets=(("diagnostic.example.test", 443),))
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.port)
        self.writers.append(writer)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        relay.release_quarantine()
        host = b"ordinary.example.test"
        writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x01\xbb")
        await writer.drain()
        reply = await reader.readexactly(10)
        self.assertEqual(reply[1], 2)
        self.assertEqual(self.calls, [])
        self.assertTrue(relay.healthy)

    async def test_ambient_keylog_and_ca_environment_have_no_file_or_trust_effect(self):
        config = ProxyConfiguration("synthetic", "https", "proxy.example.test", 443)
        baseline = HTTPSConnectTransport(config)
        baseline_roots = set(baseline._tls.get_ca_certs(binary_form=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keylog = root / "must-not-be-created.keys"
            ca_file = root / "untrusted-ambient-ca.pem"
            ca_file.write_text("SYNTHETIC INVALID CA DATA")
            ca_dir = root / "empty-ca-directory"
            ca_dir.mkdir()
            with patch.dict(
                os.environ,
                {
                    "SSLKEYLOGFILE": str(keylog),
                    "SSL_CERT_FILE": str(ca_file),
                    "SSL_CERT_DIR": str(ca_dir),
                },
            ):
                transport = HTTPSConnectTransport(config)
            self.assertIsNone(transport._tls.keylog_filename)
            self.assertFalse(keylog.exists())
            self.assertEqual(set(transport._tls.get_ca_certs(binary_form=True)), baseline_roots)
            self.assertEqual(transport._tls.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(transport._tls.check_hostname)

    async def test_keylog_enabled_after_construction_blocks_before_any_network(self):
        config = ProxyConfiguration("synthetic", "https", "proxy.example.test", 443)
        transport = HTTPSConnectTransport(config)
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / "synthetic-context-keys"
            transport._tls.keylog_filename = str(keylog)
            # Setting this on our synthetic context can create an empty header file.
            before = keylog.read_bytes()
            with patch("asyncio.open_connection") as connect:
                with self.assertRaises(RelayError):
                    await transport.connect("target.example.test", 443)
                connect.assert_not_called()
            self.assertEqual(keylog.read_bytes(), before)

    async def test_mutated_tls_policy_fails_before_socket_or_secret_access(self):
        config = ProxyConfiguration("synthetic", "https", "proxy.example.test", 443)
        tls = ssl.create_default_context()
        transport = HTTPSConnectTransport(config, tls_context=tls)
        tls.check_hostname = False
        with patch("asyncio.open_connection") as connect:
            with self.assertRaises(RelayError) as raised:
                await transport.connect("target.example.test", 443)
            connect.assert_not_called()
        self.assertNotIn("proxy.example", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
