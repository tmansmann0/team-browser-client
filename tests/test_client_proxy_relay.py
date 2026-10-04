"""Synthetic loopback sockets and generated local TLS certificate; no provider I/O."""

import asyncio
import base64
import ipaddress
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, Mock
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from team_browser.client.proxy_relay import (
    HTTPSConnectTransport,
    ProxyRelay,
    RelayError,
    RelayLimits,
    _default_tls_context,
)
from team_browser.local.proxy import ProxyConfiguration
from team_browser.local.secrets import SecretRef


class FixtureSecrets:
    def __init__(self, value=b"synthetic-user:synthetic-password"):
        self.value, self.calls = value, []

    def get(self, reference):
        self.calls.append(reference)
        return self.value


class ProxyRelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.writers, self.tasks, self.servers, self.relays = [], [], [], []
        self.failures, self.requests = [], []
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        (root / "cert.pem").write_bytes(pem)
        (root / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_tls.load_cert_chain(root / "cert.pem", root / "key.pem")
        self.client_tls = ssl.create_default_context(cadata=pem.decode())

    async def asyncTearDown(self):
        for relay in self.relays:
            await relay.stop()
        for writer in self.writers:
            writer.close()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        for writer in self.writers:
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except Exception:
                pass

    async def upstream(self, response=b"HTTP/1.1 200 Connection established\r\n\r\n", delay=0):
        async def handler(reader, writer):
            self.tasks.append(asyncio.current_task())
            self.writers.append(writer)
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                self.requests.append(request)
                await asyncio.sleep(delay)
                writer.write(response)
                await writer.drain()
                while data := await reader.read(16384):
                    writer.write(data)
                    await writer.drain()
            except (Exception, asyncio.CancelledError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=self.server_tls)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    def transport(self, port, *, host="localhost", secrets=None, limits=RelayLimits()):
        return HTTPSConnectTransport(
            ProxyConfiguration(
                "synthetic-proxy",
                "https",
                host,
                port,
                SecretRef("synthetic-secret") if secrets else None,
            ),
            secrets=secrets,
            tls_context=self.client_tls,
            limits=limits,
        )

    async def relay(self, transport, limits=RelayLimits()):
        relay = ProxyRelay(transport, on_failure=lambda: self.failures.append(True), limits=limits)
        self.relays.append(relay)
        await relay.start()
        return relay

    async def socket(self, relay):
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.port)
        self.writers.append(writer)
        return reader, writer

    async def socks(self, relay, host="example.test", port=443, command=1):
        reader, writer = await self.socket(relay)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        host = host.encode()
        writer.write(bytes([5, command, 0, 3, len(host)]) + host + port.to_bytes(2, "big"))
        await writer.drain()
        return reader, writer

    async def test_domain_connect_auth_and_bidirectional_payload(self):
        secrets = FixtureSecrets()
        transport = self.transport(await self.upstream(), secrets=secrets)
        relay = await self.relay(transport)
        # Target DNS must never be resolved locally; provider localhost may be.
        loop = asyncio.get_running_loop()
        original = loop.getaddrinfo
        resolved = []

        async def guarded(host, *args, **kwargs):
            resolved.append(host)
            self.assertEqual(host, "localhost")
            return await original(host, *args, **kwargs)

        with patch.object(loop, "getaddrinfo", side_effect=guarded):
            reader, writer = await self.socks(relay)
            self.assertEqual((await reader.readexactly(10))[:2], b"\x05\x00")
            writer.write(b"synthetic tunnel payload")
            await writer.drain()
            self.assertEqual(
                await asyncio.wait_for(reader.readexactly(24), 2), b"synthetic tunnel payload"
            )
        request = self.requests[0]
        self.assertIn(b"CONNECT example.test:443 HTTP/1.1\r\n", request)
        self.assertIn(b"Proxy-Authorization: Basic " + base64.b64encode(secrets.value), request)
        self.assertNotIn("synthetic-password", repr(transport))
        self.assertNotIn("synthetic-password", repr(transport.configuration))
        self.assertEqual(secrets.calls, [SecretRef("synthetic-secret")])
        self.assertEqual(resolved, ["localhost"])
        self.assertFalse(relay.failed)

    async def test_rejected_upstream_latches_and_closes_listener(self):
        relay = await self.relay(self.transport(await self.upstream(b"HTTP/1.1 407 Nope\r\n\r\n")))
        reader, _ = await self.socks(relay)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertTrue(relay.failed)
        self.assertEqual(self.failures, [True])
        relay.fail_closed()
        self.assertEqual(self.failures, [True])
        with self.assertRaises((ConnectionRefusedError, OSError)):
            await asyncio.open_connection("127.0.0.1", relay.port)
        with self.assertRaises(RelayError):
            await relay.start()

    async def test_tls_host_mismatch_and_untrusted_cert_fail_without_fetching_secret(self):
        secrets = FixtureSecrets()
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        expected_server_rejections = []

        def rejected_handshake(owner, context):
            if context.get(
                "message"
            ) == "Error on transport creation for incoming connection" and isinstance(
                context.get("exception"), (ConnectionResetError, ssl.SSLError)
            ):
                expected_server_rejections.append(context)
            else:
                owner.default_exception_handler(context)

        loop.set_exception_handler(rejected_handshake)
        try:
            transport = self.transport(await self.upstream(), host="127.0.0.1", secrets=secrets)
            with self.assertRaisesRegex(RelayError, "verified upstream"):
                await transport.connect("example.test", 443)
            self.assertEqual(secrets.calls, [])
            transport = HTTPSConnectTransport(transport.configuration, secrets=secrets)
            with self.assertRaises(RelayError):
                await transport.connect("example.test", 443)
            self.assertEqual(secrets.calls, [])
            await asyncio.sleep(0.01)
        finally:
            loop.set_exception_handler(previous_handler)

    async def test_insecure_tls_and_plaintext_upstream_are_rejected(self):
        ctx = ssl._create_unverified_context()
        with self.assertRaises(RelayError):
            HTTPSConnectTransport(
                ProxyConfiguration("p", "https", "localhost", 1234), tls_context=ctx
            )
        for scheme in ("http", "socks5"):
            with self.assertRaises(RelayError):
                HTTPSConnectTransport(ProxyConfiguration("p", scheme, "localhost", 1234))

    async def test_mutated_tls_context_rechecked(self):
        transport = self.transport(await self.upstream())
        self.client_tls.check_hostname = False
        with self.assertRaises(RelayError):
            await transport.connect("example.test", 443)
        self.assertFalse(self.requests)

    async def test_malformed_auth_material_never_hits_wire(self):
        for value in (b"bad\r\nInjected: yes", b":password", b"no-colon", b"x:y" * 1000):
            transport = self.transport(await self.upstream(), secrets=FixtureSecrets(value))
            with self.assertRaisesRegex(RelayError, "verified upstream") as result:
                await transport.connect("example.test", 443)
            self.assertNotIn(repr(value), str(result.exception))
        self.assertFalse(self.requests)

    async def test_target_validation_and_udp_are_rejected_before_upstream(self):
        class NoConnection:
            async def connect(self, *args):
                raise AssertionError("Must not connect")

        relay = await self.relay(NoConnection())
        for host, port, command in [
            ("localhost", 443, 1),
            ("x.local", 443, 1),
            ("127.0.0.1", 443, 1),
            ("127.1", 443, 1),
            ("0177.0.0.1", 443, 1),
            ("0x7f.0.0.1", 443, 1),
            ("0x7f.1", 443, 1),
            ("2130706433", 443, 1),
            ("0X7F.0.0.1", 443, 1),
            ("127.0.0.01", 443, 1),
            ("224.0.0.1", 443, 1),
            ("ff02::1", 443, 1),
            ("a\r\nb.test", 443, 1),
            ("example.test", 22, 1),
            ("example.test", 443, 3),
        ]:
            reader, _ = await self.socks(relay, host, port, command)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertFalse(relay.failed)
        self.assertFalse(self.failures)

    async def test_ipv6_literal_is_forwarded_without_target_resolution(self):
        relay = await self.relay(self.transport(await self.upstream()))
        reader, writer = await self.socket(relay)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        await reader.readexactly(2)
        host = "2606:4700:4700::1111"
        writer.write(b"\x05\x01\x00\x04" + ipaddress.ip_address(host).packed + b"\x01\xbb")
        await writer.drain()
        await reader.readexactly(10)
        self.assertIn(f"CONNECT [{host}]:443 HTTP/1.1".encode(), self.requests[0])

    async def test_handshake_timeout_closes_only_bad_client(self):
        limits = RelayLimits(handshake_seconds=0.05)
        relay = await self.relay(self.transport(await self.upstream()), limits)
        reader, _ = await self.socket(relay)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertTrue(relay.healthy)

    async def test_upstream_timeout_latches_failure(self):
        limits = RelayLimits(handshake_seconds=0.05)
        relay = await self.relay(
            self.transport(await self.upstream(delay=1), limits=limits), limits
        )
        reader, _ = await self.socks(relay)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertTrue(relay.failed)

    async def test_oversized_upstream_response_latches_failure(self):
        relay = await self.relay(self.transport(await self.upstream(b"x" * 9000 + b"\r\n\r\n")))
        reader, _ = await self.socks(relay)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertTrue(relay.failed)

    async def test_resource_cap_stop_and_no_restart(self):
        relay = await self.relay(
            self.transport(await self.upstream()), RelayLimits(max_connections=1)
        )
        first, _ = await self.socket(relay)
        second, _ = await self.socket(relay)
        self.assertEqual(await asyncio.wait_for(second.read(), 1), b"")
        await relay.stop()
        self.assertEqual(await asyncio.wait_for(first.read(), 1), b"")
        self.assertFalse(relay.healthy)
        self.assertFalse(relay._tasks)
        with self.assertRaises(RelayError):
            await relay.start()

    async def test_idle_tunnel_timeout_is_not_route_failure(self):
        relay = await self.relay(
            self.transport(await self.upstream()), RelayLimits(idle_seconds=0.05)
        )
        reader, _ = await self.socks(relay)
        await reader.readexactly(10)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertFalse(relay.failed)

    async def test_route_failure_aborts_other_active_tunnels(self):
        upstream = self.transport(await self.upstream())

        class FailsSecond:
            calls = 0

            async def connect(self, host, port):
                self.calls += 1
                if self.calls == 2:
                    raise RelayError("Synthetic route loss")
                return await upstream.connect(host, port)

        relay = await self.relay(FailsSecond())
        first, _ = await self.socks(relay)
        await first.readexactly(10)
        second, _ = await self.socks(relay)
        self.assertEqual(await asyncio.wait_for(second.read(), 1), b"")
        self.assertEqual(await asyncio.wait_for(first.read(), 1), b"")
        self.assertTrue(relay.failed)
        self.assertEqual(self.failures, [True])

    async def test_stop_cancels_inflight_upstream_without_route_retry(self):
        entered = asyncio.Event()

        class Slow:
            calls = 0

            async def connect(self, host, port):
                self.calls += 1
                entered.set()
                await asyncio.sleep(30)
                raise AssertionError("Cancelled work must not resume")

        transport = Slow()
        relay = await self.relay(transport)
        reader, _ = await self.socks(relay)
        await asyncio.wait_for(entered.wait(), 1)
        await asyncio.wait_for(relay.stop(), 1)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertEqual(transport.calls, 1)
        self.assertFalse(relay.healthy)
        self.assertFalse(relay.failed)

    async def test_one_way_active_stream_is_not_idle(self):
        stop_sending = asyncio.Event()

        async def stream(reader, writer):
            self.tasks.append(asyncio.current_task())
            self.writers.append(writer)
            try:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                while not stop_sending.is_set():
                    writer.write(b"s")
                    await writer.drain()
                    await asyncio.sleep(0.01)
                await reader.read()
            finally:
                writer.close()

        server = await asyncio.start_server(stream, "127.0.0.1", 0, ssl=self.server_tls)
        self.servers.append(server)
        relay = await self.relay(
            self.transport(server.sockets[0].getsockname()[1]), RelayLimits(idle_seconds=0.07)
        )
        reader, _ = await self.socks(relay)
        await reader.readexactly(10)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(20), 1), b"s" * 20)
        self.assertTrue(relay.healthy)
        stop_sending.set()
        await asyncio.sleep(0.12)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertFalse(relay.failed)

    async def test_diagnostic_quarantine_denies_without_queue_or_route_failure(self):
        relay = ProxyRelay(
            self.transport(await self.upstream()),
            on_failure=lambda: self.failures.append(True),
            diagnostic_targets=(("diagnostic.example.test", 443),),
        )
        self.relays.append(relay)
        await relay.start()
        self.assertTrue(relay.quarantined)
        for host, port in (
            ("restored.example.test", 443),
            ("diagnostic.example.test", 80),
            ("sub.diagnostic.example.test", 443),
        ):
            reader, _ = await self.socks(relay, host, port)
            self.assertEqual((await reader.readexactly(10))[:2], b"\x05\x02")
            self.assertEqual(await reader.read(), b"")
        self.assertFalse(self.requests)
        diagnostic, _ = await self.socks(relay, "DIAGNOSTIC.EXAMPLE.TEST")
        self.assertEqual((await diagnostic.readexactly(10))[:2], b"\x05\x00")
        self.assertEqual(len(self.requests), 1)
        self.assertFalse(relay.failed)
        self.assertFalse(self.failures)
        relay.release_quarantine()
        general, _ = await self.socks(relay, "restored.example.test")
        self.assertEqual((await general.readexactly(10))[:2], b"\x05\x00")
        self.assertFalse(relay.quarantined)
        self.assertEqual(len(self.requests), 2)

    async def test_pending_quarantined_connection_cannot_wait_for_release(self):
        relay = ProxyRelay(
            self.transport(await self.upstream()),
            on_failure=lambda: None,
            diagnostic_targets=(("diagnostic.example.test", 443),),
        )
        self.relays.append(relay)
        await relay.start()
        reader, writer = await self.socket(relay)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        await reader.readexactly(2)
        relay.release_quarantine()
        host = b"restored.example.test"
        writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x01\xbb")
        await writer.drain()
        self.assertEqual((await reader.readexactly(10))[:2], b"\x05\x02")
        self.assertFalse(self.requests)

    async def test_quarantine_configuration_is_bounded_and_cannot_release_failed_route(self):
        for targets in (
            (),
            (("127.1", 443),),
            (("example.test", 22),),
            (("a.test", 443),) * 9,
            (("a.test", 443), ("A.TEST", 443)),
            [("a.test", 443)],
        ):
            with self.assertRaises(RelayError):
                ProxyRelay(None, on_failure=lambda: None, diagnostic_targets=targets)
        relay = ProxyRelay(
            self.transport(await self.upstream()),
            on_failure=lambda: None,
            diagnostic_targets=(("diagnostic.example.test", 443),),
        )
        self.relays.append(relay)
        await relay.start()
        relay.fail_closed()
        with self.assertRaises(RelayError):
            relay.release_quarantine()
        self.assertTrue(relay.quarantined)


class RelayTLSDefaultsTests(unittest.TestCase):
    def test_ambient_keylog_and_ca_overrides_are_not_used(self):
        context = Mock()
        paths = SimpleNamespace(openssl_cafile="/approved/ca.pem", openssl_capath="/approved/certs")
        with (
            patch.dict(
                "os.environ", {"SSLKEYLOGFILE": "/must-not-write", "SSL_CERT_FILE": "/untrusted"}
            ),
            patch(
                "team_browser.client.proxy_relay.ssl.SSLContext", return_value=context
            ) as constructor,
            patch(
                "team_browser.client.proxy_relay.ssl.get_default_verify_paths", return_value=paths
            ),
            patch("team_browser.client.proxy_relay.os.path.isfile", return_value=True),
            patch("team_browser.client.proxy_relay.os.path.isdir", return_value=True),
            patch("team_browser.client.proxy_relay.ssl.create_default_context") as ambient,
        ):
            self.assertIs(_default_tls_context(), context)
        constructor.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations.assert_called_once_with(
            cafile="/approved/ca.pem", capath="/approved/certs"
        )
        context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        ambient.assert_not_called()

    def test_keylogging_injected_context_is_rejected(self):
        context = SimpleNamespace(
            check_hostname=True,
            verify_mode=ssl.CERT_REQUIRED,
            minimum_version=ssl.TLSVersion.TLSv1_2,
            keylog_filename="forbidden",
        )
        with self.assertRaises(RelayError):
            HTTPSConnectTransport(
                ProxyConfiguration("synthetic", "https", "proxy.example.test", 443),
                tls_context=context,
            )

    def test_missing_default_trust_roots_fail_closed(self):
        with (
            patch("team_browser.client.proxy_relay.os.path.isfile", return_value=False),
            patch("team_browser.client.proxy_relay.os.path.isdir", return_value=False),
            self.assertRaises(RelayError),
        ):
            _default_tls_context()
