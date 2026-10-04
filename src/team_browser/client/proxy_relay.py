"""Bounded local SOCKS5 CONNECT relay to one certificate-verified HTTPS proxy.

This is an application route, not an OS firewall. The local SOCKS listener has no
user authentication: any process on the host can reach it. A trusted single-user
host acceptance gate belongs to the owning runtime adapter. Never expose this
listener externally or claim that loopback alone authenticates a profile.

No target DNS is resolved here. Domain names are sent unchanged to the upstream
CONNECT proxy; only the provider endpoint is resolved locally. Only TCP ports
80/443 are supported. UDP ASSOCIATE, BIND, PAC and direct fallback do not exist.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import re
import ssl
from dataclasses import dataclass
from typing import Callable, Protocol

from team_browser.local.proxy import ProxyConfiguration
from team_browser.local.secrets import SecretStore


class RelayError(Exception):
    """Messages are fixed and must not contain hosts, credentials or wire data."""


@dataclass(frozen=True)
class RelayLimits:
    handshake_seconds: float = 10.0
    idle_seconds: float = 60.0
    max_connections: int = 32
    buffer_bytes: int = 16384

    def __post_init__(self) -> None:
        if not 0 < self.handshake_seconds <= 30 or not 0 < self.idle_seconds <= 300:
            raise ValueError("Relay timeouts must be positive and bounded")
        if (
            type(self.max_connections) is not int
            or type(self.buffer_bytes) is not int
            or not 1 <= self.max_connections <= 128
            or not 1024 <= self.buffer_bytes <= 65536
        ):
            raise ValueError("Relay resource limits are invalid")


def _target(host: str, port: int) -> str:
    if type(port) is not int or port not in (80, 443):
        raise RelayError("The target port is not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if (
            not isinstance(host, str)
            or len(host) > 253
            or not all(
                re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                for label in host.split(".")
            )
        ):
            raise RelayError("The target name is invalid") from None
        # Upstream resolvers may accept inet_aton-style short, octal or hex
        # IPv4 forms which ipaddress correctly rejects. Never reinterpret those
        # ambiguous address strings as DNS names (e.g. 127.1 or 0x7f.0.0.1).
        if all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", label) for label in host.split(".")):
            raise RelayError("Ambiguous numeric target addresses are not allowed")
        if "." not in host or host.lower().endswith((".localhost", ".local", ".internal")):
            raise RelayError("Local target names are not allowed")
        return f"{host}:{port}"
    # Explicit private/loopback IP targets cannot reach the local control plane.
    # A remote provider can still resolve a public-looking name privately; no
    # local DNS check is added because that would leak target DNS off-route.
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise RelayError("Non-public target addresses are not allowed")
    return f"[{host}]:{port}" if address.version == 6 else f"{host}:{port}"


def diagnostic_authorities(targets: tuple[tuple[str, int], ...]) -> frozenset[str]:
    """Validate a small exact trusted diagnostic list, without performing DNS."""
    if not isinstance(targets, tuple) or not 1 <= len(targets) <= 8:
        raise RelayError("A bounded nonempty diagnostic target tuple is required")
    if any(not isinstance(target, tuple) or len(target) != 2 for target in targets):
        raise RelayError("Diagnostic targets require exact host and port pairs")
    authorities = frozenset(_target(host, port).lower() for host, port in targets)
    if len(authorities) != len(targets):
        raise RelayError("Diagnostic targets must be unique")
    return authorities


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        transport = writer.transport
        if transport is not None:
            transport.abort()


class TunnelTransport(Protocol):
    async def connect(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Return a connected upstream tunnel, never a direct target socket."""
        ...


def _default_tls_context() -> ssl.SSLContext:
    # create_default_context honors SSLKEYLOGFILE and ambient CA overrides.
    # Proxy credentials must never become decryptable through a key-log file.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile if os.path.isfile(paths.openssl_cafile) else None
    capath = paths.openssl_capath if os.path.isdir(paths.openssl_capath) else None
    if cafile is None and capath is None:
        raise RelayError("Verified upstream trust roots are unavailable")
    context.load_verify_locations(cafile=cafile, capath=capath)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    return context


class HTTPSConnectTransport:
    """Credentials come only from SecretStore as UTF-8 username:password bytes.

    This store must be a reviewed OS-native store in production. Immutable Python
    strings/bytes cannot be reliably erased; values live only during a handshake.
    Test injection of a private certificate authority still requires TLS hostname
    and certificate verification. There is no insecure-mode switch.
    """

    def __init__(
        self,
        configuration: ProxyConfiguration,
        *,
        secrets: SecretStore | None = None,
        tls_context: ssl.SSLContext | None = None,
        limits: RelayLimits = RelayLimits(),
    ):
        if configuration.scheme != "https":
            raise RelayError("Only certificate-verified HTTPS upstream proxies are supported")
        if configuration.credentials is not None and secrets is None:
            raise RelayError("A native secret store is required for proxy authentication")
        self.configuration, self.secrets, self.limits = configuration, secrets, limits
        self._tls = tls_context if tls_context is not None else _default_tls_context()
        self._check_tls()

    def _check_tls(self) -> None:
        if (
            not self._tls.check_hostname
            or self._tls.verify_mode != ssl.CERT_REQUIRED
            or self._tls.keylog_filename is not None
        ):
            raise RelayError("Upstream TLS peer verification must remain enabled")
        if self._tls.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise RelayError("Upstream TLS requires TLS 1.2 or newer")

    async def connect(self, host: str, port: int):
        authority = _target(host, port)
        writer = None
        try:
            self._check_tls()
            async with asyncio.timeout(self.limits.handshake_seconds):
                reader, writer = await asyncio.open_connection(
                    self.configuration.host,
                    self.configuration.port,
                    ssl=self._tls,
                    server_hostname=self.configuration.host,
                    ssl_handshake_timeout=self.limits.handshake_seconds,
                    limit=8192,
                )
                # Fetch only after the upstream peer is authenticated. Never give
                # credentials to Playwright, the browser, argv, env or disk.
                auth = b""
                if self.configuration.credentials is not None:
                    assert self.secrets is not None
                    value = await asyncio.to_thread(
                        self.secrets.get, self.configuration.credentials
                    )
                    if (
                        not isinstance(value, bytes)
                        or not 3 <= len(value) <= 2048
                        or b":" not in value
                        or not value.split(b":", 1)[0]
                        or any(c < 32 or c == 127 for c in value)
                    ):
                        raise RelayError("Proxy authentication material is invalid")
                    value.decode("utf-8", errors="strict")
                    auth = b"Proxy-Authorization: Basic " + base64.b64encode(value) + b"\r\n"
                    del value
                request = (
                    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n".encode("ascii")
                    + auth
                    + b"\r\n"
                )
                writer.write(request)
                del request, auth
                await writer.drain()
                response = await reader.readuntil(b"\r\n\r\n")
                if len(response) > 8192 or not re.fullmatch(
                    rb"HTTP/1\.[01] 200(?: [^\r\n]*)?", response.split(b"\r\n", 1)[0]
                ):
                    raise RelayError("The upstream proxy rejected the tunnel")
                return reader, writer
        except BaseException as exc:
            if writer is not None:
                await _close(writer)
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RelayError("The verified upstream tunnel could not be established") from None


class ProxyRelay:
    """A per-profile, one-use relay with a sticky route-failure latch.

    Call only on one owning asyncio loop. A failed upstream handshake or I/O
    closes all profile tunnels and the listener before notifying its owner.
    Ordinary EOF and idle tunnel expiry close only that tunnel. A failed relay
    cannot be restarted; the owner must close the browser and obtain new checks.
    """

    def __init__(
        self,
        transport: TunnelTransport,
        *,
        on_failure: Callable[[], None],
        limits: RelayLimits = RelayLimits(),
        diagnostic_targets: tuple[tuple[str, int], ...] | None = None,
    ):
        self.transport, self.on_failure, self.limits = transport, on_failure, limits
        self._diagnostics = (
            diagnostic_authorities(diagnostic_targets) if diagnostic_targets is not None else None
        )
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._started = False
        self._closed = False
        self.failed = False
        self.port: int | None = None

    @property
    def healthy(self) -> bool:
        return self._started and not self._closed and not self.failed

    @property
    def quarantined(self) -> bool:
        return self._diagnostics is not None

    def release_quarantine(self) -> None:
        """Trusted owner only, after context proof and fresh authority checks."""
        if not self.healthy or not self.quarantined:
            raise RelayError("Only a healthy quarantined relay can be released")
        self._diagnostics = None

    async def start(self) -> int:
        if self._started or self._closed:
            raise RelayError("Relay instances cannot be restarted")
        self._started = True
        self._server = await asyncio.start_server(
            self._accept, host="127.0.0.1", port=0, limit=self.limits.buffer_bytes
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self.healthy or len(self._tasks) >= self.limits.max_connections:
            writer.close()
            return
        self._writers.add(writer)
        task = asyncio.create_task(self._serve(reader, writer, self._diagnostics))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def fail_closed(self) -> None:
        if self.failed or self._closed:
            return
        self.failed = True
        if self._server is not None:
            self._server.close()
        for writer in tuple(self._writers):
            # Abort rather than flush buffered traffic after the route is lost.
            writer.transport.abort()
        for task in tuple(self._tasks):
            if task is not asyncio.current_task():
                task.cancel()
        # The callback must synchronously request owned browser shutdown. No
        # exception payload from the provider is forwarded or logged.
        try:
            self.on_failure()
        except Exception:
            pass  # The listener/tunnels remain closed even if the owner failed.

    async def _handshake(self, reader, writer) -> tuple[str, int]:
        version, count = await reader.readexactly(2)
        if version != 5 or count == 0:
            raise RelayError("Invalid SOCKS negotiation")
        methods = await reader.readexactly(count)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            raise RelayError("Unsupported SOCKS authentication")
        writer.write(b"\x05\x00")
        await writer.drain()
        version, command, reserved, kind = await reader.readexactly(4)
        if version != 5 or command != 1 or reserved != 0:
            raise RelayError("Only SOCKS CONNECT is supported")
        if kind == 3:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("ascii")
        elif kind in (1, 4):
            host = str(ipaddress.ip_address(await reader.readexactly(4 if kind == 1 else 16)))
        else:
            raise RelayError("Unsupported SOCKS address")
        port = int.from_bytes(await reader.readexactly(2), "big")
        _target(host, port)
        return host, port

    async def _pump(self, reader, writer, activity) -> None:
        while True:
            data = await reader.read(self.limits.buffer_bytes)
            if not data:
                return
            activity[0] = asyncio.get_running_loop().time()
            writer.write(data)
            # Bounded backpressure is distinct from the shared tunnel-idle clock.
            await asyncio.wait_for(writer.drain(), self.limits.idle_seconds)
            activity[0] = asyncio.get_running_loop().time()

    async def _idle_watch(self, activity) -> None:
        while True:
            remaining = self.limits.idle_seconds - (asyncio.get_running_loop().time() - activity[0])
            if remaining <= 0:
                return
            await asyncio.sleep(remaining)

    async def _serve(self, reader, writer, admission_diagnostics) -> None:
        upstream = None
        pumps: list[asyncio.Task] = []
        try:
            try:
                async with asyncio.timeout(self.limits.handshake_seconds):
                    host, port = await self._handshake(reader, writer)
                    if (
                        admission_diagnostics is not None
                        and _target(host, port).lower() not in admission_diagnostics
                    ):
                        # Refuse rather than queue restored/background/user traffic.
                        # A denied local request is not an upstream route failure.
                        writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                        await writer.drain()
                        return
            except (Exception, asyncio.CancelledError):
                return  # Untrusted local input never trips a profile-wide latch.
            try:
                async with asyncio.timeout(self.limits.handshake_seconds):
                    remote_reader, upstream = await self.transport.connect(host, port)
                if not self.healthy:
                    return
                self._writers.add(upstream)
            except asyncio.CancelledError:
                return
            except Exception:
                self.fail_closed()
                return
            try:
                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                activity = [asyncio.get_running_loop().time()]
                pumps = [
                    asyncio.create_task(self._pump(reader, upstream, activity)),
                    asyncio.create_task(self._pump(remote_reader, writer, activity)),
                    asyncio.create_task(self._idle_watch(activity)),
                ]
                done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            except (TimeoutError, asyncio.CancelledError):
                pass  # Idle expiry is normal and does not authorize fallback.
            except Exception:
                self.fail_closed()
        finally:
            for task in pumps:
                task.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            for item in (writer, upstream):
                if item is not None:
                    self._writers.discard(item)
                    await _close(item)

    async def stop(self) -> None:
        self._closed = True
        if self._server is not None:
            self._server.close()
        for writer in tuple(self._writers):
            writer.close()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=3)
        self._writers.clear()
        if self._server is not None:
            await asyncio.wait_for(self._server.wait_closed(), timeout=1)
