"""Native, exact-endpoint OIDC HTTPS transport. Never expose this as a web proxy.

One numeric-address connection, verified TLS, no redirects/retries/proxies. DNS
runs in one killable isolated process, not a timeout-abandoned resolver thread.
See docs/oidc-transport.md for deadline and target-platform acceptance limits.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from urllib.parse import urlencode, urlsplit

from team_browser.client.auth_flow import HTTPResponse, TrustedOIDCConfiguration


class OIDCTransportError(Exception):
    """Fixed diagnostics only: callers must not dump frames, arguments or locals."""


_MAX_BODY = 65536
_MAX_HEADERS = 16384
_MAX_ADDRESSES = 32
_DNS_CLEANUP_SECONDS = 0.25
_DNS_SLOT = threading.Lock()
# Retain an unreaped child and the global slot: even constructing another
# transport cannot accumulate abandoned resolver processes. No automatic reset.
_STRANDED_RESOLVER: subprocess.Popen | None = None
_DNS_PROGRAM = r"""
import json, socket, sys
try:
    host = sys.stdin.buffer.read(254).decode('ascii')
    if not host or len(host) > 253 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in host):
        raise ValueError()
    rows = socket.getaddrinfo(host + '.', 443, family=socket.AF_UNSPEC,
                              type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not 1 <= len(rows) <= 32:
        raise ValueError()
    result = []
    for family, kind, protocol, canonname, address in rows:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP:
            raise ValueError()
        if address[1] != 443 or (family == socket.AF_INET6 and address[2:] != (0, 0)):
            raise ValueError()
        if address[0] not in result:
            result.append(address[0])
    output = json.dumps(result, separators=(',', ':')).encode('ascii')
    if len(output) > 4096:
        raise ValueError()
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
except BaseException:
    sys.exit(1)
"""


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OIDCTransportError("OIDC HTTPS deadline exceeded")
    return remaining


def _none(value: object) -> None:
    if value is not None:
        raise OIDCTransportError("OIDC native I/O acknowledgement is invalid")


def _supported_interpreter() -> None:
    # A frozen app's sys.executable can re-launch its GUI instead of executing
    # -I/-S/-c. Native packaging must supply a separately reviewed design; never
    # spawn a bootloader recursively or search PATH for another interpreter.
    if (
        sys.platform not in ("darwin", "linux")
        or sys.implementation.name != "cpython"
        or getattr(sys, "frozen", False)
        or hasattr(sys, "_MEIPASS")
        or not os.path.isabs(sys.executable)
        or not os.path.isfile(sys.executable)
        or not os.access(sys.executable, os.X_OK)
    ):
        raise OIDCTransportError("OIDC resolver runtime is unsupported")


def _resolve(host: str, deadline: float) -> list[str]:
    """Bound DNS waits and cleanup; never leave an accumulating worker pool.

    Popen itself and OS scheduling cannot have a hard real-time guarantee.
    The deadline is checked after spawn, and no late DNS result is accepted.
    The fixed helper receives only the public DNS name, never a URL or secret.
    """
    global _STRANDED_RESOLVER
    _supported_interpreter()
    if not _DNS_SLOT.acquire(blocking=False):
        raise OIDCTransportError("OIDC resolver is unavailable")
    child = None
    cleanup_confirmed = True
    try:
        _remaining(deadline)
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", _DNS_PROGRAM],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            close_fds=True,
            start_new_session=True,
        )
        cleanup_confirmed = False
        timeout = _remaining(deadline) - _DNS_CLEANUP_SECONDS
        if timeout <= 0:
            raise OIDCTransportError("OIDC HTTPS deadline exceeded")
        output = child.communicate(input=host.encode("ascii"), timeout=timeout)
        _remaining(deadline)
        if (
            type(output) is not tuple
            or len(output) != 2
            or type(output[0]) is not bytes
            or len(output[0]) > 4096
            or output[1] is not None
            or type(child.returncode) is not int
            or child.returncode != 0
        ):
            raise OIDCTransportError("OIDC DNS result is invalid")
        value = json.loads(output[0])
        # The connection layer independently validates the addresses, including
        # returns substituted by a native integration/test adapter.
        if type(value) is not list:
            raise OIDCTransportError("OIDC DNS result is invalid")
        return value
    finally:
        if child is not None:
            try:
                status = child.poll()
                if status is None:
                    _none(child.kill())
                    # Reserve time inside the SAME budget; never wait forever
                    # after TimeoutExpired or use Popen's blocking context exit.
                    timeout = max(0.0, min(_DNS_CLEANUP_SECONDS, deadline - time.monotonic()))
                    status = child.wait(timeout=timeout)
                if type(status) is not int:
                    raise OIDCTransportError("OIDC resolver cleanup is uncertain")
                for pipe in (child.stdin, child.stdout):
                    if pipe is not None:
                        _none(pipe.close())
                cleanup_confirmed = True
            except BaseException:
                _STRANDED_RESOLVER = child
        if cleanup_confirmed:
            _DNS_SLOT.release()
        else:
            raise OIDCTransportError("OIDC resolver cleanup is uncertain") from None


# Deliberately conservative across supported Python patch-level classifications.
_DENIED_V4 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
_V6_GLOBAL = ipaddress.ip_network("2000::/3")
_DENIED_V6 = tuple(
    ipaddress.ip_network(value)
    for value in ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")
)


def _addresses(value: object) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if type(value) is not list or not 1 <= len(value) <= _MAX_ADDRESSES:
        raise OIDCTransportError("OIDC DNS result is invalid")
    result = []
    for item in value:
        if type(item) is not str or len(item) > 45 or "%" in item:
            raise OIDCTransportError("OIDC DNS result is invalid")
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            raise OIDCTransportError("OIDC DNS result is invalid") from None
        if (
            not address.is_global
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or address.is_private
            or (address.version == 4 and any(address in net for net in _DENIED_V4))
            or (
                address.version == 6
                and (address not in _V6_GLOBAL or any(address in net for net in _DENIED_V6))
            )
            or address in result
        ):
            raise OIDCTransportError("OIDC destination is not allowed")
        result.append(address)
    return tuple(result)


def _context() -> ssl.SSLContext:
    # Do not use create_default_context's SSLKEYLOGFILE behavior or ambient CA
    # environment overrides. Only this interpreter's default OS/OpenSSL paths.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile if os.path.isfile(paths.openssl_cafile) else None
    capath = paths.openssl_capath if os.path.isdir(paths.openssl_capath) else None
    if cafile is None and capath is None:
        raise OIDCTransportError("OIDC native trust roots are unavailable")
    context.load_verify_locations(cafile=cafile, capath=capath)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    return context


@dataclass(frozen=True, repr=False)
class _Endpoint:
    url: str
    host: str
    authority: str
    path: str

    @classmethod
    def from_url(cls, url: str) -> _Endpoint:
        parts = urlsplit(url)
        host = parts.hostname
        if (
            not host
            or len(host) > 253
            or host.endswith((".internal", ".home.arpa", ".onion"))
            or all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", x) for x in host.split("."))
        ):
            raise OIDCTransportError("OIDC endpoint is invalid")
        return cls(url, host, parts.netloc, parts.path or "/")


class _Reader:
    def __init__(self, stream, deadline: float):
        self.stream, self.deadline = stream, deadline
        self.buffer = bytearray()

    def recv(self, maximum: int) -> bytes:
        _none(self.stream.settimeout(_remaining(self.deadline)))
        value = self.stream.recv(maximum)
        _remaining(self.deadline)
        if type(value) is not bytes or len(value) > maximum:
            raise OIDCTransportError("OIDC native read is invalid")
        return value

    def until(self, separator: bytes, maximum: int) -> bytes:
        while True:
            position = self.buffer.find(separator)
            if position >= 0:
                end = position + len(separator)
                if end > maximum:
                    raise OIDCTransportError("OIDC HTTP framing limit exceeded")
                value = bytes(self.buffer[:end])
                del self.buffer[:end]
                return value
            if len(self.buffer) >= maximum:
                raise OIDCTransportError("OIDC HTTP framing limit exceeded")
            value = self.recv(min(4096, maximum - len(self.buffer)))
            if not value:
                raise OIDCTransportError("OIDC HTTP response is incomplete")
            self.buffer.extend(value)

    def exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            value = self.recv(min(4096, size - len(self.buffer)))
            if not value:
                raise OIDCTransportError("OIDC HTTP response is incomplete")
            self.buffer.extend(value)
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value

    def response(self, url: str) -> HTTPResponse:
        lines = self.until(b"\r\n\r\n", _MAX_HEADERS)[:-4].split(b"\r\n")
        if len(lines) > 65 or any(len(line) > 4096 for line in lines):
            raise OIDCTransportError("OIDC HTTP header limit exceeded")
        if not re.fullmatch(rb"HTTP/1\.[01] 200 [\x20-\x7e]*", lines[0]):
            # This includes redirects, informational responses and proxy auth.
            raise OIDCTransportError("OIDC HTTP status is not supported")
        headers = {}
        singleton = {b"content-type", b"content-length", b"transfer-encoding", b"content-encoding"}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise OIDCTransportError("OIDC HTTP header is invalid")
            if not re.fullmatch(rb"[\t\x20-\x7e]*", value):
                raise OIDCTransportError("OIDC HTTP header is invalid")
            name = name.lower()
            if name in singleton:
                if name in headers:
                    raise OIDCTransportError("OIDC HTTP header is ambiguous")
                headers[name] = value.strip(b" \t").lower()
        if (
            not re.fullmatch(
                rb'application/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?',
                headers.get(b"content-type", b""),
            )
            or headers.get(b"content-encoding", b"identity") != b"identity"
        ):
            raise OIDCTransportError("OIDC HTTP representation is not supported")
        length, transfer = headers.get(b"content-length"), headers.get(b"transfer-encoding")
        if transfer is not None:
            if transfer != b"chunked" or length is not None or not lines[0].startswith(b"HTTP/1.1"):
                raise OIDCTransportError("OIDC HTTP framing is ambiguous")
            body = self.chunked()
        elif length is not None:
            if not re.fullmatch(rb"(?:0|[1-9][0-9]{0,5})", length) or int(length) > _MAX_BODY:
                raise OIDCTransportError("OIDC HTTP body limit exceeded")
            body = self.exact(int(length))
        else:
            body = bytearray(self.buffer)
            self.buffer.clear()
            while True:
                if len(body) > _MAX_BODY:
                    raise OIDCTransportError("OIDC HTTP body limit exceeded")
                value = self.recv(min(4096, _MAX_BODY + 1 - len(body)))
                if not value:
                    break
                body.extend(value)
            body = bytes(body)
        if self.buffer or self.recv(1):
            # Connection: close was requested. Require the end of this TLS
            # response even for framed bodies, so trailing-byte rejection does
            # not depend on how recv happened to fragment the response.
            raise OIDCTransportError("OIDC HTTP trailing bytes are invalid")
        _remaining(self.deadline)
        return HTTPResponse(200, url, body, content_type="application/json", redirected=False)

    def chunked(self) -> bytes:
        body = bytearray()
        framing = 0
        for _ in range(1024):
            line = self.until(b"\r\n", 128)
            framing += len(line) + 2
            if framing > 8192 or not re.fullmatch(rb"[0-9A-Fa-f]{1,6}\r\n", line):
                raise OIDCTransportError("OIDC HTTP chunk framing is invalid")
            size = int(line[:-2], 16)
            if len(body) + size > _MAX_BODY:
                raise OIDCTransportError("OIDC HTTP body limit exceeded")
            body.extend(self.exact(size))
            # Extensions and trailers deliberately unsupported: no second source
            # of response metadata, bounded overhead and no parser ambiguity.
            if self.exact(2) != b"\r\n":
                raise OIDCTransportError("OIDC HTTP chunk framing is invalid")
            if size == 0:
                return bytes(body)
        raise OIDCTransportError("OIDC HTTP chunk count exceeded")


class NativeOIDCHTTPSTransport:
    """Callable auth_flow.OIDCTransport, constructed only by trusted native code.

    No network at construction. Only GET(config.jwks_endpoint) and a narrowly
    validated code POST(config.token_endpoint) can reach the network. Errors
    during I/O latch this instance unavailable; remote issuance may be unknown.
    There is no reset, retry, proxy, discovery, custom TLS context or URL bridge.
    """

    def __init__(self, config: TrustedOIDCConfiguration):
        try:
            if type(config) is not TrustedOIDCConfiguration:
                raise ValueError
            config = replace(config)  # Revalidate, and retain a native snapshot.
            _supported_interpreter()
            self._token = _Endpoint.from_url(config.token_endpoint)
            self._jwks = _Endpoint.from_url(config.jwks_endpoint)
            self._client_id = config.client_id
            self._redirect_uri = config.redirect_uri
            self._tls = _context()
            self._check_tls()
        except Exception:
            raise OIDCTransportError("OIDC native HTTPS configuration is unavailable") from None
        self._lock = threading.Lock()
        self._failed = False

    def _check_tls(self) -> None:
        if (
            self._tls.verify_mode != ssl.CERT_REQUIRED
            or self._tls.check_hostname is not True
            or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2
            or self._tls.keylog_filename is not None
        ):
            raise OIDCTransportError("OIDC verified TLS is required")

    def get(self, url: str, *, timeout_seconds: int, follow_redirects: bool) -> HTTPResponse:
        return self._request("GET", url, None, timeout_seconds, follow_redirects)

    def post_form(
        self, url: str, fields: dict[str, str], *, timeout_seconds: int, follow_redirects: bool
    ) -> HTTPResponse:
        return self._request("POST", url, fields, timeout_seconds, follow_redirects)

    def _form(self, fields: object) -> bytes:
        if type(fields) is not dict:
            raise OIDCTransportError("OIDC code request is invalid")
        fields = fields.copy()
        if set(fields) != {
            "grant_type",
            "code",
            "redirect_uri",
            "client_id",
            "code_verifier",
        }:
            raise OIDCTransportError("OIDC code request is invalid")
        # Untrusted mapping callbacks are not accepted.
        if (
            any(type(value) is not str for value in fields.values())
            or fields["grant_type"] != "authorization_code"
            or fields["client_id"] != self._client_id
            or fields["redirect_uri"] != self._redirect_uri
            or not re.fullmatch(r"[\x21-\x7e]{1,4096}", fields["code"])
            or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", fields["code_verifier"])
        ):
            raise OIDCTransportError("OIDC code request is invalid")
        body = urlencode(fields).encode("ascii")
        if len(body) > 32768:
            raise OIDCTransportError("OIDC code request is invalid")
        return body

    def _request(self, method, url, fields, timeout_seconds, follow_redirects) -> HTTPResponse:
        started = time.monotonic()
        endpoint = self._jwks if method == "GET" else self._token
        if (
            type(url) is not str
            or url != endpoint.url
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 10
            or follow_redirects is not False
        ):
            raise OIDCTransportError("OIDC exact endpoint and bounded policy are required")
        body = b"" if method == "GET" else self._form(fields)
        if not self._lock.acquire(blocking=False):
            raise OIDCTransportError("OIDC HTTPS transport is busy")
        deadline = started + timeout_seconds
        raw = stream = None
        try:
            if self._failed:
                raise OIDCTransportError("OIDC HTTPS transport requires recovery")
            self._check_tls()
            addresses = _addresses(_resolve(endpoint.host, deadline))
            _remaining(deadline)
            address = addresses[0]  # One attempt, no address fallback/retry.
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            destination = (str(address), 443) if address.version == 4 else (str(address), 443, 0, 0)
            raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            _none(raw.settimeout(_remaining(deadline)))
            _none(raw.connect(destination))  # Numeric sockaddr: no second DNS lookup.
            self._peer(raw, address)
            _none(raw.settimeout(_remaining(deadline)))
            stream = self._tls.wrap_socket(
                raw,
                server_hostname=endpoint.host,
                do_handshake_on_connect=False,
                suppress_ragged_eofs=False,
            )
            _none(stream.settimeout(_remaining(deadline)))
            _none(stream.do_handshake())
            _remaining(deadline)
            self._check_tls()
            self._peer(stream, address)
            if stream.selected_alpn_protocol() not in (None, "http/1.1"):
                raise OIDCTransportError("OIDC TLS application protocol is invalid")
            headers = (
                f"{method} {endpoint.path} HTTP/1.1\r\nHost: {endpoint.authority}\r\n"
                "Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
            )
            if method == "POST":
                headers += (
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body)}\r\n"
                )
            request = headers.encode("ascii") + b"\r\n" + body
            _none(stream.settimeout(_remaining(deadline)))
            _none(stream.sendall(request))
            del request, body
            _remaining(deadline)
            response = _Reader(stream, deadline).response(endpoint.url)
        except BaseException as exc:
            self._failed = True
            if not isinstance(exc, Exception):
                raise
            raise OIDCTransportError("OIDC HTTPS request failed; recovery is required") from None
        finally:
            cleanup_ok = True
            for connection in (stream, raw):
                if connection is not None:
                    try:
                        _none(connection.close())
                    except BaseException:
                        cleanup_ok = False
            late = time.monotonic() >= deadline
            if not cleanup_ok or late:
                self._failed = True
            self._lock.release()
            if not cleanup_ok:
                raise OIDCTransportError("OIDC HTTPS cleanup is uncertain") from None
            if late:
                raise OIDCTransportError("OIDC HTTPS deadline exceeded") from None
        return response

    @staticmethod
    def _peer(stream, address) -> None:
        peer = stream.getpeername()
        expected = (str(address), 443) if address.version == 4 else (str(address), 443, 0, 0)
        if type(peer) is not tuple or len(peer) != len(expected):
            raise OIDCTransportError("OIDC connected destination is invalid")
        if type(peer[0]) is not str or any(type(x) is not int for x in peer[1:]):
            raise OIDCTransportError("OIDC connected destination is invalid")
        if ipaddress.ip_address(peer[0]) != address or peer[1:] != expected[1:]:
            raise OIDCTransportError("OIDC connected destination is invalid")
