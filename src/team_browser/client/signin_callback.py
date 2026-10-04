"""Native-only, one-attempt loopback/sign-in orchestration. Importing is inert.

No web route, generic URL launcher, token bridge, provider registration or live
platform acceptance is supplied. See docs/signin-callback.md for host duties.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import socket
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import h11

from .auth_flow import (
    AccountIdentity,
    AuthResult,
    AuthStatus,
    ManagedSignIn,
    NativeSessionMaterial,
    OIDCTransport,
    SessionVault,
    TrustedOIDCConfiguration,
)

_MAX_HEAD_BYTES = 16384
_MAX_HEADERS = 48
_MAX_CONNECTIONS = 8
_REQUEST_SECONDS = 2.0
_POLL_SECONDS = 0.05
_ACTIVE = {AuthStatus.WAITING, AuthStatus.EXCHANGING, AuthStatus.CANCELLING}
_PAGE = (
    b"<!doctype html><html lang=en><meta charset=utf-8>"
    b"<title>Team Browser sign-in</title>"
    b"<p>Return to Team Browser and check sign-in status in the app.</p></html>"
)
_HEADERS = (
    (b"content-type", b"text/html; charset=utf-8"),
    (b"cache-control", b"no-store"),
    (b"pragma", b"no-cache"),
    (
        b"content-security-policy",
        b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
    (b"referrer-policy", b"no-referrer"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"connection", b"close"),
    (b"content-length", str(len(_PAGE)).encode("ascii")),
)


class NativeBrowserError(RuntimeError):
    """Fixed diagnostics; never propagate URL-bearing native exceptions."""


class _AttemptVault:
    """Delegate unchanged storage; retain only this attempt's committed handle.

    A cancellation accepted before public terminal publication can race the
    core's final commit. Retire that ONE committed local record in this case;
    this is neither a general logout API nor provider-side revocation. No
    material is read back, exposed, cached or given broader scope here.
    """

    def __init__(self, delegate: SessionVault):
        self._delegate = delegate
        self._lock = threading.Lock()
        self._committed: str | None = None

    def assert_available(self) -> None:
        return self._delegate.assert_available()

    def store_session(self, session_id: str, material: NativeSessionMaterial) -> None:
        acknowledgement = self._delegate.store_session(session_id, material)
        if acknowledgement is None:
            with self._lock:
                self._committed = session_id
        return acknowledgement

    def delete_session(self, session_id: str) -> None:
        acknowledgement = self._delegate.delete_session(session_id)
        if acknowledgement is None:
            with self._lock:
                if self._committed == session_id:
                    self._committed = None
        return acknowledgement

    def discard_unpublished_commit(self) -> None:
        with self._lock:
            session_id = self._committed
        if session_id is None:
            raise RuntimeError("native_commit_cleanup_uncertain")
        if self.delete_session(session_id) is not None:
            raise RuntimeError("native_commit_cleanup_uncertain")


def _launch_macos_authorization(url: str, endpoint: str) -> None:
    """Private native seam, not an arbitrary-URL API or a JS callable.

    NSWorkspace.openURL: is documented thread-safe on supported macOS versions.
    It requests the OS default HTTPS handler. No shell, process arguments,
    embedded browser, environment-selected executable or browser cookie access.
    """
    if sys.platform != "darwin":
        raise NativeBrowserError("native_external_browser_unavailable")
    try:
        parsed = urlsplit(url)
        if (
            type(url) is not str
            or len(url) > 16384
            or not url.isascii()
            or any(ord(char) <= 32 or ord(char) >= 127 for char in url)
            or "\\" in url
            or parsed.scheme != "https"
            or parsed.fragment
            or not parsed.query
            or urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")) != endpoint
        ):
            raise ValueError
        # Explicit optional framework imports only at an authorized native call.
        import AppKit
        import Foundation
        import objc

        with objc.autorelease_pool():
            native_url = Foundation.NSURL.URLWithString_(url)
            if native_url is None:
                raise ValueError
            acknowledgement = AppKit.NSWorkspace.sharedWorkspace().openURL_(native_url)
            if type(acknowledgement) is not bool or acknowledgement is not True:
                raise ValueError
    except Exception:
        # Even a failed/unknown acknowledgement does not prove no page opened.
        raise NativeBrowserError("native_external_browser_launch_uncertain") from None


@dataclass(frozen=True)
class SignInSnapshot:
    """Secret-free last observation, not a backend authorization decision."""

    result: AuthResult
    listener_open: bool
    finished: bool
    cancellation_requested: bool
    native_operations_pending: bool
    can_cancel: bool
    diagnostic: str | None = None

    def public(self) -> dict:
        return {
            **self.result.public(),
            "listener_open": self.listener_open,
            "attempt_finished": self.finished,
            "cancellation_requested": self.cancellation_requested,
            "native_operations_pending": self.native_operations_pending,
            "can_cancel": self.can_cancel,
            "diagnostic": self.diagnostic,
            "native_integration_verified": False,
        }


class NativeSignInCoordinator:
    """One explicitly started native attempt; no restart or automatic retry.

    The core is constructed here with the SAME trusted configuration used to bind
    and dispatch the listener. start/cancel/shutdown/snapshot never do native I/O
    or wait for a worker. Keep this object and its vault alive until wait_finished
    confirms all work settled. Cancellation cannot revoke a provider grant.
    """

    def __init__(
        self,
        config: TrustedOIDCConfiguration,
        *,
        transport: OIDCTransport,
        vault: SessionVault,
    ):
        if type(config) is not TrustedOIDCConfiguration:
            raise TypeError("Exact trusted native configuration is required")
        if transport is None or vault is None:
            raise TypeError("Explicit native transport and vault are required")
        self._config = config
        self._vault = _AttemptVault(vault)
        self._core = ManagedSignIn(config, transport=transport, vault=self._vault)
        self._redirect = urlsplit(config.redirect_uri)
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._expired = threading.Event()
        self._finished = threading.Event()
        self._terminal = False
        self._thread: threading.Thread | None = None
        self._result = AuthResult(AuthStatus.READY, "native_start_required")
        self._diagnostic: str | None = None
        self._listener_open = False
        self._operations = 0
        # The following fields are accessed only by the owned asyncio thread.
        self._server: asyncio.Server | None = None
        self._accepting = False
        self._handlers: set[asyncio.Task] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._callback_task: asyncio.Task | None = None
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._fatal: AuthResult | None = None
        self._launch_settled: asyncio.Event | None = None
        self._launch_succeeded = False

    def snapshot(self) -> SignInSnapshot:
        with self._lock:
            result = self._result
            # A cached success never outlives the material. No UI-thread vault
            # access and no claim that cached expiry confirms OS-record deletion.
            if (
                result.status == AuthStatus.IDENTITY_VERIFIED
                and result.expires_at is not None
                and time.time() >= result.expires_at
            ):
                result = AuthResult(AuthStatus.EXPIRED, "native_session_expired")
            return SignInSnapshot(
                result,
                self._listener_open,
                self._finished.is_set(),
                self._cancel.is_set(),
                self._operations > 0,
                not self._terminal and not self._finished.is_set(),
                self._diagnostic,
            )

    def start(self, *, expected_account: AccountIdentity | None = None) -> SignInSnapshot:
        if expected_account is not None and type(expected_account) is not AccountIdentity:
            raise TypeError("An exact native account binding is required")
        with self._lock:
            if self._thread is None and not self._finished.is_set():
                self._result = AuthResult(AuthStatus.READY, "native_starting")
                self._thread = threading.Thread(
                    target=self._thread_main,
                    args=(expected_account,),
                    name="native-signin-callback",
                    daemon=False,
                )
                self._thread.start()
            return self.snapshot()

    def cancel(self) -> SignInSnapshot:
        # An event records intent even while begin, an OS opener, or vault I/O
        # blocks. Do not present intent as confirmed cancellation or revocation.
        with self._lock:
            if not self._finished.is_set() and not self._terminal:
                self._cancel.set()
                if self._thread is None:
                    self._result = AuthResult(AuthStatus.CANCELLED, "cancelled_before_start")
                    self._terminal = True
                    self._finished.set()
            return self.snapshot()

    def shutdown(self) -> SignInSnapshot:
        """Request stop; the host must still await finished before disposing."""
        return self.cancel()

    def wait_finished(self, timeout: float | None = None) -> bool:
        """Worker/test join, never call on the native UI thread."""
        return self._finished.wait(timeout)

    def _set_result(self, result: AuthResult) -> None:
        with self._lock:
            self._result = result
            if result.status not in _ACTIVE | {AuthStatus.READY}:
                self._terminal = True

    async def _publish(self, result: AuthResult) -> None:
        # The same lock orders accepting a Cancel click and publishing success.
        # If cancellation won, core.cancel may already be too late because the
        # core committed before the background cancellation worker got its turn.
        # Retire precisely that unpublished commit once, then retire the core.
        with self._lock:
            if result.status != AuthStatus.IDENTITY_VERIFIED or not (
                self._cancel.is_set() or self._expired.is_set()
            ):
                self._set_result(self._observed(result))
                return
            self._result = AuthResult(AuthStatus.CANCELLING, "waiting_for_native_cleanup")
        try:
            await self._native(self._vault.discard_unpublished_commit)
            result = self._observed(AuthResult(AuthStatus.CANCELLED, "cancelled"))
        except BaseException:
            result = AuthResult(AuthStatus.RECOVERY_REQUIRED, "vault_cleanup_uncertain")
        self._set_result(result)

    async def _native(self, method, *args, **kwargs):
        # Fixed pool, no detached daemon, no cancellation of an exchange future.
        # kwargs stay in native memory; never log args/frames/futures.
        with self._lock:
            self._operations += 1
        try:
            assert self._executor is not None
            future = asyncio.get_running_loop().run_in_executor(
                self._executor, lambda: method(*args, **kwargs)
            )
            return await asyncio.shield(future)
        finally:
            with self._lock:
                self._operations -= 1

    def _thread_main(self, expected_account: AccountIdentity | None) -> None:
        # Non-daemon workers intentionally retain outstanding exchanges. An
        # unresponsive adapter must remain visible rather than look cleaned up.
        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=3, thread_name_prefix="native-signin-io"
            ) as self._executor:
                asyncio.run(self._run(expected_account))
        except BaseException:
            self._set_result(AuthResult(AuthStatus.RECOVERY_REQUIRED, "native_host_uncertain"))
        finally:
            with self._lock:
                self._listener_open = False
            self._finished.set()

    async def _run(self, expected_account: AccountIdentity | None) -> None:
        bound = None
        watcher = None
        lifetime = None
        self._launch_settled = asyncio.Event()
        try:
            family = socket.AF_INET6 if self._redirect.hostname == "::1" else socket.AF_INET
            try:
                bound = socket.socket(family, socket.SOCK_STREAM)
                if family == socket.AF_INET6:
                    bound.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                # No REUSEPORT/REUSEADDR, DNS resolution, wildcard or fallback.
                bound.bind((self._redirect.hostname, self._redirect.port))
                bound.listen(_MAX_CONNECTIONS)
                bound.setblocking(False)
                self._server = await asyncio.start_server(
                    self._handle, sock=bound, limit=_MAX_HEAD_BYTES + 1
                )
                bound = None  # Ownership transferred to asyncio.Server.
            except (OSError, ValueError):
                self._set_result(AuthResult(AuthStatus.ERROR, "callback_bind_failed"))
                return
            with self._lock:
                self._listener_open = True
            # Independent event-loop timer also bounds listening while begin,
            # native launch or core status/vault I/O is blocked. This is a
            # conservative total window starting at bind, not an extension of
            # the core's authorization deadline.
            lifetime = asyncio.create_task(self._expire_listener())
            if self._cancel.is_set():
                self._set_result(AuthResult(AuthStatus.CANCELLED, "cancelled_before_start"))
                return
            request = await self._native(self._core.begin, expected_account=expected_account)
            self._set_result(request.result)
            if request.authorization_url is None or request.result.status != AuthStatus.WAITING:
                return
            self._accepting = not self._expired.is_set()
            watcher = asyncio.create_task(self._watch())
            if self._cancel.is_set() or self._expired.is_set():
                await watcher
                return
            try:
                acknowledgement = await self._native(
                    _launch_macos_authorization,
                    request.authorization_url,
                    self._config.authorization_endpoint,
                )
                if acknowledgement is not None:
                    raise NativeBrowserError("native_external_browser_launch_uncertain")
                self._launch_succeeded = True
            except Exception:
                with self._lock:
                    self._diagnostic = "external_browser_launch_uncertain"
                self._cancel.set()
            finally:
                request = None
                self._launch_settled.set()
            await watcher
        finally:
            # Release a waiting callback only to reject it if startup failed.
            # Never strand its task behind a launch that will not take place.
            self._launch_settled.set()
            if lifetime is not None:
                lifetime.cancel()  # Only a timer, never native work.
                await asyncio.gather(lifetime, return_exceptions=True)
            if bound is not None:
                bound.close()
            self._close_listener()
            if self._server is not None:
                await self._server.wait_closed()
            # Closing sockets releases slow readers; it does not cancel any
            # core exchange or storage operation already accepted.
            for writer in tuple(self._writers):
                writer.close()
            if self._callback_task is not None:
                await asyncio.shield(self._callback_task)
            if watcher is not None and not watcher.done():
                self._cancel.set()
                await asyncio.shield(watcher)
            if self._handlers:
                await asyncio.gather(*tuple(self._handlers), return_exceptions=True)

    def _close_listener(self) -> None:
        self._accepting = False
        if self._server is not None:
            self._server.close()
        with self._lock:
            self._listener_open = False

    async def _expire_listener(self) -> None:
        await asyncio.sleep(self._config.authorization_ttl_seconds)
        with self._lock:
            if self._terminal:
                return
            self._expired.set()
        self._close_listener()

    def _observed(self, result: AuthResult) -> AuthResult:
        # The local callback window may conservatively expire before the core
        # deadline when startup I/O was slow. Cancellation is how we retire that
        # core safely; only a confirmed local cancellation is relabeled expiry.
        # An uncertain exchange/cleanup always remains recovery_required.
        if (
            self._expired.is_set()
            and not self._cancel.is_set()
            and result.status == AuthStatus.CANCELLED
            and result.reason == "cancelled"
        ):
            return AuthResult(AuthStatus.EXPIRED, "callback_listener_expired")
        return result

    async def _watch(self) -> None:
        cancellation_sent = False
        while True:
            if (self._cancel.is_set() or self._expired.is_set()) and not cancellation_sent:
                self._close_listener()
                result = await self._native(self._core.cancel)
                cancellation_sent = True
            else:
                result = await self._native(self._core.status)
            if result.status not in _ACTIVE and self._callback_task is not None:
                # core.status can observe a terminal transition before the
                # callback's native worker has returned. Do not publish that
                # outcome while an accepted worker could still fail. Retain
                # the task and honor cancellation in _publish after it settles.
                await asyncio.shield(self._callback_task)
            if self._fatal is not None:
                self._set_result(self._fatal)
                self._close_listener()
                return
            await self._publish(result)
            if result.status not in _ACTIVE:
                self._close_listener()
                return
            await asyncio.sleep(_POLL_SECONDS)

    async def _process_callback(self, callback_url: str) -> None:
        try:
            assert self._launch_settled is not None
            await self._launch_settled.wait()
            if not self._launch_succeeded or self._cancel.is_set() or self._expired.is_set():
                return
            # This pinned core alone validates state/issuer/query and consumes
            # state. Invalid responses keep its legitimate attempt waiting.
            await self._native(self._core.complete_callback, callback_url)
        except BaseException:
            self._fatal = AuthResult(AuthStatus.RECOVERY_REQUIRED, "callback_processing_uncertain")
            self._cancel.set()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        if len(self._handlers) >= _MAX_CONNECTIONS or not self._accepting:
            writer.close()
            return
        self._handlers.add(task)
        self._writers.add(writer)
        code = 400
        try:
            async with asyncio.timeout(_REQUEST_SECONDS):
                # Cap the complete wire head as well as h11's incomplete-event
                # buffer. No custom HTTP grammar, body buffering or access log.
                head = await reader.readuntil(b"\r\n\r\n")
                if len(head) > _MAX_HEAD_BYTES or b"\n" in head.replace(b"\r\n", b""):
                    raise ValueError
                if b"\r\n " in head or b"\r\n\t" in head:
                    raise ValueError  # Do not accept obsolete folded headers.
                parser = h11.Connection(h11.SERVER, max_incomplete_event_size=_MAX_HEAD_BYTES)
                parser.receive_data(head)
                request = parser.next_event()
                callback_url = self._validated_target(request)
                if not isinstance(parser.next_event(), h11.EndOfMessage):
                    raise ValueError
                if not self._accepting or self._cancel.is_set() or self._expired.is_set():
                    code = 409
                elif self._callback_task is not None and not self._callback_task.done():
                    code = 409  # No queue/retry while a single core call is active.
                else:
                    self._callback_task = asyncio.create_task(self._process_callback(callback_url))
                    code = 200
        except (Exception, asyncio.CancelledError):
            # No URL/query/header/native exception text ever enters the page,
            # an access log, or the event loop's unhandled-exception handler.
            pass
        finally:
            try:
                response = h11.Connection(h11.SERVER)
                payload = response.send(h11.Response(status_code=code, headers=_HEADERS))
                payload += response.send(h11.Data(data=_PAGE))
                payload += response.send(h11.EndOfMessage())
                writer.write(payload)
                async with asyncio.timeout(_REQUEST_SECONDS):
                    await writer.drain()
            except Exception:
                pass
            writer.close()
            try:
                async with asyncio.timeout(_REQUEST_SECONDS):
                    await writer.wait_closed()
            except Exception:
                pass
            self._writers.discard(writer)
            self._handlers.discard(task)

    def _validated_target(self, request: object) -> str:
        if not isinstance(request, h11.Request):
            raise ValueError
        if request.method != b"GET" or request.http_version != b"1.1":
            raise ValueError
        if len(request.headers) > _MAX_HEADERS:
            raise ValueError
        hosts = []
        for name, value in request.headers:
            if len(name) > 64 or len(value) > 2048:
                raise ValueError
            if any(char < 32 or char >= 127 for char in value):
                raise ValueError
            if name == b"host":
                hosts.append(value)
            if name in {
                b"content-length",
                b"transfer-encoding",
                b"expect",
                b"upgrade",
                b"authorization",
                b"proxy-authorization",
                b"forwarded",
                b"x-real-ip",
                b"origin",
            } or name.startswith(b"x-forwarded-"):
                raise ValueError
        if hosts != [self._redirect.netloc.encode("ascii")]:
            raise ValueError
        target = request.target
        if (
            not target.isascii()
            or any(char <= 32 or char >= 127 for char in target)
            or b"\\" in target
            or b"#" in target
            or target.split(b"?", 1)[0] != self._redirect.path.encode("ascii")
            or b"?" not in target
        ):
            raise ValueError
        # The authority is always trusted configuration, never observed Host or
        # forwarded headers. Path equality is checked before copying the query.
        callback_url = self._config.redirect_uri + "?" + target.split(b"?", 1)[1].decode("ascii")
        if len(callback_url) > 8192:
            raise ValueError
        return callback_url
