"""Independent native HTTPS regressions; synthetic byte streams only, no network."""

import io
import ipaddress
import ssl
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from team_browser.client import oidc_https as https


class SyntheticStream:
    def __init__(self, parts, eof_error=None):
        self.parts = list(parts)
        self.eof_error = eof_error
        self.timeouts = []
        self.reads = 0

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, maximum):
        self.reads += 1
        if not self.parts:
            if self.eof_error:
                raise self.eof_error
            return b""
        value = self.parts.pop(0)
        if len(value) > maximum:
            value, remainder = value[:maximum], value[maximum:]
            self.parts.insert(0, remainder)
        return value


BODY = b'{"keys":[]}'
HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
LENGTH = HEAD + b"Content-Length: 11\r\n\r\n" + BODY
CHUNKED = HEAD + b"Transfer-Encoding: chunked\r\n\r\nb\r\n" + BODY + b"\r\n0\r\n\r\n"


class IndependentHTTPFramingTests(unittest.TestCase):
    def parse(self, parts, **kwargs):
        stream = SyntheticStream(parts, **kwargs)
        with patch.object(https.time, "monotonic", return_value=100):
            return https._Reader(stream, 110).response("https://keys.example.test/jwks")

    def test_valid_framing_is_independent_of_packet_boundaries(self):
        for wire in (LENGTH, CHUNKED):
            for parts in ([wire], [bytes([byte]) for byte in wire]):
                with self.subTest(wire=wire[:75], fragments=len(parts)):
                    self.assertEqual(self.parse(parts).body, BODY)

    def test_content_length_trailing_bytes_rejected_across_packet_boundaries(self):
        for parts in ([LENGTH + b"TRAILING"], [LENGTH, b"TRAILING"]):
            with self.subTest(fragments=len(parts)), self.assertRaises(https.OIDCTransportError):
                self.parse(parts)

    def test_chunked_trailing_bytes_rejected_across_packet_boundaries(self):
        for parts in ([CHUNKED + b"TRAILING"], [CHUNKED, b"TRAILING"]):
            with self.subTest(fragments=len(parts)), self.assertRaises(https.OIDCTransportError):
                self.parse(parts)

    def test_eof_delimited_body_rejects_unclean_tls_shutdown(self):
        with self.assertRaises(ssl.SSLEOFError):
            self.parse([HEAD + b"\r\n" + BODY], eof_error=ssl.SSLEOFError("SYNTHETIC"))

    def test_declared_framing_also_requires_clean_tls_shutdown(self):
        # Deliberately stricter than normal HTTP framing: this adapter requires
        # peer close_notify, even after a complete Content-Length/chunked body.
        for wire in (LENGTH, CHUNKED):
            with self.subTest(wire=wire[:75]), self.assertRaises(ssl.SSLEOFError):
                self.parse([wire], eof_error=ssl.SSLEOFError("SYNTHETIC"))

    def test_clean_shutdown_wait_cannot_reset_total_deadline(self):
        for wire in (LENGTH, CHUNKED):
            stream = SyntheticStream([wire])
            now = [100.0]
            original_recv = stream.recv

            def recv(maximum):
                if not stream.parts:
                    now[0] = 111.0
                return original_recv(maximum)

            stream.recv = recv
            with (
                self.subTest(wire=wire[:75]),
                patch.object(https.time, "monotonic", side_effect=lambda: now[0]),
                self.assertRaisesRegex(https.OIDCTransportError, "deadline"),
            ):
                https._Reader(stream, 110).response("https://keys.example.test/jwks")
            self.assertEqual(stream.timeouts, [10.0, 10.0])

    def test_incomplete_headers_and_body_fail_closed_at_every_cut(self):
        for wire in (LENGTH, CHUNKED):
            for length in range(len(wire)):
                with self.subTest(wire=wire[:75], length=length):
                    with self.assertRaises(https.OIDCTransportError):
                        self.parse([wire[:length]])

    def test_framing_ambiguity_cannot_hide_in_header_case_or_ows(self):
        cases = (
            b"Content-Length: 11\r\ncOnTeNt-LeNgTh:\t11\r\n",
            b"Content-Length: 11\r\nTransfer-Encoding:\tchunked\r\n",
            b"Transfer-Encoding: chunked\r\nTRANSFER-ENCODING: chunked\r\n",
            b"Content-Length : 11\r\n",
            b"Content-Length:\v11\r\n",
        )
        for headers in cases:
            with self.subTest(headers=headers), self.assertRaises(https.OIDCTransportError):
                self.parse([HEAD + headers + b"\r\n" + BODY])


class IndependentResolverBoundaryTests(unittest.TestCase):
    def test_special_address_ranges_reject_both_endpoints(self):
        # Independent policy table: never resolve these names or open sockets.
        for network in (
            "100.64.0.0/10",
            "192.0.0.0/24",
            "192.88.99.0/24",
            "198.18.0.0/15",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "2001::/23",
            "2002::/16",
            "3fff::/20",
        ):
            block = ipaddress.ip_network(network)
            for address in (block.network_address, block.broadcast_address):
                with self.subTest(address=address), self.assertRaises(https.OIDCTransportError):
                    https._addresses([str(address)])

    def test_one_nonpublic_answer_rejects_every_ordering(self):
        for addresses in (
            ["93.184.216.34", "169.254.169.254"],
            ["169.254.169.254", "93.184.216.34"],
            ["2606:4700:4700::1111", "::ffff:169.254.169.254"],
        ):
            with self.subTest(addresses=addresses), self.assertRaises(https.OIDCTransportError):
                https._addresses(addresses)

    def test_fixed_helper_rejects_malformed_native_rows_without_output(self):
        for rows in (
            [],
            [(2, 1, 6, "", ("93.184.216.34", 443))] * 33,
            [(2, 1, 6, "", ("93.184.216.34", 80))],
            [(10, 1, 6, "", ("2606:4700:4700::1111", 443, 0, 7))],
            [(2, 1, 17, "", ("93.184.216.34", 443))],
            [(2, 1, 6, "", ("x" * 4097, 443))],
        ):
            socket_module = SimpleNamespace(
                AF_UNSPEC=0,
                AF_INET=2,
                AF_INET6=10,
                SOCK_STREAM=1,
                IPPROTO_TCP=6,
                getaddrinfo=Mock(return_value=rows),
            )
            system = SimpleNamespace(
                stdin=SimpleNamespace(buffer=io.BytesIO(b"keys.example.test")),
                stdout=SimpleNamespace(buffer=io.BytesIO()),
                exit=Mock(side_effect=SystemExit),
            )
            with (
                self.subTest(rows=rows[:1]),
                patch.dict("sys.modules", {"socket": socket_module, "sys": system}),
                self.assertRaises(SystemExit),
            ):
                exec(https._DNS_PROGRAM, {})
            self.assertEqual(system.stdout.buffer.getvalue(), b"")
            system.exit.assert_called_once_with(1)
            socket_module.getaddrinfo.assert_called_once()

    def test_completed_child_with_uncertain_pipe_cleanup_quarantines_slot(self):
        slot = threading.Lock()
        child = SimpleNamespace(
            returncode=0,
            stdin=SimpleNamespace(close=Mock(side_effect=OSError("SYNTHETIC"))),
            stdout=io.BytesIO(),
            poll=Mock(return_value=0),
            communicate=Mock(return_value=(b'["93.184.216.34"]', None)),
        )
        with (
            patch.object(https, "_supported_interpreter"),
            patch.object(https, "_DNS_SLOT", slot),
            patch.object(https, "_STRANDED_RESOLVER", None),
            patch.object(https.time, "monotonic", return_value=100),
            patch.object(https.subprocess, "Popen", return_value=child) as spawn,
        ):
            with self.assertRaisesRegex(https.OIDCTransportError, "cleanup is uncertain"):
                https._resolve("keys.example.test", 110)
            self.assertIs(https._STRANDED_RESOLVER, child)
            self.assertTrue(slot.locked())
            with self.assertRaisesRegex(https.OIDCTransportError, "unavailable"):
                https._resolve("identity.example.test", 110)
            spawn.assert_called_once()
        child.stdout.close()


if __name__ == "__main__":
    unittest.main()
