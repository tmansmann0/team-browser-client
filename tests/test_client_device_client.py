"""Ephemeral signed fixtures with fake native stores and fake sockets only.

No private API imports, network, native Keychain, persistent access or browsers.
"""

import copy
import io
import json
import ssl
import tempfile
import time
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import jwt

from team_browser.client import device_client as client
from team_browser.client import device_keys as keys
from team_browser.client import managed_session as managed
from team_browser.client import oidc_https as https
from team_browser.client import session_vault as vault
from team_browser.client.auth_flow import AccountIdentity, NativeSessionMaterial
from team_browser.contracts.device_proof import ProofContext, key_fingerprint, verify_device_proof
from team_browser.local.macos_keychain import KeychainConfiguration
from test_client_managed_session import (
    ACCESS,
    BACKEND,
    DIAGNOSTIC,
    FakeSocket,
    FakeStore,
    ID_TOKEN,
    KEYCHAIN,
    ME,
    OIDC,
    PUBLIC,
    SESSION,
    response,
)

SCOPE = keys.TrustedDeviceScope(BACKEND.origin, ME["org_id"], ME["id"])
DEVICE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REQUEST = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
CHALLENGE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
KEY_CONFIG = KeychainConfiguration("SYNTHETIC1", "invalid.example.TeamBrowser", keys.NAMESPACE)


class DeviceClientTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.wall, self.mono = float(int(time.time())), 1000.0
        clock = SimpleNamespace(time=lambda: self.wall, monotonic=lambda: self.mono)
        for module in (client, keys, managed, vault, https):
            self.stack.enter_context(patch.object(module, "time", clock))
        self.store, self.key_store = FakeStore(), FakeStore()
        self.stack.enter_context(patch.object(vault, "_open_native_store", return_value=self.store))
        self.stack.enter_context(
            patch.object(vault, "_lease_directory", return_value=self.root / "session")
        )
        self.stack.enter_context(
            patch.object(keys, "_open_native_store", return_value=self.key_store)
        )
        self.stack.enter_context(
            patch.object(keys, "_lease_directory", return_value=self.root / "device")
        )
        self.raw, self.wire = FakeSocket(), FakeSocket()
        self.tls = SimpleNamespace(
            verify_mode=ssl.CERT_REQUIRED,
            check_hostname=True,
            minimum_version=ssl.TLSVersion.TLSv1_2,
            keylog_filename=None,
            wrap_socket=Mock(return_value=self.wire),
        )
        self.stack.enter_context(patch.object(https, "_context", return_value=self.tls))
        self.stack.enter_context(patch.object(https, "_resolve", return_value=[PUBLIC]))
        self.stack.enter_context(patch.object(managed.socket, "socket", return_value=self.raw))
        for name in ("create_connection", "getaddrinfo"):
            self.stack.enter_context(
                patch.object(managed.socket, name, side_effect=AssertionError("Network forbidden"))
            )
        self.vault = vault.MacOSSessionVault(KEYCHAIN, oidc_configuration=OIDC)
        self.stack.callback(self.vault.close)
        self.vault.recover_discard_all()
        self.vault.store_session(
            SESSION,
            NativeSessionMaterial(
                AccountIdentity(OIDC.issuer, "pairwise-native-subject"),
                ACCESS,
                ID_TOKEN,
                int(self.wall) + 300,
                OIDC.scopes,
            ),
        )
        self.session = managed.NativeManagedSession(BACKEND, vault=self.vault)
        self.owner = keys.MacOSDeviceKeys(KEY_CONFIG, SCOPE)
        self.stack.callback(self.owner.close)
        self.client = client.NativeDeviceClient(self.session, self.owner, SCOPE)
        self.client.restore()
        self.record = None
        self.public_key = None
        self.requests = []
        self.proofs = []
        self.me = copy.deepcopy(ME)
        self.inventory_extra = []
        self.rewrite = None
        self.wire.on_send = self.server

    def approval(self, action=client.EnrollmentAction.REQUEST, **changes):
        binding = self.record_binding() if action is client.EnrollmentAction.ACTIVATE else None
        return replace(
            client.NativeEnrollmentApproval(
                action,
                SCOPE,
                "Synthetic Mac",
                True,
                str(uuid4()),
                self.wall,
                self.mono,
                self.wall + 120,
                binding,
            ),
            **changes,
        )

    def record_binding(self):
        return client._record(self.record).binding()

    def server(self):
        wire = self.wire.sent[-1]
        head, body = wire.split(b"\r\n\r\n", 1)
        lines = head.decode("ascii").split("\r\n")
        method, path, _ = lines[0].split()
        headers = dict(line.split(": ", 1) for line in lines[1:])
        self.assertEqual(headers["Authorization"], f"Bearer {ACCESS}")
        if path != "/v1/me":
            self.assertEqual(headers["X-TBM-Organization"], SCOPE.organization_id)
        self.requests.append((method, path, body))
        status = 200
        if path == "/v1/me":
            result = copy.deepcopy(self.me)
        elif path == "/v1/device-enrollments" and method == "GET":
            result = ([copy.deepcopy(self.record)] if self.record else []) + copy.deepcopy(
                self.inventory_extra
            )
        elif path == "/v1/device-enrollments" and method == "POST":
            sent = json.loads(body)
            self.public_key = sent["public_key"]
            self.record = {
                "device_id": DEVICE,
                "user_id": SCOPE.member_id,
                "request_id": REQUEST,
                "registration_generation": 1,
                "name": sent["name"],
                "platform": "macos",
                "key_fingerprint": key_fingerprint(self.public_key),
                "status": "pending",
                "requested_at": int(self.wall),
                "request_expires_at": int(self.wall) + 86400,
                "approved_by": None,
                "approval_expires_at": None,
                "enabled": False,
            }
            result, status = copy.deepcopy(self.record), 201
        elif path.endswith("/challenge"):
            result = {
                "challenge_id": CHALLENGE,
                "nonce": "A" * 43,
                "expires_at": int(self.wall) + 120,
                "request_id": REQUEST,
                "registration_generation": self.record["registration_generation"],
            }
        elif path.endswith("/complete") or path.endswith("/heartbeat"):
            sent = json.loads(body)
            enrollment = path.endswith("/complete")
            proof = headers["Device-Proof"]
            context = ProofContext(
                SCOPE.origin,
                SCOPE.organization_id,
                SCOPE.member_id,
                DEVICE,
                self.record["registration_generation"],
                "POST",
                path,
                body,
                "enrollment" if enrollment else "request",
                sent["nonce"] if enrollment else None,
            )
            verify_device_proof(proof, self.public_key, context, int(self.wall))
            self.proofs.append(jwt.decode(proof, options={"verify_signature": False}))
            if enrollment:
                self.record.update(status="active", enabled=True)
                result = copy.deepcopy(self.record)
            else:
                self.assertEqual(sent["profiles"], [])
                result = {
                    "id": DEVICE,
                    "user_id": SCOPE.member_id,
                    "name": self.record["name"],
                    "platform": "macos",
                    "enabled": True,
                    "registration_generation": self.record["registration_generation"],
                    "agent_version": sent["agent_version"],
                    "last_seen_at": datetime.fromtimestamp(self.wall, timezone.utc).isoformat(),
                    "connectivity": "online",
                    "synthetic_fixture": False,
                    "secure_enrollment_available": True,
                }
        else:
            raise AssertionError("Unexpected route")
        self.wire.data = response(result, status=status)
        if self.rewrite:
            self.wire.data = self.rewrite(path, result, status)

    def request(self):
        return self.client.request_enrollment("Synthetic Mac", self.approval())

    def approve(self):
        self.record.update(
            status="approved", approved_by="owner", approval_expires_at=int(self.wall) + 600
        )

    def active(self):
        self.request()
        self.approve()
        return self.client.activate(self.approval(client.EnrollmentAction.ACTIVATE))

    def reconnect(self):
        self.session = managed.NativeManagedSession(BACKEND, vault=self.vault)
        self.client = client.NativeDeviceClient(self.session, self.owner, SCOPE)
        self.client.restore()

    def test_request_poll_activate_heartbeat_exact_product_member_proof(self):
        pending = self.request()
        self.assertEqual(pending.state, "pending")
        self.assertFalse(pending.public()["device_enrolled"])
        self.assertEqual(self.owner.status().state, "pending")
        self.assertEqual(self.client.poll_enrollment().state, "pending")
        self.approve()
        self.assertEqual(self.client.poll_enrollment().state, "approved")
        active = self.client.activate(self.approval(client.EnrollmentAction.ACTIVATE))
        self.assertTrue(active.public()["device_enrolled"])
        self.assertFalse(active.public()["managed_browser_enabled"])
        self.assertFalse(active.public()["remote_execution_enabled"])
        self.assertEqual(self.owner.status().state, "active")
        beat = self.client.heartbeat("synthetic-0.2")
        self.assertEqual(beat.heartbeat.connectivity, "online")
        self.assertEqual([p["purpose"] for p in self.proofs], ["enrollment", "request"])
        self.assertTrue(all(p["sub"] == SCOPE.member_id and p["ver"] == 2 for p in self.proofs))
        self.assertNotEqual(self.proofs[0]["jti"], self.proofs[1]["jti"])
        self.assertTrue(all(path.startswith("/v1/") for _, path, _ in self.requests))

    def test_initial_approval_must_be_explicit_exact_fresh_and_scoped(self):
        approval = self.approval()
        invalid = [
            None,
            {},
            replace(approval, approved=False),
            replace(approval, device_name="Other"),
            replace(approval, scope=replace(SCOPE, member_id="other")),
            replace(
                approval,
                observed_at=self.wall - 200,
                observed_monotonic=self.mono - 200,
                expires_at=self.wall - 1,
            ),
        ]
        for value in invalid:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(client.DeviceClientError):
                    self.client.request_enrollment("Synthetic Mac", value)
        self.assertFalse(self.requests)
        self.assertEqual(self.owner.status().state, "empty")

    def test_no_automatic_restore_generation_io_or_activation(self):
        before = dict(self.key_store.items)
        fresh = client.NativeDeviceClient(self.session, self.owner, SCOPE)
        self.assertEqual(before, self.key_store.items)
        with self.assertRaises(client.DeviceClientError):
            fresh.request_enrollment("Synthetic Mac", self.approval())
        self.assertFalse(self.requests)
        self.request()
        self.approve()
        before = len(self.requests)
        with self.assertRaises(client.DeviceClientError):
            self.client.activate(None)
        self.assertEqual(before, len(self.requests))
        self.assertEqual(self.record["status"], "approved")

    def test_auditor_or_changed_membership_cannot_generate(self):
        self.me["role"] = "auditor"
        with self.assertRaises(client.DeviceClientError):
            self.request()
        self.assertEqual(self.owner.status().state, "empty")
        self.assertEqual([path for _, path, _ in self.requests], ["/v1/me"])

    def test_changed_company_cannot_generate(self):
        self.me["org_id"] = "other"
        with self.assertRaises(client.DeviceClientError):
            self.request()
        self.assertEqual(self.owner.status().state, "empty")

    def test_uncertain_request_never_automatically_resubmits(self):
        self.rewrite = lambda path, result, status: (
            response(result, status=status, extra=b"Content-Length: 1\r\n")
            if status == 201
            else response(result)
        )
        with self.assertRaisesRegex(client.DeviceClientError, "request_outcome_uncertain"):
            self.request()
        self.assertIsNotNone(self.record)
        self.assertEqual(self.client.snapshot().state, "uncertain")
        before = len(self.requests)
        with self.assertRaisesRegex(client.DeviceClientError, "existing_key"):
            self.request()
        self.assertEqual(before, len(self.requests))
        self.rewrite = None
        self.reconnect()
        with self.assertRaisesRegex(client.DeviceClientError, "unverified"):
            self.client.poll_enrollment()
        self.assertEqual(
            sum(
                method == "POST" and path == "/v1/device-enrollments"
                for method, path, _ in self.requests
            ),
            1,
        )

    def test_lost_completion_is_reconciled_without_second_completion(self):
        self.request()
        self.approve()
        self.rewrite = lambda path, result, status: (
            response(result, body=b"{")
            if path.endswith("/complete")
            else response(result, status=status)
        )
        with self.assertRaisesRegex(client.DeviceClientError, "activation_outcome_uncertain"):
            self.client.activate(self.approval(client.EnrollmentAction.ACTIVATE))
        self.assertEqual(self.record["status"], "active")
        self.assertEqual(self.owner.status().state, "pending")
        self.rewrite = None
        self.reconnect()
        self.assertEqual(self.client.poll_enrollment().state, "active")
        self.assertEqual(self.owner.status().state, "pending")
        with self.assertRaises(client.DeviceClientError):
            self.client.heartbeat("synthetic")
        self.assertEqual(
            self.client.activate(self.approval(client.EnrollmentAction.ACTIVATE)).state, "active"
        )
        self.assertEqual(sum(path.endswith("/complete") for _, path, _ in self.requests), 1)

    def test_approval_must_bind_current_request_fingerprint_and_generation(self):
        self.request()
        self.approve()
        approval = self.approval(client.EnrollmentAction.ACTIVATE)
        changed = replace(approval, binding=replace(approval.binding, registration_generation=2))
        with self.assertRaises(client.DeviceClientError):
            self.client.activate(changed)
        self.assertFalse(any(path.endswith("/challenge") for _, path, _ in self.requests))

    def test_duplicate_fingerprint_current_member_is_ambiguous(self):
        self.request()
        other = {**self.record, "device_id": "other", "request_id": str(uuid4())}
        self.inventory_extra = [other]
        with self.assertRaises(client.DeviceClientError):
            self.client.poll_enrollment()
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])

    def test_other_member_records_do_not_supply_self_evidence(self):
        self.request()
        self.record["user_id"] = "other"
        with self.assertRaises(client.DeviceClientError):
            self.client.poll_enrollment()

    def test_same_fingerprint_different_durable_generation_rejected(self):
        self.active()
        self.record["registration_generation"] += 1
        before = len(self.proofs)
        with self.assertRaises(client.DeviceClientError):
            self.client.heartbeat("synthetic")
        self.assertEqual(before, len(self.proofs))

    def test_revocation_prevents_agent_signing(self):
        self.active()
        self.record.update(status="revoked", enabled=False, registration_generation=2)
        before = len(self.proofs)
        with self.assertRaises(client.DeviceClientError):
            self.client.heartbeat("synthetic")
        self.assertEqual(before, len(self.proofs))
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])
        self.assertEqual(self.owner.status().state, "active")

    def test_expired_approval_does_not_challenge(self):
        self.request()
        self.approve()
        self.wall += 601
        self.mono += 601
        # The foreground token is also expired; neither permits activation.
        with self.assertRaises(client.DeviceClientError):
            self.client.activate(self.approval(client.EnrollmentAction.ACTIVATE))
        self.assertFalse(any(path.endswith("/challenge") for _, path, _ in self.requests))

    def test_snapshot_expires_without_background_network(self):
        snapshot = self.active()
        count = len(self.requests)
        self.wall += 31
        self.mono += 31
        self.assertFalse(snapshot.public()["device_enrolled"])
        self.assertEqual(count, len(self.requests))

    def test_evidence_expiry_during_handshake_emits_no_device_request(self):
        def slow():
            if self.session._member_binding is not None:
                self.wall += 31
                self.mono += 31

        self.wire.on_handshake = slow
        with self.assertRaises(client.DeviceClientError):
            self.request()
        self.assertEqual([path for _, path, _ in self.requests], ["/v1/me"])

    def test_approval_expiry_is_also_a_pre_send_fence(self):
        approval = self.approval(expires_at=self.wall + 1)

        def slow():
            if self.session._member_binding is not None:
                self.wall += 2
                self.mono += 2

        self.wire.on_handshake = slow
        with self.assertRaises(client.DeviceClientError):
            self.client.request_enrollment("Synthetic Mac", approval)
        self.assertEqual([path for _, path, _ in self.requests], ["/v1/me"])

    def test_activation_approval_expiry_prevents_challenge_emission(self):
        self.request()
        self.approve()
        approval = self.approval(client.EnrollmentAction.ACTIVATE, expires_at=self.wall + 1)
        handshakes = 0

        def slow():
            nonlocal handshakes
            handshakes += 1
            if handshakes == 3:  # Membership, inventory, then the challenge socket.
                self.wall += 2
                self.mono += 2

        self.wire.on_handshake = slow
        with self.assertRaises(client.DeviceClientError):
            self.client.activate(approval)
        self.assertFalse(any(path.endswith("/challenge") for _, path, _ in self.requests))

    def test_uncertain_native_generation_is_not_presented_as_clean_failure(self):
        self.key_store.put = Mock(side_effect=RuntimeError(DIAGNOSTIC))
        with self.assertRaisesRegex(client.DeviceClientError, "request_outcome_uncertain"):
            self.request()
        self.assertEqual(self.client.snapshot().state, "uncertain")
        self.assertEqual(self.owner.status().state, "recovery_required")

    def test_pending_server_does_not_consume_activation_decision(self):
        self.request()
        decision = self.approval(client.EnrollmentAction.ACTIVATE)
        with self.assertRaises(client.DeviceClientError):
            self.client.activate(decision)
        self.assertNotIn(decision.decision_id, self.client._used_approvals)
        self.assertEqual(self.record["status"], "pending")

    def test_native_session_expiry_during_handshake_sends_no_bearer(self):
        self.wire.on_handshake = lambda: setattr(self, "wall", self.wall + 301)
        with self.assertRaises(client.DeviceClientError):
            self.request()
        self.assertFalse(self.requests)

    def test_credential_reflection_rejected_in_successful_record(self):
        self.rewrite = lambda path, result, status: (
            response({**result, "name": ACCESS}, status=status)
            if status == 201
            else response(result)
        )
        with self.assertRaises(client.DeviceClientError):
            self.request()
        self.assertNotIn(ACCESS, json.dumps(self.client.snapshot().public()))

    def test_credential_reflection_in_other_inventory_row_rejected(self):
        self.request()
        self.inventory_extra = [
            {
                **self.record,
                "device_id": "other",
                "request_id": str(uuid4()),
                "user_id": "other",
                "name": ID_TOKEN,
            }
        ]
        with self.assertRaises(client.DeviceClientError):
            self.client.poll_enrollment()
        self.assertNotIn(ID_TOKEN, json.dumps(self.client.snapshot().public()))

    def test_duplicate_json_unknown_fields_wrong_types_and_redirect_rejected(self):
        self.request()
        values = [
            response([self.record], body=b'[{"device_id":"a","device_id":"b"}]'),
            response([{**self.record, "secret": "unexpected"}]),
            response([{**self.record, "registration_generation": True}]),
            response([{**self.record, "enabled": 0}]),
            response([self.record], status=302),
            response([self.record], extra=b"Content-Encoding: gzip\r\n"),
            response([self.record], body=b"[" * 20 + b"]" * 20),
        ]
        for value in values:
            with self.subTest(case=values.index(value)):
                self.reconnect()
                self.rewrite = lambda path, result, status: (
                    value if path == "/v1/device-enrollments" else response(result)
                )
                with self.assertRaises(client.DeviceClientError):
                    self.client.poll_enrollment()
                self.assertFalse(self.client.snapshot().public()["device_enrolled"])

    def test_challenge_scope_mismatch_prevents_completion(self):
        self.request()
        self.approve()
        self.rewrite = lambda path, result, status: (
            response({**result, "request_id": str(uuid4())})
            if path.endswith("/challenge")
            else response(result, status=status)
        )
        with self.assertRaises(client.DeviceClientError):
            self.client.activate(self.approval(client.EnrollmentAction.ACTIVATE))
        self.assertFalse(any(path.endswith("/complete") for _, path, _ in self.requests))
        self.assertEqual(self.owner.status().state, "pending")

    def test_no_errors_reprs_or_public_state_disclose_proof_nonce_tokens(self):
        stream = io.StringIO()
        with redirect_stdout(stream), redirect_stderr(stream):
            snapshot = self.active()
            self.client.heartbeat("synthetic")
        text = (
            stream.getvalue()
            + repr(self.client)
            + repr(self.approval())
            + json.dumps(snapshot.public())
        )
        for secret in (ACCESS, ID_TOKEN, DIAGNOSTIC, "A" * 43):
            self.assertNotIn(secret, text)
        for raw in self.key_store.items.values():
            if b'"private_key"' in raw:
                self.assertNotIn(json.loads(raw)["private_key"], text)
        files = [path for path in self.root.rglob("*") if path.is_file()]
        self.assertTrue(all(path.stat().st_size == 0 for path in files))

    def test_exact_native_types_and_scope_only(self):
        with self.assertRaises(TypeError):
            client.NativeDeviceClient(Mock(), self.owner, SCOPE)
        with self.assertRaises(client.DeviceClientError):
            client.NativeDeviceClient(self.session, self.owner, replace(SCOPE, member_id="other"))
        with self.assertRaises(TypeError):
            self.session._device_exchange({"path": "https://evil.test"})
        for name in (
            "access_token",
            "raw_key",
            "sign",
            "approve",
            "revoke",
            "poll_commands",
            "acknowledge",
        ):
            self.assertFalse(hasattr(self.client, name))

    def test_wire_request_is_bounded_exact_and_no_generic_network_input(self):
        params = (client._DeviceOperation.INVENTORY, b"", self.wall, self.mono, self.wall + 30)
        request = client._DeviceWireRequest(*params)
        self.assertEqual(request.path, "/v1/device-enrollments")
        self.assertEqual(request.method, "GET")
        for changes in (
            {"operation": "inventory"},
            {"device_id": "x"},
            {"body": b"{}"},
            {"expires_at": self.wall + 31},
        ):
            with self.assertRaises(managed.ManagedSessionError):
                replace(request, **changes)

    def test_reused_approval_does_not_generate_again(self):
        decision = self.approval()
        self.client.request_enrollment("Synthetic Mac", decision)
        count = len(self.requests)
        with self.assertRaises(client.DeviceClientError):
            self.client.request_enrollment("Synthetic Mac", decision)
        self.assertEqual(count, len(self.requests))


if __name__ == "__main__":
    unittest.main()
