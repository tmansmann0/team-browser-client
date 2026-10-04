"""Independent public-native client regressions; synthetic keys/stores/sockets only."""

import copy
import json
import unittest
from dataclasses import replace
from unittest.mock import patch
from uuid import uuid4

import test_client_device_client as fixture
from team_browser.client import device_client as native
from team_browser.client import managed_session as managed
from team_browser.client import session_vault as vault
from team_browser.client.managed_session import MemberRole


class IndependentDeviceClientTests(unittest.TestCase):
    # Share only synthetic setup/transport primitives, not builder test methods.
    setUp = fixture.DeviceClientTests.setUp
    approval = fixture.DeviceClientTests.approval
    record_binding = fixture.DeviceClientTests.record_binding
    server = fixture.DeviceClientTests.server
    request = fixture.DeviceClientTests.request
    approve = fixture.DeviceClientTests.approve
    active = fixture.DeviceClientTests.active
    reconnect = fixture.DeviceClientTests.reconnect

    def test_device_send_rechecks_managed_lease_after_final_socket_configuration(self):
        original = self.wire.settimeout
        device_timeouts = 0

        def lose_lease(timeout):
            nonlocal device_timeouts
            if self.session._member_binding is not None:
                device_timeouts += 1
                if device_timeouts == 2:
                    self.vault._lease.close()
            return original(timeout)

        with patch.object(self.wire, "settimeout", side_effect=lose_lease):
            with self.assertRaises(native.DeviceClientError):
                self.request()
        self.assertEqual([path for _, path, _ in self.requests], ["/v1/me"])
        self.assertEqual(self.session.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])

    def test_device_send_rechecks_decision_deadline_after_final_socket_configuration(self):
        decision = self.approval(expires_at=self.wall + 1)
        original = self.wire.settimeout
        device_timeouts = 0

        def expire(timeout):
            nonlocal device_timeouts
            if self.session._member_binding is not None:
                device_timeouts += 1
                if device_timeouts == 2:
                    self.wall += 1
                    self.mono += 1
            return original(timeout)

        with patch.object(self.wire, "settimeout", side_effect=expire):
            with self.assertRaises(native.DeviceClientError):
                self.client.request_enrollment("Synthetic Mac", decision)
        self.assertEqual([path for _, path, _ in self.requests], ["/v1/me"])
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])

    def test_known_role_downgrade_between_membership_and_send_prevents_mutation(self):
        downgraded = False

        def refresh_role(verb, reference):
            nonlocal downgraded
            if verb == "put" and not downgraded:
                downgraded = True
                self.me["role"] = "auditor"
                self.assertEqual(self.session.me().role, MemberRole.AUDITOR)

        self.key_store.hook = refresh_role
        with self.assertRaises(native.DeviceClientError):
            self.request()
        self.assertTrue(downgraded)
        self.assertFalse(any(method == "POST" for method, _, _ in self.requests))
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])

    def test_role_downgrade_at_final_socket_step_prevents_device_bearer_send(self):
        original = self.wire.settimeout
        timeouts = 0
        downgraded = False

        def refresh_at_last_step(timeout):
            nonlocal timeouts, downgraded
            if self.session._member_binding is not None and not downgraded:
                timeouts += 1
                if timeouts == 2:
                    downgraded = True
                    self.me["role"] = "auditor"
                    self.assertEqual(self.session.me().role, MemberRole.AUDITOR)
            return original(timeout)

        with patch.object(self.wire, "settimeout", side_effect=refresh_at_last_step):
            with self.assertRaises(native.DeviceClientError):
                self.request()
        self.assertTrue(downgraded)
        self.assertFalse(any(method == "POST" for method, _, _ in self.requests))
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])

    def test_noncanonical_device_label_rejected_before_key_generation_or_request(self):
        for name in (" Synthetic Mac", "Synthetic Mac ", "\u00a0Synthetic Mac\u00a0", "   "):
            with self.subTest(name=repr(name)):
                before = copy.deepcopy(self.key_store.items)
                try:
                    decision = self.approval(device_name=name)
                except (native.DeviceClientError, managed.ManagedSessionError):
                    continue
                with self.assertRaises((native.DeviceClientError, managed.ManagedSessionError)):
                    self.client.request_enrollment(name, decision)
                self.assertEqual(self.key_store.items, before)
                self.assertFalse(self.requests)

    def test_changed_company_during_local_key_generation_never_emits_post(self):
        changed = False

        def switch(verb, reference):
            nonlocal changed
            if verb == "put" and not changed:
                changed = True
                self.me["org_id"] = "other-company"
                with self.assertRaises(managed.ManagedSessionError):
                    self.session.me()

        self.key_store.hook = switch
        with self.assertRaises(native.DeviceClientError):
            self.request()
        self.assertFalse(any(method == "POST" for method, _, _ in self.requests))

    def test_mutating_socket_ack_uncertainty_does_not_resubmit(self):
        old_server = self.wire.on_send

        def ambiguous():
            old_server()
            if self.requests[-1][:2] == ("POST", "/v1/device-enrollments"):
                self.wire.ack["sendall"] = False

        self.wire.on_send = ambiguous
        with self.assertRaises(native.DeviceClientError):
            self.request()
        self.assertIsNotNone(self.record)
        before = len(self.requests)
        with self.assertRaises(native.DeviceClientError):
            self.request()
        self.assertEqual(before, len(self.requests))
        self.assertEqual(self.client.snapshot().state, "uncertain")

    def test_completion_response_binding_mutation_cannot_mark_local_active(self):
        self.request()
        self.approve()
        self.rewrite = lambda path, result, status: fixture.response(
            {**result, "request_id": str(uuid4())} if path.endswith("/complete") else result,
            status=status,
        )
        with self.assertRaises(native.DeviceClientError):
            self.client.activate(self.approval(native.EnrollmentAction.ACTIVATE))
        self.assertEqual(self.record["status"], "active")
        self.assertEqual(self.owner.status().state, "pending")
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])

    def test_challenge_expiry_beyond_server_approval_cannot_emit_completion(self):
        self.request()
        self.approve()
        self.record["approval_expires_at"] = int(self.wall) + 600
        # Move the clocks near approval expiry while retaining a fresh foreground session.
        self.record["requested_at"] -= 590
        self.record["request_expires_at"] -= 590
        self.record["approval_expires_at"] -= 590
        with self.assertRaises(native.DeviceClientError):
            self.client.activate(self.approval(native.EnrollmentAction.ACTIVATE))
        self.assertTrue(any(path.endswith("/challenge") for _, path, _ in self.requests))
        self.assertFalse(any(path.endswith("/complete") for _, path, _ in self.requests))
        self.assertEqual(self.owner.status().state, "pending")

    def test_all_inventory_rows_are_checked_before_selecting_own_binding(self):
        self.request()
        self.inventory_extra = [
            {
                **self.record,
                "device_id": "another",
                "request_id": str(uuid4()),
                "user_id": "another-member",
                "enabled": True,
            }
        ]
        with self.assertRaises(native.DeviceClientError):
            self.client.poll_enrollment()
        self.assertFalse(self.client.snapshot().public()["observation_current"])

    def test_challenge_credential_reflection_never_reaches_signer(self):
        self.request()
        self.approve()
        # A syntactically valid nonce containing the synthetic bearer is still forbidden.
        reflected = fixture.ACCESS + "A" * (43 - len(fixture.ACCESS))
        self.rewrite = lambda path, result, status: fixture.response(
            {**result, "nonce": reflected} if path.endswith("/challenge") else result, status=status
        )
        with self.assertRaises(native.DeviceClientError):
            self.client.activate(self.approval(native.EnrollmentAction.ACTIVATE))
        self.assertFalse(any(path.endswith("/complete") for _, path, _ in self.requests))
        self.assertNotIn(fixture.ACCESS, json.dumps(self.client.snapshot().public()))

    def test_lost_completion_reconciliation_still_requires_unused_exact_decision(self):
        self.request()
        self.approve()
        decision = self.approval(native.EnrollmentAction.ACTIVATE)
        self.rewrite = lambda path, result, status: fixture.response(
            result, status=status, body=b"{" if path.endswith("/complete") else None
        )
        with self.assertRaises(native.DeviceClientError):
            self.client.activate(decision)
        self.rewrite = None
        with self.assertRaises(native.DeviceClientError):
            self.client.activate(decision)
        self.reconnect()
        self.client.poll_enrollment()
        self.assertEqual(self.owner.status().state, "pending")
        with self.assertRaises(native.DeviceClientError):
            self.client.activate(
                replace(self.approval(native.EnrollmentAction.ACTIVATE), approved=False)
            )
        self.assertEqual(self.owner.status().state, "pending")
        self.client.activate(self.approval(native.EnrollmentAction.ACTIVATE))
        self.assertEqual(self.owner.status().state, "active")
        self.assertEqual(sum(path.endswith("/complete") for _, path, _ in self.requests), 1)

    def test_heartbeat_wrong_member_never_publishes_active_observation(self):
        self.active()
        self.rewrite = lambda path, result, status: fixture.response(
            {**result, "user_id": "other-member"} if path.endswith("/heartbeat") else result,
            status=status,
        )
        with self.assertRaises(native.DeviceClientError):
            self.client.heartbeat("review-1")
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])
        self.assertIsNone(self.client.snapshot().heartbeat)

    def test_changed_vault_payload_during_response_cleanup_cannot_publish(self):
        original = self.wire.on_send

        def mutate_after_send():
            original()
            if self.requests[-1][:2] == ("POST", "/v1/device-enrollments"):
                self.wire.on_close = lambda: self.store.items.update(
                    {vault._PAYLOAD.account_id: b"invalid"}
                )

        self.wire.on_send = mutate_after_send
        with self.assertRaises(native.DeviceClientError):
            self.request()
        self.assertFalse(self.client.snapshot().public()["device_enrolled"])
        self.assertEqual(self.session.snapshot().status, managed.ManagedStatus.RECOVERY_REQUIRED)
