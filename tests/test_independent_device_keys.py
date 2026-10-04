"""Independent native device-key boundary review using ephemeral fake OS records.

No native Keychain, credential, browser, enrollment transport, or provider is used.
"""

import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from team_browser.client import device_keys as keys
from team_browser.client.managed_session import ManagedMembership, MemberRole
from team_browser.contracts.device_proof import (
    DeviceProofRejected,
    ProofContext,
    verify_device_proof,
)
from team_browser.local.macos_keychain import KeychainConfiguration, SecretNotFound

CONFIG = KeychainConfiguration("SYNTHETIC1", "invalid.review.DeviceKeys", keys.NAMESPACE)
SCOPE = keys.TrustedDeviceScope("https://review-api.test", "review-company", "review-member")
MEMBER = ManagedMembership(SCOPE.member_id, SCOPE.organization_id, "Synthetic", MemberRole.MEMBER)
REQUEST = "ab000000-0000-4000-8000-000000000001"
COMMAND = "ab000000-0000-4000-8000-000000000002"


class SyntheticCrash(BaseException):
    pass


class ReviewByteStore:
    def __init__(self):
        self.records = {}
        self.calls = []
        self.after = None

    def get(self, reference):
        self.calls.append(("get", reference.account_id))
        if self.after:
            self.after("get", reference.account_id)
        if reference.account_id not in self.records:
            raise SecretNotFound()
        return self.records[reference.account_id]

    def put(self, reference, value):
        self.calls.append(("put", reference.account_id))
        self.records[reference.account_id] = value
        return self.after("put", reference.account_id) if self.after else None

    def delete(self, reference):
        self.calls.append(("delete", reference.account_id))
        self.records.pop(reference.account_id, None)
        return self.after("delete", reference.account_id) if self.after else None


class IndependentDeviceKeysTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / "review-lease"
        self.store = ReviewByteStore()
        self.wall, self.mono = 1_900_000_000.0, 8000.0
        self.instances = []
        self.patches = (
            patch.object(keys, "_open_native_store", return_value=self.store),
            patch.object(keys, "_lease_directory", return_value=self.root),
            patch.object(
                keys, "time", SimpleNamespace(time=lambda: self.wall, monotonic=lambda: self.mono)
            ),
        )
        for item in self.patches:
            item.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for instance in self.instances:
            instance.close()
        for item in reversed(self.patches):
            item.stop()
        self.directory.cleanup()

    def open(self, *, restore=True, scope=SCOPE):
        instance = keys.MacOSDeviceKeys(CONFIG, scope)
        self.instances.append(instance)
        if restore:
            instance.restore()
        return instance

    def authority(self, binding=None, *, scope=SCOPE, member=MEMBER):
        return keys.NativeDeviceAuthorization(
            scope, member, binding, self.wall, self.mono, self.wall + 30
        )

    def pending(self, *, bound=True):
        instance = self.open()
        handle = instance.generate_pending(self.authority())
        binding = keys.ServerDeviceBinding(
            "review-device", REQUEST, 7, instance.status().key_fingerprint, "pending", False
        )
        if bound:
            instance.bind_pending(handle, self.authority(binding))
        return instance, handle, binding

    def active(self):
        instance, handle, binding = self.pending()
        binding = replace(binding, status="active", enabled=True)
        instance.mark_active(handle, self.authority(binding))
        return instance, handle, binding

    def reset(self):
        for instance in self.instances:
            instance.close()
        self.store.after = None
        instance = self.open(restore=False)
        instance.forget_local()
        instance.close()

    def assert_restart_blocked(self, instance):
        self.store.after = None
        self.assertEqual(instance.status().state, "recovery_required")
        self.assertTrue((self.root / keys._DIRTY).is_file())
        instance.close()
        restarted = self.open(restore=False)
        with self.assertRaises(keys.DeviceKeyError):
            restarted.restore()
        self.assertEqual(restarted.status().state, "recovery_required")

    def test_validate_binding_is_exact_read_only_and_never_promotes_pending(self):
        instance, handle, binding = self.pending()
        saved = copy.deepcopy(self.store.records)
        for status in ("pending", "approved", "active"):
            self.store.calls.clear()
            evidence = self.authority(replace(binding, status=status, enabled=status == "active"))
            self.assertIsNone(instance.validate_binding(handle, evidence))
            self.assertEqual(instance.status().state, "pending")
            self.assertEqual(saved, self.store.records)
            self.assertTrue(all(verb == "get" for verb, _ in self.store.calls))

    def test_validate_binding_rejects_same_key_under_different_binding_and_scope(self):
        instance, handle, binding = self.active()
        alternate_scope = replace(SCOPE, member_id="other-member")
        alternate_member = replace(MEMBER, member_id="other-member")
        evidence = [
            self.authority(replace(binding, device_id="other-device")),
            self.authority(replace(binding, request_id="ab000000-0000-4000-8000-000000000099")),
            self.authority(replace(binding, registration_generation=8)),
            self.authority(replace(binding, status="approved", enabled=False)),
            self.authority(binding, scope=alternate_scope, member=alternate_member),
            self.authority(binding, scope=replace(SCOPE, origin="https://other-api.test")),
            self.authority(
                binding,
                scope=replace(SCOPE, organization_id="other-company"),
                member=replace(MEMBER, tenant_id="other-company"),
            ),
            self.authority(),
            {},
        ]
        saved = copy.deepcopy(self.store.records)
        for authority in evidence:
            with self.subTest(authority_type=type(authority).__name__):
                with self.assertRaises(keys.DeviceKeyError):
                    instance.validate_binding(handle, authority)
                self.assertEqual(instance.status().state, "active")
                self.assertEqual(self.store.records, saved)
        self.assertIsNone(instance.validate_binding(handle, self.authority(binding)))

    def test_unbound_matching_fingerprint_is_not_durable_binding(self):
        instance, handle, binding = self.pending(bound=False)
        with self.assertRaises(keys.DeviceKeyError):
            instance.validate_binding(handle, self.authority(binding))
        self.assertEqual(instance.status().state, "pending")

    def test_validate_binding_rechecks_freshness_after_final_storage_reads(self):
        instance, handle, binding = self.active()
        authority = self.authority(binding)
        payload_reads = 0

        def advance(verb, account):
            nonlocal payload_reads
            if verb == "get" and account == keys._PAYLOAD.account_id:
                payload_reads += 1
                if payload_reads == 2:
                    self.wall += 30
                    self.mono += 30

        self.store.after = advance
        with self.assertRaises(keys.DeviceKeyError):
            instance.validate_binding(handle, authority)
        self.store.after = None
        self.assertEqual(payload_reads, 2)
        self.assertEqual(instance.status().state, "active")
        self.assertIsNone(instance.validate_binding(handle, self.authority(binding)))

    def test_pending_bind_and_activation_require_exact_mutation_acknowledgements(self):
        # Independently cover the two transitions, in addition to generate/delete.
        for operation in ("bind", "activate"):
            for mutation in (1, 2, 3):
                for response in (False, 0, True, b"", "success", object()):
                    with self.subTest(operation=operation, mutation=mutation, type=type(response)):
                        self.reset()
                        instance, handle, binding = self.pending(bound=operation == "activate")
                        if operation == "activate":
                            binding = replace(binding, status="active", enabled=True)
                        mutations = 0

                        def ambiguous_ack(verb, account):
                            nonlocal mutations
                            if verb == "put":
                                mutations += 1
                                if mutations == mutation:
                                    return response
                            return None

                        self.store.after = ambiguous_ack
                        method = (
                            instance.bind_pending if operation == "bind" else instance.mark_active
                        )
                        with self.assertRaises(keys.DeviceKeyError):
                            method(handle, self.authority(binding))
                        self.assert_restart_blocked(instance)

    def test_interrupted_final_transition_retains_quarantine_across_restart(self):
        for operation in ("bind", "activate"):
            with self.subTest(operation=operation):
                self.reset()
                instance, handle, binding = self.pending(bound=operation == "activate")
                if operation == "activate":
                    binding = replace(binding, status="active", enabled=True)

                def crash(verb, account):
                    if verb == "put" and account == keys._JOURNAL.account_id:
                        if json.loads(self.store.records[account])["state"] == "ready":
                            raise SyntheticCrash()

                self.store.after = crash
                method = instance.bind_pending if operation == "bind" else instance.mark_active
                with self.assertRaises(SyntheticCrash):
                    method(handle, self.authority(binding))
                self.assertEqual(
                    json.loads(self.store.records[keys._JOURNAL.account_id])["state"], "ready"
                )
                self.assert_restart_blocked(instance)

    def test_evidence_expiring_after_successful_transition_never_restores_authority(self):
        instance, handle, binding = self.pending()
        binding = replace(binding, status="active", enabled=True)
        authority = self.authority(binding)

        def expire(verb, account):
            if verb == "put" and account == keys._JOURNAL.account_id:
                if json.loads(self.store.records[account])["state"] == "ready":
                    self.wall += 30
                    self.mono += 30

        self.store.after = expire
        with self.assertRaises(keys.DeviceKeyError):
            instance.mark_active(handle, authority)
        self.assert_restart_blocked(instance)

    def test_ack_proof_binds_exact_command_lease_version_and_wire_bytes(self):
        instance, handle, binding = self.active()
        body = b'{ "registration_generation":7, "lease_version":4, "outcome":"succeeded", "result_code":"local_data_removed" }'
        request = instance.sign_agent_request(
            handle, self.authority(binding), keys.AgentOperation.ACK, body, command_id=COMMAND
        )
        self.assertIs(request.body, body)
        expected = ProofContext(
            SCOPE.origin,
            SCOPE.organization_id,
            SCOPE.member_id,
            binding.device_id,
            7,
            "POST",
            request.path,
            body,
        )
        public = instance.status().public_key
        verify_device_proof(request.proof, public, expected, int(self.wall))
        for changed in (
            replace(expected, path=expected.path.replace(COMMAND, REQUEST)),
            replace(expected, body=body.replace(b'"lease_version":4', b'"lease_version":5')),
            replace(expected, body=json.dumps(json.loads(body)).encode()),
            replace(expected, organization_id="other-company"),
            replace(expected, member_id="other-member"),
            replace(expected, device_id="other-device"),
            replace(expected, registration_generation=8),
        ):
            with self.assertRaises(DeviceProofRejected):
                verify_device_proof(request.proof, public, changed, int(self.wall))

    def test_ack_strict_fields_are_rejected_without_quarantining_key(self):
        instance, handle, binding = self.active()
        template = {
            "registration_generation": 7,
            "lease_version": 1,
            "outcome": "succeeded",
            "result_code": "local_data_removed",
        }
        for changes in (
            {"lease_version": True},
            {"lease_version": 0},
            {"lease_version": 2**63},
            {"outcome": "ok"},
            {"result_code": "cookies_removed"},
            {"url": "https://else.test"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(keys.DeviceKeyError):
                    instance.sign_agent_request(
                        handle,
                        self.authority(binding),
                        keys.AgentOperation.ACK,
                        json.dumps({**template, **changes}).encode(),
                        command_id=COMMAND,
                    )
                self.assertEqual(instance.status().state, "active")

    def test_forgotten_handle_cannot_validate_replacement_same_binding(self):
        instance, old, binding = self.active()
        instance.forget_local()
        replacement = instance.generate_pending(self.authority())
        new_binding = replace(
            binding,
            key_fingerprint=instance.status().key_fingerprint,
            status="pending",
            enabled=False,
        )
        instance.bind_pending(replacement, self.authority(new_binding))
        with self.assertRaises(keys.DeviceKeyError):
            instance.validate_binding(old, self.authority(new_binding))
        self.assertIsNone(instance.validate_binding(replacement, self.authority(new_binding)))
        self.assertEqual(instance.status().state, "pending")

    def test_extra_scope_fields_fail_closed_even_with_matching_payload_digest(self):
        instance, _, _ = self.active()
        for account in (keys._JOURNAL.account_id, keys._PAYLOAD.account_id):
            document = json.loads(self.store.records[account])
            document["scope"]["unexpected"] = "synthetic"
            self.store.records[account] = json.dumps(document).encode()
        journal = json.loads(self.store.records[keys._JOURNAL.account_id])
        journal["digest"] = hashlib.sha256(self.store.records[keys._PAYLOAD.account_id]).hexdigest()
        self.store.records[keys._JOURNAL.account_id] = json.dumps(journal).encode()
        instance.close()
        restarted = self.open(restore=False)
        with self.assertRaises(keys.DeviceKeyError):
            restarted.restore()
        self.assertEqual(restarted.status().state, "recovery_required")

    def test_different_process_identity_cannot_sign(self):
        instance, handle, binding = self.active()
        # Simulate inherited process identity without placing key bytes on disk.
        instance._lease._pid = os.getpid() + 100_000
        with self.assertRaises(keys.DeviceKeyError):
            instance.sign_agent_request(
                handle,
                self.authority(binding),
                keys.AgentOperation.POLL,
                b'{"registration_generation":7}',
            )
        self.assertEqual(instance.status().state, "recovery_required")
        instance._lease._pid = os.getpid()  # Restore ownership only for fixture disposal.
        with self.assertRaises(Exception):
            self.open(restore=False)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX fork ownership contract")
    def test_forked_close_does_not_unlock_parent_or_permit_child_signing(self):
        instance, handle, binding = self.active()
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                try:
                    instance.sign_agent_request(
                        handle,
                        self.authority(binding),
                        keys.AgentOperation.POLL,
                        b'{"registration_generation":7}',
                    )
                except keys.DeviceKeyError:
                    pass
                else:
                    os._exit(2)
                instance.close()
                try:
                    keys._ProcessLease(self.root)
                except Exception:
                    os.write(write_fd, b"blocked")
                    os._exit(0)
                os._exit(3)
            except BaseException:
                os._exit(4)
        os.close(write_fd)
        try:
            self.assertEqual(os.read(read_fd, 64), b"blocked")
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        finally:
            os.close(read_fd)
        self.assertEqual(instance.status().state, "active")
        self.assertIsNone(instance.validate_binding(handle, self.authority(binding)))
        with self.assertRaises(Exception):
            self.open(restore=False)

    def test_records_and_only_empty_lease_files_remain_after_ordinary_close(self):
        instance, handle, binding = self.active()
        saved = copy.deepcopy(self.store.records)
        instance.close()
        self.assertEqual(self.store.records, saved)
        for path in self.root.iterdir():
            self.assertEqual(path.read_bytes(), b"")
        restarted = self.open()
        self.assertEqual(restarted.status().state, "active")
        with self.assertRaises(keys.DeviceKeyError):
            restarted.validate_binding(handle, self.authority(binding))
        self.assertIsNone(restarted.validate_binding(restarted.restore(), self.authority(binding)))
