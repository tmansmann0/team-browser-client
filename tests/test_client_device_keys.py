"""Synthetic keys and mocked OS stores only. No Keychain or network activity."""

import copy
import io
import json
import multiprocessing
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt

from team_browser.client import device_keys as keys
from team_browser.client.managed_session import ManagedMembership, MemberRole
from team_browser.contracts.device_proof import (
    ProofContext,
    DeviceProofRejected,
    verify_device_proof,
)
from team_browser.local.macos_keychain import KeychainConfiguration, SecretNotFound

CONFIG = KeychainConfiguration("SYNTHETIC1", "invalid.example.TeamBrowser", keys.NAMESPACE)
SCOPE = keys.TrustedDeviceScope("https://api.example.test", "company", "product-member")
MEMBER = ManagedMembership("product-member", "company", "Synthetic member", MemberRole.MEMBER)
REQUEST = "11111111-1111-4111-8111-111111111111"
CHALLENGE = "22222222-2222-4222-8222-222222222222"
COMMAND = "33333333-3333-4333-8333-333333333333"
_ABSENT = object()
_DEFAULT = object()


class Interrupted(BaseException):
    pass


class FakeStore:
    def __init__(self):
        self.items, self.events = {}, []
        self.fault = self.hook = None

    def run(self, verb, ref, action):
        self.events.append((verb, ref.account_id))
        ordinal = len(self.events)
        if self.hook:
            self.hook(verb, ref)
        override = _DEFAULT
        for phase in ("before", "after"):
            if phase == "after":
                result = action()
            if self.fault and self.fault[:2] == (ordinal, phase):
                outcome = self.fault[2]
                if outcome == "raise":
                    raise RuntimeError("SYNTHETIC_PRIVATE_DIAGNOSTIC")
                if outcome == "interrupt":
                    raise Interrupted()
                override = outcome
        return result if override is _DEFAULT else override

    def get(self, ref):
        result = self.run("get", ref, lambda: self.items.get(ref.account_id, _ABSENT))
        if result is _ABSENT:
            raise SecretNotFound()
        return result

    def put(self, ref, value):
        def action():
            self.items[ref.account_id] = value

        return self.run("put", ref, action)

    def delete(self, ref):
        def action():
            self.items.pop(ref.account_id, None)

        return self.run("delete", ref, action)


def lease_child(path, pipe):
    try:
        lease = keys._ProcessLease(Path(path))
        pipe.send("owned")
        pipe.recv()
        lease.assert_owned()
        os._exit(0)
    except Exception:
        pipe.send("blocked")


class DeviceKeysTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "lease"
        self.store = FakeStore()
        self.wall, self.mono = 1_800_000_000.0, 1000.0
        self.instances = []
        self.patches = [
            patch.object(keys, "_open_native_store", return_value=self.store),
            patch.object(keys, "_lease_directory", return_value=self.root),
            patch.object(
                keys, "time", SimpleNamespace(time=lambda: self.wall, monotonic=lambda: self.mono)
            ),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for instance in self.instances:
            instance.close()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def open(self, restore=True, scope=SCOPE):
        instance = keys.MacOSDeviceKeys(CONFIG, scope)
        self.instances.append(instance)
        if restore:
            instance.restore()
        return instance

    def test_validate_binding_is_read_only_and_rejects_changed_server_binding(self):
        instance, handle, binding = self.active()
        before = copy.deepcopy(self.store.items)
        self.assertIsNone(instance.validate_binding(handle, self.authority(binding)))
        for changed in (
            replace(binding, request_id=CHALLENGE),
            replace(binding, registration_generation=2),
            replace(binding, status="approved", enabled=False),
        ):
            with self.assertRaises(keys.DeviceKeyError):
                instance.validate_binding(handle, self.authority(changed))
        self.assertEqual(self.store.items, before)
        self.assertEqual(instance.status().state, "active")

    def test_validate_binding_rejects_unbound_pending_key(self):
        instance = self.open()
        handle = instance.generate_pending(self.authority())
        with self.assertRaises(keys.DeviceKeyError):
            instance.validate_binding(handle, self.authority(self.binding(instance)))
        self.assertEqual(instance.status().state, "pending")

    def authority(self, binding=None, **changes):
        value = keys.NativeDeviceAuthorization(
            SCOPE, MEMBER, binding, self.wall, self.mono, self.wall + 30
        )
        return replace(value, **changes)

    def binding(self, instance, status="pending", **changes):
        value = keys.ServerDeviceBinding(
            "device", REQUEST, 1, instance.status().key_fingerprint, status, status == "active"
        )
        return replace(value, **changes)

    def pending(self):
        instance = self.open()
        handle = instance.generate_pending(self.authority())
        binding = self.binding(instance)
        instance.bind_pending(handle, self.authority(binding))
        return instance, handle, binding

    def active(self):
        instance, handle, binding = self.pending()
        binding = replace(binding, status="active", enabled=True)
        instance.mark_active(handle, self.authority(binding))
        return instance, handle, binding

    def poll(self, instance, handle, binding, body=b'{"registration_generation":1}'):
        return instance.sign_agent_request(
            handle, self.authority(binding), keys.AgentOperation.POLL, body
        )

    def context(self, request, *, purpose="request", nonce=None):
        return ProofContext(
            SCOPE.origin,
            SCOPE.organization_id,
            SCOPE.member_id,
            "device",
            1,
            "POST",
            request.path,
            request.body,
            purpose,
            nonce,
        )

    def assert_quarantined(self, instance):
        self.assertEqual(instance.status().state, "recovery_required")
        with self.assertRaises(keys.DeviceKeyError):
            instance.restore()

    def fresh_slot(self):
        for instance in self.instances:
            instance.close()
        self.store.fault = self.store.hook = None
        instance = self.open(restore=False)
        instance.forget_local()
        return instance

    def test_constructor_fixed_native_scope_and_no_record_reads(self):
        for invalid in (None, {}, replace(CONFIG, namespace="managed-signin")):
            with self.assertRaises(TypeError):
                keys.MacOSDeviceKeys(invalid, SCOPE)
        with self.assertRaises(TypeError):
            keys.MacOSDeviceKeys(CONFIG, {})
        instance = self.open(restore=False)
        self.assertEqual(self.store.events, [])
        self.assertEqual(instance.status().state, "recovery_required")
        self.assertIsNone(instance.restore())
        self.assertEqual(instance.status().state, "empty")
        self.assertFalse(self.store.items)
        self.assertFalse(
            any(hasattr(instance, name) for name in ("get", "private_key", "sign_data"))
        )

    def test_real_factory_has_no_linux_or_store_injection_fallback(self):
        self.patches[0].stop()
        try:
            with patch("team_browser.local.macos_keychain.sys.platform", "linux"):
                with self.assertRaises(Exception):
                    keys.MacOSDeviceKeys(CONFIG, SCOPE)
        finally:
            self.patches[0].start()
        with self.assertRaises(TypeError):
            keys.MacOSDeviceKeys(CONFIG, SCOPE, store=self.store)
        self.assertFalse(self.store.items)

    def test_first_enrollment_exact_proof_and_restart_preserves_pending(self):
        instance, handle, binding = self.pending()
        public = instance.status().public()
        instance.close()
        restarted = self.open()
        new_handle = restarted.restore()
        self.assertEqual(restarted.status().public(), public)
        body = keys._json(
            {
                "request_id": REQUEST,
                "registration_generation": 1,
                "challenge_id": CHALLENGE,
                "nonce": "a" * 43,
            }
        )
        approved = replace(binding, status="approved")
        proof = restarted.sign_enrollment_completion(new_handle, self.authority(approved), body)
        verified = verify_device_proof(
            proof.proof,
            public["public_key"],
            self.context(proof, purpose="enrollment", nonce="a" * 43),
            int(self.wall),
        )
        self.assertEqual(verified.expires_at, int(self.wall) + 60)
        with self.assertRaises(keys.DeviceKeyError):
            restarted.sign_enrollment_completion(handle, self.authority(approved), body)
        self.assertEqual(restarted.status().state, "pending")

    def test_restart_active_requires_current_exact_server_and_membership_evidence(self):
        instance, handle, binding = self.active()
        public = instance.status().public()
        instance.close()
        restarted = self.open()
        new_handle = restarted.restore()
        for bad in (
            None,
            {},
            self.authority(),
            self.authority(replace(binding, status="approved", enabled=False)),
            self.authority(replace(binding, registration_generation=2)),
        ):
            with self.assertRaises(keys.DeviceKeyError):
                restarted.sign_agent_request(
                    new_handle, bad, keys.AgentOperation.POLL, b'{"registration_generation":1}'
                )
        request = self.poll(restarted, new_handle, binding)
        verify_device_proof(
            request.proof, public["public_key"], self.context(request), int(self.wall)
        )
        self.assertEqual(restarted.status().state, "active")

    def test_product_member_is_not_desktop_provider_subject(self):
        instance, handle, binding = self.active()
        request = self.poll(instance, handle, binding)
        claims = jwt.decode(request.proof, options={"verify_signature": False})
        self.assertEqual(claims["ver"], 2)
        self.assertEqual(claims["sub"], MEMBER.member_id)
        with self.assertRaises(DeviceProofRejected):
            verify_device_proof(
                request.proof,
                instance.status().public_key,
                replace(self.context(request), member_id="desktop-pairwise-sub"),
                int(self.wall),
            )

    def test_fixed_agent_operations_exact_bytes_nonce_and_fresh_identifiers(self):
        instance, handle, binding = self.active()
        fixtures = (
            (keys.AgentOperation.POLL, b'{ "registration_generation":1, "max_commands":2 }', None),
            (
                keys.AgentOperation.HEARTBEAT,
                keys._json(
                    {
                        "registration_generation": 1,
                        "agent_version": "synthetic-1",
                        "profiles": [{"profile_id": "p", "generation": 1, "state": "absent"}],
                    }
                ),
                None,
            ),
            (
                keys.AgentOperation.ACK,
                keys._json(
                    {
                        "registration_generation": 1,
                        "lease_version": 2,
                        "outcome": "failed",
                        "result_code": "execution_unavailable",
                    }
                ),
                COMMAND,
            ),
        )
        seen = set()
        for operation, body, command in fixtures:
            for _ in range(2):
                request = instance.sign_agent_request(
                    handle, self.authority(binding), operation, body, command_id=command
                )
                self.assertEqual(request.body, body)
                result = verify_device_proof(
                    request.proof,
                    instance.status().public_key,
                    self.context(request),
                    int(self.wall),
                )
                self.assertNotIn(result.jti, seen)
                seen.add(result.jti)
                for context in (
                    replace(self.context(request), body=body + b" "),
                    replace(self.context(request), registration_generation=2),
                    replace(self.context(request), path="/v1/agent/devices/other/poll"),
                ):
                    with self.assertRaises(DeviceProofRejected):
                        verify_device_proof(
                            request.proof, instance.status().public_key, context, int(self.wall)
                        )
        with self.assertRaises(DeviceProofRejected):
            verify_device_proof(
                request.proof,
                instance.status().public_key,
                self.context(request),
                int(self.wall) + 60,
            )

    def test_pending_and_active_purposes_are_separate(self):
        instance, handle, pending = self.pending()
        with self.assertRaises(keys.DeviceKeyError):
            self.poll(instance, handle, replace(pending, status="active", enabled=True))
        body = keys._json(
            {
                "request_id": REQUEST,
                "registration_generation": 1,
                "challenge_id": CHALLENGE,
                "nonce": "b" * 43,
            }
        )
        with self.assertRaises(keys.DeviceKeyError):
            instance.sign_enrollment_completion(handle, self.authority(pending), body)
        active = replace(pending, status="active", enabled=True)
        instance.mark_active(handle, self.authority(active))
        with self.assertRaises(keys.DeviceKeyError):
            instance.sign_enrollment_completion(handle, self.authority(active), body)
        self.poll(instance, handle, active)

    def test_unsupported_rotation_preserves_live_key_and_no_io_mutation(self):
        instance, handle, binding = self.active()
        original = copy.deepcopy(self.store.items)
        with self.assertRaisesRegex(keys.DeviceKeyError, "rotation_not_supported"):
            instance.generate_pending(self.authority())
        self.assertEqual(self.store.items, original)
        self.poll(instance, handle, binding)

    def test_explicit_forget_confirmed_absence_invalidates_all_handles(self):
        instance, handle, binding = self.active()
        self.assertIsNone(instance.forget_local())
        self.assertNotIn(keys._PAYLOAD.account_id, self.store.items)
        self.assertEqual(instance.status().state, "empty")
        replacement = instance.generate_pending(self.authority())
        with self.assertRaises(keys.DeviceKeyError):
            self.poll(instance, handle, binding)
        self.assertNotEqual(handle, replacement)
        self.assertEqual(instance.status().state, "pending")

    def test_durable_dirty_precedes_all_keychain_mutation_and_only_two_records(self):
        instance = self.open()
        self.store.items["unrelated"] = b"SYNTHETIC_UNRELATED"
        events = []

        def observe(verb, ref):
            if verb in ("put", "delete"):
                self.assertTrue((self.root / keys._DIRTY).is_file())
                self.assertEqual((self.root / keys._DIRTY).read_bytes(), b"")
                events.append((verb, ref.account_id))

        self.store.hook = observe
        instance.generate_pending(self.authority())
        instance.forget_local()
        self.assertTrue(events)
        self.assertEqual(
            {key for _, key in events}, {keys._JOURNAL.account_id, keys._PAYLOAD.account_id}
        )
        self.assertEqual(self.store.items["unrelated"], b"SYNTHETIC_UNRELATED")
        self.assertFalse((self.root / keys._DIRTY).exists())

    def test_interruption_at_every_commit_boundary_blocks_restart(self):
        instance = self.open()
        self.store.events.clear()
        instance.generate_pending(self.authority())
        count = len(self.store.events)
        for ordinal in range(1, count + 1):
            for phase in ("before", "after"):
                with self.subTest(ordinal=ordinal, phase=phase):
                    instance = self.fresh_slot()
                    self.store.events.clear()
                    self.store.fault = (ordinal, phase, "interrupt")
                    with self.assertRaises(Interrupted):
                        instance.generate_pending(self.authority())
                    self.store.fault = None
                    self.assert_quarantined(instance)
                    instance.close()
                    restarted = self.open(restore=False)
                    self.assert_quarantined(restarted)
                    restarted.forget_local()
                    self.assertEqual(restarted.status().state, "empty")

    def test_uncertain_delete_at_every_boundary_blocks_restart(self):
        instance, _, _ = self.active()
        self.store.events.clear()
        instance.forget_local()
        count = len(self.store.events)
        for ordinal in range(1, count + 1):
            for phase in ("before", "after"):
                with self.subTest(ordinal=ordinal, phase=phase):
                    instance = self.fresh_slot()
                    instance.generate_pending(self.authority())
                    self.store.events.clear()
                    self.store.fault = (ordinal, phase, "raise")
                    with self.assertRaises(keys.DeviceKeyError):
                        instance.forget_local()
                    self.store.fault = None
                    self.assert_quarantined(instance)
                    instance.close()
                    restarted = self.open(restore=False)
                    self.assert_quarantined(restarted)

    def test_all_mutation_acknowledgements_are_exact_none(self):
        for operation in ("generate", "forget"):
            instance = self.fresh_slot()
            if operation == "forget":
                instance.generate_pending(self.authority())
            self.store.events.clear()
            (
                instance.forget_local()
                if operation == "forget"
                else instance.generate_pending(self.authority())
            )
            mutations = [
                i + 1 for i, (verb, _) in enumerate(self.store.events) if verb in ("put", "delete")
            ]
            for ordinal in mutations:
                for bad in (False, True, 0, 1, b"", "ok"):
                    with self.subTest(operation=operation, ordinal=ordinal, bad=bad):
                        instance = self.fresh_slot()
                        if operation == "forget":
                            instance.generate_pending(self.authority())
                        self.store.events.clear()
                        self.store.fault = (ordinal, "after", bad)
                        with self.assertRaises(keys.DeviceKeyError):
                            (
                                instance.forget_local()
                                if operation == "forget"
                                else instance.generate_pending(self.authority())
                            )
                        self.store.fault = None
                        instance.close()
                        self.assert_quarantined(self.open(restore=False))

    def test_write_readback_and_delete_absence_require_actual_evidence(self):
        for operation in ("put", "delete"):
            instance = self.fresh_slot()
            if operation == "delete":
                instance.generate_pending(self.authority())
            with patch.object(self.store, operation, return_value=None):
                with self.assertRaises(keys.DeviceKeyError):
                    (
                        instance.forget_local()
                        if operation == "delete"
                        else instance.generate_pending(self.authority())
                    )
            instance.close()
            self.assert_quarantined(self.open(restore=False))

    def test_final_commit_acknowledgement_uncertainty_cannot_restore_consistent_key(self):
        instance = self.open()
        real = self.store.put

        def fail_after_ready(ref, value):
            result = real(ref, value)
            if ref == keys._JOURNAL and json.loads(value)["state"] == "ready":
                raise RuntimeError("SYNTHETIC_PRIVATE_DIAGNOSTIC")
            return result

        with patch.object(self.store, "put", side_effect=fail_after_ready):
            with self.assertRaises(keys.DeviceKeyError):
                instance.generate_pending(self.authority())
        self.assertEqual(json.loads(self.store.items[keys._JOURNAL.account_id])["state"], "ready")
        instance.close()
        self.assert_quarantined(self.open(restore=False))

    def test_failed_clear_after_successful_commit_stays_quarantined(self):
        for after in (False, True):
            instance = self.fresh_slot()
            original = os.unlink

            def fail_clear(path, *args, **kwargs):
                if path == keys._DIRTY:
                    if after:
                        original(path, *args, **kwargs)
                    raise OSError("SYNTHETIC_PRIVATE_DIAGNOSTIC")
                return original(path, *args, **kwargs)

            with patch.object(keys.os, "unlink", side_effect=fail_clear):
                with self.assertRaises(keys.DeviceKeyError):
                    instance.generate_pending(self.authority())
            self.assertEqual(
                json.loads(self.store.items[keys._JOURNAL.account_id])["state"], "ready"
            )
            instance.close()
            self.assert_quarantined(self.open(restore=False))

    def test_failed_dirty_fsync_prevents_any_keychain_mutation(self):
        instance = self.open()
        self.store.events.clear()
        with patch.object(keys.os, "fsync", side_effect=OSError("synthetic")):
            with self.assertRaises(keys.DeviceKeyError):
                instance.generate_pending(self.authority())
        self.assertFalse(any(verb in ("put", "delete") for verb, _ in self.store.events))
        instance.close()
        self.assert_quarantined(self.open(restore=False))

    def test_restart_requires_consistent_versioned_bounded_records(self):
        for corruption in ("orphan", "digest", "version", "duplicate", "oversized", "epoch"):
            instance = self.fresh_slot()
            instance.generate_pending(self.authority())
            if corruption == "orphan":
                del self.store.items[keys._JOURNAL.account_id]
            elif corruption == "digest":
                self.store.items[keys._PAYLOAD.account_id] += b" "
            elif corruption == "duplicate":
                self.store.items[keys._JOURNAL.account_id] = b'{"version":1,"version":1}'
            elif corruption == "oversized":
                self.store.items[keys._PAYLOAD.account_id] = b"x" * 4097
            else:
                journal = json.loads(self.store.items[keys._JOURNAL.account_id])
                journal[corruption] = True if corruption == "version" else "a" * 64
                self.store.items[keys._JOURNAL.account_id] = keys._json(journal)
            instance.close()
            self.assert_quarantined(self.open(restore=False))

    def test_wrong_scope_cannot_restore_or_sign(self):
        instance, _, _ = self.active()
        original = copy.deepcopy(self.store.items)
        instance.close()
        other = self.open(restore=False, scope=replace(SCOPE, member_id="other"))
        self.assert_quarantined(other)
        self.assertEqual(self.store.items, original)

    def test_changed_lease_blocks_signing_and_unsafe_paths_fail(self):
        instance, handle, binding = self.active()
        os.rename(self.root / "owner.lock", self.root / "retired.lock")
        (self.root / "owner.lock").touch(mode=0o600)
        with self.assertRaises(keys.DeviceKeyError):
            self.poll(instance, handle, binding)
        instance.close()
        for filename in ("owner.lock", "retired.lock", keys._DIRTY):
            (self.root / filename).unlink(missing_ok=True)
        target = self.root / "target"
        target.touch(mode=0o600)
        (self.root / "owner.lock").symlink_to(target)
        with self.assertRaises(Exception):
            self.open(restore=False)

    def test_dirty_marker_symlink_never_follows_or_clears_target(self):
        instance, handle, binding = self.active()
        target = self.root / "unrelated"
        target.write_bytes(b"SYNTHETIC_UNRELATED")
        (self.root / keys._DIRTY).symlink_to(target)
        with self.assertRaises(keys.DeviceKeyError):
            self.poll(instance, handle, binding)
        with self.assertRaises(keys.DeviceKeyError):
            instance.forget_local()
        self.assertEqual(target.read_bytes(), b"SYNTHETIC_UNRELATED")

    def test_kernel_lease_excludes_other_instance_process_and_releases_on_exit(self):
        instance = self.open()
        with self.assertRaises(Exception):
            self.open(restore=False)
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe()
        process = context.Process(target=lease_child, args=(str(self.root), child))
        process.start()
        self.assertTrue(parent.poll(5))
        self.assertEqual(parent.recv(), "blocked")
        process.join(5)
        instance.close()
        process = context.Process(target=lease_child, args=(str(self.root), child))
        process.start()
        self.assertTrue(parent.poll(5))
        self.assertEqual(parent.recv(), "owned")
        with self.assertRaises(Exception):
            self.open(restore=False)
        parent.send("exit")
        process.join(5)
        self.assertEqual(process.exitcode, 0)
        self.open()
        parent.close()
        child.close()

    def test_freshness_clock_rollbacks_and_slow_reads(self):
        instance, handle, binding = self.active()
        original = self.authority(binding)
        for wall, mono in ((30, 0), (0, 30), (31, 31)):
            self.wall, self.mono = 1_800_000_000.0 + wall, 1000.0 + mono
            # New instance clock baseline avoids testing rollback unintentionally.
            instance._clock = None
            with self.assertRaises(keys.DeviceKeyError):
                instance.sign_agent_request(
                    handle, original, keys.AgentOperation.POLL, b'{"registration_generation":1}'
                )
        self.wall, self.mono = 1_800_000_100.0, 1100.0
        fresh = self.authority(binding)
        fired = False

        def slow(verb, ref):
            nonlocal fired
            if not fired and verb == "get" and ref == keys._PAYLOAD:
                fired = True
                self.wall += 31
                self.mono += 31

        self.store.hook = slow
        with self.assertRaises(keys.DeviceKeyError):
            instance.sign_agent_request(
                handle, fresh, keys.AgentOperation.POLL, b'{"registration_generation":1}'
            )
        self.store.hook = None
        self.wall -= 1
        with self.assertRaises(keys.DeviceKeyError):
            self.poll(instance, handle, binding)
        self.assert_quarantined(instance)

    def test_authority_rejects_auditor_wrong_product_membership_and_long_lifetime(self):
        for changes in (
            {"membership": replace(MEMBER, role=MemberRole.AUDITOR)},
            {"membership": replace(MEMBER, member_id="provider-sub")},
            {"membership": {}},
            {"expires_at": self.wall + 31},
            {"observed_at": True},
            {"observed_monotonic": float("nan")},
        ):
            with self.assertRaises(keys.DeviceKeyError):
                self.authority(**changes)

    def test_no_arbitrary_request_or_wrong_generation_or_body_fields(self):
        instance, handle, binding = self.active()
        for op, body, command in (
            ("poll", b'{"registration_generation":1}', None),
            (keys.AgentOperation.POLL, b'{"registration_generation":true}', None),
            (keys.AgentOperation.POLL, b'{"registration_generation":2}', None),
            (
                keys.AgentOperation.POLL,
                b'{"registration_generation":1,"url":"https://evil.test"}',
                None,
            ),
            (keys.AgentOperation.POLL, b'{"registration_generation":1}', "../escape"),
            (keys.AgentOperation.ACK, b'{"registration_generation":1}', "../escape"),
        ):
            with self.assertRaises(keys.DeviceKeyError):
                instance.sign_agent_request(
                    handle, self.authority(binding), op, body, command_id=command
                )
        self.poll(instance, handle, binding)

    def test_concurrent_sign_and_forget_serialize_and_retire_handle(self):
        instance, handle, binding = self.active()
        entered, release, forgotten = threading.Event(), threading.Event(), threading.Event()
        results = []
        original = keys.sign_device_proof

        def slow(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("timeout")
            return original(*args, **kwargs)

        authority = self.authority(binding)

        def sign():
            results.append(
                instance.sign_agent_request(
                    handle, authority, keys.AgentOperation.POLL, b'{"registration_generation":1}'
                )
            )

        def forget():
            instance.forget_local()
            forgotten.set()

        with patch.object(keys, "sign_device_proof", side_effect=slow):
            signer = threading.Thread(target=sign)
            signer.start()
            self.assertTrue(entered.wait(5))
            recovery = threading.Thread(target=forget)
            recovery.start()
            self.assertFalse(forgotten.wait(0.05))
            release.set()
            signer.join(5)
            recovery.join(5)
        self.assertEqual(len(results), 1)
        self.assertTrue(forgotten.is_set())
        self.assertEqual(instance.status().state, "empty")
        with self.assertRaises(keys.DeviceKeyError):
            self.poll(instance, handle, binding)

    def test_no_private_material_nonce_proof_or_diagnostic_in_repr_output_or_files(self):
        capture = io.StringIO()
        with redirect_stdout(capture), redirect_stderr(capture):
            instance, handle, binding = self.active()
            request = self.poll(instance, handle, binding)
            private = json.loads(self.store.items[keys._PAYLOAD.account_id])["private_key"]
            for value in (instance, handle, self.authority(binding), request, instance.status()):
                self.assertNotIn(private, repr(value))
                self.assertNotIn(request.proof, repr(value))
            self.store.fault = (len(self.store.events) + 1, "before", "raise")
            try:
                instance.status()
            except keys.DeviceKeyError as error:
                self.assertNotIn("SYNTHETIC_PRIVATE_DIAGNOSTIC", str(error))
        self.assertEqual(capture.getvalue(), "")
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertEqual(path.read_bytes(), b"")
        self.assertNotIn(private, json.dumps(instance.status().public()))

    def test_replaced_lease_inode_cannot_restore_even_consistent_ready_records(self):
        instance, _, _ = self.active()
        instance.close()
        (self.root / "owner.lock").rename(self.root / "old.lock")
        (self.root / "owner.lock").touch(mode=0o600)
        restarted = self.open(restore=False)
        self.assert_quarantined(restarted)
        restarted.forget_local()
        self.assertEqual(restarted.status().state, "empty")

    def test_replaced_directory_cannot_hide_interrupted_commit_quarantine(self):
        instance = self.open()
        original = self.store.put

        def replace_directory(ref, value):
            result = original(ref, value)
            if ref == keys._JOURNAL and json.loads(value)["state"] == "ready":
                self.root.rename(self.root.with_name("old-lease"))
                self.root.mkdir(mode=0o700)
                raise RuntimeError("synthetic ambiguous final acknowledgement")
            return result

        with patch.object(self.store, "put", side_effect=replace_directory):
            with self.assertRaises(keys.DeviceKeyError):
                instance.generate_pending(self.authority())
        instance.close()
        self.assertFalse((self.root / keys._DIRTY).exists())
        self.assert_quarantined(self.open(restore=False))

    def test_wrong_scope_cannot_explicitly_erase_identifiable_other_identity(self):
        instance, _, _ = self.active()
        original = copy.deepcopy(self.store.items)
        instance.close()
        wrong = self.open(restore=False, scope=replace(SCOPE, organization_id="other"))
        with self.assertRaises(keys.DeviceKeyError):
            wrong.forget_local()
        self.assertEqual(self.store.items, original)

    def test_dirty_fifo_does_not_block_or_authorize_recovery(self):
        instance, handle, binding = self.active()
        os.mkfifo(self.root / keys._DIRTY, mode=0o600)
        with self.assertRaises(keys.DeviceKeyError):
            self.poll(instance, handle, binding)
        with self.assertRaises(keys.DeviceKeyError):
            instance.forget_local()
        self.assertIn(keys._PAYLOAD.account_id, self.store.items)

    def test_clear_directory_fsync_failure_recreates_durable_quarantine(self):
        instance = self.open()
        original = keys.os.fsync
        failed = False

        def fail_after_unlink(fd):
            nonlocal failed
            if (
                keys._PAYLOAD.account_id in self.store.items
                and not (self.root / keys._DIRTY).exists()
            ):
                if not failed:
                    failed = True
                    raise OSError("synthetic uncertain marker clear")
            return original(fd)

        with patch.object(keys.os, "fsync", side_effect=fail_after_unlink):
            with self.assertRaises(keys.DeviceKeyError):
                instance.generate_pending(self.authority())
        self.assertTrue(failed)
        self.assertTrue((self.root / keys._DIRTY).exists())
        instance.close()
        self.assert_quarantined(self.open(restore=False))

    def test_private_public_mismatch_rejected_even_with_matching_journal_digest(self):
        instance = self.open()
        instance.generate_pending(self.authority())
        payload = json.loads(self.store.items[keys._PAYLOAD.account_id])
        payload["private_key"] = "ab" * 32
        encoded = keys._json(payload)
        journal = json.loads(self.store.items[keys._JOURNAL.account_id])
        journal["digest"] = keys.hashlib.sha256(encoded).hexdigest()
        self.store.items[keys._PAYLOAD.account_id] = encoded
        self.store.items[keys._JOURNAL.account_id] = keys._json(journal)
        instance.close()
        self.assert_quarantined(self.open(restore=False))

    def test_authorization_expiring_during_crypto_never_returns_a_proof(self):
        instance, handle, binding = self.active()
        original = keys.sign_device_proof

        def slow(*args, **kwargs):
            result = original(*args, **kwargs)
            self.wall += 31
            self.mono += 31
            return result

        with patch.object(keys, "sign_device_proof", side_effect=slow):
            with self.assertRaises(keys.DeviceKeyError):
                self.poll(instance, handle, binding)
        self.assertEqual(instance.status().state, "active")
        self.poll(instance, handle, binding)

    def test_new_scope_evidence_and_future_observation_cannot_authorize_old_key(self):
        instance, handle, binding = self.active()
        other_scope = replace(SCOPE, member_id="other-member")
        other_member = replace(MEMBER, member_id="other-member")
        for authority in (
            self.authority(binding, scope=other_scope, membership=other_member),
            self.authority(binding, observed_at=self.wall + 1),
            self.authority(binding, observed_monotonic=self.mono + 1),
        ):
            with self.assertRaises(keys.DeviceKeyError):
                instance.sign_agent_request(
                    handle, authority, keys.AgentOperation.POLL, b'{"registration_generation":1}'
                )
        self.poll(instance, handle, binding)

    def test_malformed_bounded_json_rejected_without_quarantining_live_key(self):
        instance, handle, binding = self.active()
        for body in (
            b'{"registration_generation":1,"registration_generation":1}',
            b'{"registration_generation":1,"max_commands":NaN}',
            b"[]",
            b"\xff",
            b"x" * 65537,
            b'{"registration_generation":1,"extra":' + b"[" * 20 + b"0" + b"]" * 20 + b"}",
        ):
            with self.assertRaises(keys.DeviceKeyError):
                self.poll(instance, handle, binding, body)
        self.assertEqual(instance.status().state, "active")
        self.poll(instance, handle, binding)


if __name__ == "__main__":
    unittest.main()
