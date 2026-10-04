"""Synthetic Linux tests only; no Apple framework, Keychain, browser or network.

Fake bytes never leave process memory. Only empty ownership lock files are
created. Faults model interruption before/after each individual OS-store call;
there is intentionally no fake transaction or rollback primitive.
"""

import copy
import io
import json
import multiprocessing
import os
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from team_browser.client import session_vault as vault
from team_browser.client.auth_flow import (
    AccountIdentity,
    AuthStatus,
    ManagedSignIn,
    NativeSessionMaterial,
)
from team_browser.local.macos_keychain import KeychainConfiguration, SecretNotFound


CONFIG = KeychainConfiguration("SYNTHETIC1", "invalid.example.TeamBrowser", vault.NAMESPACE)
SESSION = "SYNTHETIC_SESSION_REFERENCE_1234567890"
OTHER = "OTHER_SYNTHETIC_REFERENCE_123456789012"
ACCESS = "SYNTHETIC_ACCESS_NOT_A_CREDENTIAL"
ID_TOKEN = "SYNTHETIC_ID_NOT_A_CREDENTIAL"
DIAGNOSTIC = "SYNTHETIC_PRIVATE_NATIVE_DIAGNOSTIC"
_ABSENT = object()
_DEFAULT = object()


class Interrupted(BaseException):
    pass


class FakeStore:
    def __init__(self):
        self.items = {}
        self.events = []
        self.fault = None
        self.hook = None

    def _run(self, operation, reference, action):
        self.events.append((operation, reference.account_id))
        ordinal = len(self.events)
        if self.hook:
            self.hook(operation, reference)
        override = _DEFAULT
        for phase in ("before", "after"):
            if phase == "after":
                result = action()
            if self.fault and self.fault[:2] == (ordinal, phase):
                outcome = self.fault[2]
                if outcome == "raise":
                    raise RuntimeError(DIAGNOSTIC)
                if outcome == "interrupt":
                    raise Interrupted(DIAGNOSTIC)
                override = outcome
        return result if override is _DEFAULT else override

    def put(self, reference, value):
        def action():
            self.items[reference.account_id] = value
            return None

        return self._run("put", reference, action)

    def get(self, reference):
        result = self._run("get", reference, lambda: self.items.get(reference.account_id, _ABSENT))
        if result is _ABSENT:
            raise SecretNotFound()
        return result

    def delete(self, reference):
        def action():
            self.items.pop(reference.account_id, None)
            return None

        return self._run("delete", reference, action)


def lease_child(path, connection):
    try:
        lease = vault._ProcessLease(Path(path))
    except vault.SessionVaultError:
        connection.send("blocked")
        return
    connection.send("owned")
    connection.recv()
    lease.assert_owned()
    # Actual process termination, no close/context-manager cleanup.
    os._exit(0)


class SessionVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "lease"
        self.store = FakeStore()
        self.wall = 1_800_000_000.0
        self.monotonic = 1000.0
        self.instances = []
        self.patches = [
            patch.object(vault, "_open_native_store", return_value=self.store),
            patch.object(vault, "_lease_directory", return_value=self.root),
            patch.object(
                vault,
                "time",
                SimpleNamespace(time=lambda: self.wall, monotonic=lambda: self.monotonic),
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

    def open(self, recover=True, *, oidc_configuration=None):
        instance = vault.MacOSSessionVault(CONFIG, oidc_configuration=oidc_configuration)
        self.instances.append(instance)
        if recover:
            self.assertIsNone(instance.recover_discard_all())
        return instance

    def material(self, **changes):
        material = NativeSessionMaterial(
            AccountIdentity("https://identity.example.test", "synthetic-subject"),
            ACCESS,
            ID_TOKEN,
            int(self.wall) + 300,
        )
        return replace(material, **changes)

    def assert_quarantined(self, instance):
        for action in (
            instance.assert_available,
            lambda: instance.assert_session_current(SESSION),
            lambda: instance.store_session(
                SESSION,
                NativeSessionMaterial(
                    AccountIdentity("https://identity.example.test", "synthetic-subject"),
                    ACCESS,
                    ID_TOKEN,
                    1_800_000_300,
                ),
            ),
            lambda: instance.delete_session(SESSION),
        ):
            with self.assertRaises(vault.SessionVaultError):
                action()

    def test_constructor_is_typed_fixed_scope_and_no_record_access(self):
        for invalid in (None, {}, replace(CONFIG, namespace="proxy")):
            with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                vault.MacOSSessionVault(invalid)
        instance = self.open(recover=False)
        self.assertEqual(self.store.events, [])
        self.assert_quarantined(instance)
        self.assertEqual(self.store.events, [])

    def test_production_factory_does_not_use_linux_fallback(self):
        with patch("team_browser.local.macos_keychain.sys.platform", "linux"):
            # Invoke the real private factory that the fixture replaced.
            self.patches[0].stop()
            try:
                with self.assertRaises(Exception):
                    vault.MacOSSessionVault(CONFIG)
            finally:
                self.patches[0].start()
        self.assertEqual(self.store.events, [])

    def test_exact_none_success_roundtrip_and_no_public_token_getter(self):
        instance = self.open()
        self.assertIsNone(instance.assert_available())
        self.assertIsNone(instance.store_session(SESSION, self.material()))
        self.assertIsNone(instance.assert_session_current(SESSION))
        self.assertIsNone(instance.delete_session(SESSION))
        self.assertIsNone(instance.delete_session(SESSION))
        self.assertIsNone(instance.assert_available())
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        self.assertFalse(any(name in dir(instance) for name in ("get", "get_token", "get_session")))

    def test_prewrite_journal_is_confirmed_before_each_mutation(self):
        instance = self.open()
        self.store.events.clear()
        observed = []

        def check(operation, reference):
            if reference == vault._PAYLOAD and operation in ("put", "delete"):
                marker = json.loads(self.store.items[vault._JOURNAL.account_id])
                self.assertEqual(marker["state"], "quarantined")
                self.assertEqual(self.store.events[-2], ("get", vault._JOURNAL.account_id))
                observed.append(operation)

        self.store.hook = check
        instance.store_session(SESSION, self.material())
        instance.delete_session(SESSION)
        self.assertEqual(observed, ["put", "delete"])

    def test_new_instance_requires_explicit_discard_even_after_clean_commit(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        instance.close()
        before = len(self.store.events)
        restarted = self.open(recover=False)
        self.assert_quarantined(restarted)
        self.assertEqual(len(self.store.events), before)
        restarted.recover_discard_all()
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        restarted.assert_available()
        with self.assertRaises(vault.SessionVaultError):
            restarted.assert_session_current(SESSION)

    def test_explicit_recovery_never_reads_prior_payload(self):
        self.store.items[vault._JOURNAL.account_id] = b"corrupt prior journal"
        self.store.items[vault._PAYLOAD.account_id] = b"SYNTHETIC_PRIOR_MATERIAL"
        seen = []

        def observe(operation, reference):
            if operation == "get" and reference == vault._PAYLOAD:
                self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
            seen.append((operation, reference))

        self.store.hook = observe
        self.open()
        self.assertTrue(seen)

    def test_only_two_fixed_keys_are_touched_and_unrelated_items_survive(self):
        self.store.items["unrelated-owned-by-another-feature"] = b"SYNTHETIC_UNRELATED"
        instance = self.open()
        instance.store_session(SESSION, self.material())
        instance.delete_session(OTHER)
        instance.assert_session_current(SESSION)
        instance.recover_discard_all()
        self.assertEqual(
            self.store.items["unrelated-owned-by-another-feature"], b"SYNTHETIC_UNRELATED"
        )
        self.assertEqual(
            {key for _, key in self.store.events},
            {vault._PAYLOAD.account_id, vault._JOURNAL.account_id},
        )

    def test_interruption_at_every_store_boundary_cannot_restore_login(self):
        instance = self.open()
        self.store.events.clear()
        instance.store_session(SESSION, self.material())
        count = len(self.store.events)
        instance.close()
        for ordinal in range(1, count + 1):
            for phase in ("before", "after"):
                with self.subTest(ordinal=ordinal, phase=phase):
                    self.store.fault = None
                    instance = self.open()
                    self.store.events.clear()
                    self.store.fault = (ordinal, phase, "interrupt")
                    with self.assertRaises(Interrupted):
                        instance.store_session(SESSION, self.material())
                    self.store.fault = None
                    self.assert_quarantined(instance)
                    instance.close()
                    restarted = self.open(recover=False)
                    self.assert_quarantined(restarted)
                    restarted.recover_discard_all()
                    self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
                    restarted.close()

    def test_uncertain_exception_at_every_delete_boundary_stays_quarantined(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        self.store.events.clear()
        instance.delete_session(SESSION)
        count = len(self.store.events)
        instance.close()
        for ordinal in range(1, count + 1):
            for phase in ("before", "after"):
                with self.subTest(ordinal=ordinal, phase=phase):
                    instance = self.open()
                    instance.store_session(SESSION, self.material())
                    self.store.events.clear()
                    self.store.fault = (ordinal, phase, "raise")
                    with self.assertRaises(vault.SessionVaultError):
                        instance.delete_session(SESSION)
                    self.store.fault = None
                    self.assert_quarantined(instance)
                    instance.close()
                    restarted = self.open(recover=False)
                    self.assert_quarantined(restarted)
                    restarted.recover_discard_all()
                    restarted.close()

    def test_interrupted_recovery_needs_another_explicit_recovery(self):
        instance = self.open()
        count = len(self.store.events)
        instance.close()
        for ordinal in range(1, count + 1):
            for phase in ("before", "after"):
                with self.subTest(ordinal=ordinal, phase=phase):
                    instance = self.open(recover=False)
                    self.store.events.clear()
                    self.store.fault = (ordinal, phase, "interrupt")
                    with self.assertRaises(Interrupted):
                        instance.recover_discard_all()
                    self.store.fault = None
                    self.assert_quarantined(instance)
                    instance.close()
                    restarted = self.open(recover=False)
                    self.assert_quarantined(restarted)
                    restarted.recover_discard_all()
                    restarted.close()

    def test_every_mutation_requires_exact_none_not_truthiness(self):
        for operation in ("store", "delete", "recover"):
            instance = self.open()
            if operation == "delete":
                instance.store_session(SESSION, self.material())
            self.store.events.clear()
            action = {
                "store": lambda: instance.store_session(SESSION, self.material()),
                "delete": lambda: instance.delete_session(SESSION),
                "recover": instance.recover_discard_all,
            }[operation]
            action()
            mutations = [
                i + 1 for i, (verb, _) in enumerate(self.store.events) if verb in ("put", "delete")
            ]
            instance.close()
            for ordinal in mutations:
                for bad in (False, True, 0, 1, b"", "ok"):
                    with self.subTest(operation=operation, ordinal=ordinal, bad=bad):
                        instance = self.open()
                        if operation == "delete":
                            instance.store_session(SESSION, self.material())
                        self.store.events.clear()
                        self.store.fault = (ordinal, "after", bad)
                        action = {
                            "store": lambda: instance.store_session(SESSION, self.material()),
                            "delete": lambda: instance.delete_session(SESSION),
                            "recover": instance.recover_discard_all,
                        }[operation]
                        with self.assertRaises(vault.SessionVaultError):
                            action()
                        self.store.fault = None
                        self.assert_quarantined(instance)
                        instance.close()

    def test_unconfirmed_write_readback_and_delete_absence_fail_closed(self):
        for mode in ("write", "delete"):
            instance = self.open()
            if mode == "delete":
                instance.store_session(SESSION, self.material())
            method = "put" if mode == "write" else "delete"
            with patch.object(self.store, method, return_value=None):
                with self.assertRaises(vault.SessionVaultError):
                    if mode == "write":
                        instance.store_session(SESSION, self.material())
                    else:
                        instance.delete_session(SESSION)
            self.assert_quarantined(instance)
            instance.close()

    def test_missing_malformed_or_replayed_journal_never_authorizes_reads(self):
        for replacement in (None, b"garbage", False, bytearray(b"bad"), b"x" * 65537):
            with self.subTest(replacement_type=type(replacement)):
                instance = self.open()
                old = self.store.items[vault._JOURNAL.account_id]
                instance.store_session(SESSION, self.material())
                if replacement is None:
                    del self.store.items[vault._JOURNAL.account_id]
                else:
                    self.store.items[vault._JOURNAL.account_id] = replacement
                self.assert_quarantined(instance)
                instance.close()
                # A previous, syntactically valid ready journal also fails.
                instance = self.open()
                self.store.items[vault._JOURNAL.account_id] = old
                self.assert_quarantined(instance)
                instance.close()

    def test_payload_replay_after_recovery_is_detected_even_for_same_id(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        old = copy.deepcopy(self.store.items)
        instance.recover_discard_all()
        instance.store_session(SESSION, self.material())
        self.store.items[vault._PAYLOAD.account_id] = old[vault._PAYLOAD.account_id]
        self.assert_quarantined(instance)

    def test_payload_corruption_or_disappearance_is_quarantined(self):
        for value in (None, False, b"", b"corruption", b"x" * 65537):
            instance = self.open()
            instance.store_session(SESSION, self.material())
            if value is None:
                del self.store.items[vault._PAYLOAD.account_id]
            else:
                self.store.items[vault._PAYLOAD.account_id] = value
            self.assert_quarantined(instance)
            instance.close()

    def test_wall_and_monotonic_expiry_cleanup_without_polling_core(self):
        for clock in ("wall", "monotonic"):
            instance = self.open()
            instance.store_session(SESSION, self.material())
            setattr(self, clock, getattr(self, clock) + 300)
            before = len(self.store.events)
            with self.assertRaises(vault.SessionExpired):
                instance.assert_session_current(SESSION)
            self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
            # No credential read was needed after detecting expiry.
            events = self.store.events[before:]
            self.assertLess(
                events.index(("delete", vault._PAYLOAD.account_id)),
                events.index(("get", vault._PAYLOAD.account_id)),
            )
            instance.assert_available()
            instance.close()

    def test_expiry_during_slow_read_or_write_returns_no_success(self):
        for verb in ("get", "put"):
            instance = self.open()
            if verb == "get":
                instance.store_session(SESSION, self.material())
            fired = False

            def delay(operation, reference):
                nonlocal fired
                if not fired and operation == verb and reference == vault._PAYLOAD:
                    fired = True
                    self.wall += 301
                    self.monotonic += 301

            self.store.hook = delay
            with self.assertRaises(vault.SessionExpired):
                if verb == "get":
                    instance.assert_session_current(SESSION)
                else:
                    instance.store_session(SESSION, self.material())
            self.store.hook = None
            self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
            instance.assert_available()
            instance.close()

    def test_expiry_cleanup_uncertainty_requires_recovery(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        self.wall += 301
        with patch.object(self.store, "delete", return_value=False):
            with self.assertRaises(vault.SessionVaultError):
                instance.assert_session_current(SESSION)
        self.assert_quarantined(instance)

    def test_clock_rollback_and_nonfinite_clock_are_quarantined(self):
        for clock in ("wall", "monotonic"):
            for bad in (-1.0, float("nan"), float("inf"), True):
                instance = self.open()
                instance.store_session(SESSION, self.material())
                saved = getattr(self, clock)
                setattr(self, clock, bad if bad != -1 else saved - 1)
                self.assert_quarantined(instance)
                setattr(self, clock, saved)
                instance.close()

    def test_invalid_material_and_keys_never_mutate_os_records(self):
        instance = self.open()
        for session in ("../escape", "short", "x" * 129, SESSION + "\n", None):
            before = len(self.store.events)
            with self.assertRaises(vault.SessionVaultError):
                instance.store_session(session, self.material())
            self.assertEqual(len(self.store.events), before)
        for changes in (
            {"access_token": "a" * 16385},
            {"id_token": "bad\nvalue"},
            {"scopes": ("openid", "offline_access")},
            {"scopes": ["openid"]},
            {"expires_at": True},
            {"identity": {}},
        ):
            before = len(self.store.events)
            with self.assertRaises(vault.SessionVaultError):
                instance.store_session(SESSION, self.material(**changes))
            self.assertEqual(len(self.store.events), before)

    def test_expiry_and_epoch_are_bounded(self):
        for expires in (int(self.wall), int(self.wall) - 1, int(self.wall) + 3601):
            instance = self.open()
            with self.assertRaises(vault.SessionVaultError):
                instance.store_session(SESSION, self.material(expires_at=expires))
            self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
            instance.close()
        instance = self.open()
        with patch.object(vault, "_MAX_SESSIONS_PER_EPOCH", 1):
            instance.store_session(SESSION, self.material())
            instance.delete_session(SESSION)
            with self.assertRaises(vault.SessionVaultError):
                instance.store_session(OTHER, self.material())
        self.assert_quarantined(instance)

    def test_duplicate_session_reference_cannot_be_reused_in_epoch(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        instance.delete_session(SESSION)
        with self.assertRaises(vault.SessionVaultError):
            instance.store_session(SESSION, self.material())
        self.assert_quarantined(instance)

    def test_second_instance_and_cross_process_owner_are_excluded(self):
        instance = self.open()
        before = len(self.store.events)
        with self.assertRaises(vault.SessionVaultError):
            self.open()
        self.assertEqual(len(self.store.events), before)
        context = multiprocessing.get_context("fork")
        ours, theirs = context.Pipe()
        process = context.Process(target=lease_child, args=(str(self.root), theirs))
        process.start()
        self.assertTrue(ours.poll(5))
        self.assertEqual(ours.recv(), "blocked")
        process.join(5)
        self.assertEqual(process.exitcode, 0)
        instance.assert_available()
        ours.close()
        theirs.close()

    def test_real_process_exit_releases_only_empty_lease(self):
        context = multiprocessing.get_context("fork")
        ours, theirs = context.Pipe()
        process = context.Process(target=lease_child, args=(str(self.root), theirs))
        process.start()
        try:
            self.assertTrue(ours.poll(5))
            self.assertEqual(ours.recv(), "owned")
            with self.assertRaises(vault.SessionVaultError):
                self.open()
            ours.send("exit")
            process.join(5)
            self.assertEqual(process.exitcode, 0)
            instance = self.open(recover=False)
            self.assert_quarantined(instance)
            instance.recover_discard_all()
        finally:
            if process.is_alive():
                process.terminate()
                process.join(5)
            ours.close()
            theirs.close()

    def test_fork_inherited_vault_cannot_read_or_unlock_parent(self):
        instance = self.open()
        instance.store_session(SESSION, self.material())
        context = multiprocessing.get_context("fork")
        ours, theirs = context.Pipe()

        def child():
            try:
                instance.assert_session_current(SESSION)
                theirs.send("unsafe")
            except vault.SessionVaultError:
                instance.close()
                theirs.send("blocked")

        process = context.Process(target=child)
        process.start()
        self.assertTrue(ours.poll(5))
        self.assertEqual(ours.recv(), "blocked")
        process.join(5)
        self.assertEqual(process.exitcode, 0)
        instance.assert_session_current(SESSION)
        with self.assertRaises(vault.SessionVaultError):
            self.open()
        ours.close()
        theirs.close()

    def test_symlink_hardlink_unsafe_permissions_and_replaced_lock_are_refused(self):
        self.root.mkdir(mode=0o700)
        external = Path(self.temp.name) / "external"
        external.touch(mode=0o600)
        lock = self.root / "owner.lock"
        lock.symlink_to(external)
        with self.assertRaises(vault.SessionVaultError):
            self.open()
        lock.unlink()
        os.link(external, lock)
        with self.assertRaises(vault.SessionVaultError):
            self.open()
        lock.unlink()
        instance = self.open()
        lock.chmod(0o644)
        self.assert_quarantined(instance)
        instance.close()
        lock.chmod(0o600)
        instance = self.open()
        lock.rename(self.root / "old.lock")
        lock.touch(mode=0o600)
        self.assert_quarantined(instance)

    def test_competing_threads_cannot_commit_two_sessions(self):
        instance = self.open()
        results = []
        barrier = threading.Barrier(3)

        def run(session):
            barrier.wait()
            try:
                instance.store_session(session, self.material())
                results.append("stored")
            except vault.SessionVaultError:
                results.append("blocked")

        threads = [threading.Thread(target=run, args=(session,)) for session in (SESSION, OTHER)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(results, ["stored", "blocked"])
        self.assertEqual(self.store.events.count(("put", vault._PAYLOAD.account_id)), 1)
        self.assert_quarantined(instance)

    def test_secrets_never_enter_files_output_errors_or_public_returns(self):
        instance = self.open()
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            instance.store_session(SESSION, self.material())
            self.store.fault = (len(self.store.events) + 1, "before", "raise")
            with self.assertRaises(vault.SessionVaultError) as error:
                instance.assert_session_current(SESSION)
        self.store.fault = None
        public = str(error.exception) + repr(error.exception) + repr(instance) + output.getvalue()
        for secret in (ACCESS, ID_TOKEN, SESSION, DIAGNOSTIC):
            self.assertNotIn(secret, public)
        files = [path for path in Path(self.temp.name).rglob("*") if path.is_file()]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].name, "owner.lock")
        self.assertEqual(files[0].read_bytes(), b"")

    def test_provider_policy_requires_typed_configuration_before_native_construction(self):
        from dataclasses import asdict
        from test_client_provider_signin import CONFIG as ENTRA_CONFIG

        for invalid in (asdict(ENTRA_CONFIG), ENTRA_CONFIG.provider_policy, "entra", False):
            with self.subTest(invalid_type=type(invalid)):
                with self.assertRaises(TypeError):
                    self.open(oidc_configuration=invalid)
        self.assertEqual(self.store.events, [])
        self.assertEqual(vault._open_native_store.call_count, 0)

    def test_explicit_provider_policy_rejects_issuer_scope_and_resource_changes_before_io(self):
        from test_client_provider_signin import CONFIG as ENTRA_CONFIG

        instance = self.open(oidc_configuration=ENTRA_CONFIG)
        material = self.material(
            identity=AccountIdentity(ENTRA_CONFIG.issuer, "synthetic-subject"),
            scopes=ENTRA_CONFIG.scopes,
        )
        other_api = "api://44444444-4444-4444-8444-444444444444/access_as_user"
        rejected = [
            replace(material, identity=AccountIdentity("https://other.example.test", "subject")),
            replace(material, scopes=("openid",)),
            replace(material, scopes=("openid", "profile", other_api)),
            replace(material, scopes=material.scopes + ("offline_access",)),
            replace(material, scopes=material.scopes + ("https://graph.microsoft.com/User.Read",)),
            replace(material, scopes=material.scopes + ("openid",)),
            replace(material, scopes=list(material.scopes)),
        ]
        for changed in rejected:
            with self.subTest(scopes=changed.scopes, issuer=changed.identity.issuer):
                before = list(self.store.events)
                with self.assertRaises(vault.SessionVaultError):
                    instance.store_session(SESSION, changed)
                self.assertEqual(self.store.events, before)
                self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        self.assertIsNone(instance.store_session(SESSION, material))
        payload = json.loads(self.store.items[vault._PAYLOAD.account_id])
        self.assertEqual(payload["scopes"], list(ENTRA_CONFIG.scopes))
        self.assertEqual(payload["issuer"], ENTRA_CONFIG.issuer)

    def test_legacy_default_cannot_accept_expanded_provider_scopes(self):
        from test_client_provider_signin import CONFIG as ENTRA_CONFIG

        instance = self.open()
        before = list(self.store.events)
        with self.assertRaises(vault.SessionVaultError):
            instance.store_session(
                SESSION,
                self.material(
                    identity=AccountIdentity(ENTRA_CONFIG.issuer, "synthetic-subject"),
                    scopes=ENTRA_CONFIG.scopes,
                ),
            )
        self.assertEqual(self.store.events, before)

    def test_provider_policy_enforces_its_shorter_local_ttl_before_payload_write(self):
        from test_client_provider_signin import CONFIG as ENTRA_CONFIG

        configuration = replace(ENTRA_CONFIG, local_session_ttl_seconds=60)
        instance = self.open(oidc_configuration=configuration)
        material = self.material(
            identity=AccountIdentity(configuration.issuer, "synthetic-subject"),
            scopes=configuration.scopes,
            expires_at=int(self.wall) + 61,
        )
        before = len(self.store.events)
        with self.assertRaises(vault.SessionVaultError):
            instance.store_session(SESSION, material)
        self.assertFalse(any(verb != "get" for verb, _ in self.store.events[before:]))
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)
        instance.recover_discard_all()
        instance.store_session(SESSION, replace(material, expires_at=int(self.wall) + 60))
        self.monotonic += 60
        with self.assertRaises(vault.SessionExpired):
            instance.assert_session_current(SESSION)
        self.assertNotIn(vault._PAYLOAD.account_id, self.store.items)

    def test_real_entra_core_commits_to_concrete_vault_with_pinned_policy(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from test_client_provider_signin import CONFIG as ENTRA_CONFIG, SyntheticTransport

        self.wall = time.time()
        instance = self.open(oidc_configuration=ENTRA_CONFIG)
        transport = SyntheticTransport(
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            ENTRA_CONFIG,
            int(self.wall),
        )
        # Both components must observe the same fixture clock. RSA generation
        # can cross a real second boundary; mixing real auth time with the
        # frozen vault time otherwise makes a 600-second TTL appear >600.
        self.enterContext(
            patch(
                "team_browser.client.auth_flow.time",
                SimpleNamespace(time=lambda: self.wall, monotonic=time.monotonic),
            )
        )
        core = ManagedSignIn(ENTRA_CONFIG, transport=transport, vault=instance)
        request = core.begin()
        self.assertEqual(request.result.status, AuthStatus.WAITING)
        params = parse_qs(urlsplit(request.authorization_url).query)
        transport.nonce = params["nonce"][0]
        result = core.complete_callback(
            ENTRA_CONFIG.redirect_uri
            + "?"
            + urlencode({"state": params["state"][0], "code": "synthetic-code"})
        )
        self.assertEqual(result.status, AuthStatus.IDENTITY_VERIFIED)
        self.assertEqual(result.identity.issuer, ENTRA_CONFIG.issuer)
        payload = json.loads(self.store.items[vault._PAYLOAD.account_id])
        self.assertEqual(payload["scopes"], list(ENTRA_CONFIG.scopes))
        self.assertLessEqual(
            payload["expires_at"] - self.wall, ENTRA_CONFIG.local_session_ttl_seconds
        )
        self.assertIsNone(instance.assert_session_current(payload["session_id"]))
        self.assertFalse(result.public()["managed_access_available"])

    def test_core_retains_recovery_required_after_uncertain_native_store(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from test_client_auth_flow import CONFIG as AUTH_CONFIG, FakeTransport

        self.wall = time.time()
        instance = self.open()
        transport = FakeTransport(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        core = ManagedSignIn(AUTH_CONFIG, transport=transport, vault=instance)
        request = core.begin()
        self.assertEqual(request.result.status, AuthStatus.WAITING)
        params = parse_qs(urlsplit(request.authorization_url).query)
        transport.nonce = params["nonce"][0]
        original_put = self.store.put

        def uncertain(reference, value):
            result = original_put(reference, value)
            return False if reference == vault._PAYLOAD else result

        with patch.object(self.store, "put", side_effect=uncertain):
            result = core.complete_callback(
                AUTH_CONFIG.redirect_uri
                + "?"
                + urlencode(
                    {"state": params["state"][0], "code": "synthetic", "iss": AUTH_CONFIG.issuer}
                )
            )
        self.assertEqual(result.status, AuthStatus.RECOVERY_REQUIRED)
        self.assertIsNone(result.identity)
        instance.recover_discard_all()
        self.assertEqual(core.status().status, AuthStatus.RECOVERY_REQUIRED)
        self.assertFalse(core.capabilities().can_begin)


if __name__ == "__main__":
    unittest.main()
