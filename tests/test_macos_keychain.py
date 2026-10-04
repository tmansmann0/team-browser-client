"""Linux-safe Security.framework contract tests, synthetic bytes only.

Every native API is mocked. Nothing loads Apple frameworks, reads a real
Keychain, launches a prompt, changes entitlements, or stores credentials.
"""

import io
import unittest
from collections import defaultdict, deque
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from team_browser.local import macos_keychain as keychain
from team_browser.local.errors import SecretStoreUnavailable
from team_browser.local.secrets import SecretRef


CONFIG = keychain.KeychainConfiguration("SYNTHETIC1", "invalid.example.TeamBrowser", "proxy")
REF = SecretRef("synthetic-reference")
VALUE = b"SYNTHETIC-NOT-A-CREDENTIAL\x00\xff"
MODULE = "team_browser.local.macos_keychain"


class FakeData:
    def __init__(self, value):
        self.value = value
        self.converted = False

    @classmethod
    def dataWithBytes_length_(cls, value, size):
        assert size == len(value)
        return cls(value)

    def length(self):
        return len(self.value)

    def __bytes__(self):
        self.converted = True
        return self.value

    def __repr__(self):
        return "<synthetic data>"


class FakeContext:
    def __init__(self):
        self.no_ui = False
        self.invalidated = False

    def init(self):
        return self

    def setInteractionNotAllowed_(self, value):
        self.no_ui = value

    def interactionNotAllowed(self):
        return self.no_ui

    def invalidate(self):
        self.invalidated = True


class FakeSecurity:
    """Only models the bounded subset called by this adapter."""

    def __init__(self):
        for name in (
            "kSecClass",
            "kSecClassGenericPassword",
            "kSecAttrService",
            "kSecAttrAccount",
            "kSecAttrAccessGroup",
            "kSecAttrSynchronizable",
            "kSecUseDataProtectionKeychain",
            "kSecUseAuthenticationContext",
            "kSecAttrAccessible",
            "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
            "kSecValueData",
            "kSecMatchLimit",
            "kSecMatchLimitOne",
            "kSecReturnAttributes",
            "kSecReturnData",
            "kSecCodeInfoEntitlementsDict",
            "kSecCodeInfoIdentifier",
            "kSecCodeInfoTeamIdentifier",
            "kSecCodeInfoFlags",
        ):
            setattr(self, name, name)
        self.kSecCSDefaultFlags = 0
        self.kSecCSStrictValidate = 16
        self.kSecCSSigningInformation = 2
        self.kSecCodeSignatureRuntime = 65536
        self.calls = []
        self.items = {}
        self.script = defaultdict(deque)
        self.entitlements = {"com.apple.application-identifier": CONFIG.access_group}
        self.info = {
            self.kSecCodeInfoIdentifier: CONFIG.bundle_id,
            self.kSecCodeInfoTeamIdentifier: CONFIG.team_id,
            self.kSecCodeInfoEntitlementsDict: self.entitlements,
            self.kSecCodeInfoFlags: self.kSecCodeSignatureRuntime,
        }

    def _call(self, name, args, default):
        self.calls.append((name, args))
        if self.script[name]:
            value = self.script[name].popleft()
            if isinstance(value, Exception):
                raise value
            return value
        return default()

    def SecRequirementCreateWithString(self, text, flags, output):
        return self._call("requirement", (text, flags, output), lambda: (0, "requirement"))

    def SecCodeCopySelf(self, flags, output):
        return self._call("self", (flags, output), lambda: (0, "code"))

    def SecCodeCheckValidity(self, code, flags, requirement):
        return self._call("dynamic", (code, flags, requirement), lambda: 0)

    def SecCodeCopyStaticCode(self, code, flags, output):
        return self._call("static", (code, flags, output), lambda: (0, "static-code"))

    def SecStaticCodeCheckValidity(self, code, flags, requirement):
        return self._call("validate", (code, flags, requirement), lambda: 0)

    def SecCodeCopySigningInformation(self, code, flags, output):
        return self._call("info", (code, flags, output), lambda: (0, self.info))

    def identity(self, query):
        return tuple(
            query[k]
            for k in (
                self.kSecAttrAccessGroup,
                self.kSecAttrService,
                self.kSecAttrAccount,
                self.kSecAttrSynchronizable,
            )
        )

    def SecItemAdd(self, query, output):
        def perform():
            identity = self.identity(query)
            if identity in self.items:
                return (-25299, None)
            self.items[identity] = {
                k: v
                for k, v in query.items()
                if k not in (self.kSecUseAuthenticationContext, self.kSecUseDataProtectionKeychain)
            }
            return (0, None)

        return self._call("add", (query, output), perform)

    def SecItemUpdate(self, query, update):
        def perform():
            if self.kSecMatchLimit in query:
                raise AssertionError("data-protection update rejects match-query attributes")
            item = self.items.get(self.identity(query))
            if item is None or item[self.kSecAttrAccessible] != query[self.kSecAttrAccessible]:
                return -25300
            item.update(update)
            return 0

        return self._call("update", (query, update), perform)

    def SecItemCopyMatching(self, query, output):
        def perform():
            item = self.items.get(self.identity(query))
            if item is None:
                return (-25300, None)
            result = item.copy()
            if query.get(self.kSecReturnData) is not True:
                result.pop(self.kSecValueData)
            return (0, result)

        return self._call("copy", (query, output), perform)

    def SecItemDelete(self, query):
        def perform():
            if self.kSecMatchLimit in query:
                raise AssertionError("data-protection delete does not accept a finite match limit")
            return 0 if self.items.pop(self.identity(query), None) is not None else -25300

        return self._call("delete", (query,), perform)


class KeychainTests(unittest.TestCase):
    def setUp(self):
        self.security = FakeSecurity()
        self.contexts = []
        self.frameworks = keychain._Frameworks(
            self.security,
            SimpleNamespace(NSData=FakeData, NSDictionary=dict, NSArray=list),
            SimpleNamespace(LAContext=SimpleNamespace(alloc=self.new_context)),
            SimpleNamespace(autorelease_pool=nullcontext),
        )
        self.loader = patch(MODULE + "._load_frameworks", return_value=self.frameworks)
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.store = keychain.MacOSKeychainStore(CONFIG)

    def new_context(self):
        context = FakeContext()
        self.contexts.append(context)
        return context

    def operations(self):
        return [
            (name, args)
            for name, args in self.security.calls
            if name in ("add", "copy", "update", "delete")
        ]

    def test_native_apis_implement_roundtrip_update_and_idempotent_delete(self):
        self.assertIsNone(self.store.put(REF, VALUE))
        self.assertEqual(self.store.get(REF), VALUE)
        self.assertIsNone(self.store.put(REF, b"SECOND-SYNTHETIC-VALUE"))
        self.assertEqual(self.store.get(REF), b"SECOND-SYNTHETIC-VALUE")
        self.assertIsNone(self.store.delete(REF))
        self.assertIsNone(self.store.delete(REF))
        with self.assertRaises(keychain.SecretNotFound):
            self.store.get(REF)
        self.assertEqual(
            [name for name, _ in self.operations()],
            ["add", "copy", "add", "update", "copy", "delete", "copy", "delete", "copy", "copy"],
        )

    def test_every_query_has_exact_private_non_sync_no_ui_scope(self):
        self.store.put(REF, VALUE)
        self.store.put(REF, VALUE)
        self.store.get(REF)
        self.store.delete(REF)
        sec = self.security
        for name, args in self.operations():
            with self.subTest(name=name):
                query = args[0]
                self.assertEqual(query[sec.kSecClass], sec.kSecClassGenericPassword)
                self.assertEqual(query[sec.kSecAttrService], CONFIG.service)
                self.assertEqual(query[sec.kSecAttrAccount], "v1:synthetic-reference")
                self.assertEqual(query[sec.kSecAttrAccessGroup], CONFIG.access_group)
                self.assertIs(query[sec.kSecAttrSynchronizable], False)
                self.assertIs(query[sec.kSecUseDataProtectionKeychain], True)
                context = query[sec.kSecUseAuthenticationContext]
                self.assertIs(context.no_ui, True)
                self.assertTrue(context.invalidated)
                if name == "copy":
                    self.assertEqual(query[sec.kSecMatchLimit], sec.kSecMatchLimitOne)
                else:
                    self.assertNotIn(sec.kSecMatchLimit, query)
        self.assertEqual(len(self.contexts), 4)
        self.assertEqual(len({id(c) for c in self.contexts}), 4)

    def test_add_and_update_preserve_protection_and_do_not_delete(self):
        self.store.put(REF, VALUE)
        self.store.put(REF, VALUE)
        sec = self.security
        for name, args in self.operations():
            self.assertIn(name, ("add", "update"))
            self.assertEqual(
                args[0][sec.kSecAttrAccessible], sec.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            )
            self.assertNotIn(sec.kSecReturnData, args[0])
            self.assertNotIn(sec.kSecReturnAttributes, args[0])
            if name == "update":
                self.assertEqual(set(args[1]), {sec.kSecValueData})

    def test_put_never_upgrades_weaker_existing_record(self):
        self.store.put(REF, VALUE)
        item = next(iter(self.security.items.values()))
        item[self.security.kSecAttrAccessible] = "weaker-protection"
        with self.assertRaises(keychain.KeychainError) as error:
            self.store.put(REF, b"NEW-SYNTHETIC")
        self.assertEqual(error.exception.reason, keychain.KeychainFailure.CONCURRENT_CHANGE)
        self.assertEqual(bytes(item[self.security.kSecValueData]), VALUE)
        self.assertNotIn("delete", [name for name, _ in self.operations()])

    def test_namespaces_and_references_do_not_collide(self):
        self.store.put(REF, VALUE)
        other_store = keychain.MacOSKeychainStore(replace(CONFIG, namespace="other-purpose"))
        other_store.put(REF, b"OTHER-SYNTHETIC")
        self.store.put(SecretRef("another-reference"), b"ANOTHER-SYNTHETIC")
        self.store.delete(REF)
        self.assertEqual(other_store.get(REF), b"OTHER-SYNTHETIC")
        self.assertEqual(self.store.get(SecretRef("another-reference")), b"ANOTHER-SYNTHETIC")

    def test_sync_counterpart_is_never_read_or_deleted(self):
        self.store.put(REF, VALUE)
        identity, item = next(iter(self.security.items.items()))
        self.security.items[(*identity[:-1], True)] = {
            **item,
            self.security.kSecAttrSynchronizable: True,
        }
        self.store.delete(REF)
        self.assertEqual(len(self.security.items), 1)
        with self.assertRaises(keychain.SecretNotFound):
            self.store.get(REF)

    def test_missing_is_distinct_from_locked_and_denied(self):
        with self.assertRaises(keychain.SecretNotFound):
            self.store.get(REF)
        for status, reason in (
            (-25308, keychain.KeychainFailure.INTERACTION_REQUIRED),
            (-25293, keychain.KeychainFailure.AUTHORIZATION_DENIED),
            (-128, keychain.KeychainFailure.AUTHORIZATION_DENIED),
            (-34018, keychain.KeychainFailure.MISSING_ENTITLEMENT),
            (-25291, keychain.KeychainFailure.UNAVAILABLE),
            (-999999, keychain.KeychainFailure.NATIVE_FAILURE),
        ):
            with self.subTest(status=status):
                self.security.script["copy"].append((status, None))
                with self.assertRaises(keychain.KeychainError) as error:
                    self.store.get(REF)
                self.assertNotIsInstance(error.exception, keychain.SecretNotFound)
                self.assertEqual(error.exception.reason, reason)
                self.assertEqual(error.exception.status, status)

    def test_invalid_put_input_makes_no_native_call(self):
        for value in (b"", b"x" * (keychain.MAX_SECRET_BYTES + 1), "text", None, bytearray(b"x")):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.store.put(REF, value)
        self.assertEqual(self.operations(), [])
        self.assertIsNone(self.store.put(REF, b"x" * keychain.MAX_SECRET_BYTES))

    def test_ref_is_typed_and_revalidated_before_native_call(self):
        malformed = SecretRef("initially-valid")
        object.__setattr__(malformed, "account_id", "invalid\nreference")
        for reference in ("raw", None, malformed):
            for operation in (
                self.store.get,
                self.store.delete,
                lambda ref: self.store.put(ref, VALUE),
            ):
                with self.assertRaises((TypeError, ValueError)):
                    operation(reference)
        self.assertEqual(self.operations(), [])

    def test_get_checks_all_policy_attributes_before_exposing_bytes(self):
        self.store.put(REF, VALUE)
        item = next(iter(self.security.items.values()))
        for key in (
            self.security.kSecAttrService,
            self.security.kSecAttrAccount,
            self.security.kSecAttrAccessGroup,
            self.security.kSecAttrAccessible,
            self.security.kSecAttrSynchronizable,
        ):
            for present in (True, False):
                result = item.copy()
                data = FakeData(VALUE)
                result[self.security.kSecValueData] = data
                if present:
                    result[key] = "unexpected"
                else:
                    result.pop(key)
                self.security.script["copy"].append((0, result))
                with (
                    self.subTest(key=key, present=present),
                    self.assertRaises(keychain.KeychainError),
                ):
                    self.store.get(REF)
                self.assertFalse(data.converted)

    def test_get_bounds_native_data_before_copy(self):
        self.store.put(REF, VALUE)
        item = next(iter(self.security.items.values()))
        for value in (FakeData(b""), FakeData(b"x" * (keychain.MAX_SECRET_BYTES + 1)), VALUE, None):
            result = {**item, self.security.kSecValueData: value}
            self.security.script["copy"].append((0, result))
            with self.assertRaises(keychain.KeychainError):
                self.store.get(REF)
            if isinstance(value, FakeData):
                self.assertFalse(value.converted)

    def test_false_or_malformed_acknowledgement_is_never_success(self):
        for value in (
            None,
            False,
            0,
            [0, None],
            (False, None),
            (0.0, None),
            (0,),
            (0, None, None),
            (2**40, None),
            (0, VALUE),
            (-25300, VALUE),
        ):
            self.security.script["add"].append(value)
            with self.subTest(value=value), self.assertRaises(keychain.KeychainError):
                self.store.put(REF, VALUE)
        for value in (None, False, (0, None), "0", 0.0):
            self.security.script["delete"].append(value)
            with self.assertRaises(keychain.KeychainError):
                self.store.delete(REF)

    def test_failed_add_does_not_update_or_retry(self):
        self.security.script["add"].append((-25308, None))
        with self.assertRaises(keychain.KeychainError):
            self.store.put(REF, VALUE)
        self.assertEqual([name for name, _ in self.operations()], ["add"])

    def test_duplicate_update_race_raises_without_add_retry(self):
        self.security.script["add"].append((-25299, None))
        self.security.script["update"].append(-25300)
        with self.assertRaises(keychain.KeychainError):
            self.store.put(REF, VALUE)
        self.assertEqual([name for name, _ in self.operations()], ["add", "update"])

    def test_delete_verifies_metadata_only_absence(self):
        self.store.put(REF, VALUE)
        self.store.delete(REF)
        name, (query, output) = self.operations()[-1]
        self.assertEqual(name, "copy")
        self.assertIsNone(output)
        self.assertIs(query[self.security.kSecReturnAttributes], True)
        self.assertNotIn(self.security.kSecReturnData, query)

    def test_delete_omits_unsupported_limit_but_retains_exact_primary_key(self):
        self.store.put(REF, VALUE)
        self.assertIsNone(self.store.delete(REF))
        name, (query,) = self.operations()[-2]
        self.assertEqual(name, "delete")
        sec = self.security
        self.assertEqual(
            set(query),
            {
                sec.kSecClass,
                sec.kSecAttrAccessGroup,
                sec.kSecAttrService,
                sec.kSecAttrAccount,
                sec.kSecAttrSynchronizable,
                sec.kSecUseDataProtectionKeychain,
                sec.kSecUseAuthenticationContext,
            },
        )
        self.assertNotIn(sec.kSecMatchLimit, query)
        self.assertEqual(self.operations()[-1][1][0][sec.kSecMatchLimit], sec.kSecMatchLimitOne)

    def test_delete_native_error_does_not_claim_absence_or_read(self):
        self.security.script["delete"].append(-25308)
        with self.assertRaises(keychain.KeychainError) as error:
            self.store.delete(REF)
        self.assertEqual(error.exception.reason, keychain.KeychainFailure.INTERACTION_REQUIRED)
        self.assertEqual([name for name, _ in self.operations()], ["delete"])

    def test_delete_postcheck_needs_exact_not_found_none(self):
        for result in ((0, {}), (-25300, VALUE), (-25308, None), (False, None), None):
            self.security.script["copy"].append(result)
            with self.subTest(result=result), self.assertRaises(keychain.KeychainError):
                self.store.delete(REF)

    def test_native_exception_has_no_secret_or_native_message_in_public_error(self):
        output = io.StringIO()
        self.security.script["add"].append(RuntimeError(VALUE.decode("latin1")))
        with redirect_stdout(output), redirect_stderr(output):
            with self.assertRaises(keychain.KeychainError) as error:
                self.store.put(REF, VALUE)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("SYNTHETIC-NOT", str(error.exception))
        self.assertNotIn("synthetic-reference", str(error.exception))
        self.assertIsNone(error.exception.__cause__)
        self.assertTrue(error.exception.__suppress_context__)
        self.assertTrue(self.contexts[-1].invalidated)

    def test_no_prompt_when_context_refuses_no_interaction_setting(self):
        context = FakeContext()
        context.setInteractionNotAllowed_ = lambda value: False
        self.frameworks.local_authentication.LAContext.alloc = lambda: context
        with self.assertRaises(keychain.KeychainError):
            self.store.put(REF, VALUE)
        self.assertEqual(self.operations(), [])
        self.assertTrue(context.invalidated)

    def test_missing_context_and_invalidation_failure_fail_closed(self):
        context = FakeContext()
        context.init = lambda: None
        self.frameworks.local_authentication.LAContext.alloc = lambda: context
        with self.assertRaises(keychain.KeychainError):
            self.store.get(REF)
        self.assertEqual(self.operations(), [])
        context.init = lambda: context
        context.invalidate = lambda: False
        with self.assertRaises(keychain.KeychainError):
            self.store.put(REF, VALUE)

    def test_signing_checks_run_before_any_secret_operations(self):
        self.assertEqual(
            [name for name, _ in self.security.calls],
            ["requirement", "self", "dynamic", "static", "validate", "info"],
        )
        requirement = self.security.calls[0][1][0]
        self.assertIn("anchor apple generic", requirement)
        self.assertIn(CONFIG.team_id, requirement)
        self.assertIn(CONFIG.bundle_id, requirement)
        self.assertEqual(self.security.calls[4][1][1], self.security.kSecCSStrictValidate)

    def test_unsigned_tampered_or_missing_signing_data_blocks_construction(self):
        for operation, result in (
            ("requirement", (-67050, None)),
            ("self", (0, None)),
            ("dynamic", -67050),
            ("static", (-67050, None)),
            ("validate", -67050),
            ("info", (0, {})),
            ("info", (0, None)),
            ("dynamic", False),
            ("info", (False, {})),
        ):
            with self.subTest(operation=operation):
                self.security.script[operation].append(result)
                with self.assertRaises(SecretStoreUnavailable):
                    keychain.MacOSKeychainStore(CONFIG)
        self.assertEqual(self.operations(), [])

    def test_host_identity_and_private_group_cannot_be_overridden(self):
        for key in (self.security.kSecCodeInfoIdentifier, self.security.kSecCodeInfoTeamIdentifier):
            old = self.security.info[key]
            self.security.info[key] = "wrong"
            with self.assertRaises(keychain.KeychainError):
                keychain.MacOSKeychainStore(CONFIG)
            self.security.info[key] = old
        for groups in (
            ["some-shared-group"],
            [CONFIG.access_group, CONFIG.access_group],
            CONFIG.access_group,
            None,
            ["*"],
        ):
            self.security.entitlements["keychain-access-groups"] = groups
            with self.assertRaises(keychain.KeychainError):
                keychain.MacOSKeychainStore(CONFIG)
        self.security.entitlements["keychain-access-groups"] = [CONFIG.access_group]
        keychain.MacOSKeychainStore(CONFIG)
        self.security.entitlements["com.apple.application-identifier"] = "wrong"
        with self.assertRaises(keychain.KeychainError):
            keychain.MacOSKeychainStore(CONFIG)
        self.assertEqual(self.operations(), [])

    def test_debug_and_library_validation_bypasses_are_rejected(self):
        for name in (
            "get-task-allow",
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables",
        ):
            self.security.entitlements[name] = True
            with self.subTest(name=name), self.assertRaises(keychain.KeychainError):
                keychain.MacOSKeychainStore(CONFIG)
            self.security.entitlements.pop(name)

    def test_hardened_runtime_signature_flag_is_required_and_strictly_typed(self):
        sec = self.security
        for flags in (None, False, True, 0, 16, -1, 2**32, "65536", 65536.0):
            sec.info[sec.kSecCodeInfoFlags] = flags
            with self.subTest(flags=flags), self.assertRaises(keychain.KeychainError) as error:
                keychain.MacOSKeychainStore(CONFIG)
            self.assertEqual(error.exception.reason, keychain.KeychainFailure.HOST_REJECTED)
        sec.info.pop(sec.kSecCodeInfoFlags)
        with self.assertRaises(keychain.KeychainError):
            keychain.MacOSKeychainStore(CONFIG)
        for flags in (sec.kSecCodeSignatureRuntime, sec.kSecCodeSignatureRuntime | 16):
            sec.info[sec.kSecCodeInfoFlags] = flags
            keychain.MacOSKeychainStore(CONFIG)
        self.assertEqual(self.operations(), [])

    def test_update_omits_match_flags_and_return_keys(self):
        self.store.put(REF, VALUE)
        self.assertIsNone(self.store.put(REF, b"UPDATED-SYNTHETIC"))
        name, (query, update) = self.operations()[-1]
        self.assertEqual(name, "update")
        sec = self.security
        self.assertEqual(
            set(query),
            {
                sec.kSecClass,
                sec.kSecAttrAccessGroup,
                sec.kSecAttrService,
                sec.kSecAttrAccount,
                sec.kSecAttrSynchronizable,
                sec.kSecAttrAccessible,
                sec.kSecUseDataProtectionKeychain,
                sec.kSecUseAuthenticationContext,
            },
        )
        self.assertEqual(set(update), {sec.kSecValueData})


class ConfigurationAndLoadingTests(unittest.TestCase):
    def test_unconfigured_store_never_implicitly_loads_frameworks(self):
        with patch(MODULE + "._load_frameworks") as loader:
            for value in (None, {}, "namespace"):
                with self.assertRaises(TypeError):
                    keychain.MacOSKeychainStore(value)
            loader.assert_not_called()

    def test_non_macos_fails_before_any_framework_import(self):
        with (
            patch(MODULE + ".sys.platform", "linux"),
            patch("builtins.__import__") as load,
        ):
            with self.assertRaises(SecretStoreUnavailable):
                keychain.MacOSKeychainStore(CONFIG)
            load.assert_not_called()

    def test_missing_framework_does_not_fall_back_or_expose_exception(self):
        with (
            patch(MODULE + ".sys.platform", "darwin"),
            patch("builtins.__import__", side_effect=ImportError("sensitive-detail")) as load,
        ):
            with self.assertRaises(keychain.KeychainError) as error:
                keychain.MacOSKeychainStore(CONFIG)
            self.assertEqual(error.exception.reason, keychain.KeychainFailure.UNAVAILABLE)
            self.assertNotIn("sensitive-detail", str(error.exception))
            self.assertEqual(load.call_count, 1)

    def test_only_expected_native_frameworks_are_loaded(self):
        with (
            patch(MODULE + ".sys.platform", "darwin"),
            patch("builtins.__import__", side_effect=lambda name, *args: name) as load,
        ):
            result = keychain._load_frameworks()
        self.assertEqual(
            [call.args[0] for call in load.call_args_list],
            ["Foundation", "LocalAuthentication", "objc", "Security"],
        )
        self.assertEqual(result.security, "Security")

    def test_configuration_is_bounded_and_cannot_inject_signing_requirement(self):
        for changes in (
            {"team_id": ""},
            {"team_id": "short"},
            {"team_id": "A" * 11},
            {"team_id": '" or true'},
            {"bundle_id": "without-dots"},
            {"bundle_id": 'com.example.App" or true'},
            {"bundle_id": "a." + "b" * 181},
            {"namespace": "../account"},
            {"namespace": ""},
            {"namespace": "a" * 65},
            {"namespace": None},
            {"namespace": "session\n"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(CONFIG, **changes)

    def test_secret_store_does_not_claim_session_vault_semantics(self):
        for name in ("assert_available", "store_session", "delete_session"):
            self.assertFalse(hasattr(keychain.MacOSKeychainStore, name))


if __name__ == "__main__":
    unittest.main()
