"""Independent native-contract faults using synthetic mocked frameworks only."""

import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from team_browser.local import macos_keychain as keychain
from team_browser.local.secrets import SecretRef

# Reuse only inert fixture types; each fault and expected boundary is independent.
from test_macos_keychain import CONFIG, FakeContext, FakeData, FakeSecurity


class IndependentKeychainTests(unittest.TestCase):
    def setUp(self):
        self.security = FakeSecurity()
        self.contexts = []
        self.frameworks = keychain._Frameworks(
            self.security,
            SimpleNamespace(NSData=FakeData, NSDictionary=dict, NSArray=list),
            SimpleNamespace(LAContext=SimpleNamespace(alloc=self.allocate)),
            SimpleNamespace(autorelease_pool=nullcontext),
        )
        loader = patch.object(keychain, "_load_frameworks", return_value=self.frameworks)
        loader.start()
        self.addCleanup(loader.stop)
        self.store = keychain.MacOSKeychainStore(CONFIG)
        self.ref = SecretRef("independent-synthetic-reference")
        self.value = b"SYNTHETIC-ONLY-NEVER-A-LIVE-SECRET"

    def allocate(self):
        context = FakeContext()
        self.contexts.append(context)
        return context

    def operations(self):
        return [
            name for name, _ in self.security.calls if name in ("add", "copy", "update", "delete")
        ]

    def test_delete_uses_native_supported_query_without_match_limit(self):
        # Apple's data-protection server rejects non-unlimited delete limits:
        # Security/keychain/securityd/SecItemServer.c, SecServerItemDeleteWithCustomDb.
        original = self.security.SecItemDelete
        queries = []

        def native_delete(query):
            queries.append(query.copy())
            if self.security.kSecMatchLimit in query:
                return -50  # errSecParam / errSecMatchLimitUnsupported
            return original(query)

        self.security.SecItemDelete = native_delete
        self.store.put(self.ref, self.value)
        self.assertIsNone(self.store.delete(self.ref))
        self.assertIsNone(self.store.delete(self.ref))
        self.assertNotIn(self.security.kSecMatchLimit, queries[0])
        for key in (
            self.security.kSecClass,
            self.security.kSecAttrService,
            self.security.kSecAttrAccount,
            self.security.kSecAttrAccessGroup,
            self.security.kSecAttrSynchronizable,
            self.security.kSecUseDataProtectionKeychain,
        ):
            self.assertIn(key, queries[0])
        copy = next(args[0] for name, args in reversed(self.security.calls) if name == "copy")
        self.assertEqual(copy[self.security.kSecMatchLimit], self.security.kSecMatchLimitOne)
        self.assertNotIn(self.security.kSecReturnData, copy)

    def test_hardened_runtime_must_be_observed_in_signed_flags(self):
        sec = self.security
        for flags in (None, False, True, 0, 1, -1, 2**40, float(sec.kSecCodeSignatureRuntime)):
            sec.info[sec.kSecCodeInfoFlags] = flags
            with self.subTest(flags=flags), self.assertRaises(keychain.KeychainError) as raised:
                keychain.MacOSKeychainStore(CONFIG)
            self.assertEqual(raised.exception.reason, keychain.KeychainFailure.HOST_REJECTED)
        sec.info.pop(sec.kSecCodeInfoFlags)
        with self.assertRaises(keychain.KeychainError):
            keychain.MacOSKeychainStore(CONFIG)
        self.assertEqual(self.operations(), [])

    def test_duplicate_update_has_exact_scope_without_search_or_return_flags(self):
        original = self.security.SecItemUpdate
        queries = []

        def native_update(query, values):
            queries.append(query.copy())
            forbidden = (
                self.security.kSecMatchLimit,
                self.security.kSecReturnData,
                self.security.kSecReturnAttributes,
            )
            if any(key in query for key in forbidden):
                return -50
            return original(query, values)

        self.security.SecItemUpdate = native_update
        self.store.put(self.ref, self.value)
        self.assertIsNone(self.store.put(self.ref, b"SECOND-SYNTHETIC"))
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0][self.security.kSecAttrAccount], "v1:" + self.ref.account_id)
        self.assertEqual(queries[0][self.security.kSecAttrAccessGroup], CONFIG.access_group)
        self.assertIs(queries[0][self.security.kSecAttrSynchronizable], False)
        self.assertEqual(self.store.get(self.ref), b"SECOND-SYNTHETIC")

    def test_context_cleanup_failure_does_not_claim_write_rollback(self):
        context = FakeContext()
        context.invalidate = lambda: False
        self.frameworks.local_authentication.LAContext.alloc = lambda: context
        with self.assertRaises(keychain.KeychainError) as raised:
            self.store.put(self.ref, self.value)
        self.assertEqual(raised.exception.reason, keychain.KeychainFailure.INVALID_ACKNOWLEDGEMENT)
        self.assertEqual(self.operations(), ["add"])
        self.assertEqual(len(self.security.items), 1)
        self.assertNotIn("delete", self.operations())

    def test_get_does_not_return_value_if_context_cleanup_is_uncertain(self):
        self.store.put(self.ref, self.value)
        context = FakeContext()
        context.invalidate = lambda: False
        self.frameworks.local_authentication.LAContext.alloc = lambda: context
        with self.assertRaises(keychain.KeychainError):
            self.store.get(self.ref)
        self.assertEqual(self.operations(), ["add", "copy"])

    def test_typed_native_data_must_match_declared_length(self):
        self.store.put(self.ref, self.value)
        item = next(iter(self.security.items.values()))
        data = item[self.security.kSecValueData]
        data.length = lambda: len(self.value) - 1
        with self.assertRaises(keychain.KeychainError) as raised:
            self.store.get(self.ref)
        self.assertEqual(raised.exception.reason, keychain.KeychainFailure.INVALID_RECORD)

    def test_data_conversion_exception_is_redacted_and_context_invalidated(self):
        class BrokenData(FakeData):
            def __bytes__(self):
                raise RuntimeError("PRIVATE-SYNTHETIC-EXCEPTION")

        self.store.put(self.ref, self.value)
        item = next(iter(self.security.items.values()))
        item[self.security.kSecValueData] = BrokenData(self.value)
        with self.assertRaises(keychain.KeychainError) as raised:
            self.store.get(self.ref)
        self.assertNotIn("PRIVATE-SYNTHETIC", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertTrue(self.contexts[-1].invalidated)

    def test_duplicate_update_false_acknowledgement_never_retries_or_deletes(self):
        self.store.put(self.ref, self.value)
        self.security.calls.clear()
        self.security.script["update"].append(False)
        with self.assertRaises(keychain.KeychainError) as raised:
            self.store.put(self.ref, b"OTHER-SYNTHETIC")
        self.assertEqual(raised.exception.reason, keychain.KeychainFailure.INVALID_ACKNOWLEDGEMENT)
        self.assertEqual(self.operations(), ["add", "update"])

    def test_malformed_not_found_pair_does_not_become_missing_secret(self):
        self.security.script["copy"].append((-25300, {"unexpected": "synthetic"}))
        with self.assertRaises(keychain.KeychainError) as raised:
            self.store.get(self.ref)
        self.assertNotIsInstance(raised.exception, keychain.SecretNotFound)
        self.assertEqual(raised.exception.reason, keychain.KeychainFailure.INVALID_ACKNOWLEDGEMENT)

    def test_parallel_references_remain_scoped_and_each_context_is_disposed(self):
        references = [SecretRef(f"independent-parallel-{index}") for index in range(16)]

        def roundtrip(ref):
            value = ("SYNTHETIC-" + ref.account_id).encode()
            self.store.put(ref, value)
            return self.store.get(ref), value

        with ThreadPoolExecutor(max_workers=8) as pool:
            for actual, expected in pool.map(roundtrip, references):
                self.assertEqual(actual, expected)
        self.assertEqual(len(self.security.items), 16)
        self.assertEqual(len(self.contexts), 32)
        self.assertTrue(all(context.invalidated for context in self.contexts))
        self.assertEqual(len({id(context) for context in self.contexts}), 32)


if __name__ == "__main__":
    unittest.main()
