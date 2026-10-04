# Explicit encrypted bootstrap contract

Implemented in public `team_browser.contracts.bootstrap`, tested only with invented `.test` cookies and ephemeral in-memory keys. It does not read a browser's cookies, transmit data, enroll a device, grant access, or import a browser session.

A bundle binds organization, profile, profile generation, recipient device/key, trusted sender key, unique command, explicit domain allowlist, approving operator and a lifetime of at most ten minutes. The payload is sealed using ephemeral X25519 + HKDF-SHA256 + AES-256-GCM, and the complete encrypted envelope is signed with Ed25519. The expected scope and trusted signing/recipient keys must come from independent approved local enrollment; accepting values just because they appear in the envelope defeats this design.

Decryption verifies exact scope, signature, expiry, payload limits and cookie domain/security attributes. It consumes a supplied atomic durable replay guard only after full validation. A SQLite replay-ledger implementation is included in `contracts/replay.py`, with restart and competing-consumer tests. It accepts a connection factory from an already-approved private local store; it does not choose a filesystem path or store cookie values. It is not yet wired to browser import or real device enrollment.

## Required integration work

- Consent UI must name the cookie domains/source, recipient device/profile/company and purpose. A cryptographic `approved_by` field does not create user consent.
- Establish approved device keys and trusted server keys through a reviewed enrollment flow. Creating real credentials or persistent access is a separate authorization step.
- Wire the tested replay ledger into the private local store, then implement rollback-safe staged browser import and command acknowledgement.
- Pass cookie values directly through vetted local APIs; never logs, URLs, shell arguments, unencrypted staging files or backend records.
- Validate engine cookie semantics/host-only behavior and explicitly support only reviewed cookie attributes. Partitioned-cookie/expiry/session migration handling is not included yet.
- Real cookie bundles must be encrypted before leaving the source device. Server stores ciphertext only, with bounded retention and deletion policy.
- Wipe removes approved local material after acknowledgement; it cannot invalidate already copied data or automatically revoke the website's session tokens.

No actual user cookie or provider credential was used while implementing this contract. It is not wired to a live API or browser import operation.
