# Team Browser Client

Local-first browser workspace with account-free local profile management and optional managed connection contracts. This is a pre-release source candidate; no public repository or license has been published. MIT is proposed pending owner confirmation.

Developer diagnostic runner: Python 3.12+, `pip install -e ".[dev]"`, then `tbm-client`. Open http://127.0.0.1:8765/preview/. Profile metadata stays local. The private backend implementation is deliberately excluded.

Run `python -m unittest discover -s tests -v` and `ruff check src tests`. See docs/dependency-locks.md for the hashed Linux offline-generation verification environment. Installed-browser macOS and Linux paths are implemented; native acceptance remains unverified, and the current Linux executor blocks browser IPC. See docs/native-runtime.md and docs/linux-runtime.md. Explicit local-direct networking is separate from mandatory managed proxy enforcement. Inbox workspace navigation never merges cookie jars or grants Gmail API access.

The integrated desktop browser source and cloud-Mac candidate build contract are in desktop/ and docs/desktop-app.md. No signed/notarized, native-accepted install package has been produced. The loopback page is a developer diagnostic surface, not the intended end-user app.

This source candidate has no real credentials, cookies, proxy endpoints, customer records or git history. Review SOURCE_MANIFEST.json and dependency notices before publication.
