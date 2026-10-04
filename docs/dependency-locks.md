# Reproducible offline identity verification

`requirements-client-verification-linux-py312.lock` pins the complete resolved
Python verification toolchain for CPython 3.12 on Linux x86_64 with glibc. It
contains the public client's base dependencies, development tools and exact
optional Camoufox/Playwright/BrowserForge/catalogue packages. Every requirement
has distribution SHA-256 hashes. It contains no private backend dependencies,
browser executable, real credentials, package-index credentials or local paths.

This is a verification lock, not a signed production distribution. It does not
approve a Camoufox browser binary, replace the runtime admission policy, or
establish macOS/other Python/platform compatibility. The installed-browser
Linux IPC blocker described in `linux-runtime.md` is unaffected. No browser
download or native launch is needed for these offline package tests.

## Reproduce on a compatible Linux build host

Use a fresh CPython 3.12 virtual environment. From the public client source:

```sh
python3.12 -m venv .verify-venv
.verify-venv/bin/python -m pip install --only-binary=:all: --require-hashes \
  -r requirements-client-verification-linux-py312.lock
.verify-venv/bin/python -m pip check
PYTHONPATH=src TBM_TEST_OFFLINE_IDENTITY=1 \
  .verify-venv/bin/python -B -m unittest discover -s tests -v
```

The `PYTHONPATH` makes this a source verification run; no unpinned editable-build
backend is fetched. Do not run `playwright install`, Camoufox download helpers,
or set any native-acceptance environment flags. The two actual-Mac acceptance
tests remain skipped. The lock is intentionally larger than the runtime-only
dependency set because it includes HTTPX and Ruff for verification.

## Review and regeneration

Generate from the public `pyproject.toml`, not the mixed private development
project. Preserve reviewed versions with the previous lock as constraints:

```sh
uv pip compile pyproject.toml --all-extras --generate-hashes \
  --only-binary=:all: --python-version=3.12 \
  --python-platform=x86_64-unknown-linux-gnu \
  --default-index=https://pypi.org/simple \
  --constraint=requirements-client-verification-linux-py312.lock \
  --no-annotate -o candidate.lock
```

For an intentional update, review the exact package release and hashes first,
then change only its constraints. Never normalize an arbitrary installed
environment into release trust. The initial candidate was constrained to the
already reviewed exact-wheel environment, resolved against official PyPI and
then tested in a fresh environment. Do not retain direct file/URL dependencies
or private index settings in the output. Compare the final package set, install
with `--require-hashes --only-binary=:all:`, run `pip check`, execute all public
tests with offline generation enabled, and review any new skipped cases.

Changing generator or dependency provenance invalidates existing generated
identity admission. It requires a reviewed compatibility/migration decision;
do not silently reseed profiles. A real desktop release additionally needs its
own platform-specific dependency review, license notices, signed packaging,
runtime security/proxy tests and accepted native identity continuity.

Official reference: [uv locking environments](https://docs.astral.sh/uv/pip/compile/).
