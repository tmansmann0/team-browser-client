"""Opt-in, offline Linux smoke test of the already installed Chromium binary.

This runner is separate from team-profile launch and does not loosen any of its
runtime, lease, Keychain, or proxy gates. There is no URL, script, executable,
profile, environment override, or extra-flags input. The only page is generated
synthetic HTML. An unshared network namespace prevents outbound connections;
the existing Chromium sandbox is retained. No downloads or installs occur.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


CHROMIUM = Path("/usr/lib/chromium/chromium")
UNSHARE = Path("/usr/bin/unshare")

SYNTHETIC_PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; script-src 'unsafe-inline'; connect-src 'none';
img-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'">
<title>Team Browser synthetic offline smoke</title></head><body>
<p id="result">TBM_SMOKE_PENDING</p>
<script>
const key = "tbm-synthetic-smoke-visits";
const prior = localStorage.getItem(key);
const next = prior === null ? 1 : Number(prior) + 1;
localStorage.setItem(key, String(next));
document.getElementById("result").textContent = "TBM_SMOKE_VISIT_" + next;
</script></body></html>
"""


class SmokeBlocked(RuntimeError):
    """The smoke could not run with all requested isolation intact."""


@dataclass(frozen=True)
class SmokeResult:
    passed: bool
    executable: str
    version: str
    executable_sha256: str
    first_visit: bool
    persisted_second_visit: bool
    network_namespace: bool
    chromium_sandbox_disabled: bool
    production_launch_enabled: bool
    temporary_data_removed: bool


def _check_system_tool(path: Path) -> None:
    """Allow only the known system paths; reject writable or symlinked tools."""
    if path not in (CHROMIUM, UNSHARE):
        raise SmokeBlocked("Only the preinstalled Chromium and unshare paths are permitted")
    if not path.is_absolute():
        raise SmokeBlocked("A system tool path must be absolute")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise SmokeBlocked("Symlinked system-tool paths are not permitted")
        try:
            info = component.stat()
        except OSError as exc:
            raise SmokeBlocked(f"Required system tool is not installed: {path}") from exc
        if info.st_mode & 0o022:
            raise SmokeBlocked("A system-tool path is group/world writable")
        # The executor's root mount can be mapped to the non-root user. Trust
        # the OS-provided root anchor, while checking every named component.
        if (
            component != Path(component.anchor)
            and info.st_uid == os.getuid()
            and os.access(component, os.W_OK)
        ):
            raise SmokeBlocked("System tools must not be writable by the smoke user")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise SmokeBlocked("Required system tool is not a regular executable")


def _environment(root: Path) -> dict[str, str]:
    directories = {name: root / name for name in ("home", "config", "cache", "runtime", "tmp")}
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(directories["home"]),
        "XDG_CONFIG_HOME": str(directories["config"]),
        "XDG_CACHE_HOME": str(directories["cache"]),
        "XDG_RUNTIME_DIR": str(directories["runtime"]),
        "TMPDIR": str(directories["tmp"]),
        "LANG": "C.UTF-8",
    }


def _namespace_command() -> list[str]:
    return [str(UNSHARE), "--user", "--map-current-user", "--net", "--", str(CHROMIUM)]


def _browser_command(root: Path) -> list[str]:
    """No caller-controlled URL/flags and no sandbox-disabling options."""
    return [
        *_namespace_command(),
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--metrics-recording-only",
        f"--user-data-dir={root / 'profile'}",
        "--dump-dom",
        (root / "synthetic.html").as_uri(),
    ]


def _run(command: list[str], env: dict[str, str], cwd: Path, timeout: int = 30) -> str:
    """Supervise a fresh child session; terminate its group only on timeout."""
    with subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
        close_fds=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            raise SmokeBlocked(
                "Chromium smoke timed out; its child process group was stopped"
            ) from None
        if process.returncode != 0:
            detail = (stderr.strip() or stdout.strip())[-4000:]
            raise SmokeBlocked(f"Isolated Chromium exited {process.returncode}: {detail}")
        return stdout


def run_smoke() -> SmokeResult:
    """Run two offline browser processes and verify localStorage persistence."""
    if sys.platform != "linux" or os.getuid() == 0:
        raise SmokeBlocked("This smoke requires non-root Linux with user/network namespaces")
    _check_system_tool(CHROMIUM)
    _check_system_tool(UNSHARE)
    with CHROMIUM.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    with tempfile.TemporaryDirectory(prefix="tbm-offline-smoke-") as directory:
        root = Path(directory).resolve()
        env = _environment(root)
        (root / "profile").mkdir(mode=0o700)
        (root / "synthetic.html").write_text(SYNTHETIC_PAGE, encoding="utf-8")
        version = _run([*_namespace_command(), "--version"], env, root).strip()
        if not version.startswith("Chromium "):
            raise SmokeBlocked("Installed executable did not identify itself as Chromium")
        command = _browser_command(root)
        first = _run(command, env, root)
        if '<p id="result">TBM_SMOKE_VISIT_1</p>' not in first:
            raise SmokeBlocked("First browser run did not execute the fixed synthetic page")
        second = _run(command, env, root)
        if '<p id="result">TBM_SMOKE_VISIT_2</p>' not in second:
            raise SmokeBlocked("Second browser run did not retain synthetic localStorage")
    return SmokeResult(
        passed=True,
        executable=str(CHROMIUM),
        version=version,
        executable_sha256=digest,
        first_visit=True,
        persisted_second_visit=True,
        network_namespace=True,
        chromium_sandbox_disabled=False,
        production_launch_enabled=False,
        temporary_data_removed=not root.exists(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()  # No URL, executable, profile, or extra flag overrides.
    try:
        result = run_smoke()
    except (SmokeBlocked, OSError) as exc:
        print(
            json.dumps({"passed": False, "blocked": str(exc), "production_launch_enabled": False})
        )
        return 1
    print(json.dumps(asdict(result), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
