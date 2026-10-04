"""Real Linux pilot through the actual manager factory; no implied approval.

Only run after owner approval has been recorded in a private short-lived policy.
Starts fresh synthetic profiles, reports actual state, and acknowledges stop.
Optional fixed public-page checks use example.com, never localhost/file routes.
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from team_browser.client.app import create_local_app
from team_browser.client.linux_pilot import LinuxPilotRuntimeGate


def emit(value):
    print(json.dumps({"time": datetime.now(timezone.utc).isoformat(), **value}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-policy", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--hold-seconds", type=int, default=10)
    parser.add_argument("--public-page", action="store_true")
    args = parser.parse_args()
    if not 0 <= args.hold_seconds <= 120:
        parser.error("Screenshot hold must be between 0 and 120 seconds")
    if args.workspace.exists():
        parser.error("Choose a new disposable workspace; existing profile data is never opened")
    app = create_local_app(args.workspace, runtime_config=args.runtime_policy)
    store, coordinator = app.state.workspace, app.state.coordinator
    profiles = []
    gate = getattr(coordinator.adapter, "gate", None)
    if not isinstance(gate, LinuxPilotRuntimeGate) or (
        args.public_page and not gate.allow_public_example
    ):
        coordinator.shutdown()
        store.close()
        parser.error(
            "An explicit pilot policy authorizing the requested public-page scope is required"
        )

    def await_state(profile_id, target):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            coordinator.refresh()
            profile = store.get(profile_id)
            if profile["state"] == target:
                return
            if profile["state"] in {"error", "recovery_required", "blocked"}:
                running = coordinator._running.get(profile_id)
                diagnostic = (
                    getattr(running.handle, "_startup_exception", None) if running else None
                )
                if diagnostic is not None:
                    emit({"stage": "native-startup-diagnostic", "error": str(diagnostic)[:8192]})
                raise RuntimeError(f"Native state {profile['state']}: {profile['blockers']}")
            time.sleep(0.1)
        raise RuntimeError(f"Native profile did not reach {target}")

    def start(label):
        profile_id = store.create(label, network_policy="local_direct")["id"]
        profiles.append(profile_id)
        coordinator.action(profile_id, "start")
        await_state(profile_id, "running")
        return profile_id

    try:
        first = start("Linux synthetic pilot A")
        coordinator.action(first, "select")
        emit(
            {
                "stage": "real-owned-window-running",
                "profile_id": first,
                "workspace": str(args.workspace),
                "public_page_requested": args.public_page,
            }
        )
        time.sleep(args.hold_seconds)
        if args.public_page:

            async def access(handle, write=False):
                gate._check_approval()
                await handle.page.goto(
                    "https://example.com/", wait_until="domcontentloaded", timeout=15000
                )
                if write:
                    await handle.page.evaluate(
                        "localStorage.setItem('tbm_synthetic_pilot','profile-A')"
                    )
                return await handle.page.evaluate("localStorage.getItem('tbm_synthetic_pilot')")

            supervisor = coordinator.adapter.supervisor
            first_handle = coordinator._running[first].handle
            if supervisor.call(access(first_handle, True)) != "profile-A":
                raise RuntimeError("The first profile did not retain the synthetic value")
            second = start("Linux synthetic pilot B")
            if supervisor.call(access(coordinator._running[second].handle)) is not None:
                raise RuntimeError("The second profile unexpectedly shares synthetic storage")
            third = start("Linux synthetic pilot C")
            if supervisor.call(access(coordinator._running[third].handle)) is not None:
                raise RuntimeError("The third profile unexpectedly shares synthetic storage")
            for profile_id in (first, second, third, first):
                gate._check_approval()
                coordinator.action(profile_id, "select")
                emit({"stage": "profile-selected", "profile_id": profile_id})
                time.sleep(2)
            coordinator.action(first, "stop")
            await_state(first, "stopped")
            coordinator.action(first, "start")
            await_state(first, "running")
            if supervisor.call(access(coordinator._running[first].handle)) != "profile-A":
                raise RuntimeError("Synthetic storage did not survive acknowledged stop/restart")
            emit({"stage": "public-synthetic-isolation-and-persistence-passed"})
        for profile_id in profiles:
            coordinator.action(profile_id, "stop")
            await_state(profile_id, "stopped")
        emit(
            {
                "passed": True,
                "scope": "bounded-owner-approved-linux-pilot",
                "native_profiles_remaining": coordinator.resources()["resident_profiles"],
            }
        )
        return 0
    except Exception as exc:
        emit({"passed": False, "error": str(exc), "workspace_retained": str(args.workspace)})
        return 1
    finally:
        # Only request stops through the owned lifecycle. Uncertain leases stay
        # retained; never signal a guessed PID or delete an unresolved profile.
        for profile_id in profiles:
            try:
                coordinator.action(profile_id, "stop")
            except Exception:
                pass
        coordinator.shutdown()
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
