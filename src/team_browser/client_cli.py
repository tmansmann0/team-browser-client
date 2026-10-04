"""Account-free, loopback-only local workspace entry point."""

import argparse
from pathlib import Path
import uvicorn
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from team_browser.client.app import create_local_app


def mount_workspace(app, *, desktop: bool = False):
    """Serve the same shipped assets in a desktop window or diagnostic web runner."""
    static = Path(__file__).parent / "static"
    app.mount("/app", StaticFiles(directory=static, html=True), name="workspace")
    app.mount("/preview", StaticFiles(directory=static, html=True), name="preview")
    app.state.desktop_shell = desktop

    @app.get("/")
    def home():
        return RedirectResponse("/app/" if desktop else "/preview/")

    return app


def main():
    parser = argparse.ArgumentParser(prog="tbm-client")
    parser.add_argument("--workspace", type=Path, default=Path.home() / ".team-browser-client")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--runtime-policy", type=Path, help="Private reviewed installed-browser policy file"
    )
    parser.add_argument(
        "--camoufox-policy",
        type=Path,
        help="Private Camoufox setup manifest; no download or automatic execution",
    )
    parser.add_argument(
        "--camoufox-trust",
        type=Path,
        help="Separately administrator-provisioned, root-owned deployment public trust anchor",
    )
    args = parser.parse_args()
    if args.runtime_policy is not None and args.camoufox_policy is not None:
        parser.error("Choose one installed-browser or Camoufox setup policy")
    if args.camoufox_trust is not None and args.camoufox_policy is None:
        parser.error("--camoufox-trust requires --camoufox-policy")
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a non-privileged local port")
    app = create_local_app(
        args.workspace,
        port=args.port,
        runtime_config=args.runtime_policy,
        camoufox_config=args.camoufox_policy,
        camoufox_trust=args.camoufox_trust,
    )
    mount_workspace(app)
    uvicorn.run(app, host="127.0.0.1", port=args.port, proxy_headers=False)
