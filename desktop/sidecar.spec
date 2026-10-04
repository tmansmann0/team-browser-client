# Build only on the native, authorized macOS arm64 CI host.
from pathlib import Path

root = Path(SPECPATH).parent
analysis = Analysis(
    [str(root / "desktop/scripts/sidecar_entry.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[(str(root / "src/team_browser/static"), "team_browser/static")],
    hiddenimports=["uvicorn.logging", "uvicorn.loops.auto", "uvicorn.protocols.http.h11_impl", "uvicorn.lifespan.on"],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=["team_browser.api", "team_browser.demo", "sqlalchemy", "psycopg", "playwright", "camoufox", "browserforge", "tkinter"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(pyz, analysis.scripts, [], exclude_binaries=True, name="tbm-desktop-sidecar", debug=False,
    bootloader_ignore_signals=False, strip=False, upx=False, console=True, target_arch="arm64",
    codesign_identity=None, entitlements_file=None)
collect = COLLECT(exe, analysis.binaries, analysis.datas, strip=False, upx=False, name="tbm-sidecar")
