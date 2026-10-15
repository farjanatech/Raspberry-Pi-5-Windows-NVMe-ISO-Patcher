#!/usr/bin/env python3
"""Install a per-user app snapshot and freedesktop launchers, without root."""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
from typing import Optional
import shutil
import subprocess
import sys
import uuid

from pi5_studio import APP_NAME, APP_DESCRIPTION, APP_ID, __version__

APP = APP_ID
FILES = ("pi5_nvme_gui.py", "pi5_nvme_tool.py", "pi5_nvme_profiles.py", "pi5_studio/__init__.py",
         "pi5_studio/widgets.py", "pi5_studio/backend.py", "pi5_studio/image_tools.py",
         "pi5_studio/boot_hives.py", "pi5_studio/driver_hives.py", "linux_test_sign.py", "assets/pi5-nvme.png",
         "docs/RASPBERRY_PI_OS.md", "LICENSE", "pi5_studio/catalog.py", "pi5_studio/packages.py",
         "third_party/dotnet-filecatalog-MIT.txt", "uninstall_desktop.py",
         "uninstall-raspberry-pi.sh", "docs/UNINSTALL.md", "docs/ISO_BUILDER.md",
         "pi5_studio/iso_gui.py", "pi5_studio/iso_builder.py")
MARKER = "X-Pi5-NVMe-Studio=true"


def plain(value: str) -> str:
    if any(ord(c) < 32 for c in value):
        raise ValueError("Paths with control characters cannot be put in a desktop launcher.")
    return value.replace("\\", "\\\\")


def exec_arg(value: str) -> str:
    # Two parsing layers: Desktop Entry string escaping, then Exec quoting.
    if any(ord(c) < 32 for c in value):
        raise ValueError("Unsafe launcher path.")
    quoted = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return '"' + quoted.replace("\\", "\\\\").replace("%", "%%") + '"'


def desktop_text(python: Path, root: Path) -> str:
    return "\n".join(("[Desktop Entry]", "Version=1.0", "Type=Application",
                     f"Name={APP_NAME}", f"Comment={APP_DESCRIPTION}",
                     f"Exec={exec_arg(str(python))} {exec_arg(str(root / 'pi5_nvme_gui.py'))}",
                     f"TryExec={plain(str(python))}", f"Path={plain(str(root))}",
                     f"Icon={plain(str(root / 'assets/pi5-nvme.png'))}", "Terminal=false",
                     "Categories=System;Utility;", "StartupNotify=true", f"StartupWMClass={APP_NAME}",
                     "Keywords=Raspberry Pi;NVMe;Windows;ISO;ARM64;", MARKER, ""))


def replace_owned(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing to replace a symlink: {path}")
    if path.exists() and MARKER not in path.read_text(encoding="utf-8"):
        raise ValueError(f"Existing launcher is not managed by this app: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8") as f:
        f.write(text)
    temporary.chmod(0o755)
    os.replace(temporary, path)


def install(source: Path, home: Path, python: Path, desktop: bool = True,
            desktop_dir: Optional[Path] = None) -> dict:
    source, home = source.resolve(), home.resolve()
    # Preserve a venv's executable path; resolving its symlink loses the venv.
    python = python.expanduser().absolute()
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("Python executable does not exist or is not executable.")
    content = {}
    checksum = hashlib.sha256()
    for name in FILES:
        p = source / name
        if not p.is_file() or p.is_symlink():
            raise ValueError(f"Missing or symlinked installation file: {name}")
        content[name] = p.read_bytes()
        checksum.update(name.encode() + b"\0" + content[name])
    target = home / ".local/share" / APP / (f"{__version__}-" + checksum.hexdigest()[:12])
    if target.exists():
        if target.is_symlink() or any((target / name).is_symlink() or not (target / name).is_file() or
                                     (target / name).read_bytes() != data for name, data in content.items()):
            raise ValueError("Existing app snapshot differs from this version; it was not overwritten.")
    else:
        target.mkdir(parents=True, mode=0o700)
        for name, data in content.items():
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("xb") as f:
                f.write(data)
    entry = desktop_text(python, target)
    menu = home / ".local/share/applications" / (APP + ".desktop")
    replace_owned(menu, entry)
    shortcut = None
    if desktop:
        desktop_dir = desktop_dir or home / "Desktop"
        if desktop_dir.resolve() == home:
            desktop_dir = home / "Desktop"
        shortcut = desktop_dir / (APP + ".desktop")
        replace_owned(shortcut, entry)
    return {"application": str(target), "menu": str(menu), "desktop": str(shortcut) if shortcut else None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-desktop", action="store_true", help="Install the application-menu entry only")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        print("Run this installer on Linux as your regular desktop user, not with sudo.", file=sys.stderr)
        return 2
    try:
        from PySide6 import QtWidgets  # dependency check, no display required
        home = Path.home()
        desktop_dir = home / "Desktop"
        if shutil.which("xdg-user-dir"):
            result = subprocess.run(["xdg-user-dir", "DESKTOP"], capture_output=True, text=True, timeout=5, check=False)
            value = result.stdout.strip()
            if result.returncode == 0 and Path(value).is_absolute():
                desktop_dir = Path(value)
        locations = install(Path(__file__).parent, home, Path(sys.executable), not args.no_desktop, desktop_dir)
        for name, path in locations.items():
            if path:
                print(f"{name}: {path}")
        if shutil.which("update-desktop-database"):
            subprocess.run(["update-desktop-database", str(home / ".local/share/applications")], check=False, timeout=10)
        print(f"Installed. Open {APP_NAME} from your application menu.\n"
              "Your desktop may require right-click > Allow Launching or Make Executable.\n"
              "Virtual-environment users: keep the source .venv; the launcher references its Python.\n"
              "Uninstall: bash uninstall-raspberry-pi.sh (preview first with --dry-run).\n"
              "The installed snapshot also contains the uninstaller and docs/UNINSTALL.md.")
        return 0
    except (OSError, ValueError, ImportError, subprocess.TimeoutExpired) as exc:
        print(f"Installation stopped: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
