#!/usr/bin/env bash
# Installs dependencies with apt, then the app/launcher as the current user.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if (( EUID == 0 )); then
  printf '%s\n' 'Run this script as your regular user, without sudo. It requests sudo only for apt.' >&2
  exit 2
fi
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'This installer is for Raspberry Pi OS / Debian-family Linux.' >&2
  exit 2
fi
case "$(uname -m)" in
  aarch64|arm64|x86_64) ;;
  *) printf '%s\n' 'Please use 64-bit Raspberry Pi OS for this desktop release.' >&2; exit 2 ;;
esac
if [[ ${1:-} != '' && ${1:-} != --no-desktop ]]; then
  printf '%s\n' 'Usage: bash install-raspberry-pi.sh [--no-desktop]'; exit 2
fi
command -v apt-get >/dev/null || { echo 'apt-get is required; see docs/RASPBERRY_PI_OS.md.' >&2; exit 2; }
printf '%s\n' 'Installing Raspberry Pi 5 Windows NVMe ISO Patcher and native image/signing tools.'
sudo apt-get update
zip_package=7zip
apt-cache show 7zip >/dev/null 2>&1 || zip_package=p7zip-full
packages=(python3 python3-venv "$zip_package" wimtools xorriso openssl osslsigncode python3-hivex xdg-utils libgl1 libegl1 libxcb-cursor0)
python=/usr/bin/python3
if apt-cache show python3-pyside6.qtwidgets >/dev/null 2>&1; then
  packages+=(python3-pyside6.qtwidgets qt6-wayland)
  sudo apt-get install -y "${packages[@]}"
else
  sudo apt-get install -y "${packages[@]}"
  printf '%s\n' 'PySide6 is unavailable through apt here. Installing Qt Essentials into a local .venv.'
  /usr/bin/python3 -m venv .venv
  .venv/bin/python -m pip install --only-binary=:all: 'PySide6-Essentials>=6.8,<7'
  python="$PWD/.venv/bin/python"
fi
"$python" -c 'from PySide6 import QtCore, QtGui, QtWidgets; print("Qt desktop dependencies ready:", QtCore.__version__)'
# The single build action needs signing. Stop before replacing the launcher if
# these prerequisites are unavailable; an existing installation stays usable.
"$python" -c 'from pi5_studio.packages import native_versions; print("Signing tools:", native_versions())'
/usr/bin/python3 -c 'import hivex'
"$python" install_desktop.py "$@"
