#!/usr/bin/env bash
# Uses system Python, not the application's virtual environment. Never sudo.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec /usr/bin/python3 "$script_dir/uninstall_desktop.py" "$@"
