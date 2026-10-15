#!/usr/bin/env python3
"""Launch the Raspberry Pi OS desktop app. See docs/RASPBERRY_PI_OS.md."""
import sys


def main():
    try:
        from pi5_studio.iso_gui import main as run
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("PySide6"):
            print("PySide6 is missing. Run: bash install-raspberry-pi.sh\n"
                  "Or install python3-pyside6.qtwidgets using your distribution.", file=sys.stderr)
            return 2
        raise
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
