#!/usr/bin/env python3
"""Remove this user's ISO Patcher and legacy Studio installations only; no Qt or third-party imports.

Preview with --dry-run. Normal use asks for confirmation; --yes is explicit
noninteractive consent. --purge-settings additionally removes legacy Studio Qt
preferences. No recursive deletion, sudo, package-manager or network commands.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Optional

APP = 'pi5-nvme-studio'  # Stable ID shared with earlier Studio releases.
APP_NAME = 'Raspberry Pi 5 Windows NVMe ISO Patcher'
LAUNCHER = APP + '.desktop'
MARKER = 'X-Pi5-NVMe-Studio=true'
LEGACY_LAUNCHERS = {
    'pi5-boot-media.desktop': 'X-Pi5-Boot-Media=true',
    'pi5-boot-media-creator.desktop': 'X-Pi5-Boot-Media-Creator=true',
}
# Union of files installed by the published 0.2+ installers, plus this update.
# Never take a removal allowlist or deletion paths from an installed Python file.
INSTALLED_FILES = frozenset((
    'pi5_nvme_gui.py', 'pi5_nvme_tool.py', 'pi5_nvme_profiles.py',
    'linux_test_sign.py', 'pi5_studio/__init__.py', 'pi5_studio/gui.py',
    'pi5_studio/backend.py', 'pi5_studio/desktop.py', 'pi5_studio/boot_test.py',
    'pi5_studio/boot_hives.py', 'pi5_studio/catalog.py', 'pi5_studio/packages.py',
    'pi5_studio/widgets.py', 'pi5_studio/image_tools.py', 'pi5_studio/driver_hives.py',
    'assets/pi5-nvme.png', 'docs/RASPBERRY_PI_OS.md', 'docs/BOOT_TEST.md',
    'docs/NATIVE_PACKAGES.md', 'third_party/dotnet-filecatalog-MIT.txt', 'LICENSE',
    'uninstall_desktop.py', 'uninstall-raspberry-pi.sh', 'docs/UNINSTALL.md',
    'pi5_studio/iso_gui.py', 'pi5_studio/iso_builder.py', 'pi5_studio/installer_hives.py',
    'pi5_studio/resources/installer-runtime.json', 'pi5_studio/resources/pi5-install-arm64.exe',
    'pi5_studio/resources/RPi5-UEFI-Damian-Edition-v0.1.0-rc1.zip', 'docs/ISO_BUILDER.md',
))
SNAPSHOT = re.compile(r'([0-9]+\.[0-9]+\.[0-9]+(?:[-+.][A-Za-z0-9]+)*)-[0-9a-f]{12}')


class UninstallError(ValueError):
    pass


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns)


class HomeAccess:
    """Walk relative to an open HOME fd, rejecting symlinked parent directories.

    unlink/rmdir operate relative to the checked parent fd. A path swapped for a
    symlink cannot redirect the operation to that symlink's target. Mounted or
    foreign-owned subdirectories are deliberately not traversed.
    """
    def __init__(self, home: Path):
        self.home = home.expanduser().resolve(strict=True)
        if self.home == Path('/'):
            raise UninstallError('HOME cannot be the filesystem root.')
        self.fd = os.open(self.home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        s = os.fstat(self.fd)
        self.device = s.st_dev
        if s.st_uid != os.geteuid():
            self.close()
            raise UninstallError('HOME must belong to the current user.')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def relative(self, path: Path) -> str:
        # Do not resolve a candidate: that would hide a symlink or escape HOME.
        path = path.expanduser()
        if not path.is_absolute() or '..' in path.parts:
            raise UninstallError('Use an absolute path without .. components.')
        try:
            rel = path.relative_to(self.home)
        except ValueError as exc:
            raise UninstallError('Automatic removal is limited to this user\'s HOME.') from exc
        if not rel.parts or any(ord(c) < 32 for c in str(rel)):
            raise UninstallError('Unsafe removal path.')
        return rel.as_posix()

    @contextmanager
    def parent(self, relative: str):
        p = Path(relative)
        if p.is_absolute() or not p.parts or any(s in ('.', '..') for s in p.parts):
            raise UninstallError('Invalid relative removal path.')
        fd = os.dup(self.fd)
        try:
            for component in p.parts[:-1]:
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                s = os.fstat(nxt)
                if s.st_dev != self.device or s.st_uid != os.geteuid():
                    os.close(nxt)
                    raise UninstallError('Mounted or foreign-owned parent directory retained.')
                os.close(fd)
                fd = nxt
            yield fd, p.name
        finally:
            os.close(fd)

    def info(self, relative):
        try:
            with self.parent(relative) as (fd, name):
                return os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def read(self, relative, limit=256*1024):
        with self.parent(relative) as (fd, name):
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(f, 'rb') as stream:
                s = os.fstat(stream.fileno())
                if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_size > limit:
                    raise UninstallError('Not a small current-user regular file.')
                data = stream.read(limit+1)
                if len(data) > limit:
                    raise UninstallError('File exceeds inspection limit.')
                return data

    def names(self, relative):
        with self.parent(relative) as (fd, name):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                s = os.fstat(child)
                if s.st_dev != self.device or s.st_uid != os.geteuid():
                    raise UninstallError('Mounted or foreign-owned directory retained.')
                names = os.listdir(child)
                if len(names) > 4096:
                    raise UninstallError('Directory is unexpectedly large; retained for manual review.')
                return sorted(names)
            finally:
                os.close(child)


@dataclass
class Plan:
    files: dict = field(default_factory=dict)
    directories: set = field(default_factory=set)
    retained: list = field(default_factory=list)


def cache_file(relative: str) -> bool:
    p = Path(relative)
    if p.parent.as_posix() not in ('__pycache__', 'pi5_studio/__pycache__'):
        return False
    base = p.name.split('.')[0]
    source = (p.parent.parent / (base+'.py')).as_posix()
    return source in INSTALLED_FILES and bool(re.fullmatch(
        r'[A-Za-z0-9_]+\.(?:cpython-[0-9]+|pypy[0-9]+)(?:\.opt-[0-9]+)?\.pyc', p.name))


def plan_removal(access: HomeAccess, desktop_dirs: list, purge_settings=False,
                 config_home: Optional[Path] = None, all_tools=False) -> Plan:
    plan = Plan()
    app_root = '.local/share/' + APP
    folders = {str(Path(s).parent) for s in INSTALLED_FILES} - {'.'}
    folders |= {'__pycache__', 'pi5_studio/__pycache__'}

    def retain(path, reason):
        plan.retained.append((str(path), str(reason)))

    def select_file(rel):
        s = access.info(rel)
        if s is None:
            return
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_dev != access.device:
            retain(rel, 'Not a current-user regular file; links are never followed.')
            return
        plan.files[rel] = identity(s)

    def scan_snapshot(root, inside=''):
        rel = str(Path(root) / inside)
        plan.directories.add(rel)
        for name in access.names(rel):
            item = (Path(inside)/name).as_posix()
            path = (Path(root)/item).as_posix()
            s = access.info(path)
            if s is None:
                raise UninstallError('Installation changed while planning; close the patcher and retry.')
            if item in INSTALLED_FILES or cache_file(item):
                select_file(path)
            elif item in folders and stat.S_ISDIR(s.st_mode):
                scan_snapshot(root, item)
            else:
                retain(path, 'Unrecognized file/folder retained (may contain your data).')

    try:
        if access.info(app_root) is not None:
            for name in access.names(app_root):
                rel = app_root+'/'+name
                try:
                    match = SNAPSHOT.fullmatch(name)
                    if not match:
                        raise UninstallError('Not a recognized versioned application snapshot.')
                    init = access.read(rel+'/pi5_studio/__init__.py').decode('utf-8')
                    launch = access.read(rel+'/pi5_nvme_gui.py').decode('utf-8')
                    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)[\'"]\s*$', init, re.M)
                    if not version or version[1] != match[1] or 'from pi5_studio.' not in launch:
                        raise UninstallError('Snapshot identity could not be verified.')
                    scan_snapshot(rel)
                except (OSError, ValueError) as exc:
                    retain(rel, exc)
            plan.directories.add(app_root)
    except (OSError, ValueError) as exc:
        retain(app_root, exc)

    launchers = {LAUNCHER: MARKER}
    if all_tools:
        launchers.update(LEGACY_LAUNCHERS)
    locations = [access.home/'.local/share/applications', *map(Path, desktop_dirs)]
    candidates = {parent/name: marker for parent in locations for name, marker in launchers.items()}
    for path, marker in candidates.items():
        try:
            rel = access.relative(path)
            if access.info(rel) is None:
                continue
            text = access.read(rel).decode('utf-8')
            lines = [line.strip() for line in text.splitlines()]
            if '[Desktop Entry]' not in lines or marker not in lines:
                raise UninstallError('Launcher does not have the expected application ownership marker.')
            select_file(rel)
        except (OSError, ValueError) as exc:
            retain(path, exc)

    if purge_settings:
        roots = [access.home/'.config']
        if config_home is not None:
            roots.append(config_home)
        for root in dict.fromkeys(roots):
            path = root/'farjanatech/Pi5NVMeStudio.conf'
            try:
                select_file(access.relative(path))
            except (OSError, ValueError) as exc:
                retain(path, exc)
    return plan


def apply_plan(access: HomeAccess, plan: Plan) -> int:
    # All planned file identities must still match before removing the first one.
    for rel, expected in plan.files.items():
        s = access.info(rel)
        if s is None or identity(s) != expected:
            raise UninstallError('A planned file changed; nothing removed. Preview again: '+rel)
    count = 0
    for rel, expected in plan.files.items():
        with access.parent(rel) as (fd, name):
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if identity(s) != expected:
                raise UninstallError('File changed during removal; stopped: '+rel)
            os.unlink(name, dir_fd=fd)
            count += 1
    # Only empty app-specific directories. Never recursively delete any tree.
    for rel in sorted(plan.directories, key=lambda s: len(Path(s).parts), reverse=True):
        with access.parent(rel) as (fd, name):
            try:
                os.rmdir(name, dir_fd=fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                # A directory containing retained personal files is expected.
                import errno
                if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                    raise
    return count


def desktop_locations(home: Path) -> list:
    result = [home/'Desktop']
    try:
        proc = subprocess.run(['xdg-user-dir', 'DESKTOP'], shell=False, capture_output=True,
                              text=True, timeout=5, check=False)
        path = Path(proc.stdout.strip())
        if proc.returncode == 0 and path.is_absolute() and path != home:
            result.append(path)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return result


def running_studio() -> list:
    """Best-effort Linux check; never kills processes or displays their arguments."""
    found = []
    try:
        processes = list(Path('/proc').iterdir())
    except OSError:
        return found
    for proc in processes:
        if not proc.name.isdecimal() or int(proc.name) == os.getpid():
            continue
        try:
            if proc.stat().st_uid != os.geteuid():
                continue
            argv = (proc/'cmdline').read_bytes().split(b'\0')
            scripts = {b'pi5_nvme_gui.py', b'pi5_nvme_tool.py', b'linux_test_sign.py',
                       b'install_desktop.py', b'install-raspberry-pi.sh',
                       b'boot_media.py', b'boot_media_creator.py', b'install-boot-media.sh'}
            modules = {b'pi5_studio.backend', b'pi5_studio.packages', b'pi5_studio.boot_test',
                       b'pi5_studio.gui', b'pi5_studio.desktop', b'pi5_studio.iso_gui',
                       b'pi5_studio.iso_builder', b'pi5_media.gui', b'pi5_media.core',
                       b'pi5_media.disk', b'pi5_media.install'}
            if any(a.rsplit(b'/', 1)[-1] in scripts for a in argv) or any(
                    argv[i] == b'-m' and argv[i+1] in modules for i in range(len(argv)-1)):
                found.append(int(proc.name))
        except (OSError, ValueError):
            continue
    return sorted(found)


def regular_user() -> bool:
    return (sys.platform == 'linux' and os.geteuid() != 0 and os.getuid() != 0
            and not os.environ.get('SUDO_USER'))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true', help='Show removal plan; change nothing')
    mode.add_argument('--yes', action='store_true', help='Confirm removal without interactive prompt')
    parser.add_argument('--purge-settings', action='store_true', help='Also remove legacy Studio Qt preferences')
    parser.add_argument('--all-tools', action='store_true',
                        help='Also remove both legacy Boot Media Creator desktop/menu entries; keep source folders')
    parser.add_argument('--desktop-dir', type=Path, action='append', default=[],
                        help='Additional old/custom desktop folder inside HOME (repeatable)')
    args = parser.parse_args(argv)
    if not regular_user():
        print('Run on Linux as the desktop user, WITHOUT sudo. Nothing removed.', file=sys.stderr)
        return 2
    access = None
    try:
        home = Path.home().resolve(strict=True)
        access = HomeAccess(home)
        desktops = desktop_locations(home) + args.desktop_dir
        value = os.environ.get('XDG_CONFIG_HOME', '')
        config = Path(value) if value else None
        plan = plan_removal(access, desktops, args.purge_settings, config, all_tools=args.all_tools)
        print('Pi5 project uninstall plan (current user only)' if args.all_tools
              else APP_NAME+' uninstall plan (current user only)')
        for rel in plan.files:
            print('REMOVE', home/rel)
        for path, reason in plan.retained:
            print('RETAIN', path, '--', reason)
        print(f'{len(plan.files)} files selected; only empty application directories will be removed.')
        print('Preserved: Windows ISOs, workspaces, drivers, reports, signing keys, source checkout, .venv and apt dependencies.')
        if args.all_tools:
            print('Boot Media Creator ran from its source folder. This plan targets its marked launchers; source folders and .media-venv are kept.')
        if not args.purge_settings:
            print('Preferences kept. Use --purge-settings to remove Studio preferences too.')
        if args.dry_run:
            print('Dry run only. Nothing changed.')
            return 0
        active = running_studio()
        if active:
            raise UninstallError('Close the patcher, any older Studio/Creator apps and their command-line jobs first. Active PIDs: '+str(active))
        if not plan.files and not plan.directories:
            print('No removable installation found.' if not plan.retained else 'Nothing safely removable; review RETAIN entries.')
            return 3 if plan.retained else 0
        if not args.yes:
            try:
                answer = input('Close the patcher. Type UNINSTALL to remove the listed files: ')
            except EOFError:
                answer = ''
            if answer != 'UNINSTALL':
                print('Cancelled. Nothing changed.')
                return 0
        if running_studio():
            raise UninstallError('A project application started while confirming. Close it and retry.')
        count = apply_plan(access, plan)
        print(f'Removed {count} installed application files. User projects were not selected.')
        print('Menu icons may need a desktop refresh or sign-out/sign-in.')
        if plan.retained:
            print('Some unusual files/paths were retained for manual review; see docs/UNINSTALL.md.')
            return 3
        print('Application uninstall complete. Optional source/dependency cleanup: docs/UNINSTALL.md.')
        return 0
    except (OSError, ValueError) as exc:
        print(f'Uninstall stopped: {exc}. Inspect the plan before retrying.', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('\nInterrupted. Any already-removed files stay removed; see docs/UNINSTALL.md.')
        return 130
    finally:
        if access is not None:
            access.close()


if __name__ == '__main__':
    raise SystemExit(main())
