# Uninstall Raspberry Pi 5 Windows NVMe ISO Patcher

This removes the **Raspberry Pi OS desktop application**, not a Windows driver.
It works with the normal per-user snapshots made by the 0.2.x, 0.3.x, 0.4.0 and
0.4.1-dev, 1.x and 2.x installers, including older snapshots left behind by upgrades.
The renamed 2.1.x patcher uses the same managed installation paths and ownership marker, so both old and new installations are recognized.
It requires only Linux system Python 3; no Qt, pip, signing or ISO tools.

**No uninstall action is run merely by downloading or updating this repository.**
Close the patcher and any older Studio windows; let any build/command-line jobs finish before uninstalling.
Run the commands as the same desktop user who installed the application, **without sudo**.

## Remove all previous project desktop tools

Close the patcher, Studio and Boot Media Creator, then use the current uninstaller:

```bash
bash uninstall-raspberry-pi.sh --all-tools --purge-settings --yes
```

This removes recognized patcher/Studio application snapshots and preferences, plus the
marked menu/desktop entries for both earlier Boot Media Creator editions
(`pi5-boot-media.desktop` and `pi5-boot-media-creator.desktop`). It does not install
the new patcher version. Add `--dry-run` instead of `--yes` for a preview.

The Creator installers ran directly from their downloaded source folders; they
did not create separate installed copies. Those source folders, `.venv` and
`.media-venv` remain, along with your ISOs, images, reports and shared system
packages. Delete unwanted downloaded source folders in File Manager after moving
out any output or input files you wish to keep. The uninstaller does not guess
which project folders may contain personal data.

## 1. Get the uninstaller

For an existing Git checkout, open a terminal in that repository and run:

```bash
git pull --ff-only
```

Do not force-reset local changes. You do **not** need to rerun the installer
before uninstalling an older version. If the checkout is gone, download the
current repository with **Code → Download ZIP**, extract it, and open a terminal
in that extracted folder. The uninstaller can be run from any working directory.
Future installations also include it inside each installed snapshot, alongside
`pi5_nvme_gui.py`; run the same commands from that snapshot folder if necessary.

## 2. Preview, then uninstall

Preview the exact files selected for removal (this changes nothing):

```bash
bash uninstall-raspberry-pi.sh --dry-run
```

Remove the installed application, icons and launchers after reviewing the plan:

```bash
bash uninstall-raspberry-pi.sh
```

Type **UNINSTALL** at the confirmation prompt. Any other response cancels.
For automated use, `--yes` explicitly confirms the printed plan; it does not
bypass path, ownership, changed-file or running-process checks.

To also forget Studio's remembered GUI preferences, preview and then use:

```bash
bash uninstall-raspberry-pi.sh --dry-run --purge-settings
bash uninstall-raspberry-pi.sh --purge-settings
```

`--purge-settings` removes only Studio's own Qt preferences, **not projects or
signing keys**. The equivalent Python command is:

```bash
/usr/bin/python3 uninstall_desktop.py --purge-settings
```

There is no need to launch Qt or activate `.venv`. The shell wrapper deliberately
uses system Python so a missing/broken application environment is not a blocker.

## What is removed

| Item | Normal uninstall | With `--purge-settings` |
| --- | --- | --- |
| Recognized versioned app snapshots under `~/.local/share/pi5-nvme-studio/` | Known installed files, their icons and matching Python caches | Same |
| App menu entry `~/.local/share/applications/pi5-nvme-studio.desktop` | Removed only with Studio's ownership marker | Same |
| Desktop shortcut `pi5-nvme-studio.desktop` | Removed from `~/Desktop` and the currently configured desktop directory, only with the marker | Same |
| `~/.config/farjanatech/Pi5NVMeStudio.conf` | Kept | Removed |
| Corresponding settings under an absolute `$XDG_CONFIG_HOME` inside HOME | Kept | Removed |
| Empty app snapshot subdirectories and the empty app root | Removed | Same |

The icon was installed **inside the app snapshot**, not into a shared system icon
theme. Removing the snapshot's app files removes that icon as well. No systemd
service or autostart job was installed by the normal desktop installer.

The uninstaller does not recursively erase the application root. It selects only
known installed filenames inside a recognized snapshot, removes those files and
then removes empty app directories. Unknown files, folders, links, mounted paths,
foreign-owned paths and snapshots with unverifiable identities are retained and
reported. This protects data accidentally saved inside an application directory.

## What is kept (and how to finish optional cleanup)

**Windows ISOs, extracted WIM/ESD images, collections, reports, patched drivers,
generated packages, diagnostic media and private signing keys are always kept.**
They are user data, not disposable installation files. The uninstaller does not
read workspace paths from GUI preferences or erase those destinations.

**Downloaded source ZIPs, Git checkouts and their optional `.venv` are kept.**
After uninstalling, review the source folder in File Manager. Move out any projects,
inputs, keys or local code changes you need. Then you may delete that dedicated
source folder, including its `.venv`, and unwanted source ZIP downloads through
File Manager. If keeping the source but not its environment, remove only its
reviewed, app-dedicated `.venv` folder. Do not delete a venv used by another
checkout/application. Studio's fallback environment lives in the source checkout,
not under the installed snapshot. This cleanup is intentionally not automated.

**APT packages and shared Python/Qt libraries are kept.** Tools such as Python,
OpenSSL, Qt, 7-Zip, wimlib, xorriso, osslsigncode, hivex and desktop libraries may
be used by other programs. Earlier installers did not record which packages were
already present. A blanket purge or automatic `apt autoremove` is therefore not
part of uninstall. To reclaim additional space, inspect APT history and review
individual packages in the system package manager; remove only tools you know
are no longer required. Do not purge system Python, OpenSSL, Qt or desktop
libraries simply because Studio used them.

**The GitHub repository is not deleted or changed.** There is no network action,
disk formatting, bootloader edit, certificate-store change or Windows-driver
rollback. If you separately installed a Windows driver or changed Windows/UEFI
test settings, those are outside this Linux application uninstaller's scope.

## Custom desktops, unusual layouts and manual removal

A localized desktop (for example `Bureau`) is discovered with
`xdg-user-dir DESKTOP`. If a previous shortcut lives in an old/custom folder
**inside your HOME**, add it explicitly:

```bash
bash uninstall-raspberry-pi.sh --dry-run --desktop-dir "$HOME/Bureau"
bash uninstall-raspberry-pi.sh --desktop-dir "$HOME/Bureau"
```

The option is repeatable and only targets the exact `pi5-nvme-studio.desktop`
filename with the ownership marker. Manually renamed/copied shortcuts are not
searched across your account; review and remove those copies in File Manager.
An external/symlinked desktop or settings directory is not traversed by the
uninstaller. Inspect it manually rather than running as root or removing guards.

For manual cleanup, close the patcher and any older Studio windows and inspect these exact locations:

```text
~/.local/share/pi5-nvme-studio/
~/.local/share/applications/pi5-nvme-studio.desktop
<your desktop folder>/pi5-nvme-studio.desktop
~/.config/farjanatech/Pi5NVMeStudio.conf
```

Inspect each versioned snapshot before removing leftovers; preserve personal
files. Never erase all of `~/.local/share`, `~/.config`, your desktop, the
`farjanatech` settings directory, or an output/key parent directory. A broken or
partly deleted snapshot may no longer pass automatic identity checks and require
this manual review. The default installer did not install anything in `/opt` or
`/usr/local`; do not remove guessed system-wide paths. Installations created by
other scripts/accounts need their own reviewed removal procedure.

## Verification and troubleshooting

Run the dry run again. A normal repeat should select **0 files**. With settings
purged, the app-specific `.conf` should also be absent. Source folders and shared
packages remain until optional cleanup. The app entry should disappear from the
menu; refresh the desktop or sign out/in if its icon is cached.

A `RETAIN` line means something was intentionally left for review. Exit codes:
`0` = completed, previewed, cancelled by confirmation, or already absent;
`2` = refused/error; `3` = known files removed (or nothing safely removable) but
unusual entries remain; `130` = interrupted. Check the text, not just the code.
Permissions/I/O errors may leave a partial uninstall; already removed files are
not restored. Preview again and follow the manual procedure for remaining files.
The Linux process check is best-effort, so still close all app/build jobs first.
It never kills a process for you. **Do not use sudo to silence a refusal.**

Automated tests use temporary fake homes/snapshots and do not uninstall the real
user's application. They cover old versions, data preservation, symlinks, settings,
custom desktops, repeated execution, cancellation and changed-file checks. This
is not a new Windows-driver or Pi storage compatibility test.

## Path references

- The actual installation allowlist/paths are in [`install_desktop.py`](../install_desktop.py).
- Qt documents [QSettings on Unix](https://doc.qt.io/qt-6/qsettings.html#platform-specific-notes), including the user configuration location and XDG override.
- The uninstaller uses [Python descriptor-relative filesystem operations](https://docs.python.org/3/library/os.html#files-and-directories); it never imports code from installed snapshots or uses recursive `rm`/`rmtree`.
