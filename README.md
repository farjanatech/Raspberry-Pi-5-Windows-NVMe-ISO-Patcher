# The tool is not working!!! Raspberry Pi 5 Windows NVMe ISO Patcher

Patch NVMe drivers in an original Windows ARM64 ISO and rebuild a modified installation ISO for Raspberry Pi 5.

**Original Windows ARM64 ISO -> patched and signed NVMe drivers -> modified installation ISO.**

This is the renamed Pi5 NVMe Studio ISO builder, version 2.1.5. It preserves Microsoft Setup, both boot images, all Windows editions and recovery. It includes no Pi UEFI firmware, custom setup launcher, USB writer, disk formatter or diagnostic interface. Use a separate deployment tool such as WoR-Flasher afterward.

## Install on Raspberry Pi OS

Close any older project applications. Run as your normal desktop user:

```bash
cd ~
git clone https://github.com/farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher.git
cd Raspberry-Pi-5-Windows-NVMe-ISO-Patcher
bash install-raspberry-pi.sh
```

Open **Raspberry Pi 5 Windows NVMe ISO Patcher** from the desktop or application menu. Select the original ISO, choose a new output filename and click **Build ISO**. The app, menu and desktop use the supplied Raspberry Pi/Windows/NVMe icon.

Already using this new repository? Open its folder, run `git pull --ff-only`, then `bash install-raspberry-pi.sh`. Coming from the older repository? Use the fresh clone above; the new repository has independent history. The installer reuses the existing managed desktop entry, so an earlier Studio installation upgrades to the new display name. See [migration details](docs/MIGRATION.md).

The original ISO is never overwritten. Progress, a background log and a build report are saved locally. Supported driver versions must match the reviewed hashes exactly; unsupported inputs stop with an explanation.

Version 2.1.3 fixes the `winpeshl.ini does not exist in WIM image 2` build error. Original media may omit this optional startup file; the patcher preserves that absence instead of requiring or creating it. Update and reopen the app before rebuilding from the original ISO.

Version 2.1.4 also fixes the `BCD-Template` registry error ending in `Elements\12000002`. Deployment templates may omit a loader path or contain defaults for multiple firmware types. The patcher preserves these entries while enabling test-signing; the ISO's actual boot store still requires a valid EFI WinPE loader.

Version 2.1.5 checks every required registry hive before signing or image integration, preserves transaction logs for unchanged hives, and allows cancellation during large working-file copies. Unsupported output-path characters are rejected early. Error messages distinguish missing logs from saved logs and identify an ISO already verified and saved before a later reporting failure.

## Uninstall

Close the patcher, any older Studio/Boot Media Creator windows and their build jobs. Paste this entire block into a Raspberry Pi OS terminal as the same desktop user who installed them, **without sudo**. It works from any folder and does not require the source checkout or Qt.

The command downloads the standalone uninstaller from this repository, verifies its SHA256, removes recognized installed application snapshots, icons, desktop/menu entries and saved Studio preferences, and saves the result automatically in `~/Pi5-Uninstall-*/uninstall.log`. Both legacy Creator shortcut formats are included.

```bash
python3 -I - <<'PY'
import hashlib, pathlib, subprocess, sys, tempfile, urllib.request

url = "https://github.com/farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher/releases/download/v2.1.2/uninstall_desktop.py"
expected = "ed04770a96143a3abd35658a9d40d2fda1cba3451d02dd360107a02958072e01"

print("Downloading verified uninstaller...", flush=True)
with urllib.request.urlopen(url, timeout=60) as response:
    code = response.read(1024 * 1024)
if hashlib.sha256(code).hexdigest() != expected:
    raise SystemExit("Verification failed. Nothing executed.")

log = pathlib.Path(tempfile.mkdtemp(
    prefix="Pi5-Uninstall-", dir=pathlib.Path.home()
)) / "uninstall.log"

with tempfile.TemporaryDirectory(prefix="pi5-cleanup-") as folder:
    script = pathlib.Path(folder) / "uninstall.py"
    script.write_bytes(code)
    with log.open("w", encoding="utf-8") as output:
        result = subprocess.run(
            [sys.executable, "-I", "-X", "utf8", str(script),
             "--all-tools", "--purge-settings", "--yes"],
            stdout=output, stderr=subprocess.STDOUT
        )
    print(log.read_text(encoding="utf-8"))
    print("Saved log:", log)
    sys.exit(result.returncode)
PY
```

**Preserved:** your original/finished ISOs, disk images, drivers, reports, signing keys, downloaded source folders, their Python environments and shared system packages. The Creator apps ran from their source folders; removing their shortcuts does not erase those folders. After moving out any personal files, you can delete unwanted source folders in File Manager. Unknown files are retained and reported in the log.

For an offline uninstall from an existing checkout, run `bash uninstall-raspberry-pi.sh --all-tools --purge-settings --yes` there. See [uninstall details](docs/UNINSTALL.md) for previews, custom desktop folders and retained files.

## Modified installation ISO

- Original Microsoft Setup and EFI boot programs are retained.
- `sources/boot.wim` retains WinPE at index 1 and Setup at index 2.
- `sources/install.wim` contains every original Windows edition; it is not split into SWM files.
- The existing patch recipes, signed SYS/INF/CAT generation and required original Windows storage components are retained.
- Matching drivers and public signing certificates are prepared in Setup, Windows and recovery. No private signing keys enter the ISO.
- Test-signing is configured in the ISO boot BCD and Windows BCD template. An external deployment tool can replace these settings.

See [ISO details](docs/ISO_BUILDER.md), [compatibility and WoR-Flasher](docs/COMPATIBILITY.md), and [uninstall](docs/UNINSTALL.md).

The ISO layout is prepared for WoR-Flasher's ISO-input path. WoR-Flasher adds its own installer and firmware during flashing. Its Pi 5 firmware default at the documented source review differed from the previously requested Damian release. Successful WoR deployment and Windows first boot on the user's Pi have not been verified.

## Development

Automated checks exercise synthetic ISO/WIM files, package signatures, registry changes and the GUI; no private Windows files or user-input archives are used in public CI. Run `python tools/verify_source.py` to check the reviewed source snapshot. Internal module and installation identifiers retain the earlier names for compatibility; they are not extra applications.
