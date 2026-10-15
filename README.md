# Raspberry Pi 5 Windows NVMe ISO Patcher

Patch NVMe drivers in an original Windows ARM64 ISO and rebuild a modified installation ISO for Raspberry Pi 5.

**Original Windows ARM64 ISO -> patched and signed NVMe drivers -> modified installation ISO.**

This is the renamed Pi5 NVMe Studio ISO builder, version 2.1.0. It preserves Microsoft Setup, both boot images, all Windows editions and recovery. It includes no Pi UEFI firmware, custom setup launcher, USB writer, disk formatter or diagnostic interface. Use a separate deployment tool such as WoR-Flasher afterward.

## Install on Raspberry Pi OS

Close any older project applications. Run as your normal desktop user:

```bash
cd ~
git clone https://github.com/farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher.git
cd Raspberry-Pi-5-Windows-NVMe-ISO-Patcher
bash install-raspberry-pi.sh
```

Open **Raspberry Pi 5 Windows NVMe ISO Patcher** from the desktop or application menu. Select the original ISO, choose a new output filename and click **Build ISO**. The supplied icon is retained.

Already using this new repository? Open its folder, run `git pull --ff-only`, then `bash install-raspberry-pi.sh`. Coming from the older repository? Use the fresh clone above; the new repository has independent history. The installer reuses the existing managed desktop entry, so an earlier Studio installation upgrades to the new display name. See [migration details](docs/MIGRATION.md).

The original ISO is never overwritten. Progress, a background log and a build report are saved locally. Supported driver versions must match the reviewed hashes exactly; unsupported inputs stop with an explanation.

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
