# Compatibility

The patcher runs on 64-bit Raspberry Pi OS / Debian-family Linux. It requires original ARM64 Windows media with standard boot.wim images 1 and 2 and a bootable Setup image at index 2. Input install.wim or install.esd is accepted; the output is install.wim.

The previously reviewed driver recipes and exact input hashes remain in pi5_nvme_profiles.py and profiles/. Unknown originals stop the build. The supported controller binding remains PCI VEN_1E4B DEV_1202 from the supplied project evidence. No broader hardware claim is made.

## WoR-Flasher

The [Botspot WoR-Flasher source](https://github.com/Botspot/wor-flasher/blob/main/install-wor.sh), reviewed on 2026-10-14, copies boot/, efi/, sources/boot.wim and sources/install.wim from an ISO. It then adds its own PE installer to boot.wim index 2 and its own EFI files and Pi firmware to the flashed device. The patcher prepares that expected file layout; it does not modify, bundle or run WoR-Flasher.

At the 2026-10-14 source review, WoR-Flasher selected worproject/rpi5-uefi v0.3 for Pi 5. That differs from the owner's previously pinned farjanatech/rpi5-uefi damian-edition-v0.1.0-rc1. To retain that requirement, WoR-Flasher's firmware source/cache must be configured separately before flashing. The patcher's ISO intentionally contains neither release.

WoR-Flasher may replace boot settings and caches files extracted from earlier ISOs. Use the new ISO as a new source rather than assuming a cached previous extraction was refreshed. Driver handling, firmware choice, final test-signing state, deployment and physical first boot through WoR-Flasher have not been verified on the user's Pi.
