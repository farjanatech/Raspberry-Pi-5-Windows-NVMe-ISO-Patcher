# Recorded NVMe driver provenance

This note preserves the public attribution and profile records used by the ISO patcher after the owner deleted the former repository. It contains no Windows binaries, private input archives, signing keys or hardware logs, and is not a new real-input or hardware test report.

## Source method

The original numerical NVMe recipe, helper bytes and reference hashes are attributed to damian5466/rpi5-windows-drivers `nvme/build.py`, recorded Git blob `c0a207c6a0eec2e7fd19de9112ee6d308054ed06`. See [upstream source](https://github.com/damian5466/rpi5-windows-drivers/blob/main/nvme/build.py) and [licensing/attribution](../NOTICE.md).

The upstream 10.0.26100.9539 profile is retained in [pi5_nvme_tool.py](../pi5_nvme_tool.py) and [its JSON profile](../upstream-profile-26100.9539.json). The exact-input ports for [10.0.26100.1](../profiles/arm64-26100.1.json) and [10.0.26100.9278](../profiles/arm64-26100.9278.json) were imported with the existing builder. Their records identify the review level as `REAL_INPUT_STATIC_ONLY`, dated 2026-10-12.

## Existing profile records

Each JSON profile records the original SYS and INF SHA256 hashes, expected patched output SHA256, instruction offsets and expected bytes, helper placement, relocation information and disassembly-context hashes. Unknown input pairs remain blocked. Version 2.1.1 changes the provenance URL only; the recorded recipe values and binary hashes remain identical to version 2.1.0.

The recorded limitations remain: static reproducibility does not establish correct DMA behavior, driver binding, Windows kernel trust or physical installation/boot. The inherited helper assumes fixed 4 KiB pages and 64-byte cache lines. Local package-signing and synthetic image checks are separate from hardware validation. This maintenance update requests no repeat uploads or hardware tests.

The current source history begins with the [application import](https://github.com/farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher/tree/6e879254347ee7dfca7e092a4e44eeffca0256e6); the former source revision `fa592d1798b38ede557186743a9c0043a24f6235` is retained here only as an import identifier, not as a live download location.
