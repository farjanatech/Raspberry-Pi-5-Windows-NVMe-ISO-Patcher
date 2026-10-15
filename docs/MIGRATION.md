# Migration from Pi5 NVMe Studio

The active project is [Raspberry Pi 5 Windows NVMe ISO Patcher](https://github.com/farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher). Version 2.1.0 continues the ISO-only 2.0.0 builder under the owner's new name and repository.

## Existing installations

Close Studio and clone the new repository into its own folder, using the README commands. The new repository has independent history, so changing an old checkout's remote and running `git pull` is not the migration procedure. Keep old source folders until the new application is installed; an older launcher may reference their Python environment.

Run `bash install-raspberry-pi.sh` in the new clone. It updates the managed desktop and menu entries to the new display name and points them at the new versioned snapshot. It creates no second application entry. No Windows ISO, driver output, build log, USB or NVMe contents are moved or deleted.

If you want an uninstall first, run the cleanup before installing the renamed application. The updated `uninstall_desktop.py --all-tools --purge-settings --yes` uses only Linux system Python and covers both product names plus old Creator launchers. [Uninstall details](UNINSTALL.md) explain retained source folders and shared dependencies. Because both product names share the same installation identity, the cleanup also removes the newly installed patcher if run afterward.

## Stable compatibility identifiers

The `pi5_studio` module, `pi5_nvme_gui.py` entry point, `pi5-nvme-studio.desktop` filename, `~/.local/share/pi5-nvme-studio/` snapshot directory and `X-Pi5-NVMe-Studio=true` ownership marker remain stable. Old settings paths and the `studio_version` build-report field remain readable. These are implementation identifiers, not additional tools or visible product branding.

The original owner-supplied icon, GNU GPL v3 license and third-party notices are unchanged. The imported source was the old repository's [fa592d1798b38ede557186743a9c0043a24f6235 snapshot](https://github.com/farjanatech/rpi5-nvme-version-aware-tool/tree/fa592d1798b38ede557186743a9c0043a24f6235). Previous releases and experimental source history stay there; no private inputs or old binary artifacts are copied here.
