# Version 2.1.5 - ISO pipeline audit fixes

Registry compatibility checks now run for every boot, Windows and recovery environment before signing or image integration. The ISO BCD and EFI loader are also validated early. Cached hive extracts are reused, and only transaction logs belonging to edited hives are removed; unchanged boot/recovery BCD templates retain their logs.

Large working-file copies now respond to cancellation and stop when space is nearly exhausted. Unsupported output-path quoting is rejected before extraction. Failure handling preserves the original error when report or cleanup writes also fail, identifies any ISO already verified and published, and no longer claims that a missing log was saved. Automatic build progress no longer asks the user to perform a retired manual edition-selection step.

Regression coverage adds solid install.esd input, different recovery images per edition, Unicode output folders, read-only hive preflight, unchanged transaction-log preservation, copy cancellation/low-space checks, GUI failures without logs, and report-write failures after ISO publication. Existing patch profiles and test-signing remain unchanged. These are software checks; they cannot guarantee arbitrary Windows versions or hardware installation.

# Version 2.1.4 - handle deployment BCD templates separately from boot stores

The offline hive editor incorrectly required an explicit EFI application path in every Windows loader object of BCD-Template. This produced a missing Elements/12000002 error for a template entry such as {7254a080-1510-4e85-ac0f-e7fb3d444736}.

Template mode now preserves omitted paths and standard EFI/BIOS loader defaults while setting test-signing on typed Windows loader and boot-manager objects. It does not create loader paths or change other template settings. Malformed existing path values still fail. The ISO's actual boot store continues to require an explicit EFI WinPE loader. Hive errors now identify the operation and source filename.

Regression coverage includes the reported pathless object, mixed template layouts, native hive commit/readback and completed synthetic ISO builds that verify the prepared BCD template in every Windows edition. The previous optional-startup-file fix remains included. Driver patch recipes, signing, firmware policy, Microsoft Setup and the GUI workflow are unchanged. Software verification does not establish a completed build of the user's exact ISO or hardware installation.

# Version 2.1.3 - preserve optional Windows PE startup files

Version 2.1.2 stopped with wimlib error 49 when an original Setup image did not contain Windows/System32/winpeshl.ini. The builder now inventories both boot images before driver preparation and preserves the presence or absence of their startup files. It verifies existing content and continued absence after integration, while still requiring the original Setup executable in image 2. Inventory, extraction and corruption errors still stop the build.

The build report records the original startup file presence and hashes. No startup script is created or replaced. Driver profiles, signing, test-signing configuration, all-edition/recovery preparation and the supplied icon remain unchanged.

Update the installed app and rebuild from the same original ISO using a new output filename. The synthetic regression tests cover optional files present and absent, startup-file changes and incomplete or unreadable boot images. These checks do not establish a successful build of the user's exact ISO or physical Windows installation.

# Version 2.1.2 - supplied icon and complete README uninstall command

The app/window, GUI header, desktop and menu now use the owner's newly supplied icon, copied without altering its pixels. The existing asset path remains compatible with installation and removal.

The README includes a complete command that downloads and checksum-verifies the standalone uninstaller from this repository, removes recognized app snapshots/launchers/preferences and saves a local log. It works without a checkout or Qt and explains retained user data, source folders and shared dependencies.

Driver patching, signing, ISO building and the uninstaller's removal behavior are unchanged. This update does not require rebuilding an existing Windows ISO.

# Version 2.1.1 - self-contained references

The former repository has been deleted by its owner. Driver-profile provenance now links to a versioned note in this repository, and migration/licensing notes describe the current state. The README reports the maintenance version. Use release and uninstall downloads from this repository only.

Driver hashes, patch instructions, signing, image processing, GUI behavior, installation paths and uninstall behavior are unchanged. This is a metadata/documentation maintenance update; it does not establish any new hardware result.

# Version 2.1.0 - new repository and application name

The current ISO-only builder has moved to farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher and is now named **Raspberry Pi 5 Windows NVMe ISO Patcher**.

The window, desktop/menu entry, installer messages and report headings use the new name. The repository description is: Patch NVMe drivers in an original Windows ARM64 ISO and rebuild a modified installation ISO for Raspberry Pi 5.

The driver patch recipes, signing method, image integration and ISO verification are retained. The supplied icon, automatic logs, Microsoft Setup, both boot images, all Windows editions and recovery remain intact. No Pi firmware, custom Setup script, USB writer or retired diagnostic application is added.

Existing installation paths, launcher filename, ownership marker, Python module names and build-report schema remain compatible. The installer updates the existing Studio launcher. The standalone uninstaller covers the renamed application, earlier Studio snapshots and both legacy Creator launcher formats.

This repository starts from the reviewed current source snapshot and preserves its initial README commit. The owner subsequently deleted the former repository. Version 2.1.1 replaces the historical links with references maintained here; license and attribution remain intact.

Software and synthetic image checks do not establish successful Windows installation, driver binding or physical first boot. External deployment tools still control their own firmware and final boot configuration.
