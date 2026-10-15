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
