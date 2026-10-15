# Version 2.1.0 - new repository and application name

The current ISO-only builder has moved to farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher and is now named **Raspberry Pi 5 Windows NVMe ISO Patcher**.

The window, desktop/menu entry, installer messages and report headings use the new name. The repository description is: Patch NVMe drivers in an original Windows ARM64 ISO and rebuild a modified installation ISO for Raspberry Pi 5.

The driver patch recipes, signing method, image integration and ISO verification are retained. The supplied icon, automatic logs, Microsoft Setup, both boot images, all Windows editions and recovery remain intact. No Pi firmware, custom Setup script, USB writer or retired diagnostic application is added.

Existing installation paths, launcher filename, ownership marker, Python module names and build-report schema remain compatible. The installer updates the existing Studio launcher. The standalone uninstaller covers the renamed application, earlier Studio snapshots and both legacy Creator launcher formats.

This repository starts from the reviewed current source snapshot; experimental history and previous release downloads remain in the older repository. Its original README commit is preserved. License and attribution are retained; historical profile-evidence links now point to an immutable source revision.

Software and synthetic image checks do not establish successful Windows installation, driver binding or physical first boot. External deployment tools still control their own firmware and final boot configuration.
