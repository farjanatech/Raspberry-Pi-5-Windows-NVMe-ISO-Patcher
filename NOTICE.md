# Provenance and licensing notice

The existing exact-profile NVMe patch core and reviewed input ports are retained. Earlier experimental applications are not shipped. Their history remains in the previous repository: https://github.com/farjanatech/rpi5-nvme-version-aware-tool . See docs/MIGRATION.md for the imported source revision.

The original numerical NVMe recipe, helper bytes and reference hashes are
attributed to damian5466/rpi5-windows-drivers `nvme/build.py`, Git blob
`c0a207c6a0eec2e7fd19de9112ee6d308054ed06`:
https://github.com/damian5466/rpi5-windows-drivers/blob/main/nvme/build.py

No Microsoft driver binaries, Microsoft INF inputs or private signing keys are
distributed. Synthetic fixtures are not usable storage drivers. This is not an
official Microsoft, Raspberry Pi or upstream-author product or endorsement.
The desktop icon derives from the owner's supplied image; third-party marks
remain their respective owners' marks.

## Licensing

The owner-selected GNU GPL version 3 [LICENSE](LICENSE) is preserved unchanged.
This notice does not relicense third-party material or grant rights to Microsoft
binaries. Attribution and applicable third-party obligations remain relevant.

The catalog encoder adapts the .NET FileCatalog format implementation. Its MIT
notice is preserved in `third_party/dotnet-filecatalog-MIT.txt`; see
`pi5_studio/catalog.py` for source provenance.
