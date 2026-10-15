# Original ISO to finished ISO

Run Raspberry Pi 5 Windows NVMe ISO Patcher on 64-bit Raspberry Pi OS Desktop. Choose an original Windows ARM64 ISO and a new output filename, then click **Build ISO**. The build saves its log and JSON report beside the output in a hidden `.<output-name>-build-*` folder. No destination disk is selected or erased.

## Driver preparation

The existing patch recipes and signing code remain intact. Each original SYS/INF pair from both boot images, every Windows edition and each distinct recovery image must match a reviewed profile. Unknown versions are rejected rather than patched at guessed offsets. Each resulting package contains pi5nvme.sys, pi5nvme.inf, pi5nvme.cat and its public test certificate. Original stornvme.sys, its original package, and the image's existing storport/auxiliary components are preserved.

The SYSTEM hive retains the established boot-service redirection to the signed alternate binary. The complete matching package is copied to Windows/Drivers/Pi5NVMe, appended to Windows DevicePath, and its certificate is added to the extracted image's ROOT and TrustedPublisher stores. The host's trust stores are never modified. This follows Microsoft's [preloaded-package discovery mechanism](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/preloading-driver-packages); it does not claim native offline DISM servicing on Linux.

Both boot images additionally receive the installation package in $WinPEDriver$/Pi5NVMe for [Microsoft Setup's automatic driver discovery](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/limitations-dollar-sign-winpedriver-dollar-sign), and in drivers/Pi5NVMe for a deployment tool's driver collection. To avoid automatically selecting the wrong binary, all installation editions must share the same exact package; recovery and WinPE may use separate reviewed versions.

## Preserved Setup and output

Microsoft Setup executables, startnet.cmd and winpeshl.ini are not replaced. The builder inventories both boot images before driver preparation, then verifies the original startup files after integration. Optional startup files that were absent must remain absent; existing files must retain their exact contents. The original sources/setup.exe remains required in boot image 2. Presence and hashes are saved in the build report; read errors still stop the build. The output retains both boot images with index 2 bootable and writes a single sources/install.wim, even when the input uses install.esd. All Windows editions and nested recovery images receive their matching driver preparation.

Version 2.1.2 incorrectly required winpeshl.ini in boot image 2. Version 2.1.3 accepts its absence without adding a replacement script. Microsoft documents the [Windows PE startup behavior when winpeshl.ini is absent](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-create-apps?view=windows-11).

The original Microsoft EFI loader and boot-image file remain. No Raspberry Pi firmware archive, RPI_EFI.fd, custom setup executable, answer file, diskpart plan or formatting script is added. Original storage automount/SAN policies are retained.

Test-signing is set in the ISO's EFI boot BCD and each Windows edition's BCD template. Secure Boot must be off for locally test-signed drivers. WoR-Flasher or another deployer may replace boot configuration; an ISO cannot guarantee settings in an externally generated BCD.

WIM integrity, signed package membership, changed-file readback, original Setup files, final ISO contents and original-input identity are checked before the new output is published. Private keys are deleted after signing and never placed in the ISO or public CI.

## Limits

Software checks establish file and image consistency, not successful driver binding, installation or first boot on physical Pi hardware. The builder does not collect hardware diagnostics or request repeat uploads. See [compatibility](COMPATIBILITY.md) before external deployment.
