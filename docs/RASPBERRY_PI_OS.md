# Raspberry Pi OS Desktop

Use 64-bit Raspberry Pi OS. Open a terminal inside the repository folder and run:

```bash
bash install-raspberry-pi.sh
```

Run as the normal desktop user. The installer requests sudo only to install system dependencies. It uses distribution Qt packages where available, otherwise a local Python virtual environment. It installs one application-menu entry and the supplied desktop icon. Updates replace the managed launcher with a snapshot of the current ISO builder.

Open Raspberry Pi 5 Windows NVMe ISO Patcher, select the original Windows ARM64 ISO, choose a new output ISO filename and click Build ISO. Keep enough free local disk space for multiple image working copies; the app checks an estimate before building. A FAT32 output disk cannot hold a large finished ISO. Use a filesystem supporting large files.

The input stays unchanged. The finished ISO and automatically saved build log/report are the output. Flashing and Windows deployment are handled by your separately chosen external tool.
