#!/usr/bin/env python3
"""Linux-only, local-test embedded signing for exact approved unsigned outputs.

NOT driver installation. No catalog, trust-store edit, BCD edit or ISO output.
The private key goes in a separate user-selected directory, never in the result.
Requires OpenSSL and osslsigncode. No timestamp or external signing service used.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
from typing import Optional

import pi5_nvme_tool as core


class SigningError(Exception):
    pass


def require(ok: bool, text: str) -> None:
    if not ok:
        raise SigningError(text)


def tools() -> dict:
    return {name: shutil.which(name) for name in ("openssl", "osslsigncode")}


def command(argv: list, timeout: int = 120) -> str:
    try:
        result = subprocess.run(argv, shell=False, capture_output=True, timeout=timeout,
                                check=False, env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SigningError(f"{Path(argv[0]).name} did not finish successfully: {exc}") from exc
    text = (result.stdout + result.stderr).decode("utf-8", "replace")
    require(result.returncode == 0, f"{Path(argv[0]).name} failed: {text[-4000:]}")
    return text[-16384:]


def unsigned_content(signed: bytes, original_size: int) -> bytes:
    """Strip only the new Authenticode envelope and restore its PE checksum.

    A comparison with the reviewed unsigned input proves that signing did not
    alter instructions, imports, version resources or loader metadata.
    """
    pe = core.PE(signed)
    at, length = pe.directory(4)
    require(at == original_size and length >= 8 and at + length == len(signed),
            "Unexpected signature layout; signed output was rejected.")
    require(pe.machine == core.MACHINE_ARM64, "Signed result is not ARM64.")
    require(pe.u32(pe.checksum_offset) == core.pe_checksum(signed, pe.checksum_offset),
            "Signed PE checksum is invalid.")
    restored = bytearray(signed[:at])
    struct.pack_into("<II", restored, pe.optional + 112 + 4 * 8, 0, 0)
    struct.pack_into("<I", restored, pe.checksum_offset, core.pe_checksum(restored, pe.checksum_offset))
    return bytes(restored)


def new_dir(path: Path) -> Path:
    require(not path.exists() and not path.is_symlink(), f"Choose a NEW directory: {path}")
    require(path.parent.is_dir(), f"Parent directory does not exist: {path.parent}")
    path.mkdir(mode=0o700)
    return path


def contained(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def sign_candidate(source: Path, output: Path, key_directory: Path,
                   profiles: Optional[list] = None) -> dict:
    """Create a new local key and sign a whitelisted unsigned candidate only.

    profiles is an explicit caller-supplied allowlist for developer test fixtures;
    normal CLI calls use the bundled exact-input profiles.
    """
    require(sys.platform == "linux", "This stage is implemented for Linux only.")
    source, output, key_directory = (p.expanduser().absolute() for p in (source, output, key_directory))
    require(source.is_file() and not source.is_symlink(), "Select a regular unsigned SYS, not a symlink.")
    paths = [p.resolve() for p in (source, output, key_directory)]
    require(not contained(paths[0], paths[1]) and not contained(paths[0], paths[2]),
            "Output/key directory may not contain the input.")
    require(not contained(paths[1], paths[2]) and not contained(paths[2], paths[1]),
            "Private keys and distributable output must be in SEPARATE directories.")
    for p in (output, key_directory):
        require(not p.exists() and not p.is_symlink() and p.parent.is_dir(),
                "Both output and key directory must be new, with existing parent directories.")
    blob = core.read_file(source)
    digest = core.sha256(blob)
    known = core.load_profiles([]) if profiles is None else profiles
    for p in known:
        core.validate_profile(p)
    matched = [p for p in known if p["output_sha256"] == digest]
    require(len(matched) == 1, "SYS is not an exact reviewed UNSIGNED output. No signing was attempted.")
    profile = matched[0]
    pe = core.PE(blob)
    require(pe.machine == core.MACHINE_ARM64 and pe.directory(4) == (0, 0)
            and pe.file_version() == profile["source_version"], "Candidate metadata differs from its profile.")
    require(pe.u32(pe.checksum_offset) == core.pe_checksum(blob, pe.checksum_offset),
            "Unsigned candidate checksum is invalid.")
    executables = tools()
    require(all(executables.values()), "Install the openssl and osslsigncode Linux packages first.")
    new_dir(key_directory)
    new_dir(output)
    key = key_directory / "local-test-key.pem"
    cert = output / "local-test-certificate.pem"
    cert_der = output / "local-test-certificate.cer"
    staged = output / ".unsigned-input.tmp"
    signed = output / ".signed-output.tmp"
    final = output / "stornvme.sys"
    try:
        # Private material is never printed, embedded in the output, or trusted on
        # the host. A 0700 directory protects it even during OpenSSL creation.
        command([executables["openssl"], "genpkey", "-algorithm", "RSA",
                 "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)])
        key.chmod(stat.S_IRUSR | stat.S_IWUSR)
        command([executables["openssl"], "req", "-new", "-x509", "-sha256", "-days", "365",
                 "-key", str(key), "-subj", "/CN=Pi5 NVMe LOCAL TEST ONLY",
                 "-addext", "basicConstraints=critical,CA:FALSE",
                 "-addext", "keyUsage=critical,digitalSignature",
                 "-addext", "extendedKeyUsage=codeSigning", "-out", str(cert)])
        command([executables["openssl"], "x509", "-in", str(cert), "-outform", "DER", "-out", str(cert_der)])
        with staged.open("xb") as f:
            f.write(blob)
        command([executables["osslsigncode"], "sign", "-h", "sha256", "-certs", str(cert),
                 "-key", str(key), "-n", "Pi5 NVMe experimental local test",
                 "-in", str(staged), "-out", str(signed)])
        verification = command([executables["osslsigncode"], "verify", "-CAfile", str(cert), "-in", str(signed)])
        result = core.read_file(signed)
        require(unsigned_content(result, len(blob)) == blob,
                "Signing changed reviewed unsigned image content; result rejected.")
        require(core.sha256(core.read_file(source)) == digest, "Input changed during signing.")
        signed.rename(final)
        report = {
            "schema": 1, "status": "EMBEDDED_TEST_SIGNATURE_VERIFIED_ONLY",
            "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "profile": profile["id"],
            "driver_version": profile["source_version"], "unsigned_sha256": digest,
            "signed_sha256": core.sha256(result), "certificate_sha256": core.sha256(cert_der.read_bytes()),
            "image_content_unchanged": True, "private_key_in_output": False,
            "catalog_generated": False, "driver_installed": False, "iso_generated": False,
            "windows_load_tested": False, "hardware_tested": False,
            "signature_verifier": "osslsigncode with this local self-signed certificate as trust anchor",
            "verification_log": verification,
            "limitations": ["This certificate is NOT a Microsoft or production driver signature.",
                            "No trusted root or test-signing setting was changed on any OS.",
                            "No catalog was generated; this is NOT an installable driver package.",
                            "Windows kernel acceptance, driver binding and boot remain untested.",
                            "No modified ISO has been produced."]}
        (output / "signing-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (output / "NOT_READY_TO_INSTALL.txt").write_text(
            "EMBEDDED LOCAL TEST SIGNATURE ONLY. NOT AN INSTALLABLE DRIVER PACKAGE.\n"
            "No INF/catalog integration, first-boot configuration, or ISO is supplied.\n"
            "Do not replace the installed Windows storage driver with this file.\n"
            "Keep the separate private-key directory private. Do not upload its contents.\n", encoding="utf-8")
        return report
    except Exception:
        # Leave audit material, but never publish a partly verified SYS as final.
        raise
    finally:
        for p in (staged, signed):
            if p.is_file() and not p.is_symlink():
                p.unlink()


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sys_file", type=Path, help="Previously built exact-profile unsigned SYS")
    p.add_argument("--out", type=Path, required=True, help="New result directory")
    p.add_argument("--key-dir", type=Path, required=True, help="New private-key directory OUTSIDE the result")
    p.add_argument("--acknowledge-experimental", action="store_true",
                   help="Required: accept a local test certificate, NOT an installable package")
    a = p.parse_args(argv)
    if not a.acknowledge_experimental:
        p.error("--acknowledge-experimental is required; this does not install or prepare bootable media")
    try:
        r = sign_candidate(a.sys_file, a.out, a.key_dir)
        print(r["status"])
        print("Signed file SHA-256:", r["signed_sha256"])
        print("Private key is outside the output. Keep it private.")
        print("No catalog, driver installation, boot configuration, or modified ISO was produced.")
        return 0
    except (SigningError, core.ToolError, OSError, ValueError) as exc:
        print(f"Signing stopped: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
