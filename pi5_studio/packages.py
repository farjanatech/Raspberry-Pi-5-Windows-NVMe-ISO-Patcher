"""Build native-Linux, cryptographically checked experimental NVMe packages.

Input is the builder's collection folder. Every SYS/INF pair is checked
again; reports are not trusted as authorization. Nothing installs a driver,
changes an ISO, edits BCD/registry, or changes a certificate store. Keys are
created separately from package output. Windows package acceptance is untested.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Callable, Optional
import zipfile

import pi5_nvme_tool as core
import linux_test_sign as signer
from . import APP_NAME
from .catalog import build_catalog, check_membership, pe_digest, require_sha256_signature, CatalogError

STATUS = "LOCAL_TEST_PACKAGE_CRYPTO_VERIFIED"
PACKAGE_FILES = ("pi5nvme.sys", "pi5nvme.inf", "pi5nvme.cat", "local-test-certificate.pem", "local-test-certificate.cer")
LIMITATIONS = [
    "Linux signature and catalog membership checks are NOT Windows driver-package validation.",
    "InfVerif, Inf2Cat signability, Windows catalog lookup, driver binding and kernel trust have NOT been validated.",
    "The renamed pi5nvme service/binary are an experimental deployment identity; runtime behavior is NOT tested.",
    "No driver was installed, no certificate was trusted, and no BCD or Windows registry was changed.",
    "No Windows image was modified. No bootable ISO was generated.",
    "Do not replace your installed Windows storage driver or test on your only boot disk.",
    "Packages contain locally derived Microsoft files: do not commit them or private keys to a public repository.",
]


class PackageError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def safe_path(path: Path) -> Path:
    path = path.expanduser().absolute()
    require(not any(ord(c) < 32 for c in str(path)), "Paths may not contain control characters")
    require(all(not p.is_symlink() for p in (path, *path.parents)), "Symlinked input/output paths are not supported")
    return path.resolve()


def read_regular(path: Path, limit: int = core.MAX_FILE) -> bytes:
    """Avoid following symlinks or blocking on a FIFO substituted for an input."""
    path = safe_path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "Input must be a regular file")
        require(before.st_size <= limit, "Input exceeds the size limit")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= limit and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "Input changed during reading")
    return data


def native_versions() -> dict:
    paths = signer.tools()
    require(all(paths.values()), "Install openssl and osslsigncode before preparing packages")
    code = signer.command([paths["osslsigncode"], "--version"])
    version = re.search(r"osslsigncode\s+(\d+)\.(\d+)", code)
    require(version is not None and tuple(map(int, version.groups())) >= (2, 8),
            "This stage requires osslsigncode 2.8 or newer; the installed version is unsupported")
    openssl = signer.command([paths["openssl"], "version"])
    return {"osslsigncode": code.splitlines()[0], "openssl": openssl.splitlines()[0]}


def write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def hardware_id(value: str) -> str:
    value = value.upper()
    require(len(value) <= 200 and bool(re.fullmatch(r"PCI\\[A-Z0-9_&]+", value)), "Invalid PCI hardware/compatible ID")
    return value


def package_inf(original: bytes, profile: dict, binding: str) -> bytes:
    """Keep reviewed installation sections while isolating filename and service.

    This constrained transformation is NOT a replacement for Windows InfVerif.
    Native packages are experimental until the renamed service has been tested.
    """
    binding = hardware_id(binding)
    text = core.decode_inf(core.make_inf(original, profile, binding))
    sections = core.inf_sections(text)
    require("stornvme_service_inst" in sections, "Missing reviewed boot service section")
    service = sections["stornvme_service_inst"]
    # Numeric service constants may be literals or one [Strings] substitution.
    strings = core.inf_values(sections.get("strings", []))
    for key, value in (("StartType", 0), ("ServiceType", 1), ("ErrorControl", 3)):
        matches = [line.split("=", 1)[1].split(";", 1)[0].strip()
                   for line in service if re.match(rf"\s*{key}\s*=", line, re.I)]
        require(len(matches) == 1, f"Missing or duplicate service key {key}")
        raw = matches[0]
        if re.fullmatch(r"%[A-Za-z0-9_]+%", raw):
            raw = strings.get(raw[1:-1].lower(), "")
        try:
            actual = int(raw, 0)
        except ValueError as exc:
            raise PackageError(f"Cannot resolve service constant {key}") from exc
        require(actual == value, f"Reviewed service does not declare expected {key}")
    require(not re.search(r"\bpi5nvme\b", text, re.I), "INF already has deployment identity")
    text, catalog_count = re.subn(r"(?mi)^(\s*CatalogFile\s*=\s*)pi5-stornvme\.cat\s*$",
                                 r"\g<1>pi5nvme.cat", text)
    require(catalog_count == 1, "Unexpected catalog directive")
    text, file_count = re.subn(r"\bstornvme\.sys\b", "pi5nvme.sys", text, flags=re.I)
    require(file_count >= 3, "Missing binary/source/copy/service references")
    text, service_count = re.subn(r"(?mi)^(\s*AddService\s*=\s*)stornvme(\s*,)",
                                 r"\g<1>pi5nvme\g<2>", text)
    require(service_count >= 1, "Missing original service registration")
    require(not re.search(r"\bstornvme\.sys\b|^\s*AddService\s*=\s*stornvme\s*,", text, re.I | re.M),
            "Stock driver filename/service reference remains")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    result = b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le")
    require(core.inspect_inf(result)["driver_version"] == profile["source_version"], "Final INF version changed")
    # INF SourceDisksFiles must refer only to the single packaged binary.
    source_lines = core.inf_sections(core.decode_inf(result)).get("sourcedisksfiles", [])
    source_names = {line.split("=", 1)[0].strip().lower() for line in source_lines if "=" in line and not line.lstrip().startswith(";")}
    require(source_names == {"pi5nvme.sys"}, "Unexpected additional package source files")
    return result


def prepare_collection(collection: Path, binding: str = r"PCI\CC_010802", *, profiles: Optional[list] = None,
                       check_cancel: Callable[[], None] = lambda: None) -> list[dict]:
    """All-or-nothing preflight. Deduplicate identical original pairs.

    profiles is a Python-only fixture hook; CLI/GUI always use the bundled catalog.
    No external report, profile path or unchecked offset authorizes a build.
    """
    binding = hardware_id(binding)
    collection = safe_path(collection)
    require(collection.is_dir(), "The builder's driver collection folder is missing")
    approved = core.load_profiles([]) if profiles is None else profiles
    for p in approved:
        core.validate_profile(p)
    grouped: dict[tuple, dict] = {}
    env_dirs = sorted(p for p in collection.iterdir() if re.fullmatch(r"(?:boot|install|recovery)-[1-9][0-9]*", p.name))
    require(0 < len(env_dirs) <= 64, "No supported environment folders were found")
    for folder in env_dirs:
        check_cancel()
        folder = safe_path(folder)
        require(folder.is_dir(), "Environment path is not a directory")
        sys_path = folder / "original-inputs" / "stornvme.sys"
        inf_path = folder / "original-inputs" / "stornvme.inf"
        source, original_inf = read_regular(sys_path), read_regular(inf_path, 4 * 1024 * 1024)
        report = core.analyze(source, original_inf, approved)
        require(report["status"] == "ELIGIBLE_FOR_HASH_CHECKED_BUILD",
                f"{folder.name}: " + "; ".join(report["blockers"]))
        profile = next(p for p in approved if p["source_sha256"] == core.sha256(source))
        key = (profile["source_sha256"], profile["inf_sha256"])
        if key not in grouped:
            patched, patch_log = core.apply_patch(source, profile)
            # Prove the final INF and hash layout are supported before creating keys.
            final_inf = package_inf(original_inf, profile, binding)
            patched = bytes(patched)
            pe_digest(patched)
            grouped[key] = dict(profile=profile, unsigned=patched, inf=final_inf,
                                patch_log=patch_log, environments=[], sources=[])
        item = grouped[key]
        item["environments"].append(folder.name)
        item["sources"].extend(((sys_path, core.sha256(source)), (inf_path, core.sha256(original_inf))))
        # Independently compare an earlier GUI candidate when one was produced.
        candidate = folder / "analysis" / "unsigned-package" / "stornvme.sys"
        if candidate.exists() or candidate.is_symlink():
            require(read_regular(candidate) == item["unsigned"], f"{folder.name}: existing candidate differs from reviewed output")
    return list(grouped.values())


def verify_package(folder: Path, *, profiles: Optional[list] = None,
                   expected_certificate_sha256: Optional[str] = None) -> dict:
    """Read-only checks of the finished SYS/INF/CAT and pinned local certificate.

    The certificate is only a LOCAL trust anchor, not Microsoft/Windows trust.
    A caller validating a previously received package should pin its cert hash
    through expected_certificate_sha256 obtained from their own build record.
    """
    folder = safe_path(folder)
    files = {name: read_regular(folder / name, core.MAX_FILE if name.endswith(".sys") else 4 * 1024 * 1024)
             for name in PACKAGE_FILES}
    certificate_hash = core.sha256(files["local-test-certificate.cer"])
    if expected_certificate_sha256 is not None:
        require(certificate_hash == expected_certificate_sha256.lower(), "Certificate differs from the pinned local build certificate")
    known = core.load_profiles([]) if profiles is None else profiles
    signed = files["pi5nvme.sys"]
    pe = core.PE(signed)
    cert_offset, _ = pe.directory(4)
    restored = signer.unsigned_content(signed, cert_offset)
    matches = [p for p in known if p["output_sha256"] == core.sha256(restored)]
    require(len(matches) == 1, "Signed SYS does not normalize to one reviewed unsigned output")
    profile = matches[0]
    require(pe.file_version() == profile["source_version"], "Signed binary version differs")
    inf_text = core.decode_inf(files["pi5nvme.inf"])
    require(core.inspect_inf(files["pi5nvme.inf"])["driver_version"] == profile["source_version"], "Signed package SYS/INF version mismatch")
    require(re.search(r"(?mi)^\s*CatalogFile\s*=\s*pi5nvme\.cat\s*$", inf_text) is not None,
            "INF points to another catalog")
    require(re.search(r"(?mi)^\s*ServiceBinary\s*=\s*%12%\\pi5nvme\.sys\s*$", inf_text) is not None,
            "INF points to another driver binary")
    require_sha256_signature(files["pi5nvme.cat"])
    check_membership(files["pi5nvme.cat"], {k: files[k] for k in ("pi5nvme.sys", "pi5nvme.inf")})
    executable = signer.tools()["osslsigncode"]
    require(executable is not None, "osslsigncode is required for signature verification")
    # Pin the leaf as well as specifying the local trust anchor. No CRL retrieval.
    base = [executable, "verify", "-ignore-cdp", "-CAfile", str(folder / "local-test-certificate.pem"),
            "-require-leaf-hash", "sha256:" + certificate_hash]
    logs = {}
    for name in ("pi5nvme.sys", "pi5nvme.cat"):
        logs[name] = signer.command(base + ["-in", str(folder / name)])
    logs["sys_catalog_member"] = signer.command(base + ["-catalog", str(folder / "pi5nvme.cat"), "-in", str(folder / "pi5nvme.sys")])
    require(all(read_regular(folder / n) == b for n, b in files.items()), "Package changed during verification")
    return dict(status=STATUS, profile=profile["id"], driver_version=profile["source_version"],
                unsigned_sha256=profile["output_sha256"], certificate_sha256=certificate_hash,
                files_sha256={n: core.sha256(b) for n, b in files.items()},
                embedded_signature_verified=True, catalog_signature_verified=True,
                sys_catalog_verified_by="osslsigncode and deterministic CTL equality",
                inf_catalog_verified_by="raw SHA-256 in authenticated CTL; osslsigncode cannot natively verify INF files",
                catalog_format="minimal Microsoft V2 CTL with PE Authenticode SHA-256 and INF SHA-256",
                windows_inf_validation=False, windows_catalog_lookup_tested=False,
                windows_driver_loading_tested=False, hardware_tested=False,
                driver_installed=False, iso_generated=False, verification_logs=logs)


def build_collection(collection: Path, output: Path, key_directory: Path, binding: str = r"PCI\CC_010802", *,
                     profiles: Optional[list] = None, check_cancel: Callable[[], None] = lambda: None,
                     progress: Callable[[int, str], None] = lambda percent, text: None) -> dict:
    """Create new, separate signed packages for each unique reviewed pair."""
    require(sys.platform == "linux", "The native signing backend requires Linux")
    collection, output, key_directory = map(safe_path, (collection, output, key_directory))
    for a, b in ((output, key_directory), (output, collection), (key_directory, collection)):
        require(a != b and a not in b.parents and b not in a.parents,
                "Collection, output and private-key directories must be separate, non-nested locations")
    for path in (output, key_directory):
        require(not path.exists() and path.parent.is_dir(), "Output and private-key folders must be NEW with existing parents")
    versions = native_versions()
    progress(2, "Rechecking originals, exact recipes and any existing candidate bytes")
    items = prepare_collection(collection, binding, profiles=profiles, check_cancel=check_cancel)
    check_cancel()
    # Reserve new directories. No previous output, key or source is overwritten.
    key_directory.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    stage = output / ".incomplete"
    stage.mkdir(mode=0o700)
    write_new(output / "BUILD_INCOMPLETE.txt", b"No package is approved while this marker exists. Inspect any failure report.\n")
    result = dict(schema=1, status="PREPARING_PACKAGES", created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                  package_count=len(items), packages=[], deployment_identity="pi5nvme", private_keys_exported=False,
                  native_tools=versions,
                  iso_modified=False, iso_generated=False, driver_installed=False, limitations=list(LIMITATIONS))
    try:
        for index, item in enumerate(items):
            check_cancel()
            profile = item["profile"]
            # Names are generated from already-validated numeric file versions.
            version = profile["source_version"]
            require(bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version)), "Invalid profile version")
            package_name = version + "-" + profile["source_sha256"][:12]
            package = stage / package_name
            package.mkdir(mode=0o700)
            progress(10 + int(index / len(items) * 70), f"Signing driver and catalog for {version}")
            unsigned_file = package / ".unsigned.sys"
            write_new(unsigned_file, item["unsigned"])
            signing_dir = package / ".embedded"
            keys = key_directory / package_name
            signed_report = signer.sign_candidate(unsigned_file, signing_dir, keys, profiles=profiles)
            check_cancel()
            # Copy only public signing output. The private directory is never traversed.
            for name in ("local-test-certificate.pem", "local-test-certificate.cer"):
                write_new(package / name, read_regular(signing_dir / name))
            write_new(package / "pi5nvme.sys", read_regular(signing_dir / "stornvme.sys"))
            write_new(package / "pi5nvme.inf", item["inf"])
            cat_input = package / ".unsigned.cat"
            write_new(cat_input, build_catalog({n: read_regular(package / n) for n in ("pi5nvme.sys", "pi5nvme.inf")}))
            signer.command([signer.tools()["osslsigncode"], "sign", "-h", "sha256",
                            "-certs", str(package / "local-test-certificate.pem"),
                            "-key", str(keys / "local-test-key.pem"), "-in", str(cat_input), "-out", str(package / "pi5nvme.cat")])
            check_cancel()
            report = verify_package(package, profiles=profiles, expected_certificate_sha256=signed_report["certificate_sha256"])
            report.update(source_sha256=profile["source_sha256"], original_inf_sha256=profile["inf_sha256"],
                          image_content_unchanged_by_signing=True, service="pi5nvme", start_type=0,
                          requested_binding=hardware_id(binding), environments=item["environments"],
                          package_name=package_name, limitations=list(LIMITATIONS))
            # Command logs contain local filenames; retain them locally but exclude
            # them from the explicitly shareable evidence JSON.
            write_new(package / "verification.json", json_bytes(report))
            write_new(package / "WINDOWS_VALIDATION_REQUIRED.txt", ("\n".join(LIMITATIONS) + "\n").encode("utf-8"))
            write_new(package / "SHA256SUMS.txt", "".join(f"{h}  {n}\n" for n, h in report["files_sha256"].items()).encode("ascii"))
            for path, expected in item["sources"]:
                require(core.sha256(read_regular(path)) == expected, "An original input changed during packaging")
            unsigned_file.unlink()
            cat_input.unlink()
            shutil.rmtree(signing_dir)  # Only our private temporary stage, not user data.
            public = {k: v for k, v in report.items() if k != "verification_logs"}
            result["packages"].append(public)
        check_cancel()
        # Validate all original sources a second time before finalizing the batch.
        for item in items:
            for path, expected in item["sources"]:
                require(core.sha256(read_regular(path)) == expected, "An original input changed before finalization")
        (output / ".incomplete").rename(output / "packages")
        result["status"] = STATUS
        write_new(output / "package-report.json", json_bytes(result))
        summary = package_summary(result)
        write_new(output / "summary.txt", summary.encode("utf-8"))
        # Export reports only. Never include SYS/INF/CAT or any key/certificate.
        with zipfile.ZipFile(output / "package-evidence.zip", "x", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("package-report.json", json_bytes(result))
            archive.writestr("summary.txt", summary)
        (output / "BUILD_INCOMPLETE.txt").unlink()
        progress(100, "Local package signatures and membership verified. Windows and ISO integration still untested.")
        return result
    except Exception as exc:
        result.update(status="PACKAGE_BUILD_STOPPED", error=str(exc), iso_generated=False)
        write_new(output / "failure-report.json", json_bytes(result))
        raise


def package_summary(result: dict) -> str:
    lines = [APP_NAME + " - native Linux package report", "", "Status: " + result["status"],
             "No driver was installed. No ISO was modified or generated.", ""]
    for row in result.get("packages", []):
        lines += [row["driver_version"] + ": " + row["status"],
                  "  Environments: " + ", ".join(row.get("environments", [])),
                  "  Signed SYS SHA-256: " + row["files_sha256"]["pi5nvme.sys"],
                  "  Signed CAT SHA-256: " + row["files_sha256"]["pi5nvme.cat"],
                  "  Catalog membership: SYS + INF verified; Windows verification pending.", ""]
    lines += ["LIMITATIONS:", *LIMITATIONS]
    return "\n".join(lines) + "\n"
