"""Native Linux ISO collection and exact-profile candidate builder.

No mount, root, shell, networking, signing, driver installation, ISO mutation,
registry edits or security-policy changes. A candidate is NOT installable.
7-Zip reads ISO/UDF; wimlib reads WIM/ESD; the existing core handles the binary.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import signal
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from typing import Callable, Dict, List, Optional
import uuid
import xml.etree.ElementTree as ET
import zipfile

import pi5_nvme_tool as core
from . import APP_NAME, __version__

MIB = 1024 * 1024
GIB = 1024 * MIB
LIMITATIONS = [
    "Exact-profile matching is required; no guessed offsets or forced profiles are used.",
    "File, signature and image verification do not establish successful Windows installation or hardware boot.",
]



class StudioError(Exception):
    pass


class Cancelled(StudioError):
    pass


class Cancellation:
    def __init__(self) -> None:
        self.event = threading.Event()

    def cancel(self) -> None:
        self.event.set()

    def check(self) -> None:
        if self.event.is_set():
            raise Cancelled("Cancelled. The original ISO is unchanged; partial project files were kept.")


def stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def file_identity(path: Path) -> tuple:
    s = path.stat()
    if not stat.S_ISREG(s.st_mode):
        raise StudioError("Input must be a regular file, not a disk device or directory.")
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def checked_path(path: Path) -> Path:
    p = path.expanduser().resolve()
    if any(ord(c) < 32 for c in str(p)):
        raise StudioError("File paths containing control characters are not supported.")
    return p


def digest(path: Path, cancel: Cancellation, progress: Optional[Callable[[float], None]] = None) -> str:
    identity = file_identity(path)
    size = identity[2]
    h = hashlib.sha256()
    done = 0
    with path.open("rb") as stream:
        while True:
            cancel.check()
            block = stream.read(4 * MIB)
            if not block:
                break
            h.update(block)
            done += len(block)
            if progress:
                progress(done / max(size, 1))
    if file_identity(path) != identity:
        raise StudioError("An input file changed while being read. Retry using stable copies.")
    return h.hexdigest()


def atomic_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with tmp.open("x", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def tools_available() -> Dict[str, Optional[str]]:
    return {"7zip": shutil.which("7zz") or shutil.which("7z"),
            "wimlib": shutil.which("wimlib-imagex")}


class Runner:
    """Bounded file-backed subprocess output; cancellation never blocks on readline."""
    def __init__(self, cancel: Cancellation, log: Callable[[str], None] = lambda text: None) -> None:
        self.cancel = cancel
        self.log = log

    def run(self, argv: List[str], output: Optional[Path] = None,
            limit: int = 16 * MIB, timeout: int = 7200,
            stdin_path: Optional[Path] = None) -> bytes:
        self.cancel.check()
        if not argv or not all(isinstance(a, str) and "\0" not in a for a in argv):
            raise StudioError("Invalid command arguments.")
        self.log("$ " + shlex.join(argv))
        # Temporary output is file-backed, avoiding pipe deadlocks and RAM growth.
        with tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as memory_output:
            target = output.open("xb") if output else memory_output
            process = None
            input_stream = None
            try:
                env = dict(os.environ, LC_ALL="C", LANG="C", WIMLIB_IMAGEX_IGNORE_CASE="1")
                if stdin_path is not None:
                    if stdin_path.is_symlink() or not stdin_path.is_file():
                        raise StudioError("Command input must be a regular nonsymlink file.")
                    input_stream = stdin_path.open("rb")
                process = subprocess.Popen(argv, stdin=input_stream or subprocess.DEVNULL, stdout=target,
                                           stderr=err, env=env, shell=False, start_new_session=(os.name == "posix"))
                started = time.monotonic()
                while process.poll() is None:
                    self.cancel.check()
                    if time.monotonic() - started > timeout:
                        raise StudioError("External tool timed out; partial output is retained.")
                    if os.fstat(target.fileno()).st_size > limit or os.fstat(err.fileno()).st_size > 4 * MIB:
                        raise StudioError("External tool exceeded its output limit.")
                    if output and shutil.disk_usage(output.parent).free < 128 * MIB:
                        raise StudioError("Workspace is nearly full. Choose a larger output drive.")
                    time.sleep(0.08)
                self.cancel.check()
                size = os.fstat(target.fileno()).st_size
                if size > limit or os.fstat(err.fileno()).st_size > 4 * MIB:
                    raise StudioError("External tool exceeded its output limit.")
                err.seek(0)
                detail = err.read(4 * MIB).decode("utf-8", "replace").strip()
                if process.returncode:
                    raise StudioError(f"{Path(argv[0]).name} exited {process.returncode}: {detail[-3000:]}")
                if detail:
                    self.log(detail[-3000:])
                if output:
                    return b""
                target.seek(0)
                return target.read(limit + 1)
            except OSError as exc:
                raise StudioError(f"Could not run {Path(argv[0]).name}: {exc}") from exc
            finally:
                if process is not None and process.poll() is None:
                    if os.name == "posix":
                        try: os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError: pass
                    else:
                        process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        if os.name == "posix":
                            try: os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError: pass
                        else:
                            process.kill()
                        process.wait()
                if input_stream is not None:
                    input_stream.close()
                if output:
                    target.close()


def safe_archive_path(value: str) -> str:
    value = value.replace("\\", "/")
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or any(part in ("..", ".") for part in value.split("/"))
            or any(ord(c) < 32 for c in value) or ":" in value or "//" in value):
        raise StudioError("Unsafe or ambiguous path in the ISO listing.")
    return value


def iso_members(data: bytes) -> Dict[str, dict]:
    """Parse 7z -slt -ba records; reject duplicate Windows image paths."""
    if len(data) > 16 * MIB:
        raise StudioError("ISO file listing is too large.")
    records = []
    current: dict = {}
    for line in data.decode("utf-8", "strict").splitlines() + [""]:
        if not line.strip():
            if current:
                records.append(current)
                current = {}
        elif " = " in line:
            key, value = line.split(" = ", 1)
            if key in current:
                raise StudioError("Ambiguous ISO listing record.")
            current[key] = value
    members: Dict[str, dict] = {}
    for rec in records:
        name = rec.get("Path", "")
        if not name:
            continue
        # Only the three fixed ISO members we need will ever be extracted.
        lower = name.replace("\\", "/").lower()
        if lower.startswith("sources/install") and lower.endswith(".swm"):
            raise StudioError("Split SWM installation media is not supported in this release.")
        if lower not in ("sources/boot.wim", "sources/install.wim", "sources/install.esd"):
            continue
        name = safe_archive_path(name)
        if lower in members:
            raise StudioError("Duplicate case-insensitive Windows image paths in the ISO.")
        try:
            size = int(rec["Size"])
        except (KeyError, ValueError) as exc:
            raise StudioError("Missing or invalid Windows image size.") from exc
        if size < 208 or size > 64 * GIB or rec.get("Folder") == "+":
            raise StudioError("Invalid Windows image member.")
        members[lower] = {"path": name, "size": size}
    if "sources/boot.wim" not in members:
        raise StudioError("No sources/boot.wim found. Choose a complete Windows installation ISO.")
    if sum(k in members for k in ("sources/install.wim", "sources/install.esd")) != 1:
        raise StudioError("Expected exactly one install.wim or install.esd in the ISO.")
    return members


@dataclass(frozen=True)
class Image:
    kind: str
    index: int
    name: str
    architecture: str
    build: str
    size: int

    def as_dict(self) -> dict:
        return dict(kind=self.kind, index=self.index, name=self.name,
                    architecture=self.architecture, build=self.build, size=self.size)


def wim_images(data: bytes, kind: str) -> List[Image]:
    if not data or len(data) > 4 * MIB:
        raise StudioError("Invalid WIM metadata size.")
    # XML emitted by wimlib can be UTF-16LE or UTF-8. Decode before DTD checks.
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16")
    elif b"\x00" in data[:100]:
        text = data.decode("utf-16-le")
    else:
        text = data.decode("utf-8-sig")
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise StudioError("DTD/entity-bearing WIM metadata is not accepted.")
    try:
        root = ET.fromstring(text)
        if root.tag != "WIM":
            raise StudioError("Expected WIM XML metadata.")
        images = []
        seen = set()
        for node in root.findall("IMAGE"):
            index = int(node.attrib["INDEX"])
            if index in seen or not 1 <= index <= 128:
                raise StudioError("Invalid or duplicate WIM image index.")
            seen.add(index)
            arch = node.findtext("WINDOWS/ARCH", "unknown")
            version = node.find("WINDOWS/VERSION")
            parts = [] if version is None else [version.findtext(k, "0") for k in ("MAJOR", "MINOR", "BUILD", "SPBUILD")]
            build = ".".join(parts) if len(parts) == 4 and all(re.fullmatch(r"\d{1,6}", x) for x in parts) else "unknown"
            size = int(node.findtext("TOTALBYTES", "0"))
            images.append(Image(kind, index, node.findtext("NAME") or f"Image {index}",
                                {"12": "ARM64", "9": "x64", "0": "x86"}.get(arch, f"unknown ({arch})"),
                                build, size))
        if not images:
            raise StudioError("No image indexes were found.")
        return images
    except (ET.ParseError, KeyError, ValueError) as exc:
        raise StudioError(f"Invalid WIM XML: {exc}") from exc


class Session:
    def __init__(self, cancel: Optional[Cancellation] = None,
                 notify: Callable[[str, int, str], None] = lambda stage, percent, detail: None,
                 runner: Optional[Runner] = None) -> None:
        self.cancel = cancel or Cancellation()
        self.notify = notify
        self.runner = runner or Runner(self.cancel, self.log)
        self.root: Optional[Path] = None
        self.iso: Optional[Path] = None
        self.identity: Optional[tuple] = None
        self.tools = tools_available()
        self.images: List[Image] = []
        self.media: Dict[str, Path] = {}
        self.media_hashes: Dict[str, str] = {}
        self.data: dict = {}

    def log(self, text: str) -> None:
        self.notify("log", -1, text)
        if self.root:
            with (self.root / "activity.log").open("a", encoding="utf-8") as f:
                f.write(stamp() + " " + text + "\n")

    def check_tools(self) -> None:
        missing = [key for key, value in self.tools.items() if not value]
        if missing:
            raise StudioError("Missing tools: " + ", ".join(missing) + ". Install 7zip (or p7zip-full) and wimtools.")

    def save(self) -> None:
        if self.root:
            atomic_json(self.root / "project.json", self.data)

    def inspect(self, iso: Path, output: Path, expected_sha256: str = "") -> dict:
        self.check_tools()
        iso = checked_path(iso)
        output = checked_path(output)
        identity = file_identity(iso)
        if iso.suffix.lower() != ".iso":
            raise StudioError("Choose an .iso file.")
        if not output.is_dir():
            raise StudioError("Choose an existing output folder.")
        if expected_sha256 and not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
            raise StudioError("The optional Microsoft SHA-256 must have exactly 64 hexadecimal characters.")
        self.iso, self.identity = iso, identity
        self.notify("inspect", 0, "Reading the ISO file table")
        members = iso_members(self.runner.run([self.tools["7zip"], "l", "-slt", "-ba", "-bd", "--", str(iso)]))
        required = sum(m["size"] for m in members.values()) + 2 * GIB
        if shutil.disk_usage(output).free < required:
            raise StudioError(f"Workspace needs at least {required / GIB:.1f} GiB free for extracted images and working files.")
        self.root = output / ("pi5-nvme-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
        self.root.mkdir(mode=0o700)
        (self.root / "images").mkdir()
        self.data = dict(schema=1, studio_version=__version__, created_utc=stamp(),
                         source_name=iso.name, source_sha256=None, status="INSPECTING",
                         source_authenticity="Not authenticated; compare the hash with Microsoft's download page.",
                         runtime_validation="NOT PERFORMED", iso_modified=False, bootable_iso_written=False,
                         limitations=list(LIMITATIONS), images=[], results=[])
        self.save()
        try:
            self.notify("inspect", 5, "Calculating ISO SHA-256 (this can take several minutes)")
            source_hash = digest(iso, self.cancel, lambda fraction: self.notify("inspect", 5 + int(fraction * 25), "Hashing the source ISO"))
            self.data["source_sha256"] = source_hash
            if expected_sha256 and source_hash != expected_sha256.lower():
                raise StudioError("The ISO does not match the supplied Microsoft SHA-256. Extraction stopped.")
            if expected_sha256:
                self.data["source_authenticity"] = "Matches user-supplied SHA-256; its provenance was not independently verified."
            for n, (member, info) in enumerate(sorted(members.items())):
                self.cancel.check()
                kind = "boot" if member.endswith("boot.wim") else "install"
                target = self.root / "images" / PurePosixPath(member).name
                self.notify("inspect", 32 + n * 25, f"Extracting {member}; the source remains read-only")
                self.runner.run([self.tools["7zip"], "x", "-so", "-bd", "-y", "-spd", "--", str(iso), info["path"]],
                                output=target, limit=info["size"])
                if target.stat().st_size != info["size"]:
                    raise StudioError("Extracted Windows image size differs from the ISO listing.")
                metadata = self.runner.run([self.tools["wimlib"], "info", str(target), "--xml"], limit=4 * MIB)
                self.images.extend(wim_images(metadata, kind))
                self.media[kind] = target
                self.media_hashes[kind] = digest(target, self.cancel)
            if file_identity(iso) != identity:
                raise StudioError("The source ISO changed during extraction. Discard this project.")
            self.data["images"] = [image.as_dict() for image in self.images]
            self.data["media_sha256"] = dict(self.media_hashes)
            if any(image.architecture != "ARM64" for image in self.images):
                raise StudioError("This release requires ARM64 in every boot/install image; another architecture was found.")
            self.data["status"] = "INSPECTED"
            self.save()
            self.notify("inspect", 100, "Images discovered. Select a Windows edition, then collect its drivers.")
            return self.data
        except Exception as exc:
            self.fail(exc)
            raise

    def fail(self, exc: Exception) -> None:
        self.data["status"] = "CANCELLED" if isinstance(exc, Cancelled) else "FAILED"
        self.data["error"] = str(exc)
        self.data["bootable_iso_written"] = False
        self.save()
        self.log(str(exc))

    def extract_file(self, wim: Path, index: int, source: str, dest: Path, limit: int) -> None:
        if index < 1 or not source.startswith("/Windows/"):
            raise StudioError("Invalid internal extraction request.")
        self.runner.run([self.tools["wimlib"], "extract", str(wim), str(index), source,
                         "--to-stdout", "--no-globs"], output=dest, limit=limit)
        if not dest.stat().st_size:
            raise StudioError(f"Empty file extracted: {source}")

    def collect_one(self, image: Image, wim: Path, batch: Path, candidates: bool, hardware_id: str) -> dict:
        label = f"{image.kind}-{image.index}"
        folder = batch / label
        folder.mkdir()
        pair = folder / "original-inputs"
        pair.mkdir(mode=0o700)
        self.extract_file(wim, image.index, "/Windows/System32/drivers/stornvme.sys", pair / "stornvme.sys", 64 * MIB)
        self.extract_file(wim, image.index, "/Windows/INF/stornvme.inf", pair / "stornvme.inf", 4 * MIB)
        source, inf = core.read_file(pair / "stornvme.sys"), core.read_file(pair / "stornvme.inf", 4 * MIB)
        profiles = core.load_profiles([])
        target = None if image.build == "unknown" else image.build
        report = core.analyze(source, inf, profiles, target)
        report["requested_binding"] = hardware_id
        report["image"] = image.as_dict()
        driver = package_inf = None
        if report["status"] == "ELIGIBLE_FOR_HASH_CHECKED_BUILD":
            if candidates:
                profile = next(p for p in profiles if p["source_sha256"] == core.sha256(source))
                driver, changes = core.apply_patch(source, profile)
                package_inf = core.make_inf(inf, profile, hardware_id)
                report["patch_log"] = changes
                report["status"] = "BUILT_UNSIGNED_HASH_VERIFIED"
            else:
                report["status"] = "ANALYZED_PROFILE_MATCH_NO_BUILD"
        core.write_bundle(folder / "analysis", report, driver, package_inf)
        return dict(image=image.as_dict(), status=report["status"], version=report.get("file_version"),
                    source_sha256=report["source_sha256"], inf_sha256=report["inf_sha256"],
                    blockers=report["blockers"], report=str((folder / "analysis" / "report.json").relative_to(self.root)))

    def collect(self, edition: int, candidates: bool = False, recovery: bool = True,
                hardware_id: str = r"PCI\CC_010802") -> dict:
        if self.root is None or self.data.get("status") not in ("INSPECTED", "ANALYZED", "ANALYZED_WITH_BLOCKERS"):
            raise StudioError("Inspect an ISO successfully before collecting its files.")
        if not re.fullmatch(r"PCI\\[A-Z0-9_&]+", hardware_id.upper()):
            raise StudioError("Enter a valid PCI hardware ID or use the generic NVMe class.")
        selected = next((im for im in self.images if im.kind == "install" and im.index == edition), None)
        if selected is None:
            raise StudioError("The selected Windows edition does not exist.")
        self.cancel.check()
        if file_identity(self.iso) != self.identity:
            raise StudioError("The original ISO changed. Inspect it again.")
        batch = self.root / ("collection-" + uuid.uuid4().hex[:8])
        batch.mkdir()
        self.data.update(status="COLLECTING", selected_edition=edition, requested_candidates=candidates,
                         collection=str(batch.relative_to(self.root)), results=[])
        self.save()
        try:
            for kind, media in self.media.items():
                self.notify("collect", 0, f"Verifying extracted {kind} image integrity")
                if digest(media, self.cancel) != self.media_hashes[kind]:
                    raise StudioError("An extracted WIM/ESD changed. Start a new inspection.")
            tasks = [(im, self.media["boot"]) for im in self.images if im.kind == "boot"]
            tasks.append((selected, self.media["install"]))
            if recovery:
                self.notify("collect", 5, "Locating recovery image for the selected edition")
                recovery_wim = batch / "winre.wim"
                try:
                    self.extract_file(self.media["install"], edition, "/Windows/System32/Recovery/winre.wim", recovery_wim, 4 * GIB)
                    recovery_images = wim_images(self.runner.run([self.tools["wimlib"], "info", str(recovery_wim), "--xml"], limit=4 * MIB), "recovery")
                    if any(im.architecture != "ARM64" for im in recovery_images):
                        raise StudioError("Recovery image is not ARM64.")
                    tasks.extend((im, recovery_wim) for im in recovery_images)
                except Cancelled:
                    raise
                except StudioError as exc:
                    self.data["results"].append(dict(image={"kind": "recovery", "index": None, "name": "Recovery"},
                                                     status="EXTRACTION_FAILED", blockers=[str(exc)]))
            else:
                self.data["results"].append(dict(image={"kind": "recovery", "index": None, "name": "Recovery"},
                                                 status="NOT_INSPECTED", blockers=["Recovery inspection was not selected."]))
            for n, (image, media) in enumerate(tasks):
                self.cancel.check()
                self.notify("collect", 10 + int(n / max(len(tasks), 1) * 80), f"Analyzing {image.kind} {image.index}: {image.name}")
                try:
                    result = self.collect_one(image, media, batch, candidates, hardware_id.upper())
                except Cancelled:
                    raise
                except (StudioError, core.ToolError, ValueError) as exc:
                    result = dict(image=image.as_dict(), status="BLOCKED", blockers=[str(exc)])
                self.data["results"].append(result)
                self.save()
            if file_identity(self.iso) != self.identity:
                raise StudioError("The source changed during collection. Discard this project.")
            bad = any(r["status"] not in ("ANALYZED_PROFILE_MATCH_NO_BUILD", "BUILT_UNSIGNED_HASH_VERIFIED") for r in self.data["results"])
            self.data["status"] = "ANALYZED_WITH_BLOCKERS" if bad else "ANALYZED"
            self.data["iso_build_status"] = "NOT_IMPLEMENTED"
            self.save()
            summary = self.summary()
            (batch / "summary.txt").write_text(summary, encoding="utf-8")
            # Explicit allowlist: never publish the original binary pair, WIMs or logs.
            with zipfile.ZipFile(batch / "evidence.zip", "x", zipfile.ZIP_DEFLATED) as z:
                z.writestr("summary.txt", summary)
                z.writestr("project.json", json.dumps(self.data, indent=2))
                for row in self.data["results"]:
                    if row.get("report"):
                        p = self.root / row["report"]
                        z.write(p, f"{row['image']['kind']}-{row['image']['index']}/report.json")
            self.notify("collect", 100, "Analysis finished. Review results; no modified ISO was created.")
            return self.data
        except Exception as exc:
            self.fail(exc)
            raise

    def summary(self) -> str:
        lines = [f"{APP_NAME} {__version__}", "", f"Source: {self.data['source_name']}",
                 f"ISO SHA-256: {self.data['source_sha256']}", f"Status: {self.data['status']}",
                 "Original ISO unchanged. No bootable ISO generated.", ""]
        for row in self.data["results"]:
            im = row["image"]
            lines.append(f"{im['kind']} / {im['name']}: {row['status']}")
            lines.extend("  - " + reason for reason in row.get("blockers", []))
        lines += ["", "LIMITATIONS:"] + ["- " + value for value in LIMITATIONS]
        return "\n".join(lines) + "\n"
