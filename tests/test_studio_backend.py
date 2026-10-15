import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from pi5_studio import backend as b
from test_pi5_nvme_tool import fixture


def xml(kind="install", arch="12", count=1):
    return ("<WIM>" + "".join(f'<IMAGE INDEX="{n}"><NAME>{kind} {n}</NAME><TOTALBYTES>4096</TOTALBYTES>'
        f'<WINDOWS><ARCH>{arch}</ARCH><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR>'
        '<BUILD>22621</BUILD><SPBUILD>1702</SPBUILD></VERSION></WINDOWS></IMAGE>'
        for n in range(1, count + 1)) + "</WIM>").encode()


LISTING = b"Path = sources/boot.wim\nSize = 208\nFolder = -\n\nPath = sources/install.wim\nSize = 208\nFolder = -\n\n"


class FakeRunner:
    def __init__(self, arch="12", missing_inf=False):
        self.arch = arch
        self.missing_inf = missing_inf
        self.calls = []
        self.cancel = b.Cancellation()

    def run(self, argv, output=None, limit=0, timeout=0):
        self.cancel.check()
        self.calls.append(argv)
        if argv[1] == "l":
            return LISTING
        if argv[1] == "info":
            kind = "boot" if argv[2].endswith("boot.wim") else "install"
            return xml(kind, self.arch, 2 if kind == "boot" else 1)
        if argv[1] == "x":
            output.write_bytes(b"x" * 208)
            return b""
        if "Recovery/winre.wim" in argv[4]:
            raise b.StudioError("Synthetic recovery image not present")
        sys_bytes, inf_bytes, _, _ = fixture()
        if argv[4].endswith(".inf"):
            if self.missing_inf:
                raise b.StudioError("Synthetic INF missing")
            output.write_bytes(inf_bytes)
        else:
            output.write_bytes(sys_bytes)
        return b""


class BackendTests(unittest.TestCase):
    def test_listing(self):
        members = b.iso_members(LISTING)
        self.assertEqual(members["sources/boot.wim"]["size"], 208)

    def test_listing_esd(self):
        self.assertIn("sources/install.esd", b.iso_members(LISTING.replace(b"install.wim", b"install.esd")))

    def test_listing_duplicate(self):
        with self.assertRaises(b.StudioError):
            b.iso_members(LISTING + b"Path = SOURCES/BOOT.WIM\nSize = 208\n\n")

    def test_listing_two_install_images(self):
        with self.assertRaises(b.StudioError):
            b.iso_members(LISTING + b"Path = sources/install.esd\nSize = 208\n\n")

    def test_split_wim_rejected(self):
        with self.assertRaises(b.StudioError):
            b.iso_members(LISTING.replace(b"install.wim", b"install.swm"))

    def test_listing_bad_size(self):
        with self.assertRaises(b.StudioError):
            b.iso_members(LISTING.replace(b"Size = 208", b"Size = -5"))

    def test_paths(self):
        for name in ("../sources/boot.wim", "/sources/boot.wim", "C:/x", "a\n/b", "a//b", "a/./b"):
            with self.subTest(name=name), self.assertRaises(b.StudioError):
                b.safe_archive_path(name)
        self.assertEqual(b.safe_archive_path(r"sources\boot.wim"), "sources/boot.wim")

    def test_metadata(self):
        images = b.wim_images(xml(count=2), "install")
        self.assertEqual([i.index for i in images], [1, 2])
        self.assertEqual(images[0].architecture, "ARM64")
        self.assertEqual(images[0].build, "10.0.22621.1702")

    def test_utf16_xml(self):
        self.assertEqual(b.wim_images(xml().decode().encode("utf-16"), "install")[0].index, 1)

    def test_xml_entities_rejected(self):
        for encoding in ("utf-8", "utf-16"):
            with self.assertRaises(b.StudioError):
                b.wim_images(('<!DOCTYPE WIM [<!ENTITY a "test">]>' + xml().decode()).encode(encoding), "install")

    def test_duplicate_indices(self):
        with self.assertRaises(b.StudioError):
            b.wim_images(xml(count=2).replace(b'INDEX="2"', b'INDEX="1"'), "install")

    def test_bad_xml(self):
        for data in (b"", b"<a/>", b"<WIM></WIM>", b"<WIM>"):
            with self.subTest(data=data), self.assertRaises(b.StudioError):
                b.wim_images(data, "boot")

    def test_cancel_hash(self):
        token = b.Cancellation()
        token.cancel()
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "input.iso"
            f.write_bytes(b"input")
            with self.assertRaises(b.Cancelled):
                b.digest(f, token)

    def test_regular_file_required(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(b.StudioError):
            b.file_identity(Path(tmp))

    def test_runner_no_shell(self):
        runner = b.Runner(b.Cancellation())
        value = "file ; $(touch should-not-exist)"
        result = runner.run([sys.executable, "-c", "import sys; print(sys.argv[1])", value])
        self.assertEqual(result.decode().strip(), value)

    def test_runner_output_limit(self):
        with self.assertRaises(b.StudioError):
            b.Runner(b.Cancellation()).run([sys.executable, "-c", "print('x'*10000)"], limit=32)

    def test_runner_error(self):
        with self.assertRaisesRegex(b.StudioError, "exited 7"):
            b.Runner(b.Cancellation()).run([sys.executable, "-c", "import sys; sys.exit(7)"])

    def test_runner_cancellation(self):
        token = b.Cancellation()
        timer = threading.Timer(0.15, token.cancel)
        timer.start()
        try:
            with self.assertRaises(b.Cancelled):
                b.Runner(token).run([sys.executable, "-c", "import time; time.sleep(20)"])
        finally:
            timer.join()

    def test_runner_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "test"
            output.write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                b.Runner(b.Cancellation()).run([sys.executable, "-c", "print('changed')"], output=output)
            self.assertEqual(output.read_bytes(), b"original")

    def session(self, tmp, **kwargs):
        iso = Path(tmp) / "Official named input.iso"
        iso.write_bytes(b"synthetic iso - NOT Microsoft")
        session = b.Session(runner=FakeRunner(**kwargs))
        session.tools = {"7zip": "fake7z", "wimlib": "fakewim"}
        return iso, session

    def test_missing_tools(self):
        session = b.Session()
        session.tools = {"7zip": None, "wimlib": None}
        with self.assertRaises(b.StudioError):
            session.inspect(Path("file.iso"), Path("."))

    def test_complete_unknown_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            original = iso.read_bytes()
            session.inspect(iso, Path(tmp))
            result = session.collect(1)
            self.assertEqual(result["status"], "ANALYZED_WITH_BLOCKERS")
            self.assertFalse(result["iso_modified"])
            self.assertFalse(result["bootable_iso_written"])
            self.assertEqual(iso.read_bytes(), original)
            batch = session.root / result["collection"]
            with zipfile.ZipFile(batch / "evidence.zip") as z:
                self.assertFalse(any(name.endswith((".sys", ".inf", ".wim")) for name in z.namelist()))
                self.assertIn("summary.txt", z.namelist())
            self.assertFalse(list(session.root.rglob("unsigned-package")))

    def test_exact_candidate_only_with_reviewed_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            session.inspect(iso, Path(tmp))
            _, _, profile, _ = fixture()
            with patch.object(b.core, "load_profiles", return_value=[profile]):
                result = session.collect(1, candidates=True, recovery=False)
            built = [r for r in result["results"] if r["status"] == "BUILT_UNSIGNED_HASH_VERIFIED"]
            self.assertEqual(len(built), 3)
            self.assertFalse(result["bootable_iso_written"])
            self.assertEqual(len(list(session.root.rglob("NOT_READY_TO_INSTALL.txt"))), 3)

    def test_wrong_iso_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            with self.assertRaisesRegex(b.StudioError, "SHA-256"):
                session.inspect(iso, Path(tmp), "0" * 64)
            self.assertEqual(session.data["status"], "FAILED")

    def test_hash_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            with self.assertRaises(b.StudioError):
                session.inspect(iso, Path(tmp), "not-a-hash")
            self.assertIsNone(session.root)

    def test_matching_iso_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            session.inspect(iso, Path(tmp), hashlib.sha256(iso.read_bytes()).hexdigest().upper())
            self.assertIn("user-supplied", session.data["source_authenticity"])

    def test_x64_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp, arch="9")
            with self.assertRaisesRegex(b.StudioError, "ARM64"):
                session.inspect(iso, Path(tmp))

    def test_missing_inf_becomes_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp, missing_inf=True)
            session.inspect(iso, Path(tmp))
            result = session.collect(1, recovery=False)
            self.assertTrue(any("INF missing" in str(r["blockers"]) for r in result["results"]))

    def test_reject_unknown_edition(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            session.inspect(iso, Path(tmp))
            with self.assertRaises(b.StudioError):
                session.collect(99)

    def test_changed_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            session.inspect(iso, Path(tmp))
            session.media["boot"].write_bytes(b"tampered")
            with self.assertRaisesRegex(b.StudioError, "changed"):
                session.collect(1)

    def test_changed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            session.inspect(iso, Path(tmp))
            iso.write_bytes(b"changed ISO")
            with self.assertRaisesRegex(b.StudioError, "changed"):
                session.collect(1)

    def test_unique_workspaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, first = self.session(tmp)
            first.inspect(iso, Path(tmp))
            second = b.Session(runner=FakeRunner())
            second.tools = dict(first.tools)
            second.inspect(iso, Path(tmp))
            self.assertNotEqual(first.root, second.root)

    def test_analysis_requires_inspection(self):
        with self.assertRaises(b.StudioError):
            b.Session().collect(1)

    def test_low_disk_space(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso, session = self.session(tmp)
            space = type("Space", (), {"free": 1})()
            with patch.object(b.shutil, "disk_usage", return_value=space), self.assertRaises(b.StudioError):
                session.inspect(iso, Path(tmp))
            self.assertIsNone(session.root)
