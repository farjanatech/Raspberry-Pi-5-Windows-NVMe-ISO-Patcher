"""Synthetic fixture tests. No Microsoft driver bytes or hardware tests included."""
import copy
import io
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
import zipfile

import pi5_nvme_tool as t


def fixture():
    b = bytearray(0x1A20)
    b[:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", b, 0x84, 0xAA64, 2)
    struct.pack_into("<H", b, 0x94, 0xF0)
    o = 0x98
    struct.pack_into("<H", b, o, 0x20B)
    struct.pack_into("<I", b, o + 16, 0x1000)
    struct.pack_into("<Q", b, o + 24, 0x140000000)
    struct.pack_into("<II", b, o + 32, 0x1000, 0x200)
    struct.pack_into("<II", b, o + 56, 0x4000, 0x200)
    struct.pack_into("<H", b, o + 68, 1)
    struct.pack_into("<I", b, o + 108, 16)
    def directory(index, rva, size):
        struct.pack_into("<II", b, o + 112 + index * 8, rva, size)
    h = o + 0xF0
    b[h:h + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", b, h + 8, 0x600, 0x1000, 0x800, 0x200)
    struct.pack_into("<I", b, h + 36, 0x60000020)
    h += 40
    b[h:h + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", b, h + 8, 0x1000, 0x2000, 0x1000, 0xA00)
    struct.pack_into("<I", b, h + 36, 0x40000040)
    def off(rva):
        return rva - 0x1000 + 0x200 if rva < 0x2000 else rva - 0x2000 + 0xA00
    def put(rva, data):
        b[off(rva):off(rva) + len(data)] = data
    put(0x1010, struct.pack("<I", 0x52800024))
    put(0x1020, struct.pack("<I", 0xD63F0100))
    put(0x1024, struct.pack("<I", 0xD63F0100))
    put(0x1028, struct.pack("<I", 0xD63F0100))
    # ADRP x8, +0x1000 ; LDR x8,[x8,#0xA0] ; BLR x8.
    put(0x1040, struct.pack("<III", 0xB0000008, 0xF9405108, 0xD63F0100))
    directory(1, 0x2010, 40)
    put(0x2010, struct.pack("<IIIII", 0x2080, 0, 0, 0x2060, 0x20A0))
    put(0x2060, b"storport.sys\0")
    put(0x2080, struct.pack("<QQQ", 0x20C0, 0x20E0, 0))
    put(0x20A0, struct.pack("<QQQ", 0x20C0, 0x20E0, 0))
    put(0x20C0, b"\0\0StorPortGetPhysicalAddress\0")
    put(0x20E0, b"\0\0StorPortAllocateDmaMemory\0")
    directory(12, 0x20A0, 24)
    directory(10, 0x2300, 0x100)
    put(0x2300, struct.pack("<I", 0x100))
    put(0x23E0, struct.pack("<IH", 0x440, 2))
    entries = [((rva - 0x1000) // 4) | (1 << 10) | (8 << 11)
               for rva in (0x1020, 0x1024, 0x1028)]
    block = struct.pack("<IIIII", 0x1000, 20, *entries)
    record = struct.pack("<QI", 8, len(block)) + block
    put(0x2440, struct.pack("<II", 1, len(record)) + record)
    # Version resource: RT_VERSION / id 1 / language 1033 / data.
    directory(2, 0x2500, 0x200)
    for rva in (0x2500, 0x2520, 0x2540):
        put(rva, bytes(14) + struct.pack("<H", 1))
    put(0x2510, struct.pack("<II", 16, 0x80000020))
    put(0x2530, struct.pack("<II", 1, 0x80000040))
    put(0x2550, struct.pack("<II", 1033, 0x60))
    key = "VS_VERSION_INFO\0".encode("utf-16-le")
    version = bytearray(92)
    struct.pack_into("<HHH", version, 0, 92, 52, 0)
    version[6:6 + len(key)] = key
    struct.pack_into("<IIII", version, 40, 0xFEEF04BD, 0x10000, (10 << 16), (12345 << 16) | 6)
    put(0x2560, struct.pack("<IIII", 0x2600, 92, 0, 0))
    put(0x2600, version)
    # Debug/PDB identity (made-up GUID).
    codeview = b"RSDS" + bytes(range(16)) + struct.pack("<I", 2) + b"C:\\fake\\stornvme.pdb\0"
    directory(6, 0x2800, 28)
    put(0x2800, bytes(12) + struct.pack("<IIII", 2, len(codeview), 0x2830, off(0x2830)))
    put(0x2830, codeview)
    directory(4, 0x1A00, 32)
    b[0x1A00:] = struct.pack("<IHH", 32, 0x200, 2) + bytes(24)
    inf = ("[Version]\r\nSignature=\"$Windows NT$\"\r\nClass=SCSIAdapter\r\n"
           "Provider=%MSFT%\r\nDriverVer=06/21/2006,10.0.12345.6\r\n"
           "[Manufacturer]\r\n%MSFT%=NVME,NTarm64\r\n[NVME.NTarm64]\r\n"
           "%Name%=Stornvme_Inst,PCI\\CC_010802\r\n[Stornvme_Inst]\r\n"
           "CopyFiles=CopyDriver\r\n[CopyDriver]\r\nstornvme.sys\r\n"
           "[Strings]\r\nMSFT=\"Microsoft\"\r\nName=\"Synthetic fixture\"\r\n").encode("utf-16")
    profile = copy.deepcopy(t.BUILTIN_PROFILE)
    profile.update(id="SYNTHETIC-NOT-A-REAL-DRIVER", source_version="10.0.12345.6",
                   source_sha256=t.sha256(b), inf_sha256=t.sha256(inf),
                   provenance="synthetic test fixture", runtime_evidence="NONE / synthetic only")
    profile["edits"] = [{"rva": 0x1010, "before": "24008052", "after": "04008052"}]
    profile["helper"]["rva"] = 0x1700
    profile["calls"] = [{"rva": x, "before": "00013fd6"} for x in (0x1020, 0x1024)]
    profile["relocation"].update(table_size=len(record), iat_index=0)
    # Independent explicit golden construction for this fixture. No engine calls.
    expected = bytearray(b[:0x1A00])
    expected[off(0x1010):off(0x1010) + 4] = bytes.fromhex("04008052")
    helper = bytes.fromhex(profile["helper"]["bytes"])
    expected[off(0x1700):off(0x1700) + len(helper)] = helper
    struct.pack_into("<I", expected, o + 0xF0 + 8, 0x700 + len(helper))
    for site in (0x1020, 0x1024):
        struct.pack_into("<I", expected, off(site), 0x94000000 + ((0x1700 - site) // 4))
    new_block = struct.pack("<III", 0x1000, 12, entries[-1])
    new_record = struct.pack("<QI", 8, 12) + new_block
    new_table = struct.pack("<II", 1, len(new_record)) + new_record + bytes(8)
    expected[off(0x2440):off(0x2440) + 40] = new_table
    expected[o + 112 + 32:o + 112 + 40] = bytes(8)
    # Independent checksum: full integer sum followed by end-around folding.
    checksum_offset = o + 64
    expected[checksum_offset:checksum_offset + 4] = bytes(4)
    total = sum(struct.unpack("<" + "H" * (len(expected) // 2), expected))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    struct.pack_into("<I", expected, checksum_offset, total + len(expected))
    profile["output_sha256"] = t.sha256(expected)
    return bytes(b), inf, profile, bytes(expected)


class Tests(unittest.TestCase):
    def setUp(self):
        self.source, self.inf, self.profile, self.expected = fixture()
        self.pe = t.PE(self.source)

    def test_version(self):
        self.assertEqual(self.pe.file_version(), "10.0.12345.6")

    def test_imports(self):
        self.assertEqual(len(self.pe.imports()), 2)
        self.assertEqual(self.pe.imports()[0]["name"], "StorPortGetPhysicalAddress")

    def test_pdb(self):
        self.assertEqual(self.pe.debug_info()[0]["pdb_name"], "stornvme.pdb")
        self.assertEqual(self.pe.debug_info()[0]["age"], 2)

    def test_dynamic_table(self):
        self.assertEqual(self.pe.dynamic_relocations()["size"], 32)
        self.assertEqual(len(self.pe.dynamic_relocations()["records"][0]["blocks"][0]["entries"]), 3)

    def test_inf_encodings(self):
        text = t.decode_inf(self.inf)
        for encoded in (self.inf, text.encode("utf-8"), text.encode("utf-16-le"),
                        b"\xfe\xff" + text.encode("utf-16-be")):
            self.assertEqual(t.inspect_inf(encoded)["driver_version"], "10.0.12345.6")

    def test_gold_patch(self):
        result, log = t.apply_patch(self.source, self.profile)
        self.assertEqual(result, self.expected)
        self.assertGreater(len(log), 5)
        self.assertEqual(t.PE(result).directory(4), (0, 0))

    def test_source_unchanged(self):
        saved = self.source
        t.apply_patch(self.source, self.profile)
        self.assertEqual(self.source, saved)

    def test_wrong_source_hash(self):
        changed = bytearray(self.source)
        changed[0x210] ^= 1
        with self.assertRaisesRegex(t.ToolError, "source-hash"):
            t.apply_patch(bytes(changed), self.profile)

    def test_wrong_output_hash(self):
        self.profile["output_sha256"] = "0" * 64
        with self.assertRaisesRegex(t.ToolError, "Output hash"):
            t.apply_patch(self.source, self.profile)

    def test_instruction_mismatch(self):
        self.profile["edits"][0]["before"] = "00000000"
        with self.assertRaisesRegex(t.ToolError, "Precondition"):
            t.apply_patch(self.source, self.profile)

    def test_duplicate_edits(self):
        self.profile["edits"] *= 2
        with self.assertRaisesRegex(t.ToolError, "Overlapping"):
            t.apply_patch(self.source, self.profile)

    def test_helper_cannot_overlap_code(self):
        self.profile["helper"]["rva"] = 0x1100
        with self.assertRaisesRegex(t.ToolError, "logical"):
            t.apply_patch(self.source, self.profile)

    def test_occupied_helper(self):
        altered = bytearray(self.source)
        altered[self.pe.offset(0x1700)] = 1
        self.profile["source_sha256"] = t.sha256(altered)
        with self.assertRaisesRegex(t.ToolError, "Precondition"):
            t.apply_patch(bytes(altered), self.profile)

    def test_relocation_wrong_index(self):
        self.profile["relocation"]["iat_index"] = 1
        with self.assertRaisesRegex(t.ToolError, "semantics"):
            t.apply_patch(self.source, self.profile)

    def test_relocation_strategy_none(self):
        self.profile["relocation"]["mode"] = "none"
        with self.assertRaisesRegex(t.ToolError, "present"):
            t.apply_patch(self.source, self.profile)

    def test_relocation_missing_site(self):
        self.profile["calls"][1]["rva"] = 0x1048
        with self.assertRaisesRegex(t.ToolError, "exactly once"):
            t.apply_patch(self.source, self.profile)

    def test_unknown_version_analysis_no_build(self):
        report = t.analyze(self.source, self.inf, [t.BUILTIN_PROFILE], "22621.1702")
        self.assertEqual(report["status"], "BLOCKED")
        self.assertTrue(any("No reviewed recipe" in r for r in report["blockers"]))
        self.assertEqual(report["analysis_errors"], [])

    def test_profile_match_analysis(self):
        report = t.analyze(self.source, self.inf, [self.profile], "12345.6")
        self.assertEqual(report["status"], "ELIGIBLE_FOR_HASH_CHECKED_BUILD")

    def test_already_patched(self):
        report = t.analyze(self.expected, self.inf, [self.profile])
        self.assertTrue(any("already-patched" in r for r in report["blockers"]))

    def test_old_target_blocks(self):
        report = t.analyze(self.source, self.inf, [self.profile], "12344.1")
        self.assertTrue(any("older than" in r for r in report["blockers"]))

    def test_inf_version_mismatch(self):
        changed = t.decode_inf(self.inf).replace("12345.6", "12345.7").encode("utf-8")
        report = t.analyze(self.source, changed, [self.profile])
        self.assertTrue(any("version and INF" in r for r in report["blockers"]))

    def test_inf_generation(self):
        generated = t.make_inf(self.inf, self.profile, r"PCI\VEN_1234&DEV_5678")
        text = t.decode_inf(generated)
        self.assertIn("Pi5 NVMe local test build", text)
        self.assertIn(r"PCI\VEN_1234&DEV_5678", text)
        self.assertIn("10.0.12345.6", text)
        self.assertEqual(t.inspect_inf(generated)["catalogs"], {"catalogfile": "pi5-stornvme.cat"})
        self.assertNotEqual(t.sha256(generated), t.sha256(self.inf))

    def test_bad_hardware_id(self):
        for value in ("*", "PCI\\A\n[Version]", "PCI\\VEN_X,OTHER", "PCI\\A;comment"):
            with self.assertRaises(t.ToolError):
                t.make_inf(self.inf, self.profile, value)

    def test_inf_hash_mismatch(self):
        with self.assertRaisesRegex(t.ToolError, "INF does not match"):
            t.make_inf(self.inf + b"\0\0", self.profile, r"PCI\CC_010802")

    def test_duplicate_inf_section(self):
        with self.assertRaisesRegex(t.ToolError, "Duplicate"):
            t.inspect_inf(b"[Version]\nDriverVer=1/1/2000,10.0.1.1\n[Version]\n")

    def test_pe_truncations(self):
        for length in (0, 3, 63, 64, 100, 200, 400, 600, 1500):
            with self.assertRaises(t.ToolError):
                t.PE(self.source[:length])

    def test_wrong_machine(self):
        changed = bytearray(self.source)
        struct.pack_into("<H", changed, 0x84, 0x8664)
        report = t.analyze(bytes(changed), self.inf, [self.profile])
        self.assertTrue(any("not an ARM64" in r for r in report["blockers"]))

    def test_sections_cannot_overlap(self):
        changed = bytearray(self.source)
        struct.pack_into("<I", changed, self.pe.sections[1]["header"] + 20, 0x400)
        with self.assertRaisesRegex(t.ToolError, "Overlapping"):
            t.PE(bytes(changed))

    def test_rva_out_of_bounds(self):
        with self.assertRaises(t.ToolError):
            self.pe.offset(0x999999, 8)
        with self.assertRaises(t.ToolError):
            self.pe.offset(0x17FC, 8)

    def test_resource_cycle(self):
        changed = bytearray(self.source)
        struct.pack_into("<I", changed, self.pe.offset(0x2534), 0x80000020)
        with self.assertRaisesRegex(t.ToolError, "Cyclic"):
            t.PE(bytes(changed)).file_version()

    def test_unknown_relocation_version(self):
        changed = bytearray(self.source)
        struct.pack_into("<I", changed, self.pe.offset(0x2440), 2)
        report = t.analyze(bytes(changed), self.inf, [self.profile])
        self.assertTrue(any("Unknown dynamic" in r for r in report["blockers"]))

    def test_truncated_relocation(self):
        changed = bytearray(self.source)
        struct.pack_into("<I", changed, self.pe.offset(0x2444), 0x100000)
        with self.assertRaises(t.ToolError):
            t.PE(bytes(changed)).dynamic_relocations()

    def test_zero_relocation_block(self):
        changed = bytearray(self.source)
        struct.pack_into("<I", changed, self.pe.offset(0x2458), 0)
        with self.assertRaises(t.ToolError):
            t.PE(bytes(changed)).dynamic_relocations()

    def test_hints(self):
        hints = t.callsite_hints(self.pe, self.pe.imports(), self.pe.dynamic_relocations())
        locations = {r["rva"] for r in hints["candidates"]}
        self.assertIn("0x1020", locations)
        self.assertIn("0x1048", locations)
        self.assertFalse(hints["automatically_patchable"])

    def test_checksum_odd_length(self):
        self.assertEqual(t.pe_checksum(b"\x01\x02\0\0\0\0\x05", 2), 0x201 + 5 + 7)

    def test_branches(self):
        self.assertEqual(t.branch_link(0x1000, 0x1004), bytes.fromhex("01000094"))
        self.assertEqual(t.branch_link(0x1004, 0x1000), bytes.fromhex("ffffff97"))
        with self.assertRaises(t.ToolError):
            t.branch_link(0, 1)
        with self.assertRaises(t.ToolError):
            t.branch_link(0, 1 << 27)

    def test_target_build_formats(self):
        for value in ("22621", "22621.1702", "10.0.22621.1702"):
            self.assertEqual(t.build_number(value), 22621)
        for value in ("bad", "1.2.3", "", "-1"):
            with self.assertRaises(t.ToolError):
                t.build_number(value)

    def test_dependency_missing_module(self):
        with tempfile.TemporaryDirectory() as td:
            report = t.dependency_check(self.pe.imports(), Path(td), False)
            self.assertEqual(report["status"], "incomplete")

    def test_dependency_missing_exports(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "storport.sys").write_bytes(self.source)
            report = t.dependency_check(self.pe.imports(), Path(td), False)
            self.assertEqual(report["status"], "missing_exports")

    def test_profile_schema(self):
        t.validate_profile(t.BUILTIN_PROFILE)
        for key in ("source_sha256", "output_sha256", "inf_sha256"):
            p = copy.deepcopy(self.profile)
            p[key] = "bad"
            with self.assertRaises(t.ToolError):
                t.validate_profile(p)

    def test_output_never_overwrites(self):
        report = t.analyze(self.source, self.inf, [self.profile])
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "result"
            t.write_bundle(folder, report)
            old = (folder / "report.json").read_bytes()
            with self.assertRaises(t.ToolError):
                t.write_bundle(folder, report)
            self.assertEqual((folder / "report.json").read_bytes(), old)
            with zipfile.ZipFile(folder / "evidence.zip") as z:
                self.assertEqual(set(z.namelist()), {"report.json", "report.txt"})

    def test_cli_unknown_build(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "stornvme.sys").write_bytes(self.source)
            (root / "stornvme.inf").write_bytes(self.inf)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = t.main([str(root), "--out", str(root / "output")])
            self.assertEqual(code, 3)
            self.assertFalse((root / "output" / "unsigned-package").exists())
            self.assertEqual((root / "stornvme.sys").read_bytes(), self.source)

    def test_cli_known_custom_profile(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "stornvme.sys").write_bytes(self.source)
            (root / "stornvme.inf").write_bytes(self.inf)
            (root / "profile.json").write_text(json.dumps(self.profile))
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = t.main([str(root), "--profile", str(root / "profile.json"), "--out", str(root / "output")])
            self.assertEqual(code, 0)
            self.assertEqual((root / "output" / "unsigned-package" / "stornvme.sys").read_bytes(), self.expected)

    def test_analyze_only_never_builds(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "stornvme.sys").write_bytes(self.source)
            (root / "stornvme.inf").write_bytes(self.inf)
            (root / "profile.json").write_text(json.dumps(self.profile))
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = t.main([str(root), "--profile", str(root / "profile.json"),
                               "--out", str(root / "output"), "--analyze-only"])
            self.assertEqual(code, 0)
            self.assertFalse((root / "output" / "unsigned-package").exists())

    def test_no_profile_override(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "override.json"
            p.write_text(json.dumps(t.BUILTIN_PROFILE))
            with self.assertRaisesRegex(t.ToolError, "Duplicate"):
                t.load_profiles([p])

    def test_small_header_mutations_controlled(self):
        rng = random.Random(20261011)
        for _ in range(100):
            changed = bytearray(self.source)
            at = rng.randrange(0x200)
            changed[at] ^= 1 << rng.randrange(8)
            try:
                t.PE(bytes(changed))
            except t.ToolError:
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
