#!/usr/bin/env python3
"""Pi 5 NVMe version-aware inspector and profile-gated offline patch builder.

Python 3.9+, standard library only. No downloads, installation, signing, or
system modifications. Unknown binaries produce analysis, never guessed patches.

The bundled recipe's numeric patch facts come from damian5466's nvme/build.py
(Git blob c0a207c6a0eec2e7fd19de9112ee6d308054ed06). This is an independent,
data-driven implementation, not the upstream script. See README.md for limits.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple
import uuid
import zipfile

VERSION = "1.1.0"
MAX_FILE = 64 * 1024 * 1024
MAX_ITEMS = 65536
MACHINE_ARM64 = 0xAA64
REPO = "https://github.com/damian5466/rpi5-windows-drivers"
# Facts of the upstream recipe, NOT a declaration of local hardware validation.
BUILTIN_PROFILE: Dict[str, Any] = {
    "schema": 1,
    "id": "upstream-arm64-26100.9539",
    "source_sha256": "10330d2cf54a03208c677713332c77e38ce5c0029d87cf7a0fd9af33e121d249",
    "inf_sha256": "8cfb0401ac12f2ce0a9a2dfe80a3eaba999997cb4e7c293ab03be62ae9e1fed1",
    "output_sha256": "f647dd0e011997ef8c652d3cd9a887963cb31f202a7d0f0505c6221e787a8530",
    "source_version": "10.0.26100.9539",
    "provenance": REPO + "/blob/main/nvme/build.py",
    "recipe_blob_sha1": "c0a207c6a0eec2e7fd19de9112ee6d308054ed06",
    "runtime_evidence": "Upstream reports Windows ARM64 26200.9539 / Pi 5 D0. Not tested here.",
    "inf_model_section": "NVME.NTarm64",
    "inf_install_section": "Stornvme_Inst",
    "inf_date": "09/19/2026",
    "edits": [
        {"rva": rva, "before": struct.pack("<I", 0x52800020 | reg).hex(),
         "after": struct.pack("<I", 0x52800000 | reg).hex()}
        for rva, reg in [(0x483C, 6), (0x489C, 6), (0x5518, 6), (0x5564, 6),
                         (0x55D8, 4), (0x6568, 4), (0x6798, 4), (0x6E58, 4)]
    ],
    "helper": {
        "rva": 0x39F90, "section": ".text",
        "bytes": "e90302aa2a054091297a0bd5290101913f010aeba3ffff549f3f03d500011fd6"
    },
    "calls": [{"rva": rva, "before": "00013fd6"}
              for rva in [0xB654, 0xB838, 0x1FD1C, 0x2389C, 0x38B28]],
    "relocation": {
        "mode": "arm64-import-transfer-v1", "table_size": 5316,
        "register": 8, "iat_index": 28, "indirect_call": 1
    }
}


class ToolError(Exception):
    """A controlled failure, never authorization to guess or bypass checks."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ToolError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_file(path: Path, limit: int = MAX_FILE) -> bytes:
    with path.open("rb") as f:
        data = f.read(limit + 1)
    need(len(data) <= limit, f"File exceeds the {limit}-byte size limit: {path.name}")
    return data


def integer(value: Any) -> int:
    need(isinstance(value, (str, int)) and not isinstance(value, bool), "Expected an integer")
    try:
        result = int(value, 0) if isinstance(value, str) else value
    except ValueError as exc:
        raise ToolError(f"Invalid integer: {value}") from exc
    need(0 <= result <= 0xFFFFFFFF, "Integer is outside the supported 32-bit range")
    return result


def hexbytes(text: str) -> bytes:
    try:
        return bytes.fromhex(text)
    except (ValueError, TypeError) as exc:
        raise ToolError("Invalid hexadecimal byte string") from exc


def build_number(text: str) -> int:
    # Accept 22621, 22621.1702, or a four-part Windows version.
    need(bool(re.fullmatch(r"\d+(?:\.\d+){0,3}", text)), "Invalid target build format")
    parts = [int(x) for x in text.split(".")]
    need(len(parts) in (1, 2, 4), "Use 22621, 22621.1702, or 10.0.22621.1702")
    return parts[2] if len(parts) == 4 else parts[0]


class PE:
    """Bounded, read-only PE32+ parser; intentionally rejects ambiguous layouts."""
    def __init__(self, data: bytes):
        self.data = data
        need(len(data) >= 64 and data[:2] == b"MZ", "Input is not a DOS/PE image")
        self.pe = self.u32(0x3C)
        need(self.slice(self.pe, 4) == b"PE\0\0", "Missing PE signature")
        self.machine = self.u16(self.pe + 4)
        count = self.u16(self.pe + 6)
        need(1 <= count <= 96, "Unsupported section count")
        self.optional = self.pe + 24
        opt_size = self.u16(self.pe + 20)
        need(opt_size >= 112, "Truncated optional header")
        self.slice(self.optional, opt_size)
        need(self.u16(self.optional) == 0x20B, "Only PE32+ images are supported")
        self.imagebase = self.u64(self.optional + 24)
        self.sizeofimage = self.u32(self.optional + 56)
        self.headers_size = self.u32(self.optional + 60)
        self.checksum_offset = self.optional + 64
        self.subsystem = self.u16(self.optional + 68)
        self.entrypoint = self.u32(self.optional + 16)
        directory_count = self.u32(self.optional + 108)
        need(directory_count <= (opt_size - 112) // 8, "Data directories exceed optional header")
        need(self.headers_size <= len(data), "Headers exceed file")
        self.directories = [self.unpack("<II", self.optional + 112 + n * 8)
                            for n in range(directory_count)]
        table = self.optional + opt_size
        need(table + count * 40 <= self.headers_size, "Section table exceeds headers")
        self.sections: List[Dict[str, Any]] = []
        for n in range(count):
            p = table + n * 40
            name = self.slice(p, 8).split(b"\0")[0].decode("ascii", "replace")
            vs, rva, raw_size, raw = self.unpack("<IIII", p + 8)
            flags = self.u32(p + 36)
            if raw_size:
                need(raw >= self.headers_size, "Section raw data overlaps headers")
                self.slice(raw, raw_size)
            need(rva + max(vs, raw_size) <= self.sizeofimage, "Section exceeds SizeOfImage")
            section = dict(name=name, rva=rva, virtual_size=vs, raw_size=raw_size,
                           raw=raw, flags=flags, header=p)
            for old in self.sections:
                if raw_size and old["raw_size"]:
                    need(raw + raw_size <= old["raw"] or old["raw"] + old["raw_size"] <= raw,
                         "Overlapping section file ranges")
                a, b = max(vs, raw_size), max(old["virtual_size"], old["raw_size"])
                if a and b:
                    need(rva + a <= old["rva"] or old["rva"] + b <= rva,
                         "Overlapping section RVA ranges")
            self.sections.append(section)

    def slice(self, offset: int, size: int) -> bytes:
        need(offset >= 0 and size >= 0 and offset + size <= len(self.data), "Out-of-bounds PE data")
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int) -> Tuple[Any, ...]:
        return struct.unpack(fmt, self.slice(offset, struct.calcsize(fmt)))

    def u16(self, offset: int) -> int:
        return self.unpack("<H", offset)[0]

    def u32(self, offset: int) -> int:
        return self.unpack("<I", offset)[0]

    def u64(self, offset: int) -> int:
        return self.unpack("<Q", offset)[0]

    def directory(self, index: int) -> Tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def offset(self, rva: int, size: int = 1) -> int:
        need(rva >= 0 and size > 0, "Invalid RVA range")
        if rva + size <= self.headers_size:
            self.slice(rva, size)
            return rva
        for section in self.sections:
            delta = rva - section["rva"]
            if 0 <= delta and delta + size <= section["raw_size"]:
                return section["raw"] + delta
        raise ToolError(f"RVA 0x{rva:X} (+{size}) is not backed by file bytes")

    def section_at(self, rva: int, size: int = 1) -> Dict[str, Any]:
        self.offset(rva, size)
        for section in self.sections:
            if section["rva"] <= rva and rva + size <= section["rva"] + section["raw_size"]:
                return section
        raise ToolError("Patch location must be inside a section, not the headers")

    def cstring(self, rva: int, limit: int = 1024) -> str:
        start = self.offset(rva)
        end = self.data.find(b"\0", start, min(len(self.data), start + limit))
        need(end >= 0, "Unterminated PE string")
        self.offset(rva, end - start + 1)
        return self.data[start:end].decode("ascii", "replace")

    def imports(self) -> List[Dict[str, Any]]:
        rva, size = self.directory(1)
        if not rva:
            return []
        need(size >= 20, "Truncated import directory")
        result = []
        for n in range(min(size // 20, MAX_ITEMS)):
            pos = self.offset(rva + n * 20, 20)
            lookup, timestamp, chain, name, iat = self.unpack("<IIIII", pos)
            if (lookup, timestamp, chain, name, iat) == (0, 0, 0, 0, 0):
                return result
            dll = self.cstring(name)
            need(iat != 0, "Import descriptor has no IAT")
            table = lookup or iat
            for index in range(MAX_ITEMS):
                item = self.u64(self.offset(table + index * 8, 8))
                if item == 0:
                    break
                if item & (1 << 63):
                    symbol, ordinal = None, item & 0xFFFF
                else:
                    symbol, ordinal = self.cstring(item + 2), None
                result.append(dict(module=dll, name=symbol, ordinal=ordinal,
                                   iat_rva=iat + index * 8))
                need(len(result) < MAX_ITEMS, "Excessive import count")
            else:
                raise ToolError("Unterminated import thunk array")
        raise ToolError("Unterminated import descriptor table")

    def exports(self) -> Dict[str, Any]:
        rva, size = self.directory(0)
        if not rva:
            return {"names": {}, "ordinals": {}}
        pos = self.offset(rva, 40)
        base, functions, names, eat, npt, ot = self.unpack("<IIIIII", pos + 16)
        need(functions <= MAX_ITEMS and names <= MAX_ITEMS, "Excessive export count")
        by_ordinal: Dict[int, Any] = {}
        for index in range(functions):
            target = self.u32(self.offset(eat + 4 * index, 4))
            if target:
                forward = self.cstring(target) if rva <= target < rva + size else None
                by_ordinal[base + index] = {"rva": target, "forwarder": forward}
        by_name: Dict[str, Any] = {}
        for index in range(names):
            text = self.cstring(self.u32(self.offset(npt + index * 4, 4)))
            ordinal_index = self.u16(self.offset(ot + index * 2, 2))
            need(ordinal_index < functions, "Invalid export ordinal index")
            if base + ordinal_index in by_ordinal:
                by_name[text] = by_ordinal[base + ordinal_index]
        return {"names": by_name, "ordinals": by_ordinal}

    def file_version(self) -> Optional[str]:
        rva, size = self.directory(2)
        if not rva:
            return None
        # Walk numeric RT_VERSION (16), then resource id and language directories.
        def resource_bytes(relative: int, length: int) -> int:
            need(0 <= relative and relative + length <= size, "Resource escapes directory")
            return self.offset(rva + relative, length)
        def entries(relative: int) -> List[Tuple[int, int]]:
            p = resource_bytes(relative, 16)
            total = self.u16(p + 12) + self.u16(p + 14)
            need(total <= 4096, "Excessive resource directory entries")
            return [self.unpack("<II", resource_bytes(relative + 16 + i * 8, 8))
                    for i in range(total)]
        roots = [value for key, value in entries(0) if key == 16]
        if not roots:
            return None
        leaves: List[int] = []
        visited = set()
        def walk(value: int, depth: int) -> None:
            need(depth <= 4, "Resource recursion depth exceeded")
            if not value & 0x80000000:
                leaves.append(value)
                return
            sub = value & 0x7FFFFFFF
            need(sub not in visited, "Cyclic resource directory")
            visited.add(sub)
            for _, child in entries(sub):
                walk(child, depth + 1)
        for root in roots:
            walk(root, 0)
        versions = set()
        for leaf in leaves:
            p = resource_bytes(leaf, 16)
            data_rva, length = self.unpack("<II", p)
            need(6 <= length <= 1024 * 1024, "Invalid version resource length")
            b = self.slice(self.offset(data_rva, length), length)
            total, value_length, kind = struct.unpack_from("<HHH", b)
            need(6 <= total <= length, "Invalid VS_VERSION_INFO length")
            key = "VS_VERSION_INFO\0".encode("utf-16-le")
            need(b[6:6 + len(key)] == key, "Invalid VS_VERSION_INFO key")
            value_start = (6 + len(key) + 3) & ~3
            need(kind == 0 and value_length >= 52 and value_start + value_length <= total,
                 "Invalid fixed version information")
            signature, revision, ms, ls = struct.unpack_from("<IIII", b, value_start)
            need(signature == 0xFEEF04BD, "Missing VS_FIXEDFILEINFO signature")
            versions.add(f"{ms >> 16}.{ms & 65535}.{ls >> 16}.{ls & 65535}")
        need(len(versions) <= 1, "Conflicting resource file versions")
        return next(iter(versions), None)

    def debug_info(self) -> List[Dict[str, Any]]:
        rva, size = self.directory(6)
        if not rva:
            return []
        need(size % 28 == 0 and size // 28 <= 1024, "Malformed debug directory")
        result = []
        for index in range(size // 28):
            p = self.offset(rva + index * 28, 28)
            kind, length, address, pointer = self.unpack("<IIII", p + 12)
            if kind == 2 and length >= 24:
                b = self.slice(pointer, length)
                if b[:4] == b"RSDS":
                    guid = uuid.UUID(bytes_le=b[4:20]).hex.upper()
                    age = struct.unpack_from("<I", b, 20)[0]
                    pdb = b[24:].split(b"\0")[0].decode("utf-8", "replace")
                    result.append(dict(pdb_name=pdb.replace("\\", "/").split("/")[-1],
                                       guid=guid, age=age, symbol_key=guid + f"{age:X}"))
        return result

    def dynamic_relocations(self) -> Optional[Dict[str, Any]]:
        rva, directory_size = self.directory(10)
        if not rva:
            return None
        need(directory_size >= 4, "Truncated load configuration")
        declared = self.u32(self.offset(rva, 4))
        size = min(directory_size, declared)
        pointer = self.u64(self.offset(rva + 0xC0, 8)) if size >= 0xC8 else 0
        relative = self.u32(self.offset(rva + 0xE0, 4)) if size >= 0xE6 else 0
        section_index = self.u16(self.offset(rva + 0xE4, 2)) if size >= 0xE6 else 0
        loc = None
        containing = None
        if section_index:
            need(section_index <= len(self.sections), "Invalid dynamic relocation section index")
            containing = self.sections[section_index - 1]
            need(relative + 8 <= containing["raw_size"], "Dynamic relocation header exceeds section")
            loc = containing["raw"] + relative
        if pointer:
            need(pointer >= self.imagebase, "Invalid dynamic relocation virtual address")
            pointer_rva = pointer - self.imagebase
            pointer_loc = self.offset(pointer_rva, 8)
            need(loc is None or loc == pointer_loc, "Conflicting dynamic relocation pointers")
            loc = pointer_loc
            containing = self.section_at(pointer_rva, 8)
        if loc is None:
            need(relative == 0, "Relocation offset exists without its section")
            return None
        version, payload_size = self.unpack("<II", loc)
        need(payload_size <= MAX_FILE and loc + 8 + payload_size <= containing["raw"] + containing["raw_size"],
             "Dynamic relocation table exceeds section")
        self.slice(loc, 8 + payload_size)
        if version != 1:
            return dict(offset=loc, version=version, size=payload_size, records=[],
                        unsupported=True, reason="Only version-1 tables are decoded")
        records = []
        cursor, end = loc + 8, loc + 8 + payload_size
        while cursor < end:
            need(cursor + 12 <= end, "Truncated dynamic relocation record header")
            symbol, length = self.unpack("<QI", cursor)
            need(cursor + 12 + length <= end, "Truncated dynamic relocation payload")
            payload = self.slice(cursor + 12, length)
            blocks = []
            if symbol == 8:
                at = 0
                while at < length:
                    need(at + 8 <= length, "Truncated import-transfer block")
                    page, block_size = struct.unpack_from("<II", payload, at)
                    need(page % 4096 == 0 and block_size >= 8 and block_size % 4 == 0
                         and at + block_size <= length, "Invalid import-transfer block")
                    items = []
                    for b in range(at + 8, at + block_size, 4):
                        word = struct.unpack_from("<I", payload, b)[0]
                        items.append(dict(word=word, rva=page + (word & 1023) * 4,
                                          indirect_call=(word >> 10) & 1,
                                          register=(word >> 11) & 31,
                                          import_type=(word >> 16) & 1,
                                          iat_index=word >> 17))
                    blocks.append(dict(page=page, entries=items))
                    at += block_size
            records.append(dict(symbol=symbol, payload=payload, blocks=blocks))
            need(len(records) <= MAX_ITEMS, "Excessive dynamic relocation records")
            cursor += 12 + length
        return dict(offset=loc, version=version, size=payload_size, records=records,
                    unsupported=False)


def decode_inf(data: bytes) -> str:
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16")
        elif b"\x00" in data[:256]:
            text = data.decode("utf-16-le")
        else:
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = data.decode("cp1252")
    except UnicodeError as exc:
        raise ToolError("Cannot decode the INF") from exc
    need("\x00" not in text, "INF contains embedded NUL characters")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def inf_sections(text: str) -> Dict[str, List[str]]:
    sections: Dict[str, List[str]] = {}
    current = None
    for line in text.splitlines():
        match = re.fullmatch(r"\s*\[([^\]]+)\]\s*(?:;.*)?", line)
        if match:
            current = match[1].strip().lower()
            need(current not in sections, f"Duplicate INF section: {current}")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    need("version" in sections, "Missing INF [Version] section")
    return sections


def inf_values(lines: List[str]) -> Dict[str, str]:
    result = {}
    for line in lines:
        # Relevant Version keys do not need quoted semicolons or continuations.
        code = line.split(";", 1)[0].strip()
        if "=" in code:
            key, value = code.split("=", 1)
            key = key.strip().lower()
            need(key not in result, f"Duplicate INF key: {key}")
            result[key] = value.strip()
    return result


def inspect_inf(data: bytes) -> Dict[str, Any]:
    text = decode_inf(data)
    sections = inf_sections(text)
    version = inf_values(sections["version"])
    raw = version.get("driverver", "")
    match = re.fullmatch(r"\s*([^,]+),\s*(\d+\.\d+\.\d+\.\d+)\s*", raw)
    need(match is not None, "Invalid or missing INF DriverVer")
    arm64_sections = sorted(s for s in sections if ".ntarm64" in s)
    return dict(sha256=sha256(data), driver_version=match[2], date=match[1].strip(),
                arm64_sections=arm64_sections, class_name=version.get("class"),
                class_guid=version.get("classguid"),
                references_stornvme=bool(re.search(r"\bstornvme\.sys\b", text, re.I)),
                catalogs={k: v for k, v in version.items() if k.startswith("catalogfile")},
                matching_version_is_not_proof_of_matching_package=True)


def validate_profile(profile: Dict[str, Any]) -> None:
    need(isinstance(profile, dict) and profile.get("schema") == 1, "Unsupported profile schema")
    for key in ("source_sha256", "inf_sha256", "output_sha256"):
        need(isinstance(profile.get(key), str) and
             bool(re.fullmatch("[0-9a-f]{64}", profile[key])), f"Invalid profile {key}")
    need(bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", profile.get("id", ""))), "Invalid profile id")
    need(bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", profile.get("source_version", ""))),
         "Profile needs the expected four-part source version")
    for key in ("provenance", "runtime_evidence", "inf_model_section", "inf_install_section", "inf_date"):
        need(isinstance(profile.get(key), str) and bool(profile[key]), f"Missing profile {key}")
    for key in ("inf_model_section", "inf_install_section"):
        need(bool(re.fullmatch(r"[A-Za-z0-9_.-]+", profile[key])), f"Invalid profile {key}")
    need(".ntarm64" in profile["inf_model_section"].lower(), "Profile model section is not ARM64")
    try:
        dt.datetime.strptime(profile["inf_date"], "%m/%d/%Y")
    except ValueError as exc:
        raise ToolError("Invalid profile INF date") from exc
    need(isinstance(profile.get("edits"), list) and 1 <= len(profile["edits"]) <= 256,
         "Profile needs a bounded edit list")
    for edit in profile["edits"]:
        rva = integer(edit["rva"])
        old, new = hexbytes(edit["before"]), hexbytes(edit["after"])
        need(rva % 4 == 0 and 0 < len(old) <= 256 and len(old) == len(new) and len(old) % 4 == 0,
             "Invalid aligned instruction replacement")
    helper = profile.get("helper", {})
    need(isinstance(helper.get("section"), str), "Missing helper section")
    need(integer(helper["rva"]) % 4 == 0, "Unaligned helper")
    code = hexbytes(helper["bytes"])
    need(0 < len(code) <= 4096 and len(code) % 4 == 0, "Invalid helper length")
    need(isinstance(profile.get("calls"), list) and 1 <= len(profile["calls"]) <= 256,
         "Profile needs call redirections")
    for call in profile["calls"]:
        need(integer(call["rva"]) % 4 == 0 and len(hexbytes(call["before"])) == 4,
             "Invalid call site")
    relocation = profile.get("relocation", {})
    need(relocation.get("mode") in ("none", "arm64-import-transfer-v1"),
         "Unsupported dynamic relocation strategy")
    if relocation["mode"] != "none":
        integer(relocation["table_size"])
        need(0 <= integer(relocation["register"]) <= 31, "Invalid relocation register")
        need(0 <= integer(relocation["iat_index"]) < (1 << 15), "Invalid relocation import index")
        need(integer(relocation["indirect_call"]) in (0, 1), "Invalid relocation call flag")


def load_profiles(paths: List[Path]) -> List[Dict[str, Any]]:
    profiles = [BUILTIN_PROFILE]
    # The optional companion keeps the original single-file CLI usable.
    # Its records are exact real-input static ports, NOT hardware approvals.
    try:
        from pi5_nvme_profiles import ADDITIONAL_PROFILES
    except ModuleNotFoundError as exc:
        if exc.name != "pi5_nvme_profiles":
            raise
    else:
        profiles.extend(ADDITIONAL_PROFILES)
    for path in paths:
        try:
            value = json.loads(read_file(path, 1024 * 1024).decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise ToolError(f"Invalid profile JSON: {path}") from exc
        profiles.append(value)
    seen = set()
    for profile in profiles:
        try:
            validate_profile(profile)
        except (KeyError, TypeError, ValueError) as exc:
            raise ToolError(f"Malformed profile: {exc}") from exc
        need(profile["source_sha256"] not in seen, "Duplicate/ambiguous profile source hash")
        seen.add(profile["source_sha256"])
    return profiles


def pe_checksum(data: bytes, offset: int) -> int:
    need(0 <= offset and offset + 4 <= len(data) and offset % 2 == 0, "Invalid checksum location")
    total = 0
    for index in range(0, len(data), 2):
        word = 0 if offset <= index < offset + 4 else int.from_bytes(data[index:index + 2], "little")
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF


def branch_link(site: int, target: int) -> bytes:
    displacement = target - site
    need(displacement % 4 == 0 and -(1 << 27) <= displacement < (1 << 27),
         "ARM64 BL target is unaligned or outside +/-128 MiB")
    return struct.pack("<I", 0x94000000 | ((displacement // 4) & 0x3FFFFFF))


def relocate_table(pe: PE, profile: Dict[str, Any]) -> Optional[Tuple[int, bytes, List[int]]]:
    table = pe.dynamic_relocations()
    recipe = profile["relocation"]
    if recipe["mode"] == "none":
        need(table is None, "Profile says no dynamic relocation table, but one is present")
        return None
    need(table is not None and not table["unsupported"], "Expected a supported dynamic relocation table")
    need(table["size"] == integer(recipe["table_size"]), "Unexpected dynamic relocation table size")
    targets = {integer(c["rva"]) for c in profile["calls"]}
    need(len(targets) == len(profile["calls"]), "Duplicate profile call sites")
    removed: List[int] = []
    encoded_records = []
    for record in table["records"]:
        payload = record["payload"]
        if record["symbol"] == 8:
            encoded_blocks = []
            for block in record["blocks"]:
                remaining = []
                for entry in block["entries"]:
                    if entry["rva"] not in targets:
                        remaining.append(struct.pack("<I", entry["word"]))
                        continue
                    need(entry["import_type"] == 0 and
                         entry["register"] == integer(recipe["register"]) and
                         entry["iat_index"] == integer(recipe["iat_index"]) and
                         entry["indirect_call"] == integer(recipe["indirect_call"]),
                         "Relocation semantics differ from the profile")
                    removed.append(entry["rva"])
                if remaining:
                    encoded_blocks.append(struct.pack("<II", block["page"], 8 + 4 * len(remaining))
                                          + b"".join(remaining))
            payload = b"".join(encoded_blocks)
        encoded_records.append(struct.pack("<QI", record["symbol"], len(payload)) + payload)
    need(len(removed) == len(targets) and set(removed) == targets,
         "Did not find each required import-transfer relocation exactly once")
    payload = b"".join(encoded_records)
    need(len(payload) <= table["size"], "Relocation rewrite unexpectedly grew")
    encoded = (struct.pack("<II", 1, len(payload)) + payload
               + bytes(table["size"] - len(payload)))
    return table["offset"], encoded, sorted(removed)


def apply_patch(source: bytes, profile: Dict[str, Any]) -> Tuple[bytes, List[Dict[str, Any]]]:
    """All transformations are made to a copy and accepted only by exact output hash."""
    validate_profile(profile)
    need(sha256(source) == profile["source_sha256"], "No exact source-hash match")
    pe = PE(source)
    need(pe.machine == MACHINE_ARM64 and pe.subsystem == 1, "Expected an ARM64 native driver")
    need(pe.file_version() == profile["source_version"], "Profile/source version mismatch")
    need(not pe.directory(13)[0], "Delay imports are not supported for patch builds")
    result = bytearray(source)
    changed_ranges: List[Tuple[int, int]] = []
    log: List[Dict[str, Any]] = []

    def edit(offset: int, before: bytes, after: bytes, purpose: str) -> None:
        need(len(before) == len(after) and len(before) > 0, "Invalid byte replacement")
        pe.slice(offset, len(before))
        need(source[offset:offset + len(before)] == before, f"Precondition failed: {purpose}")
        end = offset + len(before)
        for start0, end0 in changed_ranges:
            need(end <= start0 or end0 <= offset, "Overlapping patch operations")
        changed_ranges.append((offset, end))
        result[offset:end] = after
        log.append(dict(purpose=purpose, file_offset=f"0x{offset:X}",
                        length=len(before), before_sha256=sha256(before), after_sha256=sha256(after)))

    for item in profile["edits"]:
        rva = integer(item["rva"])
        before, after = hexbytes(item["before"]), hexbytes(item["after"])
        section = pe.section_at(rva, len(before))
        need(section["flags"] & 0x20000000 != 0, "Instruction edit is not executable")
        edit(pe.offset(rva, len(before)), before, after, f"allocation instruction RVA 0x{rva:X}")

    helper = profile["helper"]
    helper_rva = integer(helper["rva"])
    code = hexbytes(helper["bytes"])
    section = pe.section_at(helper_rva, len(code))
    need(section["name"] == helper["section"] and section["flags"] & 0x20000000 != 0,
         "Unexpected helper section")
    need(section["flags"] & 0x80000000 == 0, "Refusing a writable/executable helper section")
    # This engine only uses profile-selected zero padding beyond the logical end.
    need(helper_rva >= section["rva"] + section["virtual_size"],
         "Helper overlaps existing logical section contents")
    edit(pe.offset(helper_rva, len(code)), bytes(len(code)), code, "cache-maintenance helper")
    new_size = helper_rva + len(code) - section["rva"]
    edit(section["header"] + 8, struct.pack("<I", section["virtual_size"]),
         struct.pack("<I", new_size), "extend executable section logical size")
    for call in profile["calls"]:
        rva = integer(call["rva"])
        need(pe.section_at(rva, 4)["flags"] & 0x20000000 != 0, "Call site is not executable")
        edit(pe.offset(rva, 4), hexbytes(call["before"]), branch_link(rva, helper_rva),
             f"redirect PRP helper call RVA 0x{rva:X}")

    relocation = relocate_table(pe, profile)
    if relocation is not None:
        loc, rewritten, removed = relocation
        edit(loc, pe.slice(loc, len(rewritten)), rewritten, "repair import-transfer relocations")
        log.append(dict(purpose="removed relocation sites", rvas=[f"0x{x:X}" for x in removed]))

    cert_offset, cert_size = pe.directory(4)
    need(cert_offset > 0 and cert_size >= 8 and cert_offset + cert_size == len(source),
         "Expected a terminal embedded-signature area; no overlay guessing is allowed")
    need(cert_offset >= max(s["raw"] + s["raw_size"] for s in pe.sections),
         "Certificate overlaps section data")
    security_header = pe.optional + 112 + 4 * 8
    edit(security_header, pe.slice(security_header, 8), bytes(8), "clear invalidated signature directory")
    need(all(end <= cert_offset for _, end in changed_ranges), "Patch overlaps certificate bytes")
    del result[cert_offset:]
    struct.pack_into("<I", result, pe.checksum_offset, pe_checksum(result, pe.checksum_offset))
    output = bytes(result)
    need(sha256(output) == profile["output_sha256"],
         "Output hash differs from the reviewed reference; no driver will be written")
    # Re-parse the result; the cryptographic comparison above remains mandatory.
    rebuilt = PE(output)
    need(rebuilt.directory(4) == (0, 0), "Output retains a certificate directory")
    need(rebuilt.imports() == pe.imports(), "Patch changed the normal import table")
    need(rebuilt.file_version() == pe.file_version(), "Patch changed the file version")
    log.append(dict(purpose="remove invalidated signature and recalculate PE checksum",
                    old_size=len(source), new_size=len(output), output_sha256=sha256(output)))
    return output, log


def make_inf(source: bytes, profile: Dict[str, Any], hardware_id: str) -> bytes:
    need(sha256(source) == profile["inf_sha256"], "INF does not match the profile's original package")
    hardware_id = hardware_id.upper()
    need(bool(re.fullmatch(r"PCI\\[A-Z0-9_&]+", hardware_id)), "Invalid PCI hardware/compatible ID")
    text = decode_inf(source)
    sections = inf_sections(text)
    model = profile["inf_model_section"].lower()
    install = profile["inf_install_section"]
    need(model in sections and install.lower() in sections, "Missing expected INF installation sections")
    need("strings" in sections, "INF lacks [Strings]")
    info = inspect_inf(source)
    need(info["driver_version"] == profile["source_version"], "SYS/INF version mismatch")
    need(info["references_stornvme"], "INF does not reference stornvme.sys")
    need(not re.search(r"\bPi5Local(?:Provider|Description)\b", text, re.I),
         "INF already contains local patch keys")
    # Preserve all source sections and OS decorations except the reviewed ARM64
    # model binding and Version provider/date/catalog keys. Never lower OS gates.
    output = []
    current = None
    for line in text.splitlines():
        match = re.fullmatch(r"\s*\[([^\]]+)\]\s*(?:;.*)?", line)
        if match:
            current = match[1].strip().lower()
            output.append(line)
            if current == "version":
                output.extend(["Provider = %Pi5LocalProvider%", "CatalogFile = pi5-stornvme.cat",
                               f"DriverVer = {profile['inf_date']},{profile['source_version']}"])
            elif current == model:
                output.extend([f"%Pi5LocalDescription% = {install}, {hardware_id}", ""])
            elif current == "strings":
                output.extend(['Pi5LocalProvider = "Pi5 NVMe local test build"',
                               'Pi5LocalDescription = "NVMe Controller (Pi5 DMA compatibility, local test)"'])
            continue
        if current == model:
            continue
        if current == "version" and re.match(r"\s*(Provider|DriverVer|CatalogFile(?:\.[A-Za-z0-9_.]+)?)\s*=", line, re.I):
            continue
        output.append(line)
    text_out = "\r\n".join(output) + "\r\n"
    result = b"\xff\xfe" + text_out.encode("utf-16-le")
    checked = inspect_inf(result)
    need(checked["driver_version"] == profile["source_version"], "Generated INF failed validation")
    return result


def instruction_label(word: int, rva: int) -> str:
    """Small diagnostic decoder, not a complete disassembler or proof engine."""
    if word & 0xFFFFFC1F == 0xD63F0000:
        return f"blr x{(word >> 5) & 31}"
    if word & 0xFFFFFC1F == 0xD61F0000:
        return f"br x{(word >> 5) & 31}"
    if word & 0xFFFFFC1F == 0xD65F0000:
        return f"ret x{(word >> 5) & 31}"
    if word & 0xFC000000 in (0x94000000, 0x14000000):
        displacement = word & 0x3FFFFFF
        if displacement & 0x2000000:
            displacement -= 0x4000000
        op = "bl" if word & 0x80000000 else "b"
        return f"{op} 0x{rva + displacement * 4:X}"
    if word & 0x7F800000 == 0x52800000:
        width = "x" if word & 0x80000000 else "w"
        value = ((word >> 5) & 0xFFFF) << (16 * ((word >> 21) & 3))
        return f"movz {width}{word & 31}, #0x{value:X}"
    if word & 0x9F000000 == 0x90000000:
        immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
        if immediate & 0x100000:
            immediate -= 0x200000
        return f"adrp x{word & 31}, 0x{(rva & ~4095) + (immediate << 12):X}"
    if word & 0xFFC00000 == 0xF9400000:
        return f"ldr x{word & 31}, [x{(word >> 5) & 31}, #0x{((word >> 10) & 4095) * 8:X}]"
    return f".word 0x{word:08X}"


def context_at(pe: PE, rva: int, preceding: int = 8, following: int = 2) -> List[Dict[str, Any]]:
    section = pe.section_at(rva, 4)
    start = max(section["rva"], rva - preceding * 4)
    end = min(section["rva"] + section["raw_size"], rva + (following + 1) * 4)
    return [dict(rva=f"0x{pc:X}", bytes=pe.slice(pe.offset(pc, 4), 4).hex(),
                 instruction=instruction_label(pe.u32(pe.offset(pc, 4)), pc))
            for pc in range(start, end, 4)]


def callsite_hints(pe: PE, imports: List[Dict[str, Any]], table: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    relevant = {"StorPortAllocateContiguousMemorySpecifyCacheNode",
                "StorPortAllocateContiguousMemorySpecifyCache",
                "StorPortAllocateDmaMemory", "StorPortGetPhysicalAddress",
                "StorPortFreeContiguousMemorySpecifyCache", "StorPortFreeDmaMemory",
                "MmAllocateContiguousMemorySpecifyCache", "MmAllocateContiguousMemorySpecifyCacheNode"}
    by_iat = {row["iat_rva"]: row for row in imports}
    hints: Dict[int, Dict[str, Any]] = {}
    # Relocation metadata supplies useful call-site evidence independently of the
    # exact code offsets. It is NOT evidence that a call handles a PRP list.
    if table and not table["unsupported"]:
        iat_base, iat_size = pe.directory(12)
        for record in table["records"]:
            for block in record["blocks"]:
                for entry in block["entries"]:
                    if not entry["indirect_call"] or entry["import_type"]:
                        continue
                    iat = iat_base + entry["iat_index"] * 8
                    item = by_iat.get(iat) if iat_base and entry["iat_index"] * 8 < iat_size else None
                    if item and item["name"] in relevant:
                        pc = entry["rva"]
                        hints[pc] = dict(rva=f"0x{pc:X}", import_name=item["name"],
                                         evidence="import-transfer metadata / IAT index",
                                         context=context_at(pe, pc))
    # Exact adjacent ADRP/LDR/BLR triplets: helpful on older binaries without
    # import-transfer metadata. More complex code sequences remain unresolved.
    for section in pe.sections:
        if not section["flags"] & 0x20000000:
            continue
        length = min(section["raw_size"], section["virtual_size"])
        for rel in range(8, length - 3, 4):
            pc = section["rva"] + rel
            call = pe.u32(section["raw"] + rel)
            if call & 0xFFFFFC1F != 0xD63F0000:
                continue
            load = pe.u32(section["raw"] + rel - 4)
            page = pe.u32(section["raw"] + rel - 8)
            if load & 0xFFC00000 != 0xF9400000 or page & 0x9F000000 != 0x90000000:
                continue
            if (load & 31) != ((call >> 5) & 31) or (page & 31) != ((load >> 5) & 31):
                continue
            displacement = (((page >> 5) & 0x7FFFF) << 2) | ((page >> 29) & 3)
            if displacement & 0x100000:
                displacement -= 0x200000
            iat = ((pc - 8) & ~4095) + (displacement << 12) + ((load >> 10) & 4095) * 8
            item = by_iat.get(iat)
            if item and item["name"] in relevant and pc not in hints:
                hints[pc] = dict(rva=f"0x{pc:X}", import_name=item["name"],
                                 evidence="adjacent ADRP/LDR/BLR pattern; not control-flow verified",
                                 context=context_at(pe, pc))
            need(len(hints) <= 2048, "Too many candidate call sites")
    return dict(coverage="partial", automatically_patchable=False,
                warning="Candidates are not patch sites. No PRP ownership, buffer lifetime, or cache-argument proof is performed.",
                candidates=[hints[k] for k in sorted(hints)])


def dependency_check(imports: List[Dict[str, Any]], system_dir: Optional[Path],
                     has_delay_imports: bool) -> Dict[str, Any]:
    if system_dir is None:
        return dict(status="not_checked", note="Supply --system-dir for a limited export-name check.")
    need(system_dir.is_dir(), "--system-dir must name the target Windows System32 directory")
    cache: Dict[str, Any] = {}
    rows = []
    for entry in imports:
        module = entry["module"]
        name = module.lower()
        need(bool(re.fullmatch(r"[A-Za-z0-9_.-]+", module)) and ".." not in module,
             "Unsafe import module filename")
        if name not in cache:
            if name.startswith(("api-ms-", "ext-ms-")):
                cache[name] = {"status": "unresolved_api_set"}
            else:
                # Exact common file locations; avoid recursive system-directory scans.
                paths = [system_dir / name, system_dir / "drivers" / name,
                         system_dir / module, system_dir / "drivers" / module]
                path = next((p for p in paths if p.is_file()), None)
                if path is None:
                    cache[name] = {"status": "module_not_supplied"}
                else:
                    try:
                        b = read_file(path)
                        dependency = PE(b)
                        need(dependency.machine == MACHINE_ARM64, "Dependency is not ARM64")
                        cache[name] = dict(status="parsed", exports=dependency.exports(),
                                           file_sha256=sha256(b), version=dependency.file_version())
                    except (OSError, ToolError) as exc:
                        cache[name] = dict(status="unresolved_module", error=str(exc))
        module_info = cache[name]
        row = dict(module=module, name=entry["name"], ordinal=entry["ordinal"])
        if module_info["status"] != "parsed":
            row["status"] = module_info["status"]
        else:
            exports = module_info["exports"]
            found = exports["names"].get(entry["name"]) if entry["name"] is not None else exports["ordinals"].get(entry["ordinal"])
            if found is None:
                row["status"] = "missing_export"
            elif found["forwarder"]:
                row.update(status="forwarder_unresolved", forwarder=found["forwarder"])
            else:
                row["status"] = "direct_export_present"
        rows.append(row)
    missing = sum(r["status"] == "missing_export" for r in rows)
    unresolved = sum(r["status"] not in ("direct_export_present", "missing_export") for r in rows)
    status = "missing_exports" if missing else ("incomplete" if unresolved or has_delay_imports else "direct_exports_present")
    return dict(status=status, missing_exports=missing, unresolved_imports=unresolved,
                delay_imports_checked=False, imports=rows,
                modules={k: {field: value for field, value in v.items() if field != "exports"} for k, v in cache.items()},
                warning="Matching export names does not establish calling semantics, Windows compatibility, or runtime safety.")


def analyze(source: bytes, inf: bytes, profiles: List[Dict[str, Any]],
            target_build: Optional[str] = None, system_dir: Optional[Path] = None) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "tool_version": VERSION,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "ANALYSIS_PENDING",
        "source_sha256": sha256(source), "source_bytes": len(source),
        "inf_sha256": sha256(inf), "target_build_supplied": target_build,
        "blockers": [], "warnings": [], "analysis_errors": [],
        "runtime_validation": "NOT PERFORMED",
        "automatic_installation": False, "automatic_signing": False,
        "signature_trust_validation": "NOT PERFORMED; certificate presence alone is not trust",
    }
    blockers = report["blockers"]
    profile = next((p for p in profiles if p["source_sha256"] == report["source_sha256"]), None)
    already = next((p for p in profiles if p["output_sha256"] == report["source_sha256"]), None)
    report["profile"] = None if profile is None else {
        k: profile[k] for k in ("id", "source_version", "provenance", "runtime_evidence", "output_sha256")}
    if profile is not None and "review" in profile:
        report["profile"]["review_level"] = profile["review"]["level"]
        report["warnings"].append("This exact-input recipe is a static-only port; it has NOT passed Windows/Pi hardware testing.")
    if already:
        blockers.append("Input matches an already-patched unsigned output; use original Microsoft input files.")
    elif profile is None:
        blockers.append("No reviewed recipe matches this exact SYS SHA-256. New versions are analysis-only.")
    if profile and profile["inf_sha256"] != report["inf_sha256"]:
        blockers.append("INF SHA-256 does not match the profile's original INF.")
    try:
        pe = PE(source)
    except ToolError as exc:
        blockers.append(str(exc))
        report["status"] = "BLOCKED"
        return report
    report["pe"] = dict(machine=f"0x{pe.machine:04X}", architecture="ARM64" if pe.machine == MACHINE_ARM64 else "not_ARM64",
                        subsystem=pe.subsystem, entrypoint_rva=f"0x{pe.entrypoint:X}",
                        sections=[{k: v for k, v in s.items() if k != "header"} for s in pe.sections],
                        embedded_certificate_present=bool(pe.directory(4)[0]),
                        delay_imports_present=bool(pe.directory(13)[0]))
    if pe.machine != MACHINE_ARM64:
        blockers.append("Input is not an ARM64 PE32+ driver.")
    if pe.subsystem != 1:
        blockers.append("Input is not a native-subsystem image.")
    for name, function in (("file_version", pe.file_version), ("pdb", pe.debug_info),
                           ("imports", pe.imports)):
        try:
            report[name] = function()
        except ToolError as exc:
            report["analysis_errors"].append(f"{name}: {exc}")
            report[name] = None
    try:
        report["inf"] = inspect_inf(inf)
        if not report["inf"]["arm64_sections"]:
            blockers.append("INF has no ARM64 model sections.")
        if not report["inf"]["references_stornvme"]:
            blockers.append("INF does not reference stornvme.sys.")
        if report.get("file_version") and report["file_version"] != report["inf"]["driver_version"]:
            blockers.append("SYS file version and INF DriverVer differ.")
    except ToolError as exc:
        report["analysis_errors"].append(f"INF: {exc}")
    file_version = report.get("file_version")
    if not file_version:
        blockers.append("No unambiguous file-version resource was obtained.")
    elif profile and file_version != profile["source_version"]:
        blockers.append("File-version resource disagrees with the profile.")
    if target_build and file_version and build_number(target_build) < build_number(file_version):
        blockers.append("The supplied target Windows build is older than the donor driver's build family; cross-build use is not approved by this tool.")
    if not target_build:
        report["warnings"].append("Target Windows build was not supplied; OS compatibility remains unverified.")
    if pe.directory(13)[0]:
        blockers.append("Delay imports are present; this builder does not validate them.")
    try:
        table = pe.dynamic_relocations()
        report["dynamic_relocations"] = None if table is None else dict(
            version=table["version"], size=table["size"], unsupported=table["unsupported"],
            record_symbols=[r["symbol"] for r in table["records"]],
            import_transfer_entries=sum(len(b["entries"]) for r in table["records"] for b in r["blocks"]))
        if table and table["unsupported"]:
            blockers.append("Unknown dynamic relocation table version; analysis is incomplete.")
        if pe.machine == MACHINE_ARM64 and report.get("imports") is not None:
            report["callsite_hints"] = callsite_hints(pe, report["imports"], table)
    except ToolError as exc:
        report["analysis_errors"].append(f"dynamic relocations/call-site analysis: {exc}")
    if report.get("imports") is not None:
        report["dependency_check"] = dependency_check(report["imports"], system_dir, bool(pe.directory(13)[0]))
        if system_dir and report["dependency_check"]["status"] != "direct_exports_present":
            blockers.append("The requested target dependency check did not resolve every normal import to a direct export.")
    if report["analysis_errors"]:
        blockers.append("At least one structural analysis failed; no patch will be emitted.")
    report["warnings"].extend([
        "An exact patch/output hash does not prove correct DMA behavior or hardware stability.",
        "Unknown files are not authenticated as Microsoft originals by this tool.",
        "Any built output is UNSIGNED and lacks a catalog; it is not ready for installation.",
        "A separate recovery boot device and expendable NVMe test data are recommended for later hardware testing.",
    ])
    report["status"] = "ELIGIBLE_FOR_HASH_CHECKED_BUILD" if not blockers else "BLOCKED"
    return report


def report_text(report: Dict[str, Any]) -> str:
    lines = [f"Pi5 NVMe version-aware tool {VERSION}", "=" * 44,
             f"Status: {report['status']}", f"File version: {report.get('file_version', 'unavailable')}",
             f"SYS SHA-256: {report['source_sha256']}", f"INF SHA-256: {report['inf_sha256']}",
             "Runtime validation: NOT PERFORMED", "Source files are opened read-only.", ""]
    for key in ("blockers", "analysis_errors", "warnings"):
        if report.get(key):
            lines += [key.upper() + ":"] + [f"  - {x}" for x in report[key]] + [""]
    if report.get("profile"):
        lines += ["PROFILE:", json.dumps(report["profile"], indent=2), ""]
    hints = report.get("callsite_hints", {})
    lines += ["CALL-SITE HINTS (not validated patch sites):", hints.get("warning", "Not available")]
    for hint in hints.get("candidates", []):
        lines += [f"\n{hint['rva']} {hint['import_name']} -- {hint['evidence']}"]
        for instruction in hint["context"]:
            lines.append(f"  {instruction['rva']:>10}  {instruction['bytes']}  {instruction['instruction']}")
    lines += ["", "This report omits the original SYS and INF. It can contain import names,",
              "symbol identifiers, filenames and short instruction byte excerpts. Review before sharing.", ""]
    return "\n".join(lines)


def find_inputs(sys_path: Optional[Path], inf_path: Optional[Path]) -> Tuple[Path, Path]:
    if sys_path is None:
        if os.name == "nt" and os.environ.get("WINDIR"):
            root = Path(os.environ["WINDIR"])
            sys_path = root / "System32" / "drivers" / "stornvme.sys"
            if inf_path is None:
                inf_path = root / "INF" / "stornvme.inf"
        else:
            sys_path = Path("stornvme.sys")
    if sys_path.is_dir():
        sys_path = sys_path / "stornvme.sys"
    sys_path = sys_path.expanduser().resolve()
    if inf_path is None:
        candidates = [sys_path.with_name("stornvme.inf")]
        # Only use the corresponding Windows root, not an unrelated host INF.
        if sys_path.parent.name.lower() == "drivers" and sys_path.parent.parent.name.lower() == "system32":
            candidates.append(sys_path.parent.parent.parent / "INF" / "stornvme.inf")
        inf_path = next((p for p in candidates if p.is_file()), None)
    need(sys_path.is_file(), f"SYS not found: {sys_path}")
    need(inf_path is not None, "Matching INF not found; supply its path as the second argument")
    inf_path = inf_path.expanduser().resolve()
    need(inf_path.is_file(), f"INF not found: {inf_path}")
    need(sys_path != inf_path, "SYS and INF must be separate files")
    return sys_path, inf_path


def inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def write_bundle(output: Path, report: Dict[str, Any], driver: Optional[bytes] = None,
                 inf: Optional[bytes] = None) -> None:
    output = output.expanduser().resolve()
    need(not output.exists(), "Output directory already exists; choose a new directory (nothing is overwritten)")
    if os.name == "nt" and os.environ.get("WINDIR"):
        need(not inside(output, Path(os.environ["WINDIR"]).resolve()), "Do not write output under the Windows directory")
    need(output.parent.is_dir(), "Output parent directory does not exist")
    report_json = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    text = report_text(report).encode("utf-8")
    files = {"report.json": report_json, "report.txt": text}
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.json", report_json)
        z.writestr("report.txt", text)
    files["evidence.zip"] = zipped.getvalue()
    if driver is not None:
        need(inf is not None, "Internal error: output INF is missing")
        files["unsigned-package/stornvme.sys"] = driver
        files["unsigned-package/pi5-stornvme.inf"] = inf
        files["unsigned-package/NOT_READY_TO_INSTALL.txt"] = (
            "UNSIGNED LOCAL TEST OUTPUT. No catalog is included.\n"
            "Do not copy this driver into Windows/System32/drivers.\n"
            "Review the report and verify target OS/UEFI compatibility first.\n"
            "Use a separate recovery boot device and expendable test storage.\n"
            "A driver developer must validate the INF, sign the SYS, generate\n"
            "a new catalog, sign it, and verify package membership/signatures.\n"
            "This program does not install drivers or change boot/security settings.\n"
        ).encode("utf-8")
    # A fresh destination is reserved exclusively. Files use exclusive creation.
    # On I/O failure a partial result may remain; no pre-existing file is replaced.
    output.mkdir(exist_ok=False)
    for relative, content in files.items():
        path = output / relative
        path.parent.mkdir(exist_ok=True)
        with path.open("xb") as f:
            f.write(content)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("sys_file", type=Path, nargs="?", help="Original stornvme.sys, or its containing folder")
    p.add_argument("inf_file", type=Path, nargs="?", help="Matching original stornvme.inf; auto-detected when possible")
    p.add_argument("--out", type=Path, help="New output folder (must not exist)")
    p.add_argument("--analyze-only", action="store_true", help="Never emit a patched driver, even with a matching profile")
    p.add_argument("--target-build", help="Intended Windows build, e.g. 22621.1702; older donor/target mismatch blocks builds")
    p.add_argument("--system-dir", type=Path, help="Target Windows System32 for limited normal-import/export checks")
    p.add_argument("--profile", type=Path, action="append", default=[], help="Additional locally reviewed JSON recipe; repeatable")
    binding = p.add_mutually_exclusive_group()
    binding.add_argument("--hardware-id", help=r"Controller ID, e.g. PCI\VEN_1234&DEV_5678")
    binding.add_argument("--any-device", action="store_true", help=r"Use PCI\CC_010802 generic NVMe binding (default)")
    p.add_argument("--export-builtin-profile", type=Path, help="Export the bundled recipe JSON, then exit; never overwrites")
    p.add_argument("--list-profiles", action="store_true", help="List exact-input recipes and their runtime evidence, then exit")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.export_builtin_profile:
            with args.export_builtin_profile.open("x", encoding="utf-8") as f:
                json.dump(BUILTIN_PROFILE, f, indent=2)
                f.write("\n")
            print(f"Exported: {args.export_builtin_profile}")
            return 0
        if args.target_build:
            build_number(args.target_build)
        profiles = load_profiles(args.profile)
        if args.list_profiles:
            for profile in profiles:
                print(f"{profile['id']}: {profile['source_version']}")
                print(f"  SYS SHA-256: {profile['source_sha256']}")
                print(f"  {profile['runtime_evidence']}")
            return 0
        sys_path, inf_path = find_inputs(args.sys_file, args.inf_file)
        source, inf_source = read_file(sys_path), read_file(inf_path, 4 * 1024 * 1024)
        output = args.out or Path.cwd() / ("pi5-nvme-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
        need(not output.expanduser().resolve().exists(), "Output folder already exists; nothing was overwritten")
        need(not inside(sys_path, output.expanduser().resolve()) and not inside(inf_path, output.expanduser().resolve()),
             "Output folder cannot contain the input files")
        report = analyze(source, inf_source, profiles, args.target_build, args.system_dir)
        report["input_filenames"] = {"sys": sys_path.name, "inf": inf_path.name}
        report["mode"] = "analyze_only" if args.analyze_only else "auto_profile_build"
        hardware_id = (args.hardware_id or r"PCI\CC_010802").upper()
        need(bool(re.fullmatch(r"PCI\\[A-Z0-9_&]+", hardware_id)), "Invalid PCI hardware/compatible ID")
        report["requested_binding"] = hardware_id
        driver_output = inf_output = None
        if report["status"] == "ELIGIBLE_FOR_HASH_CHECKED_BUILD":
            if args.analyze_only:
                report["status"] = "ANALYZED_PROFILE_MATCH_NO_BUILD"
            else:
                profile = next(p for p in profiles if p["source_sha256"] == sha256(source))
                try:
                    driver_output, log = apply_patch(source, profile)
                    inf_output = make_inf(inf_source, profile, hardware_id)
                    report["patch_log"] = log
                    report["built_files"] = {"stornvme.sys": sha256(driver_output),
                                             "pi5-stornvme.inf": sha256(inf_output)}
                    report["status"] = "BUILT_UNSIGNED_HASH_VERIFIED"
                except ToolError as exc:
                    driver_output = inf_output = None
                    report["status"] = "BUILD_BLOCKED"
                    report["blockers"].append(str(exc))
        # Detect changed inputs during execution; no output is a valid build if
        # the files on disk changed after the snapshot was read.
        need(sha256(read_file(sys_path)) == report["source_sha256"] and
             sha256(read_file(inf_path, 4 * 1024 * 1024)) == report["inf_sha256"],
             "Input files changed during processing; rerun with stable copies")
        write_bundle(output, report, driver_output, inf_output)
        print(f"Status: {report['status']}")
        print(f"Driver file version: {report.get('file_version', 'unavailable')}")
        print(f"Report: {output.resolve() / 'report.txt'}")
        print(f"Shareable evidence: {output.resolve() / 'evidence.zip'}")
        for reason in report["blockers"]:
            print(f"  BLOCKED: {reason}")
        if driver_output is not None:
            print("Unsigned output passed the reference hash check. It is NOT ready to install.")
        elif args.analyze_only and not report["blockers"]:
            print("Analysis complete; no driver was generated.")
        else:
            print("No patched driver was generated. Source files were not modified.")
        return 3 if report["blockers"] else 0
    except (ToolError, OSError, ValueError, KeyError, TypeError, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; inputs were not opened for writing.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
