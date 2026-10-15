"""Minimal, deterministic SHA-256 Microsoft catalog encoder for local tests.

V2 CTL layout follows Microsoft.DotNet.Build.Tasks.FileCatalog (MIT), pinned
reference listed in docs/NATIVE_PACKAGES.md. PE members use Authenticode image
hashes, not whole-file hashes. This is NOT Inf2Cat signability/Windows validation.
No signing, downloads, file writes, or trust-store changes occur in this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Mapping

import pi5_nvme_tool as core

MAX_CATALOG = 4 * 1024 * 1024
OID_BASE = "1.3.6.1.4.1.311."


class CatalogError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CatalogError(message)


def der(tag: int, payload: bytes) -> bytes:
    require(0 <= tag <= 255 and tag & 31 != 31, "Unsupported ASN.1 tag")
    require(len(payload) <= MAX_CATALOG, "Catalog element exceeds size limit")
    n = len(payload)
    length = bytes([n]) if n < 128 else bytes([128 + (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + payload


def sequence(*items: bytes) -> bytes:
    return der(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return der(0x31, b"".join(sorted(items)))


def oid(value: str) -> bytes:
    try:
        arcs = [int(p) for p in value.split(".")]
    except ValueError as exc:
        raise CatalogError("Invalid OID") from exc
    require(len(arcs) >= 2 and 0 <= arcs[0] <= 2 and all(0 <= a < 2**32 for a in arcs), "Invalid OID")
    require(arcs[0] == 2 or arcs[1] < 40, "Invalid second OID arc")
    result = bytearray()
    for number in [40 * arcs[0] + arcs[1], *arcs[2:]]:
        digits = [number & 127]
        number >>= 7
        while number:
            digits.append(128 | (number & 127))
            number >>= 7
        result.extend(reversed(digits))
    return der(6, bytes(result))


@dataclass(frozen=True)
class Element:
    tag: int
    payload: bytes
    encoded: bytes


def elements(blob: bytes) -> list[Element]:
    """Read a single DER level with strict definite, minimal, bounded lengths."""
    require(len(blob) <= MAX_CATALOG, "Catalog exceeds size limit")
    pos, result = 0, []
    while pos < len(blob):
        begin = pos
        require(pos + 2 <= len(blob), "Truncated DER header")
        tag, n = blob[pos], blob[pos + 1]
        require(tag & 31 != 31 and tag != 0, "Unsupported DER tag")
        pos += 2
        if n & 128:
            count = n & 127
            require(1 <= count <= 4 and pos + count <= len(blob), "Indefinite or truncated DER length")
            require(blob[pos] != 0, "Non-minimal DER length")
            n = int.from_bytes(blob[pos:pos + count], "big")
            require(n >= 128, "Non-minimal DER long length")
            pos += count
        require(pos + n <= len(blob), "Truncated DER payload")
        result.append(Element(tag, blob[pos:pos + n], blob[begin:pos + n]))
        require(len(result) <= 1024, "Too many DER elements")
        pos += n
    return result


def one(blob: bytes, tag: int) -> Element:
    values = elements(blob)
    require(len(values) == 1 and values[0].tag == tag, "Unexpected DER structure")
    return values[0]


def extract_ctl(catalog: bytes) -> bytes:
    """Extract CTL bytes without claiming to verify the signature.

    The caller MUST separately authenticate the signed envelope using an external
    verifier, then compare these exact bytes to the expected member list.
    """
    outer = elements(one(catalog, 0x30).payload)
    require(len(outer) == 2 and outer[0].encoded == oid("1.2.840.113549.1.7.2") and outer[1].tag == 0xA0,
            "Not PKCS#7 SignedData")
    fields = elements(one(outer[1].payload, 0x30).payload)
    require(4 <= len(fields) <= 6 and fields[0].encoded == der(2, b"\x01") and fields[1].tag == 0x31,
            "Unsupported catalog SignedData")
    require(fields[2].tag == 0x30 and fields[-1].tag == 0x31, "Invalid SignedData content")
    require(all(f.tag in (0xA0, 0xA1) for f in fields[3:-1]), "Unexpected SignedData field")
    content = elements(fields[2].payload)
    require(len(content) == 2 and content[0].encoded == oid(OID_BASE + "10.1") and content[1].tag == 0xA0,
            "SignedData content is not a Microsoft CTL")
    return one(content[1].payload, 0x30).encoded


def require_sha256_signature(catalog: bytes) -> None:
    """Constrain the envelope to one SHA-256 signer before native verification."""
    extract_ctl(catalog)
    outer = elements(one(catalog, 0x30).payload)
    fields = elements(one(outer[1].payload, 0x30).payload)
    algorithm = sequence(oid("2.16.840.1.101.3.4.2.1"), der(5, b""))
    require(fields[1].encoded == set_of(algorithm), "Signed catalog must use SHA-256")
    signer = elements(one(fields[-1].payload, 0x30).payload)
    require(len(signer) in (6, 7) and signer[2].encoded == algorithm,
            "Expected exactly one SHA-256 catalog signer")


def pe_digest(blob: bytes, algorithm: str = "sha256") -> bytes:
    """Hash the supported contiguous ARM64 PE layout, fail closed on others.

    Omit CheckSum, the certificate-directory entry and the certificate table.
    Hash headers, all file-backed sections in physical order and trailing bytes
    before the certificate. Sparse/overlapping layouts are not guessed.
    """
    require(algorithm in ("sha1", "sha256"), "Unsupported digest algorithm")
    require(len(blob) <= core.MAX_FILE, "PE exceeds size limit")
    pe = core.PE(blob)
    require(pe.machine == core.MACHINE_ARM64, "Catalog PE member is not ARM64")
    headers = pe.u32(pe.optional + 60)
    checksum = pe.checksum_offset
    security = pe.optional + 112 + 4 * 8
    require(0 < checksum < checksum + 4 <= security and security + 8 <= headers <= len(blob), "Invalid PE hash header ranges")
    certificate, length = pe.directory(4)
    require(bool(certificate) == bool(length), "Invalid certificate directory")
    if length:
        require(length >= 8 and certificate % 8 == 0 and certificate + length == len(blob), "Unsupported certificate layout")
    end = certificate if length else len(blob)
    h = hashlib.new(algorithm)
    for start, stop in ((0, checksum), (checksum + 4, security), (security + 8, headers)):
        h.update(blob[start:stop])
    cursor = headers
    for section in sorted(pe.sections, key=lambda s: s["raw"]):
        if not section["raw_size"]:
            continue
        require(section["raw"] == cursor and cursor + section["raw_size"] <= end,
                "Non-contiguous or overlapping PE file layout is not supported")
        h.update(blob[cursor:cursor + section["raw_size"]])
        cursor += section["raw_size"]
    require(cursor <= end, "Certificate overlaps PE content")
    h.update(blob[cursor:end])
    return h.digest()


def descriptor(is_pe: bool) -> bytes:
    if is_pe:
        # SpcPeImageData: BIT STRING flags + optional SpcLink file/unicode.
        return sequence(oid(OID_BASE + "2.1.15"),
                        sequence(der(3, b"\x00"), der(0xA0, der(0xA2, der(0x80, b"")))))
    return sequence(oid(OID_BASE + "2.1.25"), der(0xA2, der(0x80, b"")))


def build_catalog(files: Mapping[str, bytes]) -> bytes:
    """Build a small V2 catalog for exactly one SYS and its final INF.

    SHA-1 members are lookup markers only. SHA-256 members contain the actual
    authenticated digest. The outer catalog is later signed using SHA-256.
    """
    require(set(files) == {"pi5nvme.sys", "pi5nvme.inf"}, "Expected exactly pi5nvme.sys and pi5nvme.inf")
    members: dict[bytes, bytes] = {}
    for filename, blob in sorted(files.items()):
        require(isinstance(blob, bytes) and 0 < len(blob) <= core.MAX_FILE, "Invalid catalog member bytes")
        is_pe = filename.endswith(".sys")
        for algorithm in ("sha1", "sha256"):
            digest = pe_digest(blob, algorithm) if is_pe else hashlib.new(algorithm, blob).digest()
            attrs = [sequence(oid(OID_BASE + "12.2.3"), set_of(der(0x82, b"")))]
            if algorithm == "sha256":
                indirect = sequence(descriptor(is_pe),
                                    sequence(sequence(oid("2.16.840.1.101.3.4.2.1"), der(5, b"")), der(4, digest)))
                attrs.append(sequence(oid(OID_BASE + "2.1.4"), set_of(indirect)))
            member = sequence(der(4, digest), set_of(*attrs))
            require(digest not in members or members[digest] == member, "Ambiguous member identifier")
            members[digest] = member
    identifiers = sorted(members)
    ctl = sequence(sequence(oid(OID_BASE + "12.1.1")),
                   der(4, hashlib.sha256(b"".join(identifiers)).digest()[:16]),
                   der(0x17, b"000101000000Z"),
                   sequence(oid(OID_BASE + "12.1.3"), der(5, b"")),
                   sequence(*(members[i] for i in identifiers)))
    return sequence(oid("1.2.840.113549.1.7.2"),
                    der(0xA0, sequence(der(2, b"\x01"), set_of(),
                                       sequence(oid(OID_BASE + "10.1"), der(0xA0, ctl)), set_of())))


def check_membership(catalog: bytes, files: Mapping[str, bytes]) -> None:
    """Require the signed CTL to equal the one derived from the current files.

    Byte equality checks all members, algorithms, types and attributes. It is
    only a membership check; it does not authenticate the enclosing signature.
    """
    expected = extract_ctl(build_catalog(files))
    require(extract_ctl(catalog) == expected, "Catalog membership does not match the SYS/INF bytes")
