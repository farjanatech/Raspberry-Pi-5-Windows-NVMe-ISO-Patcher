"""Catalog/packaging unit tests plus native OpenSSL/osslsigncode checks.

Fixtures are synthetic; private real-input validation is a separate local run.
No Windows installation, trust changes, ISO mutation or hardware I/O occurs.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import pi5_nvme_tool as core
import linux_test_sign as signer
from pi5_studio import catalog as cat, packages as pkg
from test_pi5_nvme_tool import fixture


def package_fixture():
    source, original_inf, p, expected = fixture()
    text = core.decode_inf(original_inf)
    text += ("\n[SourceDisksFiles]\nstornvme.sys=1\n"
             "[Stornvme_Inst.Services]\nAddService=stornvme,2,Stornvme_Service_Inst\n"
             "[Stornvme_Service_Inst]\nStartType=0\nServiceType=1\nErrorControl=3\n"
             "ServiceBinary=%12%\\stornvme.sys\nLoadOrderGroup=SCSI Miniport\n"
             "[Stornvme_copyfiles]\nstornvme.sys,,,0x100\n")
    inf = b'\xff\xfe' + text.replace('\r\n', '\n').replace('\n', '\r\n').encode('utf-16-le')
    p = copy.deepcopy(p)
    p['inf_sha256'] = core.sha256(inf)
    return source, inf, p, bytes(expected)


def collection_at(root: Path, labels=('boot-1', 'install-3')):
    source, inf, profile, unsigned = package_fixture()
    c = root / 'collection'
    c.mkdir()
    for label in labels:
        pair = c / label / 'original-inputs'
        pair.mkdir(parents=True)
        (pair/'stornvme.sys').write_bytes(source)
        (pair/'stornvme.inf').write_bytes(inf)
    return c, profile, unsigned


class CatalogTests(unittest.TestCase):
    def setUp(self):
        _, inf, _, unsigned = package_fixture()
        self.files = {'pi5nvme.sys': unsigned, 'pi5nvme.inf': inf}
        self.data = cat.build_catalog(self.files)

    def test_catalog_is_deterministic(self):
        self.assertEqual(self.data, cat.build_catalog(dict(reversed(list(self.files.items())))))

    def test_membership_has_all_files(self):
        cat.check_membership(self.data, self.files)
        ctl = cat.elements(cat.one(cat.extract_ctl(self.data), 0x30).payload)
        self.assertEqual(len(cat.elements(ctl[-1].payload)), 4)

    def test_sha256_member_is_cryptographic_digest(self):
        digest = hashlib.sha256(self.files['pi5nvme.inf']).digest()
        self.assertIn(cat.der(4, digest), cat.extract_ctl(self.data))
        self.assertIn(cat.oid('2.16.840.1.101.3.4.2.1'), self.data)

    def test_inf_byte_change_rejected(self):
        changed = {**self.files, 'pi5nvme.inf': self.files['pi5nvme.inf'] + b'\0'}
        with self.assertRaises(cat.CatalogError): cat.check_membership(self.data, changed)

    def test_sys_byte_change_rejected(self):
        b = bytearray(self.files['pi5nvme.sys']); b[0x300] ^= 1
        with self.assertRaises(cat.CatalogError): cat.check_membership(self.data, {**self.files, 'pi5nvme.sys': bytes(b)})

    def test_checksum_excluded_from_authenticode_not_full_hash(self):
        b = bytearray(self.files['pi5nvme.sys']); p = core.PE(b)
        old = cat.pe_digest(bytes(b)); b[p.checksum_offset] ^= 1
        self.assertEqual(old, cat.pe_digest(bytes(b)))
        self.assertNotEqual(core.sha256(self.files['pi5nvme.sys']), core.sha256(b))

    def test_pe_full_hash_not_catalog_hash(self):
        self.assertNotEqual(cat.pe_digest(self.files['pi5nvme.sys']), hashlib.sha256(self.files['pi5nvme.sys']).digest())

    def test_no_unknown_members(self):
        with self.assertRaises(cat.CatalogError): cat.build_catalog({**self.files, 'extra.dll': b'foo'})

    def test_no_missing_member(self):
        with self.assertRaises(cat.CatalogError): cat.build_catalog({'pi5nvme.sys': self.files['pi5nvme.sys']})

    def test_truncated_der_is_rejected(self):
        for n in range(len(self.data)):
            with self.assertRaises(cat.CatalogError): cat.extract_ctl(self.data[:n])

    def test_unsigned_catalog_not_mistaken_for_signed(self):
        with self.assertRaises(cat.CatalogError): cat.require_sha256_signature(self.data)

    def test_trailing_der_is_rejected(self):
        with self.assertRaises(cat.CatalogError): cat.extract_ctl(self.data + b'\x05\x00')

    def test_indefinite_nonminimal_and_invalid_lengths(self):
        for value in (b'\x30\x80\x00\x00', b'\x30\x81\x00', b'\x30\x82\x00\x80', b'\x30\xff', b'\x30\x03\x00'):
            with self.subTest(value=value), self.assertRaises(cat.CatalogError): cat.elements(value)

    def test_non_arm64_rejected(self):
        b = bytearray(self.files['pi5nvme.sys']); pe = struct.unpack_from('<I', b, 0x3c)[0]
        struct.pack_into('<H', b, pe + 4, 0x8664)
        with self.assertRaises(cat.CatalogError): cat.pe_digest(bytes(b))

    def test_invalid_algorithm_rejected(self):
        with self.assertRaises(cat.CatalogError): cat.pe_digest(self.files['pi5nvme.sys'], 'md5')

    def test_wrong_envelope_oid(self):
        b = self.data.replace(cat.oid('1.2.840.113549.1.7.2'), cat.oid('1.2.840.113549.1.7.1'), 1)
        with self.assertRaises(cat.CatalogError): cat.extract_ctl(b)

    def test_der_long_length_roundtrip(self):
        for size in (0, 1, 127, 128, 255, 256, 65536):
            data = b'x' * size
            self.assertEqual(cat.one(cat.der(4, data), 4).payload, data)

    def test_marker_and_descriptor_layout(self):
        self.assertIn(bytes.fromhex('3010060a2b0601040182370c020331028200'), self.data)
        self.assertIn(cat.oid(cat.OID_BASE + '2.1.15'), self.data)
        self.assertIn(cat.oid(cat.OID_BASE + '2.1.25'), self.data)


class PackageGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.collection, self.profile, self.unsigned = collection_at(self.root)
    def tearDown(self): self.tmp.cleanup()
    def prepare(self): return pkg.prepare_collection(self.collection, profiles=[self.profile])
    def build(self):
        return pkg.build_collection(self.collection, self.root/'out', self.root/'keys', profiles=[self.profile])

    def test_deduplicate_identical_pairs(self):
        rows = self.prepare()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['environments'], ['boot-1', 'install-3'])

    def test_inf_identity_and_boot_service(self):
        text = core.decode_inf(self.prepare()[0]['inf'])
        self.assertIn('CatalogFile = pi5nvme.cat', text)
        self.assertIn('AddService=pi5nvme,2', text)
        self.assertIn('ServiceBinary=%12%\\pi5nvme.sys', text)
        self.assertNotIn('stornvme.sys', text)
        self.assertIn('StartType=0', text)

    def test_unknown_real_input_not_authorized_by_report(self):
        path = self.collection/'boot-1/original-inputs/stornvme.sys'
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaises(pkg.PackageError): self.prepare()
        self.assertFalse((self.root/'keys').exists())

    def test_inf_mismatch_rejected(self):
        path = self.collection/'boot-1/original-inputs/stornvme.inf'
        path.write_bytes(path.read_bytes() + b'\0\0')
        with self.assertRaises(pkg.PackageError): self.prepare()

    def test_earlier_candidate_must_match(self):
        path = self.collection/'boot-1/analysis/unsigned-package/stornvme.sys'
        path.parent.mkdir(parents=True); path.write_bytes(b'wrong')
        with self.assertRaises(pkg.PackageError): self.prepare()

    def test_matching_candidate_accepted(self):
        path = self.collection/'boot-1/analysis/unsigned-package/stornvme.sys'
        path.parent.mkdir(parents=True); path.write_bytes(self.unsigned)
        self.assertEqual(len(self.prepare()), 1)

    def test_read_symlink_rejected(self):
        alias = self.root/'alias'; alias.symlink_to(self.collection, target_is_directory=True)
        with self.assertRaises(pkg.PackageError): pkg.prepare_collection(alias, profiles=[self.profile])

    def test_special_file_rejected(self):
        fifo = self.root/'pipe'; os.mkfifo(fifo)
        with self.assertRaises(pkg.PackageError): pkg.read_regular(fifo)

    def test_read_limit(self):
        p = self.root/'large'; p.write_bytes(b'x' * 100)
        with self.assertRaises(pkg.PackageError): pkg.read_regular(p, 10)

    def test_private_key_directory_cannot_nest_in_output(self):
        with self.assertRaises(pkg.PackageError): pkg.build_collection(self.collection, self.root/'out', self.root/'out/keys', profiles=[self.profile])

    def test_output_cannot_nest_in_inputs(self):
        with self.assertRaises(pkg.PackageError): pkg.build_collection(self.collection, self.collection/'out', self.root/'keys', profiles=[self.profile])

    def test_existing_output_preserved(self):
        (self.root/'out').mkdir(); (self.root/'out/keep').write_text('existing')
        with self.assertRaises(pkg.PackageError): self.build()
        self.assertEqual((self.root/'out/keep').read_text(), 'existing')

    def test_missing_tools_stops_before_writes(self):
        with patch.object(signer, 'tools', return_value={'openssl': None, 'osslsigncode': None}), self.assertRaises(pkg.PackageError): self.build()
        self.assertFalse((self.root/'keys').exists()); self.assertFalse((self.root/'out').exists())

    def test_cancel_before_writes(self):
        def cancel(): raise RuntimeError('cancel')
        with self.assertRaisesRegex(RuntimeError, 'cancel'):
            pkg.prepare_collection(self.collection, profiles=[self.profile], check_cancel=cancel)
        self.assertFalse((self.root/'out').exists())

    def test_bad_binding(self):
        for value in ('PCI\\X; rm -rf', 'USB\\CC_1', 'PCI\\X\nY', 'PCI\\' + 'X'*200):
            with self.assertRaises(pkg.PackageError): pkg.hardware_id(value)

    def test_read_only_preflight_preserves_files(self):
        before = {p: p.read_bytes() for p in self.collection.rglob('*') if p.is_file()}
        self.prepare()
        self.assertTrue(all(p.read_bytes() == b for p, b in before.items()))

    def test_unexpected_service_behavior_stops(self):
        source, inf, p, _ = package_fixture()
        text = core.decode_inf(inf).replace('StartType=0', 'StartType=3')
        inf = b'\xff\xfe' + text.encode('utf-16-le'); p['inf_sha256'] = core.sha256(inf)
        with self.assertRaises(pkg.PackageError): pkg.package_inf(inf, p, r'PCI\CC_010802')


NATIVE = all(signer.tools().values())


@unittest.skipUnless(NATIVE, 'Native openssl/osslsigncode not available; these are NOT mocked')
class NativePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.collection, cls.profile, cls.unsigned = collection_at(cls.root)
        cls.result = pkg.build_collection(cls.collection, cls.root/'result', cls.root/'private-keys', profiles=[cls.profile])
        cls.package = next((cls.root/'result/packages').iterdir())
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def test_native_embedded_catalog_and_sys_member_verification(self):
        r = pkg.verify_package(self.package, profiles=[self.profile], expected_certificate_sha256=self.result['packages'][0]['certificate_sha256'])
        self.assertEqual(r['status'], pkg.STATUS)
        self.assertTrue(r['embedded_signature_verified']); self.assertTrue(r['catalog_signature_verified'])
        self.assertFalse(r['windows_driver_loading_tested']); self.assertFalse(r['iso_generated'])

    def test_signing_preserves_reviewed_binary(self):
        signed = (self.package/'pi5nvme.sys').read_bytes()
        self.assertEqual(signer.unsigned_content(signed, len(self.unsigned)), self.unsigned)
        self.assertEqual(cat.pe_digest(signed), cat.pe_digest(self.unsigned))

    def test_evidence_has_reports_only(self):
        with zipfile.ZipFile(self.root/'result/package-evidence.zip') as z:
            self.assertEqual(set(z.namelist()), {'package-report.json', 'summary.txt'})
            self.assertNotIn(b'PRIVATE KEY', z.read('package-report.json'))

    def test_key_absent_from_output_and_permissions(self):
        self.assertTrue(list((self.root/'result').rglob('*.pem')))  # public certificate only
        for p in (self.root/'result').rglob('*'):
            if p.is_file(): self.assertNotIn(b'-----BEGIN PRIVATE KEY', p.read_bytes())
        key = next((self.root/'private-keys').rglob('local-test-key.pem'))
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_no_incomplete_marker_after_success(self):
        self.assertFalse((self.root/'result/BUILD_INCOMPLETE.txt').exists())
        self.assertFalse((self.root/'result/.incomplete').exists())

    def modified_package(self, name, mutation):
        dest = Path(tempfile.mkdtemp(dir=self.root))/'copy'; shutil.copytree(self.package, dest)
        path = dest/name; path.write_bytes(mutation(path.read_bytes()))
        return dest

    def test_tampered_inf_rejected(self):
        folder = self.modified_package('pi5nvme.inf', lambda b: b+b'\r\x00\n\x00')
        with self.assertRaises((pkg.PackageError, cat.CatalogError)): pkg.verify_package(folder, profiles=[self.profile])

    def test_tampered_sys_rejected(self):
        def change(b):
            x=bytearray(b); x[0x300]^=1; return bytes(x)
        folder=self.modified_package('pi5nvme.sys', change)
        with self.assertRaises((pkg.PackageError, signer.SigningError)): pkg.verify_package(folder, profiles=[self.profile])

    def test_tampered_catalog_signature_rejected(self):
        def change(b): return b[:-1]+bytes([b[-1]^1])
        folder=self.modified_package('pi5nvme.cat', change)
        with self.assertRaises((signer.SigningError, cat.CatalogError)): pkg.verify_package(folder, profiles=[self.profile])

    def test_wrong_certificate_pin_rejected(self):
        with self.assertRaises(pkg.PackageError): pkg.verify_package(self.package, profiles=[self.profile], expected_certificate_sha256='0'*64)

    def test_evidence_does_not_claim_windows_readiness(self):
        data=json.loads((self.root/'result/package-report.json').read_text())
        self.assertFalse(data['iso_generated']); self.assertFalse(data['driver_installed'])
        self.assertEqual(data['package_count'], 1)
        self.assertNotIn('verification_logs', data['packages'][0])

    def test_sources_unchanged(self):
        source, inf, _, _ = package_fixture()
        for label in ('boot-1','install-3'):
            self.assertEqual((self.collection/label/'original-inputs/stornvme.sys').read_bytes(), source)
            self.assertEqual((self.collection/label/'original-inputs/stornvme.inf').read_bytes(), inf)


if __name__ == '__main__': unittest.main()
