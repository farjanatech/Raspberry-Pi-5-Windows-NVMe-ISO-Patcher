"""Embedded-signing guards and real OpenSSL/osslsigncode on synthetic PE only.

CI never contains Microsoft's SYS/INF files or the user's private key.
"""
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import linux_test_sign as signer
import pi5_nvme_tool as core
from test_pi5_nvme_tool import fixture


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _, _, self.profile, self.data = fixture()
        self.source = self.root / 'candidate.sys'
        self.source.write_bytes(self.data)
        self.out, self.keydir = self.root / 'output', self.root / 'private-keys'

    def run_sign(self):
        return signer.sign_candidate(self.source, self.out, self.keydir, [self.profile])

    def test_unknown_hash_stops_before_command(self):
        self.source.write_bytes(self.data + b'changed')
        with mock.patch.object(signer, 'command') as command:
            with self.assertRaises(signer.SigningError): self.run_sign()
        command.assert_not_called()
        self.assertFalse(self.out.exists())
        self.assertFalse(self.keydir.exists())

    def test_existing_output_is_not_overwritten(self):
        self.out.mkdir(); (self.out/'keep.txt').write_text('keep')
        with self.assertRaises(signer.SigningError): self.run_sign()
        self.assertEqual((self.out/'keep.txt').read_text(), 'keep')
        self.assertFalse(self.keydir.exists())

    def test_existing_key_directory_is_not_overwritten(self):
        self.keydir.mkdir(); (self.keydir/'keep.txt').write_text('keep')
        with self.assertRaises(signer.SigningError): self.run_sign()
        self.assertEqual((self.keydir/'keep.txt').read_text(), 'keep')
        self.assertFalse(self.out.exists())

    def test_nested_private_keys_rejected(self):
        self.keydir = self.out / 'keys'
        with self.assertRaises(signer.SigningError): self.run_sign()
        self.assertFalse(self.out.exists())

    def test_same_directories_rejected(self):
        self.keydir = self.out
        with self.assertRaises(signer.SigningError): self.run_sign()

    def test_symlink_input_rejected(self):
        link = self.root / 'link.sys'; link.symlink_to(self.source)
        self.source = link
        with self.assertRaises(signer.SigningError): self.run_sign()

    def test_missing_tools_rejected_without_writes(self):
        with mock.patch.object(signer, 'tools', return_value={'openssl': None, 'osslsigncode': None}):
            with self.assertRaises(signer.SigningError): self.run_sign()
        self.assertFalse(self.out.exists())
        self.assertFalse(self.keydir.exists())

    def test_unsigned_file_not_mistaken_for_signed(self):
        with self.assertRaises(signer.SigningError): signer.unsigned_content(self.data, len(self.data))

    def test_signature_envelope_restore_and_checksum_guard(self):
        b = bytearray(self.data); p = core.PE(b)
        b.extend(struct.pack('<IHH', 16, 0x200, 2) + bytes(8))
        struct.pack_into('<II', b, p.optional + 112 + 4*8, len(self.data), 16)
        struct.pack_into('<I', b, p.checksum_offset, core.pe_checksum(b, p.checksum_offset))
        self.assertEqual(signer.unsigned_content(bytes(b), len(self.data)), self.data)
        b[0x500] ^= 1
        with self.assertRaises(signer.SigningError): signer.unsigned_content(bytes(b), len(self.data))

    def test_subprocess_uses_no_shell(self):
        result = mock.Mock(returncode=0, stdout=b'ok', stderr=b'')
        with mock.patch('subprocess.run', return_value=result) as run:
            self.assertEqual(signer.command(['some-tool', ';not-a-shell']), 'ok')
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertEqual(run.call_args.args[0], ['some-tool', ';not-a-shell'])

    @unittest.skipUnless(all(signer.tools().values()), 'Native OpenSSL and osslsigncode are required')
    def test_native_embedded_signature_on_synthetic_arm64_pe(self):
        report = self.run_sign()
        self.assertEqual(report['status'], 'EMBEDDED_TEST_SIGNATURE_VERIFIED_ONLY')
        self.assertFalse(report['catalog_generated'])
        self.assertFalse(report['windows_load_tested'])
        self.assertFalse(report['iso_generated'])
        self.assertEqual(self.source.read_bytes(), self.data)
        self.assertEqual(signer.unsigned_content((self.out/'stornvme.sys').read_bytes(), len(self.data)), self.data)
        private = self.keydir/'local-test-key.pem'
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.keydir.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(private.read_bytes(), [p.read_bytes() for p in self.out.iterdir()])
        self.assertFalse(any('PRIVATE KEY' in p.read_text(errors='ignore') for p in self.out.iterdir()))
        self.assertTrue((self.out/'NOT_READY_TO_INSTALL.txt').is_file())
        with self.assertRaises(signer.SigningError): self.run_sign()


if __name__ == '__main__':
    unittest.main()
