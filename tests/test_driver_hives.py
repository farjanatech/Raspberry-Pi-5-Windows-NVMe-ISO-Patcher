"""Driver preload structure and native Windows certificate serialization."""
import ctypes
import os
import ssl
import struct
import unittest
from pi5_studio import driver_hives as d, boot_hives as h
from tests.test_bcd_strings import MemoryHive, LOADER


class DriverPreloadTests(unittest.TestCase):
    def test_device_path_preserved_and_only_public_certificates_added(self):
        hive = MemoryHive()
        hive.values[d.VERSION_KEY] = {'DevicePath': (2, (r'%SystemRoot%\inf;C:\VendorDrivers'+'\0').encode('utf-16-le'))}
        parts = d.VERSION_KEY.split('\\')
        hive.paths.update('\\'.join(parts[:i]) for i in range(1, len(parts)+1))
        certificate = b'\x30'+b'SYNTHETIC CERTIFICATE'*20
        changes = d.plan_software(hive, [certificate, certificate])
        self.assertEqual(len(changes), 3)
        self.assertEqual(changes[0][:3], (d.VERSION_KEY, 'DevicePath', 2))
        self.assertEqual(changes[0][3].decode('utf-16-le'),
                         r'%SystemRoot%\inf;C:\VendorDrivers;%SystemRoot%\Drivers\Pi5NVMe'+'\0')
        for path, key, kind, value in changes[1:]:
            self.assertIn('SystemCertificates', path)
            self.assertEqual((key, kind), ('Blob', 3))
            self.assertEqual(struct.unpack('<III', value[:12]), (32, 1, len(certificate)))
            self.assertEqual(value[12:], certificate)

    def test_windows_bcd_template_does_not_require_winpe_flag(self):
        hive = MemoryHive()
        hive.values[LOADER+r'\Elements\26000022']['Element'] = (3, b'\0')
        self.assertEqual(len(h.plan_bcd(hive, template=True)), 2)
        with self.assertRaises(h.HiveError): h.plan_bcd(hive)

    @unittest.skipUnless(os.name == 'nt', 'Native Windows crypt32 serialization check')
    def test_blob_matches_windows_api_without_modifying_a_trust_store(self):
        der = next(data for data, kind, trust in ssl.enum_certificates('ROOT') if kind == 'x509_asn')
        lib = ctypes.WinDLL('crypt32')
        lib.CertCreateCertificateContext.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
        lib.CertCreateCertificateContext.restype = ctypes.c_void_p
        lib.CertSerializeCertificateStoreElement.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        lib.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
        data = ctypes.create_string_buffer(der)
        context = lib.CertCreateCertificateContext(1, data, len(der))
        self.assertTrue(context)
        try:
            size = ctypes.c_uint32()
            self.assertTrue(lib.CertSerializeCertificateStoreElement(context, 0, None, ctypes.byref(size)))
            output = ctypes.create_string_buffer(size.value)
            self.assertTrue(lib.CertSerializeCertificateStoreElement(context, 0, output, ctypes.byref(size)))
            self.assertEqual(output.raw[:size.value], d.certificate_blob(der))
        finally:
            lib.CertFreeCertificateContext(context)
