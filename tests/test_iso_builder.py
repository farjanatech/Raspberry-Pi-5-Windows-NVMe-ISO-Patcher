"""Synthetic ISO roundtrip: original Setup, signed driver preload and WoR layout."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pi5_studio import iso_builder as builder
from pi5_studio.backend import StudioError
from tests.image_fixtures import native_ready, synthetic_iso, run, listing
from tests.test_native_tools import capture
from tests.test_catalog_packages import package_fixture

class BuildGuards(unittest.TestCase):
    def test_existing_paths_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(builder.sys, 'platform', 'linux'):
            p, out = Path(tmp)/'input.iso', Path(tmp)/'existing.iso'
            p.write_bytes(b'input'); out.write_bytes(b'previous completed build')
            for target in (p, out):
                with self.assertRaises(StudioError): builder.Build().run(p, target)
            self.assertEqual(p.read_bytes(), b'input')
            self.assertEqual(out.read_bytes(), b'previous completed build')

    def test_complete_original_setup_assets_required(self):
        with self.assertRaisesRegex(StudioError, 'original Windows'):
            builder.source_members(listing([('sources/boot.wim', 100)]))
        files = [(p, 100) for p in ('sources/boot.wim', 'sources/install.wim',
            'efi/boot/bootaa64.efi', 'efi/microsoft/boot/bcd', 'boot/boot.sdi',
            'efi/microsoft/boot/efisys.bin', 'setup.exe', 'sources/setup.exe')]
        for path in ('Pi5Studio/install.ini', 'autounattend.xml', '$WinPEDriver$/old.inf'):
            with self.subTest(path=path), self.assertRaisesRegex(StudioError, 'original ISO'):
                builder.source_members(listing(files+[(path, 10)]))


def original_fixture(root):
    synthetic_iso(root)
    _, inf, profile, _ = package_fixture()
    tree = root/'image'
    (tree/'Windows/INF/stornvme.inf').write_bytes(inf)
    shutil.copyfile(root/'hives/SOFTWARE', tree/'Windows/System32/config/SOFTWARE')
    shutil.copyfile(root/'hives/BCD', tree/'Windows/System32/config/BCD-Template')
    (tree/'Windows/System32/startnet.cmd').write_bytes(b'wpeinit\r\n')
    (tree/'Windows/System32/winpeshl.ini').write_bytes(b'[LaunchApp]\r\nAppPath=X:\\sources\\setup.exe\r\n')
    (tree/'sources').mkdir()
    (tree/'sources/setup.exe').write_bytes(b'ORIGINAL SETUP PLACEHOLDER')
    (root/'media/setup.exe').write_bytes(b'ORIGINAL ROOT SETUP PLACEHOLDER')
    (root/'media/sources/setup.exe').write_bytes(b'ORIGINAL ISO SETUP PLACEHOLDER')
    (root/'media/support').mkdir()
    (root/'media/support/keep-me.txt').write_bytes(b'Original auxiliary installation content')
    boot = root/'media/sources/boot.wim'; boot.unlink()
    capture(tree, boot, 'Synthetic ARM64 PE')
    capture(tree, boot, 'Synthetic ARM64 Setup', append=True)
    run('wimlib-imagex', 'info', boot, '2', '--boot')
    (tree/'Windows/System32/Recovery').mkdir()
    recovery = root/'recovery.wim'; capture(tree, recovery, 'Synthetic ARM64 recovery')
    shutil.copyfile(recovery, tree/'Windows/System32/Recovery/winre.wim')
    install = root/'media/sources/install.wim'; install.unlink()
    capture(tree, install, 'Synthetic Windows Pro')
    capture(tree, install, 'Synthetic Windows Home', append=True)
    source = root/'input.iso'
    run('xorriso', '-as', 'mkisofs', '-iso-level', '3', '-J', '-R', '-e',
        'efi/microsoft/boot/efisys.bin', '-no-emul-boot', '-o', source, root/'media')
    return source, profile


@unittest.skipUnless(native_ready(), 'Requires native Linux image tools and hivex')
class NativePreparedISO(unittest.TestCase):
    def test_setup_preserved_all_images_signed_and_wor_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source, profile = original_fixture(root)
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            job = builder.Build(); out = root/'finished.iso'
            result = job.run(source, out, profiles=[profile])
            self.assertEqual(result['status'], 'DRIVER_PREPARED_ISO_BUILT')
            self.assertTrue(result['final_iso_readback_verified'])
            self.assertTrue(result['microsoft_setup_readback_verified'])
            self.assertEqual(len(result['editions']), 2)
            for field in ('windows_installation_verified', 'custom_setup_included', 'custom_firmware_included'):
                self.assertFalse(result[field])
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
            self.assertEqual(set(p.name for p in job.root.iterdir()), {'build.log', 'build-report.json'})
            self.assertNotIn(b'PRIVATE KEY', (job.root/'build.log').read_bytes())
            files = builder.entries(run('7z', 'l', '-slt', '-ba', '-bd', '--', out))
            self.assertIn('sources/install.wim', files)
            self.assertNotIn('sources/install.swm', files)
            self.assertFalse(any(k.startswith('pi5studio/') or k.endswith(('.key', '.pem', '.fd')) for k in files))
            for name in ('setup.exe', 'sources/setup.exe', 'support/keep-me.txt', 'boot/bcd',
                         'efi/boot/bootaa64.efi', 'efi/microsoft/boot/efisys.bin'):
                self.assertEqual(run('7z', 'x', '-so', '-bd', '-y', '-spd', '--', out, files[name]['path']),
                                 (root/'media'/name).read_bytes())
            boot, install = root/'readback-boot.wim', root/'readback-install.wim'
            for path, name in ((boot, 'sources/boot.wim'), (install, 'sources/install.wim')):
                path.write_bytes(run('7z', 'x', '-so', '-bd', '-y', '-spd', '--', out, files[name]['path']))
            self.assertEqual(builder.boot_index(boot), 2)
            for index in (1, 2):
                for name in ('Windows/System32/startnet.cmd', 'Windows/System32/winpeshl.ini', 'sources/setup.exe'):
                    self.assertEqual(run('wimlib-imagex', 'extract', boot, index, '/'+name, '--to-stdout'),
                                     (root/'image'/name).read_bytes())
                for folder in ('$WinPEDriver$/Pi5NVMe', 'drivers/Pi5NVMe', 'Windows/Drivers/Pi5NVMe'):
                    for name in ('pi5nvme.sys', 'pi5nvme.inf', 'pi5nvme.cat', 'local-test-certificate.cer'):
                        self.assertTrue(run('wimlib-imagex', 'extract', boot, index, '/'+folder+'/'+name, '--to-stdout'))
            check_script = r'''import hivex,sys,json
from pi5_studio import boot_hives as h
system=hivex.Hivex(sys.argv[1]);software=hivex.Hivex(sys.argv[2])
n=h.node(system,r'ControlSet001\Services\mountmgr')
policy=next((v for v in system.node_values(n) if system.value_key(v)=='NoAutoMount'),None)
print(json.dumps({'image':h.text(h.get(system,r'ControlSet001\Services\stornvme','ImagePath')),
'policy':bytes(system.value_value(policy)[1]).hex() if policy else None,
'device_path':h.text(h.get(software,r'Microsoft\Windows\CurrentVersion','DevicePath'))}))
'''
            for index in (1, 2):
                recovery = root/f'recovery-{index}.wim'
                recovery.write_bytes(run('wimlib-imagex', 'extract', install, index,
                                         '/Windows/System32/Recovery/winre.wim', '--to-stdout'))
                for image, image_index in ((boot, index), (install, index), (recovery, 1)):
                    hives = []
                    for name in ('SYSTEM', 'SOFTWARE'):
                        path = root/name; path.write_bytes(run('wimlib-imagex', 'extract', image, image_index,
                                                              '/Windows/System32/config/'+name, '--to-stdout'))
                        hives.append(path)
                    state = json.loads(run('/usr/bin/python3', '-c', check_script, *hives))
                    self.assertIn('pi5nvme.sys', state['image'])
                    self.assertIsNone(state['policy'])
                    self.assertIn(r'%SystemRoot%\Drivers\Pi5NVMe', state['device_path'])
                    self.assertTrue(run('wimlib-imagex', 'extract', image, image_index,
                                        '/Windows/System32/drivers/pi5nvme.sys', '--to-stdout'))

    def test_unknown_driver_stops_without_publishing_an_iso(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source, _ = original_fixture(root)
            job = builder.Build()
            with self.assertRaises(StudioError): job.run(source, root/'out.iso', profiles=[])
            self.assertFalse((root/'out.iso').exists())
            self.assertTrue((job.root/'build.log').is_file())
            self.assertEqual(json.loads((job.root/'build-report.json').read_text())['status'], 'FAILED')
            self.assertFalse((job.root/'private-keys').exists())
