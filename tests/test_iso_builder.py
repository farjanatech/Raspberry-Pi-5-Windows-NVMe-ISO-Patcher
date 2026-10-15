"""Synthetic ISO roundtrip: original Setup, signed driver preload and WoR layout."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pi5_studio import iso_builder as builder
from pi5_studio.backend import StudioError, Cancellation, Cancelled, MIB
from tests.image_fixtures import native_ready, synthetic_iso, run, listing
from tests.test_native_tools import capture
from tests.test_catalog_packages import package_fixture
from tests.test_bcd_strings import DUMP

class BuildGuards(unittest.TestCase):
    def test_unrepresentable_output_paths_stop_before_work_starts(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(builder.sys, 'platform', 'linux'):
            root = Path(tmp); source = root/'original.iso'; source.write_bytes(b'unchanged source')
            # Backslash is a path separator on Windows, so exercise the WIM
            # grammar through a filename containing a double quote instead.
            job = builder.Build()
            with patch.object(builder, 'prerequisites') as prerequisites:
                with self.assertRaisesRegex(StudioError, 'Unsupported quote/backslash'):
                    job.run(source, root/'bad"output.iso')
                prerequisites.assert_not_called()
            self.assertIsNone(job.root)
            self.assertEqual(list(root.iterdir()), [source])

    def test_copy_cancels_between_blocks_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'large.wim'; source.write_bytes(b'A'*(9*MIB))
            target = root/'copy.wim'; token = Cancellation(); checks = 0
            original_check = token.check
            def cancel_after_one_block():
                nonlocal checks
                checks += 1
                if checks == 3: token.cancel()
                original_check()
            with patch.object(token, 'check', side_effect=cancel_after_one_block):
                with self.assertRaises(Cancelled): builder.copy_file(source, target, token)
            self.assertEqual(target.stat().st_size, 4*MIB)
            self.assertEqual(source.stat().st_size, 9*MIB)
            with self.assertRaises(FileExistsError): builder.copy_file(source, target, Cancellation())
            self.assertEqual(target.stat().st_size, 4*MIB)

    def test_copy_low_space_stops_before_writing_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'original'; source.write_bytes(b'original data')
            target = root/'copy'
            with patch.object(builder.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 0})()):
                with self.assertRaisesRegex(StudioError, 'nearly full'):
                    builder.copy_file(source, target, Cancellation())
            self.assertEqual(target.stat().st_size, 0)
            self.assertEqual(source.read_bytes(), b'original data')

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

    def test_startup_inventory_errors_are_not_treated_as_absent_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            job = builder.Build(); job.root = Path(tmp); job.tools = {'wimlib': 'wimlib-imagex'}
            with patch.object(job.runner, 'run', side_effect=StudioError('unreadable WIM')):
                with self.assertRaisesRegex(StudioError, 'unreadable WIM'):
                    job.setup_snapshot(Path(tmp)/'boot.wim', 'originals')
            with patch.object(job.runner, 'run', return_value=b'not a WIM listing\n'):
                with self.assertRaisesRegex(StudioError, 'Invalid boot image file listing'):
                    job.setup_snapshot(Path(tmp)/'boot.wim', 'originals')

    def test_existing_startup_file_read_errors_are_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            job = builder.Build(); job.root = Path(tmp); job.tools = {'wimlib': 'wimlib-imagex'}
            files = b'/\n/Windows/System32\n/Windows/System32/startnet.cmd\n'
            with patch.object(job.runner, 'run', return_value=files), \
                    patch.object(job, 'extract', side_effect=StudioError('file read failed')):
                with self.assertRaisesRegex(StudioError, 'file read failed'):
                    job.setup_snapshot(Path(tmp)/'boot.wim', 'originals')


def original_fixture(root, missing_startup=(), *, esd=False, distinct_recovery=False, bad_template=False):
    synthetic_iso(root)
    _, inf, profile, _ = package_fixture()
    tree = root/'image'
    (tree/'Windows/INF/stornvme.inf').write_bytes(inf)
    shutil.copyfile(root/'hives/SOFTWARE', tree/'Windows/System32/config/SOFTWARE')
    shutil.copyfile(root/'hives/BCD-TEMPLATE', tree/'Windows/System32/config/BCD-Template')
    if bad_template:
        (tree/'Windows/System32/config/BCD-Template').write_bytes(b'Invalid registry hive')
    for hive in ('SYSTEM', 'SOFTWARE', 'BCD-Template'):
        for suffix in ('.LOG', '.LOG1', '.LOG2'):
            (tree/'Windows/System32/config'/(hive+suffix)).write_bytes(b'Original '+(hive+suffix).encode())
    (tree/'Windows/System32/startnet.cmd').write_bytes(b'wpeinit\r\n')
    (tree/'Windows/System32/winpeshl.ini').write_bytes(b'[LaunchApp]\r\nAppPath=X:\\sources\\setup.exe\r\n')
    (tree/'sources').mkdir()
    (tree/'sources/setup.exe').write_bytes(b'ORIGINAL SETUP PLACEHOLDER')
    for name in missing_startup:
        (tree/name).unlink()
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
    if distinct_recovery:
        other_tree = root/'other-recovery'
        shutil.copytree(tree, other_tree, ignore=shutil.ignore_patterns('Recovery'))
        (other_tree/'edition-marker.txt').write_bytes(b'Home recovery')
        other_wim = root/'other-recovery.wim'; capture(other_tree, other_wim, 'Home recovery')
        shutil.copyfile(other_wim, tree/'Windows/System32/Recovery/winre.wim')
    capture(tree, install, 'Synthetic Windows Home', append=True)
    if esd:
        run('wimlib-imagex', 'export', install, 'all', root/'media/sources/install.esd', '--compress=LZMS', '--solid')
        install.unlink()
    source = root/'input.iso'
    run('xorriso', '-as', 'mkisofs', '-iso-level', '3', '-J', '-R', '-e',
        'efi/microsoft/boot/efisys.bin', '-no-emul-boot', '-o', source, root/'media')
    return source, profile


@unittest.skipUnless(native_ready(), 'Requires native Linux image tools and hivex')
class NativePreparedISO(unittest.TestCase):
    def test_setup_preserved_all_images_signed_and_wor_layout(self):
        self.check_prepared_iso()

    def test_setup_without_winpeshl_ini_builds_without_adding_it(self):
        self.check_prepared_iso(('Windows/System32/winpeshl.ini',))

    def test_setup_without_optional_startup_scripts_preserves_absence(self):
        self.check_prepared_iso(('Windows/System32/winpeshl.ini', 'Windows/System32/startnet.cmd'))

    def test_solid_esd_with_distinct_recoveries_in_unicode_folder(self):
        self.check_prepared_iso(esd=True, distinct_recovery=True, unicode_folder=True)

    def check_prepared_iso(self, missing_startup=(), *, esd=False, distinct_recovery=False, unicode_folder=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if unicode_folder:
                root = root/'Pi images - বাংলা'; root.mkdir()
            source, profile = original_fixture(root, missing_startup, esd=esd, distinct_recovery=distinct_recovery)
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            progress = []
            job = builder.Build(notify=lambda p,t: progress.append((p,t))); out = root/'finished.iso'
            result = job.run(source, out, profiles=[profile])
            self.assertEqual(result['status'], 'DRIVER_PREPARED_ISO_BUILT')
            self.assertTrue(result['final_iso_readback_verified'])
            self.assertTrue(result['microsoft_setup_readback_verified'])
            self.assertEqual(len(result['editions']), 2)
            self.assertFalse(any('Select a Windows edition' in t for _,t in progress))
            self.assertEqual(len(result['hive_preflight']), 14)
            self.assertTrue(result['bcd_preflight']['preflight_verified'])
            self.assertTrue(all(r['preflight_verified'] for r in result['hive_preflight']))
            edited_recoveries = {r['environment'] for r in result['hives'] if r['environment'].startswith('recovery-')}
            self.assertEqual(len(edited_recoveries), 2 if distinct_recovery else 1)
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
                members = run('wimlib-imagex', 'dir', boot, index).decode().replace('\\', '/').splitlines()
                for name in ('Windows/System32/startnet.cmd', 'Windows/System32/winpeshl.ini', 'sources/setup.exe'):
                    record = next(r for r in result['microsoft_setup_originals']
                                  if r['image_index'] == index and r['path'] == '/'+name)
                    if name in missing_startup:
                        self.assertNotIn('/'+name, members)
                        self.assertFalse(record['present'])
                        self.assertIsNone(record['sha256'])
                    else:
                        expected = (root/'image'/name).read_bytes()
                        self.assertEqual(run('wimlib-imagex', 'extract', boot, index, '/'+name, '--to-stdout'), expected)
                        self.assertTrue(record['present'])
                        self.assertEqual(record['sha256'], hashlib.sha256(expected).hexdigest())
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
                template = root/f'prepared-template-{index}'
                template.write_bytes(run('wimlib-imagex', 'extract', install, index,
                                         '/Windows/System32/config/BCD-Template', '--to-stdout'))
                template_before = json.loads(run('/usr/bin/python3', '-c', DUMP, root/'hives/BCD-TEMPLATE'))
                template_after = json.loads(run('/usr/bin/python3', '-c', DUMP, template))
                template_report = next(r for r in result['hives']
                                       if r['environment'] == f'install-{index}' and r['mode'] == 'template')
                self.assertEqual(len(template_report['changes']), 5)
                for change in template_report['changes']:
                    self.assertTrue(change['path'].endswith(r'\Elements\16000049'))
                    self.assertEqual(template_after[change['path']].pop('Element'), [3,'01'])
                self.assertEqual({p:v for p,v in template_before.items() if v},
                                 {p:v for p,v in template_after.items() if v})
                for image, image_index in ((boot, index), (install, index), (recovery, 1)):
                    members = run('wimlib-imagex', 'dir', image, image_index).decode().replace('\\', '/').splitlines()
                    for hive in ('SYSTEM', 'SOFTWARE', 'BCD-Template'):
                        for suffix in ('.LOG', '.LOG1', '.LOG2'):
                            member = '/Windows/System32/config/'+hive+suffix
                            if hive == 'BCD-Template' and image != install:
                                self.assertIn(member, members)
                                self.assertEqual(run('wimlib-imagex', 'extract', image, image_index, member, '--to-stdout'),
                                                 b'Original '+(hive+suffix).encode())
                            else:
                                self.assertNotIn(member, members)
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

    def test_bad_template_fails_before_signing_or_media_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source, profile=original_fixture(root, bad_template=True)
            before=hashlib.sha256(source.read_bytes()).hexdigest(); job=builder.Build()
            with patch.object(builder, 'build_collection') as sign:
                with self.assertRaisesRegex(StudioError, 'Hive size'):
                    job.run(source, root/'out.iso', profiles=[profile])
                sign.assert_not_called()
            self.assertFalse((job.root/'media').exists())
            self.assertFalse((job.root/'private-keys').exists())
            self.assertFalse((root/'out.iso').exists())
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),before)

    def test_post_publication_report_failure_keeps_the_verified_iso(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source, profile=original_fixture(root); out=root/'finished.iso'
            job=builder.Build(); save=job.save
            def save_until_published():
                if out.exists(): raise OSError('Simulated report storage failure')
                save()
            with patch.object(job, 'save', side_effect=save_until_published):
                with self.assertRaisesRegex(StudioError, 'verified ISO was already saved'):
                    job.run(source,out,profiles=[profile])
            self.assertTrue(out.is_file())
            self.assertTrue(job.report['verified_output_published'])
            self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(),job.report['iso_sha256'])

    def test_missing_setup_executable_stops_before_signing_or_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source, profile = original_fixture(root, ('sources/setup.exe',))
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            job = builder.Build(); out = root/'out.iso'
            with self.assertRaisesRegex(StudioError, 'Setup executable is missing'):
                job.run(source, out, profiles=[profile])
            self.assertFalse(out.exists())
            self.assertFalse((job.root/'signed').exists())
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

    def test_unknown_driver_stops_without_publishing_an_iso(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source, _ = original_fixture(root)
            job = builder.Build()
            with self.assertRaises(StudioError): job.run(source, root/'out.iso', profiles=[])
            self.assertFalse((root/'out.iso').exists())
            self.assertTrue((job.root/'build.log').is_file())
            self.assertEqual(json.loads((job.root/'build-report.json').read_text())['status'], 'FAILED')
            self.assertFalse((job.root/'private-keys').exists())


@unittest.skipUnless(shutil.which('wimlib-imagex'), 'Requires native wimlib')
class NativeStartupPreservation(unittest.TestCase):
    def test_optional_presence_is_tracked_per_image_and_changes_are_rejected(self):
        cases = (
            (1, 'add', '/Windows/System32/winpeshl.ini'),
            (2, 'delete', '/Windows/System32/winpeshl.ini'),
            (2, 'add', '/sources/setup.exe'),
            (1, 'delete', '/Windows/System32/startnet.cmd'),
        )
        for index, operation, member in cases:
            with self.subTest(index=index, operation=operation, member=member), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); tree = root/'image'; boot = root/'boot.wim'
                system = tree/'Windows/System32'; system.mkdir(parents=True)
                (system/'startnet.cmd').write_bytes(b'wpeinit\r\n')
                capture(tree, boot, 'Synthetic PE')
                (system/'winpeshl.ini').write_bytes(b'Original shell settings')
                (tree/'sources').mkdir(); (tree/'sources/setup.exe').write_bytes(b'Original setup')
                capture(tree, boot, 'Synthetic Setup', append=True)
                job = builder.Build(); job.root = root; job.tools = {'wimlib': shutil.which('wimlib-imagex')}
                original = job.setup_snapshot(boot, 'originals')
                self.assertIsNone(original[1, '/Windows/System32/winpeshl.ini'])
                self.assertIsNotNone(original[2, '/Windows/System32/winpeshl.ini'])
                replacement = root/'replacement'; replacement.write_bytes(b'Unexpected startup change')
                command = ('add '+builder.quoted(replacement)+' '+builder.quoted(member)
                           if operation == 'add' else 'delete '+builder.quoted(member))
                run('wimlib-imagex', 'update', boot, index, '--command='+command)
                with self.assertRaisesRegex(StudioError, 'Original Microsoft Setup file changed'):
                    job.verify_setup(boot, original)

    def test_corrupt_boot_wim_is_not_treated_as_optional_file_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); boot = root/'broken.wim'; boot.write_bytes(b'Not a WIM')
            job = builder.Build(); job.root = root; job.tools = {'wimlib': shutil.which('wimlib-imagex')}
            with self.assertRaises(StudioError):
                job.setup_snapshot(boot, 'originals')
