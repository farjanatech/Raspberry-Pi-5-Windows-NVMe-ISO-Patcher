"""Uninstall tests use fake HOME directories; never the real user's install."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import install_desktop as installer
import uninstall_desktop as u

ROOT = Path(__file__).resolve().parent.parent


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)/'user with spaces'
        self.home.mkdir()
        self.access = u.HomeAccess(self.home)

    def tearDown(self):
        self.access.close()
        self.tmp.cleanup()

    def put(self, path, content='data'):
        p = self.home/path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def snapshot(self, version='0.4.1-dev', suffix='123456abcdef'):
        root = '.local/share/'+u.APP+'/'+version+'-'+suffix
        self.put(root+'/pi5_nvme_gui.py', 'from pi5_studio.desktop import main\n')
        self.put(root+'/pi5_studio/__init__.py', '__version__ = "'+version+'"\n')
        self.put(root+'/pi5_studio/gui.py')
        self.put(root+'/assets/pi5-nvme.png')
        return self.home/root

    def launcher(self, folder='.local/share/applications'):
        return self.put(folder+'/'+u.LAUNCHER, '[Desktop Entry]\nName=Pi5 NVMe Studio\n'+u.MARKER+'\n')

    def plan(self, **kwargs):
        return u.plan_removal(self.access, [self.home/'Desktop'], **kwargs)

    def invoke(self, args, answer='UNINSTALL', active=None):
        out = io.StringIO()
        with patch.object(u, 'regular_user', return_value=True), \
             patch.object(u.Path, 'home', return_value=self.home), \
             patch.object(u, 'desktop_locations', return_value=[self.home/'Desktop']), \
             patch.object(u, 'running_studio', return_value=active or []), \
             patch('builtins.input', return_value=answer), \
             patch.dict(os.environ, {'XDG_CONFIG_HOME': ''}), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            return u.main(args), out.getvalue()

    def test_empty_home_is_noop(self):
        p = self.plan()
        self.assertFalse(p.files)
        self.assertEqual(u.apply_plan(self.access, p), 0)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_all_historical_versions_and_icons(self):
        roots = [self.snapshot(v) for v in ['0.2.0', '0.3.0', '0.4.0', '0.4.0-dev', '0.4.1-dev']]
        menu, desktop = self.launcher(), self.launcher('Desktop')
        p = self.plan()
        self.assertEqual(len(p.files), 22)
        u.apply_plan(self.access, p)
        self.assertTrue(all(not r.exists() for r in roots))
        self.assertFalse(menu.exists())
        self.assertFalse(desktop.exists())
        self.assertFalse((self.home/'.local/share'/u.APP).exists())
        self.assertTrue((self.home/'Desktop').is_dir())
        self.assertTrue((self.home/'.local/share/applications').is_dir())

    def test_all_installer_files_have_uninstall_rule(self):
        self.assertEqual(installer.APP, u.APP)
        self.assertEqual(installer.APP_NAME, u.APP_NAME)
        self.assertLessEqual(set(installer.FILES), u.INSTALLED_FILES)
        self.assertIn('uninstall_desktop.py', installer.FILES)
        self.assertIn('docs/UNINSTALL.md', installer.FILES)

    def test_real_source_install_uninstall_roundtrip(self):
        result = installer.install(ROOT, self.home, Path(sys.executable))
        root = Path(result['application'])
        self.assertTrue((root/'uninstall_desktop.py').is_file())
        p = self.plan()
        self.assertFalse(p.retained)
        self.assertEqual(len(p.files), len(installer.FILES)+2)
        u.apply_plan(self.access, p)
        self.assertFalse(root.exists())
        self.assertTrue((ROOT/'pi5_nvme_gui.py').is_file())

    def test_multiple_installations(self):
        self.snapshot(suffix='aaaaaaaaaaaa')
        self.snapshot(suffix='bbbbbbbbbbbb')
        p = self.plan()
        self.assertEqual(len(p.files), 8)
        u.apply_plan(self.access, p)
        self.assertFalse(self.plan().files)

    def test_all_tools_removes_both_creator_editions_and_studio(self):
        self.snapshot('1.0.2')
        self.launcher()
        names = [('pi5-boot-media.desktop', 'X-Pi5-Boot-Media=true'),
                 ('pi5-boot-media-creator.desktop', 'X-Pi5-Boot-Media-Creator=true')]
        old_launchers = []
        for name, marker in names:
            for folder in ('.local/share/applications', 'Desktop', 'Bureau'):
                old_launchers.append(self.put(folder+'/'+name, '[Desktop Entry]\n'+marker+'\n'))
        sources = [self.put('old-creator/boot_media_creator.py'),
                   self.put('old-creator/.venv/pyvenv.cfg'),
                   self.put('old-repo/.media-venv/pyvenv.cfg'),
                   self.put('old-creator/output/Windows.iso')]
        p = u.plan_removal(self.access, [self.home/'Desktop', self.home/'Bureau'], all_tools=True)
        self.assertFalse(p.retained)
        self.assertEqual(len(p.files), 11)
        u.apply_plan(self.access, p)
        self.assertTrue(all(not f.exists() for f in old_launchers))
        self.assertTrue(all(f.exists() for f in sources))
        self.assertFalse(self.plan(all_tools=True).files)

    def test_creator_cleanup_is_explicit_and_checks_exact_marker(self):
        valid = self.put('Desktop/pi5-boot-media.desktop', '[Desktop Entry]\nX-Pi5-Boot-Media=true\n')
        wrong = self.put('Desktop/pi5-boot-media-creator.desktop',
                         '[Desktop Entry]\nComment=X-Pi5-Boot-Media-Creator=true\n')
        self.assertFalse(self.plan().files)
        p = self.plan(all_tools=True)
        self.assertEqual(len(p.files), 1)
        self.assertTrue(p.retained)
        u.apply_plan(self.access, p)
        self.assertFalse(valid.exists())
        self.assertTrue(wrong.exists())

    def test_all_tools_cli_purges_preferences_and_is_repeatable(self):
        self.snapshot('2.0.0')
        self.put('Desktop/pi5-boot-media.desktop', '[Desktop Entry]\nX-Pi5-Boot-Media=true\n')
        setting = self.put('.config/farjanatech/Pi5NVMeStudio.conf')
        code, text = self.invoke(['--yes', '--all-tools', '--purge-settings'])
        self.assertEqual(code, 0)
        self.assertFalse(setting.exists())
        self.assertIn('source folders', text)
        self.assertEqual(self.invoke(['--yes', '--all-tools', '--purge-settings'])[0], 0)

    def test_current_builder_and_legacy_creator_processes_are_detected(self):
        proc_root = self.home/'fake-proc'
        proc_root.mkdir()
        commands = [b'python\0-m\0pi5_studio.iso_builder\0',
                    b'python\0/home/pi/old/boot_media.py\0',
                    b'python\0/home/pi/old/boot_media_creator.py\0',
                    b'python\0-m\0pi5_media.disk\0',
                    b'python\0/home/pi/unrelated.py\0']
        for pid, command in enumerate(commands, 999990):
            directory = proc_root/str(pid)
            directory.mkdir()
            (directory/'cmdline').write_bytes(command)
        with patch.object(u, 'Path', return_value=proc_root):
            self.assertEqual(u.running_studio(), [999990, 999991, 999992, 999993])

    def test_dry_run_does_not_write(self):
        root = self.snapshot()
        before = {p.relative_to(self.home):p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        code, text = self.invoke(['--dry-run'])
        after = {p.relative_to(self.home):p.read_bytes() for p in self.home.rglob('*') if p.is_file()}
        self.assertEqual(code, 0)
        self.assertIn('Dry run only', text)
        self.assertTrue(root.exists())
        self.assertEqual(before, after)

    def test_interactive_cancel(self):
        root = self.snapshot()
        code, text = self.invoke([], answer='no')
        self.assertEqual(code, 0)
        self.assertIn('Cancelled', text)
        self.assertTrue(root.exists())

    def test_interactive_confirm(self):
        root = self.snapshot()
        code, text = self.invoke([])
        self.assertEqual(code, 0)
        self.assertIn('uninstall complete', text)
        self.assertFalse(root.exists())

    def test_yes_and_second_uninstall(self):
        self.snapshot()
        self.assertEqual(self.invoke(['--yes'])[0], 0)
        code, text = self.invoke(['--yes'])
        self.assertEqual(code, 0)
        self.assertIn('No removable installation', text)

    def test_eof_cancels(self):
        self.snapshot()
        out = io.StringIO()
        with patch.object(u, 'regular_user', return_value=True), \
             patch.object(u.Path, 'home', return_value=self.home), \
             patch.object(u, 'desktop_locations', return_value=[]), \
             patch.object(u, 'running_studio', return_value=[]), \
             patch('builtins.input', side_effect=EOFError), contextlib.redirect_stdout(out):
            self.assertEqual(u.main([]), 0)
        self.assertTrue(self.plan().files)

    def test_root_or_sudo_is_refused(self):
        self.snapshot()
        with patch.object(u, 'regular_user', return_value=False), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(u.main(['--yes']), 2)
        self.assertTrue(self.plan().files)
        with patch.object(u.os, 'geteuid', return_value=0):
            self.assertFalse(u.regular_user())
        with patch.dict(os.environ, {'SUDO_USER': 'somebody'}):
            self.assertFalse(u.regular_user())

    def test_active_job_blocks_even_yes(self):
        self.snapshot()
        code, text = self.invoke(['--yes'], active=[12345])
        self.assertEqual(code, 2)
        self.assertIn('12345', text)
        self.assertTrue(self.plan().files)

    def test_unknown_data_inside_snapshot_is_kept(self):
        root = self.snapshot()
        data = root/'collection-abcd/original-inputs/stornvme.sys'
        data.parent.mkdir(parents=True)
        data.write_bytes(b'private driver')
        (root/'local-test-key.pem').write_text('PRIVATE KEY')
        p = self.plan()
        u.apply_plan(self.access, p)
        self.assertEqual(data.read_bytes(), b'private driver')
        self.assertEqual((root/'local-test-key.pem').read_text(), 'PRIVATE KEY')
        self.assertFalse((root/'pi5_nvme_gui.py').exists())
        self.assertTrue(p.retained)

    def test_every_workspace_source_venv_and_key_preserved(self):
        self.snapshot()
        names = ['Downloads/windows.iso', 'projects/collection/report.json', 'keys/local-test-key.pem',
                 'repo/.venv/pyvenv.cfg', 'repo/pi5_nvme_gui.py', 'output/pi5nvme.sys']
        for name in names: self.put(name, name)
        u.apply_plan(self.access, self.plan(purge_settings=True))
        for name in names: self.assertEqual((self.home/name).read_text(), name)

    def test_preferences_opt_in_only(self):
        setting = self.put('.config/farjanatech/Pi5NVMeStudio.conf')
        other = self.put('.config/farjanatech/AnotherApp.conf')
        global_setting = self.put('.config/farjanatech.conf')
        u.apply_plan(self.access, self.plan())
        self.assertTrue(setting.exists())
        u.apply_plan(self.access, self.plan(purge_settings=True))
        self.assertFalse(setting.exists())
        self.assertTrue(other.exists())
        self.assertTrue(global_setting.exists())

    def test_xdg_preferences_inside_home(self):
        f = self.put('custom-conf/farjanatech/Pi5NVMeStudio.conf')
        p = self.plan(purge_settings=True, config_home=self.home/'custom-conf')
        u.apply_plan(self.access, p)
        self.assertFalse(f.exists())

    def test_external_and_relative_xdg_paths_are_retained(self):
        for config in [Path(self.tmp.name), Path('relative')]:
            p = self.plan(purge_settings=True, config_home=config)
            self.assertTrue(p.retained)
            self.assertFalse(p.files)

    def test_localized_and_previous_desktop(self):
        f = self.launcher('Bureau ancien')
        p = u.plan_removal(self.access, [self.home/'Bureau ancien'])
        u.apply_plan(self.access, p)
        self.assertFalse(f.exists())

    def test_external_desktop_refused(self):
        p = u.plan_removal(self.access, [Path(self.tmp.name)])
        self.assertTrue(p.retained)
        self.assertFalse(p.files)

    def test_other_app_launcher_not_removed(self):
        f = self.put('.local/share/applications/'+u.LAUNCHER, '[Desktop Entry]\nName=Another app\n')
        p = self.plan()
        self.assertTrue(p.retained)
        u.apply_plan(self.access, p)
        self.assertTrue(f.exists())

    def test_marker_substring_not_enough(self):
        f = self.put('Desktop/'+u.LAUNCHER, '[Desktop Entry]\nComment='+u.MARKER+'\n')
        self.assertFalse(self.plan().files)
        self.assertTrue(f.exists())

    def test_launcher_symlink_preserves_target(self):
        target = self.put('target.txt', '[Desktop Entry]\n'+u.MARKER+'\n')
        link = self.home/'Desktop'/u.LAUNCHER
        link.parent.mkdir()
        link.symlink_to(target)
        p = self.plan()
        self.assertTrue(p.retained)
        u.apply_plan(self.access, p)
        self.assertTrue(target.exists())
        self.assertTrue(link.is_symlink())

    def test_symlink_app_root_preserves_outside(self):
        target = Path(self.tmp.name)/'outside'
        target.mkdir()
        sentinel = target/'DO-NOT-DELETE'; sentinel.write_text('keep')
        link = self.home/'.local/share'/u.APP
        link.parent.mkdir(parents=True)
        link.symlink_to(target, target_is_directory=True)
        p = self.plan()
        self.assertTrue(p.retained)
        self.assertFalse(p.files)
        u.apply_plan(self.access, p)
        self.assertTrue(sentinel.exists())

    def test_symlink_snapshot_refused(self):
        root = self.snapshot()
        link = root.parent/'0.4.1-dev-aaaaaaaaaaaa'
        link.symlink_to(root, target_is_directory=True)
        p = self.plan()
        self.assertTrue(p.retained)
        self.assertFalse(any('aaaaaaaaaaaa' in name for name in p.files))

    def test_symlink_nested_module_is_not_followed(self):
        root = self.snapshot()
        file = root/'pi5_studio/gui.py'; file.unlink()
        target = self.put('secret.txt', 'sensitive')
        file.symlink_to(target)
        p = self.plan()
        u.apply_plan(self.access, p)
        self.assertTrue(file.is_symlink())
        self.assertEqual(target.read_text(), 'sensitive')

    def test_pycache_only_matching_modules(self):
        root = self.snapshot()
        cache = root/'pi5_studio/__pycache__'; cache.mkdir()
        yes = cache/'gui.cpython-313.pyc'; yes.write_bytes(b'cache')
        no = cache/'mydata.cpython-313.pyc'; no.write_bytes(b'keep')
        p = self.plan()
        u.apply_plan(self.access, p)
        self.assertFalse(yes.exists())
        self.assertTrue(no.exists())

    def test_bad_snapshot_name_is_retained(self):
        root = self.snapshot()
        bad = root.with_name('backup-or-user-project'); root.rename(bad)
        p = self.plan()
        self.assertFalse(p.files)
        self.assertTrue(p.retained)
        self.assertTrue(bad.exists())

    def test_version_mismatch_and_missing_identity_retained(self):
        root = self.snapshot()
        (root/'pi5_studio/__init__.py').write_text('__version__ = "99.0.0"\n')
        self.assertFalse(self.plan().files)
        (root/'pi5_studio/__init__.py').unlink()
        self.assertFalse(self.plan().files)

    def test_installed_source_never_executed(self):
        root = self.snapshot()
        signal = self.home/'should-not-exist'
        (root/'pi5_studio/__init__.py').write_text('__version__ = "0.4.1-dev"\n'
            f'open({str(signal)!r}, "w").write("bad")\n')
        self.assertTrue(self.plan().files)
        self.assertFalse(signal.exists())

    def test_change_after_preview_stops_before_deletion(self):
        root = self.snapshot()
        p = self.plan()
        (root/'assets/pi5-nvme.png').write_text('changed')
        with self.assertRaises(u.UninstallError): u.apply_plan(self.access, p)
        self.assertTrue((root/'pi5_nvme_gui.py').exists())

    def test_parent_symlink_swap_cannot_delete_target(self):
        root = self.snapshot()
        p = self.plan()
        old = root.parent.with_name('kept-old'); root.parent.rename(old)
        outside = self.home/'unrelated'; outside.mkdir()
        sentinel = outside/'sentinel'; sentinel.write_text('keep')
        root.parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)): u.apply_plan(self.access, p)
        self.assertEqual(sentinel.read_text(), 'keep')
        self.assertTrue((old/root.name/'pi5_nvme_gui.py').exists())

    def test_dotdot_and_home_root_rejected(self):
        for path in [self.home, self.home/'..'/'other', Path('relative'), Path('/tmp')]:
            with self.assertRaises(u.UninstallError): self.access.relative(path)
        with self.assertRaises(u.UninstallError): u.HomeAccess(Path('/'))

    def test_retained_data_cli_exit_three(self):
        root = self.snapshot()
        (root/'notes.txt').write_text('keep')
        code, text = self.invoke(['--yes'])
        self.assertEqual(code, 3)
        self.assertIn('RETAIN', text)
        self.assertTrue((root/'notes.txt').exists())

    def test_discovery_uses_no_shell_and_falls_back(self):
        p = subprocess.CompletedProcess([], 0, str(self.home/'Bureau')+'\n', '')
        with patch.object(u.subprocess, 'run', return_value=p) as call:
            dirs = u.desktop_locations(self.home)
            self.assertIn(self.home/'Bureau', dirs)
            self.assertFalse(call.call_args.kwargs['shell'])
        with patch.object(u.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertEqual(u.desktop_locations(self.home), [self.home/'Desktop'])

    def test_python_cache_patterns(self):
        for name in ['pi5_nvme_tool.cpython-311.pyc', 'pi5_nvme_tool.cpython-313.opt-1.pyc']:
            self.assertTrue(u.cache_file('__pycache__/'+name))
        self.assertFalse(u.cache_file('__pycache__/private-key.pyc'))
        self.assertFalse(u.cache_file('docs/__pycache__/gui.cpython-313.pyc'))


if __name__ == '__main__':
    unittest.main()
