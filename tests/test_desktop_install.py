from pathlib import Path
import sys
import tempfile
import unittest

import install_desktop as installer


class DesktopTests(unittest.TestCase):
    def source(self, tmp):
        source = Path(tmp) / 'source with spaces'
        source.mkdir()
        for name in installer.FILES:
            p = source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"synthetic installer test content")
        return source

    def test_install_under_user_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.source(tmp)
            home = Path(tmp) / 'user home'
            result = installer.install(source, home, Path(sys.executable))
            self.assertTrue(Path(result['desktop']).is_file())
            text = Path(result['menu']).read_text()
            self.assertIn(installer.MARKER, text)
            self.assertIn('Terminal=false', text)
            self.assertIn('Exec="', text)

    def test_repeat_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.source(tmp)
            home = Path(tmp) / 'home'
            one = installer.install(source, home, Path(sys.executable))
            two = installer.install(source, home, Path(sys.executable))
            self.assertEqual(one, two)

    def test_upgrade_reuses_legacy_launchers_with_new_branding(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.source(tmp)
            home = Path(tmp)/'existing user'
            legacy = '[Desktop Entry]\nName=Pi5 NVMe Studio\nX-Pi5-NVMe-Studio=true\n'
            paths = [home/'.local/share/applications/pi5-nvme-studio.desktop',
                     home/'Desktop/pi5-nvme-studio.desktop']
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(legacy)
            result = installer.install(source, home, Path(sys.executable))
            self.assertEqual(Path(result['menu']), paths[0])
            self.assertEqual(Path(result['desktop']), paths[1])
            for path in paths:
                text = path.read_text()
                self.assertIn('Name=Raspberry Pi 5 Windows NVMe ISO Patcher\n', text)
                self.assertIn('Comment='+installer.APP_DESCRIPTION+'\n', text)
                self.assertIn(str(Path(result['application'])/'pi5_nvme_gui.py'), text)
                self.assertEqual(list(path.parent.glob('*.desktop')), [path])

    def test_menu_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.source(tmp)
            result = installer.install(source, Path(tmp) / 'home', Path(sys.executable), desktop=False)
            self.assertIsNone(result['desktop'])

    def test_localized_desktop(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.source(tmp)
            home = Path(tmp) / 'home'
            result = installer.install(source, home, Path(sys.executable), desktop_dir=home / 'Bureau')
            self.assertEqual(Path(result['desktop']).parent.name, 'Bureau')

    def test_percent_and_shell_chars(self):
        argument = installer.exec_arg('/tmp/100% "x" $y `z` \\ p')
        self.assertIn('100%%', argument)
        self.assertTrue(argument.startswith('"') and argument.endswith('"'))
        with self.assertRaises(ValueError):
            installer.exec_arg('/tmp/path\nnew')

    def test_missing_file_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.source(tmp)
            (source / installer.FILES[0]).unlink()
            with self.assertRaises(ValueError):
                installer.install(source, Path(tmp) / 'home', Path(sys.executable))

    def test_do_not_overwrite_other_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'other.desktop'
            path.write_text('[Desktop Entry]\nName=Other\n')
            with self.assertRaises(ValueError):
                installer.replace_owned(path, installer.MARKER)
            self.assertIn('Name=Other', path.read_text())

    def test_symlink_launcher_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'link.desktop'
            p.symlink_to(Path(tmp) / 'target')
            with self.assertRaises(ValueError):
                installer.replace_owned(p, installer.MARKER)

    def test_venv_path_not_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.source(tmp)
            python = Path(tmp) / 'venv-python'
            python.symlink_to(sys.executable)
            result = installer.install(source, Path(tmp) / 'home', python, desktop=False)
            self.assertIn(str(python), Path(result['menu']).read_text())
