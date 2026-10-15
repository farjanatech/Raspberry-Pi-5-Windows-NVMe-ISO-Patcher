"""Real Linux 7-Zip/wimlib round trips on SYNTHETIC images, never Windows media."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from pi5_studio.backend import Session, tools_available
from test_pi5_nvme_tool import fixture

TOOLS = tools_available()
READY = all(TOOLS.values()) and shutil.which('xorriso')


def run(argv):
    subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)


def capture(source, target, name, append=False):
    run([TOOLS['wimlib'], 'append' if append else 'capture', str(source), str(target), name,
         '--image-property=WINDOWS/ARCH=12', '--image-property=WINDOWS/VERSION/MAJOR=10',
         '--image-property=WINDOWS/VERSION/MINOR=0', '--image-property=WINDOWS/VERSION/BUILD=22621',
         '--image-property=WINDOWS/VERSION/SPBUILD=1702'])


def create_iso(root, esd=False):
    pair = fixture()
    tree = root / 'image'
    (tree / 'Windows/System32/drivers').mkdir(parents=True)
    (tree / 'Windows/INF').mkdir(parents=True)
    (tree / 'Windows/System32/drivers/stornvme.sys').write_bytes(pair[0])
    (tree / 'Windows/INF/stornvme.inf').write_bytes(pair[1])
    media = root / 'media'
    (media / 'sources').mkdir(parents=True)
    recovery = root / 'winre.wim'
    capture(tree, recovery, 'Synthetic recovery - not Windows')
    capture(tree, media / 'sources/boot.wim', 'Synthetic PE - not Windows')
    capture(tree, media / 'sources/boot.wim', 'Synthetic Setup - not Windows', append=True)
    (tree / 'Windows/System32/Recovery').mkdir()
    shutil.copyfile(recovery, tree / 'Windows/System32/Recovery/winre.wim')
    install = media / 'sources/install.wim'
    capture(tree, install, 'Synthetic Pro - not Windows')
    if esd:
        run([TOOLS['wimlib'], 'export', str(install), 'all', str(media / 'sources/install.esd'), '--compress=LZMS', '--solid'])
        install.unlink()
    iso = root / ('synthetic ESD.iso' if esd else 'synthetic WIM.iso')
    run(['xorriso', '-as', 'mkisofs', '-iso-level', '3', '-J', '-R', '-o', str(iso), str(media)])
    return iso


@unittest.skipUnless(READY, 'Native tools absent: requires 7-Zip, wimlib and xorriso')
class NativeToolTests(unittest.TestCase):
    def round_trip(self, esd):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            iso = create_iso(root, esd)
            before = iso.read_bytes()
            session = Session()
            info = session.inspect(iso, root)
            self.assertEqual(len(info['images']), 3)
            result = session.collect(1)
            self.assertEqual(len(result['results']), 4)
            self.assertTrue(all(row['status'] == 'BLOCKED' for row in result['results']))
            self.assertEqual(len(list(session.root.rglob('report.json'))), 4)
            self.assertEqual(iso.read_bytes(), before)
            self.assertFalse(result['bootable_iso_written'])

    def test_real_wim_iso_roundtrip(self):
        self.round_trip(False)

    def test_real_solid_esd_iso_roundtrip(self):
        self.round_trip(True)
