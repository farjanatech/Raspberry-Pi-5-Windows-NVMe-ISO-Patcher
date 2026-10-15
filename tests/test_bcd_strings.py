"""BCD regression tests use synthetic data, not redistributed Windows hives.

The real failing input used a REG_SZ EFI path. Cover it independently of the
old REG_BINARY fixtures, including native commit/readback when hivex exists.
"""
import copy
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from pi5_studio import boot_hives as bh, image_tools as bt
from tests.image_fixtures import listing, run

EFI = r'\windows\system32\boot\winload.efi'
LOADER = r'Objects\{7619dcc9-fafe-11d9-b411-000476eba25f}'
MANAGER = r'Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}'
PATH_KEY = LOADER + r'\Elements\12000002'


def path_value(value=EFI, kind=1):
    return kind, (value + '\0').encode('utf-16-le')


class MemoryHive:
    """Minimal read-only hivex-shaped fixture; no native hive is needed."""
    def __init__(self, kind=1):
        self.values = {
            LOADER+r'\Description': {'Type': (4, struct.pack('<I', 0x10200003))},
            LOADER+r'\Elements\26000022': {'Element': (3, b'\x01')},
            PATH_KEY: {'Element': path_value(kind=kind)},
            MANAGER+r'\Description': {'Type': (4, struct.pack('<I', 0x10100002))},
        }
        self.paths = {''}
        for path in self.values:
            pieces = path.split('\\')
            self.paths.update('\\'.join(pieces[:i]) for i in range(1, len(pieces)+1))
    def root(self): return ''
    def node_children(self, path):
        prefix = path+'\\' if path else ''
        return sorted(p for p in self.paths if p.startswith(prefix) and p != path
                      and '\\' not in p[len(prefix):])
    def node_name(self, path): return path.rsplit('\\', 1)[-1]
    def node_get_child(self, parent, name):
        path = parent+'\\'+name if parent else name
        return path if path in self.paths else None
    def node_get_value(self, path, key):
        return (path, key) if key in self.values.get(path, {}) else None
    def value_value(self, handle): return self.values[handle[0]][handle[1]]


class BcdStringTests(unittest.TestCase):
    def test_reg_sz_real_layout(self):
        self.assertEqual(bh.bcd_loader_path(path_value()), EFI)
    def test_legacy_binary_layout(self):
        self.assertEqual(bh.bcd_loader_path(path_value(kind=3)), EFI)
    def test_standard_system32_layout(self):
        path = r'\Windows\System32\winload.efi'
        self.assertEqual(bh.bcd_loader_path(path_value(path)), path)
    def test_case_is_preserved(self):
        path = r'\WINDOWS\System32\BOOT\Winload.EFI'
        self.assertEqual(bh.bcd_loader_path(path_value(path)), path)
    def test_missing_value(self):
        with self.assertRaises(bh.HiveError): bh.bcd_loader_path(None)
    def test_wrong_registry_types(self):
        for kind in (0, 2, 4, 7, 11):
            with self.subTest(kind=kind), self.assertRaisesRegex(bh.HiveError, 'registry type'):
                bh.bcd_loader_path(path_value(kind=kind))
    def test_odd_byte_length(self):
        with self.assertRaises(bh.HiveError): bh.bcd_loader_path((1, b'\x00'))
    def test_empty_path(self):
        for raw in (b'', b'\0\0'):
            with self.subTest(raw=raw), self.assertRaises(bh.HiveError): bh.bcd_loader_path((1, raw))
    def test_unterminated_string(self):
        with self.assertRaisesRegex(bh.HiveError, 'terminating'):
            bh.bcd_loader_path((1, EFI.encode('utf-16-le')))
    def test_embedded_nul(self):
        with self.assertRaisesRegex(bh.HiveError, 'embedded NUL'):
            bh.bcd_loader_path(path_value(EFI+'\0ignored'))
    def test_extra_nul(self):
        with self.assertRaises(bh.HiveError): bh.bcd_loader_path(path_value(EFI+'\0'))
    def test_control_character(self):
        with self.assertRaises(bh.HiveError): bh.bcd_loader_path(path_value(EFI+'\n'))
    def test_oversized_path(self):
        with self.assertRaisesRegex(bh.HiveError, 'byte length'):
            bh.bcd_loader_path(path_value('x'*600))
    def test_malformed_utf16(self):
        with self.assertRaisesRegex(bh.HiveError, 'valid UTF-16LE'):
            bh.bcd_loader_path((1, b'\x00\xd8\0\0'))
    def test_bios_path_is_not_rewritten(self):
        with self.assertRaisesRegex(bh.HiveError, 'winload.exe'):
            bh.bcd_loader_path(path_value(EFI.replace('.efi', '.exe')))
    def test_suffix_only_match_is_rejected(self):
        for path in ('notwinload.efi', r'\elsewhere\winload.efi', r'\windows\system32\boot\notwinload.efi'):
            with self.subTest(path=path), self.assertRaises(bh.HiveError): bh.bcd_loader_path(path_value(path))
    def test_ambiguous_paths(self):
        for path in ('windows\\system32\\boot\\winload.efi', 'C:'+EFI,
                     EFI.replace('\\','/'), EFI.replace('boot\\','boot\\..\\boot\\')):
            with self.subTest(path=path), self.assertRaises(bh.HiveError): bh.bcd_loader_path(path_value(path))
    def test_plan_changes_only_testsigning_not_loader_path(self):
        for kind in (1, 3):
            h=MemoryHive(kind); before=copy.deepcopy(h.values)
            changes=bh.plan_bcd(h)
            self.assertEqual(len(changes), 2)
            self.assertEqual({p for p,_,_,_ in changes},
                             {LOADER+r'\Elements\16000049', MANAGER+r'\Elements\16000049'})
            self.assertTrue(all(key=='Element' and t==3 and raw==b'\x01' for _,key,t,raw in changes))
            self.assertEqual(before, h.values)
    def test_non_winpe_still_rejected(self):
        h=MemoryHive();h.values[LOADER+r'\Elements\26000022']['Element']=(3,b'\0')
        with self.assertRaisesRegex(bh.HiveError, 'explicitly a WinPE'): bh.plan_bcd(h)
    def test_wrong_boolean_type_still_rejected(self):
        h=MemoryHive();h.values[LOADER+r'\Elements\26000022']['Element']=(4,b'\x01\0\0\0')
        with self.assertRaises(bh.HiveError): bh.plan_bcd(h)


def hivex_ready():
    try:
        return subprocess.run(['/usr/bin/python3','-c','import hivex'],
                              capture_output=True, timeout=10).returncode==0
    except (OSError, subprocess.TimeoutExpired):
        return False


DUMP = r'''
import hivex, json, sys
h=hivex.Hivex(sys.argv[1]);out={}
def walk(n, path):
    out[path]={h.value_key(v):[h.value_value(v)[0],bytes(h.value_value(v)[1]).hex()]
               for v in h.node_values(n)}
    for c in h.node_children(n):
        walk(c,path+'\\'+h.node_name(c) if path else h.node_name(c))
walk(h.root(),'');print(json.dumps(out,sort_keys=True))
'''


@unittest.skipUnless(hivex_ready(), 'Requires system python3-hivex; no Windows hive is bundled')
class NativeBcdStringTests(unittest.TestCase):
    def test_reg_sz_and_binary_commit_preserve_all_other_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            run('/usr/bin/python3',bt.ROOT/'tests/make_boot_fixtures.py',root)
            for name,kind in (('BCD',1),('BCD-BINARY',3)):
                before_bytes=(root/name).read_bytes()
                before=json.loads(run('/usr/bin/python3','-c',DUMP,root/name))
                result=json.loads(run('/usr/bin/python3',bt.ROOT/'pi5_studio/boot_hives.py',
                                      'bcd',root/name,root/(name+'.new')))
                after=json.loads(run('/usr/bin/python3','-c',DUMP,root/(name+'.new')))
                self.assertTrue(result['readback_verified'])
                self.assertEqual(before[PATH_KEY]['Element'][0],kind)
                self.assertEqual(before[PATH_KEY],after[PATH_KEY])
                for change in result['changes']:
                    after[change['path']].pop(change['key'])
                self.assertEqual({p:v for p,v in before.items() if v},
                                 {p:v for p,v in after.items() if v})
                self.assertEqual((root/name).read_bytes(),before_bytes)
    def test_realistic_bios_store_rejected_by_efi_editor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            run('/usr/bin/python3',bt.ROOT/'tests/make_boot_fixtures.py',root)
            source=root/'BCD-BIOS';before=source.read_bytes();out=root/'no-output'
            result=subprocess.run(['/usr/bin/python3',str(bt.ROOT/'pi5_studio/boot_hives.py'),
                                   'bcd',str(source),str(out)],capture_output=True)
            self.assertEqual(result.returncode,2)
            self.assertIn(b'winload.exe',result.stderr)
            self.assertFalse(out.exists());self.assertEqual(source.read_bytes(),before)


if __name__=='__main__': unittest.main()
