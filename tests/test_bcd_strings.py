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
SETUP_TEMPLATE = r'Objects\{7254a080-1510-4e85-ac0f-e7fb3d444736}'


def path_value(value=EFI, kind=1):
    return kind, (value + '\0').encode('utf-16-le')


class MemoryHive:
    """Minimal read-only hivex-shaped fixture; no native hive is needed."""
    def __init__(self, kind=1, values=None):
        self.values = values if values is not None else {
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


class BcdTemplateTests(unittest.TestCase):
    def template(self, path=None, empty_element=False):
        values = {
            SETUP_TEMPLATE+r'\Description': {'Type': (4, struct.pack('<I', 0x10200003))},
            SETUP_TEMPLATE+r'\Elements\22000002': {'Element': path_value(r'\Windows')},
            MANAGER+r'\Description': {'Type': (4, struct.pack('<I', 0x10100002))},
        }
        if path is not None or empty_element:
            values[SETUP_TEMPLATE+r'\Elements\12000002'] = {} if empty_element else {'Element': path}
        return MemoryHive(values=values)

    def test_template_with_no_loader_path_changes_only_testsigning(self):
        hive = self.template(); before = copy.deepcopy(hive.values)
        changes = bh.plan_bcd(hive, template=True)
        self.assertEqual(set(changes), {
            (base+r'\Elements\16000049', 'Element', 3, b'\x01') for base in (SETUP_TEMPLATE, MANAGER)})
        self.assertEqual(hive.values, before)

    def test_template_loader_without_elements_is_preserved(self):
        hive = self.template()
        values = {p:v for p,v in hive.values.items() if not p.startswith(SETUP_TEMPLATE+r'\Elements')}
        hive = MemoryHive(values=values)
        self.assertEqual(len(bh.plan_bcd(hive, template=True)), 2)

    def test_existing_efi_and_bios_template_paths_are_preserved(self):
        for suffix in ('efi', 'exe'):
            for directory in (r'\Windows\System32', r'\Windows\System32\Boot'):
                for kind in (1, 3):
                    with self.subTest(suffix=suffix, directory=directory, kind=kind):
                        hive = self.template(path_value(directory+'\\winload.'+suffix, kind))
                        before = copy.deepcopy(hive.values)
                        self.assertEqual(len(bh.plan_bcd(hive, template=True)), 2)
                        self.assertEqual(hive.values, before)

    def test_template_rejects_present_but_missing_or_malformed_path_values(self):
        with self.assertRaisesRegex(bh.HiveError, 'Required registry value missing'):
            bh.plan_bcd(self.template(empty_element=True), template=True)
        for path in (path_value(kind=4), (1,b''), (1,EFI.encode('utf-16-le')),
                     path_value(r'\unrelated\winload.efi')):
            with self.subTest(path=path), self.assertRaises(bh.HiveError):
                bh.plan_bcd(self.template(path), template=True)

    def test_missing_path_in_actual_winpe_boot_store_is_still_rejected(self):
        hive = self.template()
        values = dict(hive.values)
        values[SETUP_TEMPLATE+r'\Elements\26000022'] = {'Element': (3,b'\x01')}
        with self.assertRaisesRegex(bh.HiveError, 'Required registry path missing'):
            bh.plan_bcd(MemoryHive(values=values))

    def test_template_without_a_windows_loader_is_rejected(self):
        hive = self.template()
        hive.values[SETUP_TEMPLATE+r'\Description']['Type'] = (4,struct.pack('<I',0x10200004))
        with self.assertRaises(bh.HiveError):
            bh.plan_bcd(hive, template=True)


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
    def test_preflight_does_not_write_or_modify_any_hive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); run('/usr/bin/python3',bt.ROOT/'tests/make_boot_fixtures.py',root)
            before={p.name:p.read_bytes() for p in root.iterdir()}
            for mode,name in (('system','SYSTEM'),('bcd','BCD'),('template','BCD-TEMPLATE')):
                result=json.loads(run('/usr/bin/python3',bt.ROOT/'pi5_studio/boot_hives.py',
                                      mode,root/name,'--check-only'))
                self.assertTrue(result['preflight_verified'])
            result=json.loads(run('/usr/bin/python3',bt.ROOT/'pi5_studio/driver_hives.py',
                                  root/'SOFTWARE','--check-only'))
            self.assertTrue(result['preflight_verified'])
            self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})

    def test_template_commit_preserves_missing_paths_and_every_unrelated_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            run('/usr/bin/python3',bt.ROOT/'tests/make_boot_fixtures.py',root)
            source=root/'BCD-TEMPLATE'; output=root/'prepared-template'
            original=source.read_bytes()
            before=json.loads(run('/usr/bin/python3','-c',DUMP,source))
            result=json.loads(run('/usr/bin/python3',bt.ROOT/'pi5_studio/boot_hives.py',
                                  'template',source,output))
            after=json.loads(run('/usr/bin/python3','-c',DUMP,output))
            self.assertTrue(result['readback_verified'])
            self.assertEqual(result['mode'], 'template')
            self.assertEqual(len(result['changes']), 5)
            self.assertNotIn(SETUP_TEMPLATE+r'\Elements\12000002',after)
            for change in result['changes']:
                self.assertTrue(change['path'].endswith(r'\Elements\16000049'))
                self.assertEqual((change['key'],change['type'],change['hex']),('Element',3,'01'))
                self.assertEqual(after[change['path']].pop('Element'),[3,'01'])
            self.assertEqual({p:v for p,v in before.items() if v},
                             {p:v for p,v in after.items() if v})
            self.assertEqual(source.read_bytes(),original)

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
