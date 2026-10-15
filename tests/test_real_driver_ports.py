"""Private opt-in tests. Set NVME_REAL_INPUT_ROOT locally; NEVER upload SYS/INF to CI.

The external directory must contain boot/ and recovery/, each with the original
stornvme.sys and stornvme.inf. No binary, complete disassembly or signed output
is exported by this test. Hardware behavior is not tested.
"""
import os
from pathlib import Path
import struct
import unittest
import pi5_nvme_tool as core
from pi5_nvme_profiles import ADDITIONAL_PROFILES
from tests.reference_driver_emit import SPECS, reference_emit

ROOT = os.environ.get('NVME_REAL_INPUT_ROOT')


@unittest.skipUnless(ROOT, 'Private real inputs are not bundled; set NVME_REAL_INPUT_ROOT only locally')
class RealDriverPortTests(unittest.TestCase):
    def pairs(self):
        for kind, spec in SPECS.items():
            folder = Path(ROOT) / kind
            source = (folder / 'stornvme.sys').read_bytes()
            inf = (folder / 'stornvme.inf').read_bytes()
            profile = next(p for p in ADDITIONAL_PROFILES if p['source_version'] == spec['version'])
            yield folder, spec, profile, source, inf

    def test_inputs_and_inf_are_exact_and_statically_eligible(self):
        for _, spec, p, source, inf in self.pairs():
            with self.subTest(version=spec['version']):
                self.assertEqual(core.sha256(source), p['source_sha256'])
                self.assertEqual(core.sha256(inf), p['inf_sha256'])
                r = core.analyze(source, inf, core.load_profiles([]), spec['version'])
                self.assertEqual(r['status'], 'ELIGIBLE_FOR_HASH_CHECKED_BUILD', r['blockers'])
                self.assertEqual(r['runtime_validation'], 'NOT PERFORMED')

    def test_independent_emitter_matches_production_output(self):
        for folder, spec, p, source, inf in self.pairs():
            with self.subTest(version=spec['version']):
                expected = reference_emit(source, spec)
                actual, _ = core.apply_patch(source, p)
                self.assertEqual(expected, actual)
                self.assertEqual(core.sha256(actual), p['output_sha256'])
                self.assertEqual(core.apply_patch(source, p)[0], actual)
                self.assertEqual((folder / 'stornvme.sys').read_bytes(), source)
                self.assertEqual((folder / 'stornvme.inf').read_bytes(), inf)

    def test_imports_version_checksum_and_cache_helper(self):
        for _, spec, p, source, _ in self.pairs():
            with self.subTest(version=spec['version']):
                actual, _ = core.apply_patch(source, p)
                old, new = core.PE(source), core.PE(actual)
                self.assertEqual(old.imports(), new.imports())
                self.assertEqual(old.debug_info(), new.debug_info())
                self.assertEqual(old.file_version(), new.file_version())
                self.assertEqual(new.directory(4), (0, 0))
                self.assertEqual(new.u32(new.checksum_offset), core.pe_checksum(actual, new.checksum_offset))
                at = new.offset(p['helper']['rva'], 32)
                self.assertEqual(actual[at:at+32].hex(), p['helper']['bytes'])
                for call in p['calls']:
                    word = new.u32(new.offset(call['rva']))
                    immediate = word & 0x3ffffff
                    if immediate & (1 << 25): immediate -= 1 << 26
                    self.assertEqual(call['rva'] + immediate * 4, p['helper']['rva'])
                    self.assertEqual(word >> 26, 0b100101)

    def test_only_five_conflicting_import_transfers_removed(self):
        for _, spec, p, source, _ in self.pairs():
            with self.subTest(version=spec['version']):
                actual, _ = core.apply_patch(source, p)
                def transfers(data):
                    return {e['rva']: e for r in core.PE(data).dynamic_relocations()['records'] for b in r['blocks'] for e in b['entries']}
                old, new = transfers(source), transfers(actual)
                self.assertEqual(set(old) - set(new), set(spec['prp']))
                self.assertEqual(new, {r:e for r,e in old.items() if r not in spec['prp']})
                for r in spec['prp']:
                    self.assertEqual(old[r]['register'], 8)
                    self.assertEqual(old[r]['iat_index'], spec['iat_index'])

    def test_prp_argument_and_result_store_context(self):
        for _, spec, p, source, _ in self.pairs():
            with self.subTest(version=spec['version']):
                pe = core.PE(source)
                for guard in p['review']['context_sha256']:
                    at = pe.offset(guard['rva'], guard['length'])
                    self.assertEqual(core.sha256(source[at:at+guard['length']]), guard['sha256'])
                for r in spec['prp']:
                    # Reviewed PRP paths pass the request-extension/list base in x2
                    # and store the returned physical address in its +0x1020 slot.
                    before = [pe.u32(pe.offset(x)) for x in range(r-16, r, 4)]
                    after = pe.u32(pe.offset(r+4))
                    base = (after >> 5) & 31
                    self.assertIn(0xaa0003e2 | (base << 16), before)
                    self.assertEqual(after & ~(31 << 5), 0xf9081000)

    def test_allocation_and_release_dispatch_context(self):
        for _, spec, p, source, _ in self.pairs():
            with self.subTest(version=spec['version']):
                pe = core.PE(source)
                for reg, code, rv in [(6, 0x52, r) for r in spec['alloc']] + [(4, 0x53, r) for r in spec['free']]:
                    self.assertEqual(pe.u32(pe.offset(rv)), 0x52800020 | reg)
                    words = [pe.u32(pe.offset(r)) for r in range(rv+4, rv+36, 4)]
                    self.assertIn(0x52800000 | (code << 5), words)
                    self.assertIn(0xd63f0100, words)

    def test_generated_inf_preserves_boot_service_and_source(self):
        for folder, spec, p, _, inf in self.pairs():
            with self.subTest(version=spec['version']):
                for hw in (r'PCI\CC_010802', r'PCI\VEN_1234&DEV_ABCD'):
                    generated = core.make_inf(inf, p, hw)
                    text = core.decode_inf(generated)
                    self.assertIn(hw, text)
                    self.assertIn('CatalogFile = pi5-stornvme.cat', text)
                    self.assertIn('StartType      = %SERVICE_BOOT_START%', text)
                    self.assertEqual(core.inspect_inf(generated)['driver_version'], spec['version'])
                self.assertEqual((folder / 'stornvme.inf').read_bytes(), inf)

    def test_altered_input_or_wrong_profile_fails(self):
        pairs = list(self.pairs())
        for i, (_, spec, p, source, _) in enumerate(pairs):
            with self.subTest(version=spec['version']):
                changed = bytearray(source); changed[0x500] ^= 1
                with self.assertRaises(core.ToolError): core.apply_patch(bytes(changed), p)
                with self.assertRaises(core.ToolError): core.apply_patch(source, pairs[1-i][2])


if __name__ == '__main__':
    unittest.main()
