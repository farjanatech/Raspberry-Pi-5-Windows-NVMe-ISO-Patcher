"""Catalog/guard tests require no Microsoft binaries."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
import pi5_nvme_tool as core
from pi5_nvme_profiles import ADDITIONAL_PROFILES
from test_pi5_nvme_tool import fixture


class ProfileCatalogTests(unittest.TestCase):
    def test_catalog_has_three_exact_distinct_pairs(self):
        p = core.load_profiles([])
        self.assertEqual({v['source_version'] for v in p},
                         {'10.0.26100.9539', '10.0.26100.9278', '10.0.26100.1'})
        self.assertEqual(len({v['source_sha256'] for v in p}), 3)
        self.assertEqual(len({v['output_sha256'] for v in p}), 3)

    def test_new_recipes_are_explicitly_static_only(self):
        for p in ADDITIONAL_PROFILES:
            self.assertEqual(p['review']['level'], 'REAL_INPUT_STATIC_ONLY')
            self.assertIn('NOT TESTED', p['runtime_evidence'])
            self.assertEqual(len(p['calls']), 5)
            self.assertEqual(p['helper']['bytes'], core.BUILTIN_PROFILE['helper']['bytes'])

    def test_recovery_inlining_is_not_replaced_by_newer_offsets(self):
        p = {v['source_version']: v for v in ADDITIONAL_PROFILES}
        self.assertEqual(len(p['10.0.26100.1']['edits']), 17)
        self.assertEqual(len(p['10.0.26100.9278']['edits']), 8)
        self.assertEqual(p['10.0.26100.1']['relocation']['iat_index'], 0)
        self.assertEqual(p['10.0.26100.9278']['relocation']['iat_index'], 28)

    def test_exported_json_matches_runtime_recipes(self):
        root = Path(__file__).resolve().parents[1]
        for p in ADDITIONAL_PROFILES:
            d = json.loads((root / 'profiles' / ('arm64-' + p['source_version'][5:] + '.json')).read_text())
            self.assertEqual(p, d)

    def test_duplicate_builtin_port_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'duplicate.json'
            path.write_text(json.dumps(ADDITIONAL_PROFILES[0]))
            with self.assertRaises(core.ToolError):
                core.load_profiles([path])

    def test_list_does_not_need_driver_inputs(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(core.main(['--list-profiles']), 0)
        self.assertIn('26100.9278', out.getvalue())
        self.assertIn('NOT TESTED', out.getvalue())

    def test_unrecognized_binary_remains_blocked(self):
        source, inf, _, _ = fixture()
        report = core.analyze(source, inf, core.load_profiles([]), '26100.9278')
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertIn('No reviewed recipe', ' '.join(report['blockers']))

    def test_static_review_warning_is_propagated(self):
        source, inf, p, _ = fixture()
        p['review'] = {'level': 'REAL_INPUT_STATIC_ONLY'}
        report = core.analyze(source, inf, [p], '12345.6')
        self.assertEqual(report['profile']['review_level'], 'REAL_INPUT_STATIC_ONLY')
        self.assertTrue(any('NOT passed' in w for w in report['warnings']))

    def test_old_upstream_recipe_not_changed(self):
        self.assertEqual(core.BUILTIN_PROFILE['source_sha256'], '10330d2cf54a03208c677713332c77e38ce5c0029d87cf7a0fd9af33e121d249')
        self.assertEqual(core.BUILTIN_PROFILE['output_sha256'], 'f647dd0e011997ef8c652d3cd9a887963cb31f202a7d0f0505c6221e787a8530')


if __name__ == '__main__':
    unittest.main()
