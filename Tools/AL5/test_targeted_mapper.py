"""Manifest and safety-contract checks; not an EFILive/Lua execution test."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'Tools/AL5/AL5_TARGETED_DIFFERENTIAL_MAPPER_v6.lua'
MANIFEST = ROOT / 'Docs/AL5/TunerPro/TARGETED_MARKER_CASES_v6.json'


class TargetedMapperTests(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text(encoding='utf8')
        self.manifest = json.loads(MANIFEST.read_text())

    def test_manifest_matches_every_lua_case(self):
        cases = self.manifest['cases']
        parsed = re.findall(
            r'\{id="([DH]\d+)",column=(\d+),row=(\d+),expected=([^,]+),'
            r'target=([^,]+),columns=(\d+),rows=(\d+),label=', self.text)
        self.assertEqual(83, len(cases))
        self.assertEqual(len(cases), len(parsed))
        seen = set()
        for case, row in zip(cases, parsed):
            self.assertEqual(case['id'], row[0])
            for key, value in zip(
                    ['column', 'row', 'expected', 'target', 'columns', 'rows'], row[1:]):
                self.assertAlmostEqual(case[key], float(value))
            key = (case['id'], case['column'], case['row'])
            self.assertNotIn(key, seen)
            seen.add(key)
            self.assertTrue(0 <= case['row'] < case['rows'])
            self.assertTrue(0 <= case['column'] < case['columns'])
            self.assertNotEqual(case['expected'], case['target'])
        self.assertTrue(set(self.manifest['skipped_ids']).isdisjoint(c['id'] for c in cases))

    def test_throttle_sampling_covers_each_gear_and_orientation(self):
        for id in ['D5073', 'D5074', 'D5075']:
            actual = {(c['column'], c['row']) for c in self.manifest['cases'] if c['id'] == id}
            self.assertEqual({(col, row) for col in range(5) for row in (0, 8, 16)}, actual)

    def test_only_established_efi_api_allowlist(self):
        allowed = {'_efiGetFileProp', '_efiGetPartNumber', '_efiOpenFile',
                   '_efiCloseFile', '_efiGetCalId', '_efiGetCalProp',
                   '_efiGetCalValue', '_efiSetCalValue'}
        self.assertEqual(allowed, set(re.findall(r'\b_efi\w+', self.text)))
        self.assertNotRegex(self.text, r'os\.(execute|remove|rename)|io\.popen|loadfile|dofile')
        # All setter calls target the secondary, never GUI_FD or literal zero.
        for match in re.findall(r'q\(_efiSetCalValue,([^\n]+)', self.text):
            self.assertFalse('GUI_FD' in match or match.startswith('0,'))
        self.assertIn('fd<=0 or fd~=math.floor(fd)', self.text)
        self.assertLess(self.text.index('fd<=0'), self.text.index('local ok,runerr=pcall'))
        self.assertIn('if clean~=baseline then error', self.text)
        self.assertIn('if final_gui~=gui_raw then error', self.text)
        self.assertLess(self.text.index('q(_efiCloseFile,fd)'), self.text.index('f:write(json(report)'))
        self.assertIn('checksum_finalized=false,flash_ready=false,completed=false', self.text)


if __name__ == '__main__':
    unittest.main()
