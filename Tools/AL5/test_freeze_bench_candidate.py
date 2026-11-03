"""File-only package integrity tests; fake build bytes never execute."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import freeze_bench_candidate as package


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root/'repo';self.repo.mkdir()
        self.source = self.repo/'Apps/Example.cs';self.source.parent.mkdir();self.source.write_text('example')
        self.app = self.root/'app';self.app.mkdir();(self.app/'PcmHammer.exe').write_bytes(b'not executable')
        self.writer = self.root/'writer';self.writer.mkdir();(self.writer/'WriteCandidateTool.dll').write_bytes(b'not executable')
        self.evidence = self.root/'result.json';self.evidence.write_text('{"hardware_access":false}')
        self.output = self.root/'package'
        self.paths = patch.object(package, 'source_paths', return_value=['Apps/Example.cs'])
        self.paths.start();self.addCleanup(self.paths.stop)

    def seal(self):
        return package.seal(self.repo,self.output,self.app,self.writer,[self.evidence])

    def test_roundtrip_copies_inputs_without_executing_and_checks_source_drift(self):
        self.seal();result=package.verify(self.output,self.repo)
        self.assertTrue(result['verified']);self.assertEqual(4,result['files_checked'])
        self.assertFalse(result['tests_rerun']);self.assertFalse(result['hardware_access'])
        self.source.write_text('changed')
        self.assertEqual(['Apps/Example.cs'],package.verify(self.output,self.repo)['source_drift'])
        self.assertTrue(package.verify(self.output)['verified'])

    def test_missing_and_modified_files_fail_without_repair(self):
        self.seal();target=self.output/'application/PcmHammer.exe';target.write_bytes(b'changed')
        self.assertEqual(['application/PcmHammer.exe'],package.verify(self.output)['mismatches'])
        target.unlink();self.assertFalse(package.verify(self.output)['verified'])
        self.assertFalse(target.exists())

    def test_added_file_cannot_hide_in_a_verified_package(self):
        self.seal();(self.output/'unexpected.dll').write_bytes(b'unknown')
        self.assertEqual(['unexpected.dll'],package.verify(self.output)['unexpected_files'])

    def test_overwrite_and_recursive_copy_are_rejected(self):
        self.seal()
        with self.assertRaises(ValueError):self.seal()
        with self.assertRaises(ValueError):package.seal(self.repo,self.app/'nested',self.app,self.writer,[self.evidence])

    def test_path_traversal_and_authority_changes_rejected(self):
        for relative in ('../escape','source/../../escape',str(self.root/'absolute')):
            with self.assertRaises(ValueError):package.safe_child(self.root,relative)
        self.seal();manifest=self.output/'manifest.json';value=json.loads(manifest.read_text())
        value['live_write_enabled']=True;manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError):package.verify(self.output)

    def test_source_list_drift_detects_new_or_removed_inputs(self):
        self.seal()
        with patch.object(package,'source_paths',return_value=['Apps/New.cs']):
            self.assertEqual(['Apps/Example.cs','Apps/New.cs'],package.verify(self.output,self.repo)['source_drift'])


if __name__=='__main__':unittest.main()
