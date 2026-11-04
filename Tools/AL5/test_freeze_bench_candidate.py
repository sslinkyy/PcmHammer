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

    def test_optional_backup_tool_is_sealed_and_verified_without_running_it(self):
        backup=self.root/'backup';backup.mkdir();(backup/'SavedBackupTool.dll').write_bytes(b'not executable')
        package.seal(self.repo,self.output,self.app,self.writer,[self.evidence],backup_tool=backup)
        self.assertTrue(package.verify(self.output,self.repo)['verified'])
        (self.output/'offline_backup/SavedBackupTool.dll').write_bytes(b'changed')
        self.assertEqual(['offline_backup/SavedBackupTool.dll'],package.verify(self.output)['mismatches'])

    def test_missing_backup_build_rejected_before_output(self):
        with self.assertRaises(ValueError):
            package.seal(self.repo,self.output,self.app,self.writer,[self.evidence],backup_tool=self.root/'missing')
        self.assertFalse(self.output.exists())

    def test_application_scope_reports_tool_kernel_and_doc_drift_without_rebuild_claim(self):
        extras = ['Docs/TCMHammer/status.md', 'Tools/AL5/offline.py', 'Kernels/reader.s']
        for relative in extras:
            path = self.repo/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('old')
        with patch.object(package,'source_paths',return_value=['Apps/Example.cs',*extras]):
            self.seal()
            for relative in extras:(self.repo/relative).write_text('new')
            self.assertFalse(package.verify(self.output,self.repo)['verified'])
            result=package.verify(self.output,self.repo,application_only=True)
            self.assertTrue(result['verified']);self.assertTrue(result['package_integrity_verified'])
            self.assertTrue(result['application_inputs_match']);self.assertFalse(result['source_snapshot_matches'])
            for group in ('documentation','tools','kernel'):
                self.assertEqual(1,len(result['source_drift_by_group'][group]))
            self.source.write_text('changed')
            self.assertFalse(package.verify(self.output,self.repo,application_only=True)['verified'])

    def test_application_scope_still_rejects_corruption_and_requires_checkout(self):
        self.seal()
        with self.assertRaises(ValueError):package.verify(self.output,application_only=True)
        (self.output/'application/PcmHammer.exe').write_bytes(b'changed')
        self.assertFalse(package.verify(self.output,self.repo,application_only=True)['verified'])

    def test_build_configuration_and_unknown_inputs_are_application_drift(self):
        for name in ('Directory.Build.props','Apps/global.json','future-input'):
            self.assertEqual('application',package.drift_group(name))


if __name__=='__main__':unittest.main()
