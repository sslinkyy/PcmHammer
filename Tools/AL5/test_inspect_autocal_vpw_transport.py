"""File-identity regressions for the offline collector; never run native code."""
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import inspect_autocal_vpw_transport as collector


class CollectorIdentityTests(unittest.TestCase):
    def test_artifact_changes_reject_a_mixed_evidence_report(self):
        for changed in ('hapi', 'dumpbin', 'prior'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                paths = {key: root / key for key in ('hapi', 'dumpbin', 'prior')}
                for key, path in paths.items():
                    path.write_bytes(key.encode() * 128)
                pe = types.SimpleNamespace(
                    OPTIONAL_HEADER=types.SimpleNamespace(ImageBase=0x400000),
                    sections=[types.SimpleNamespace(VirtualAddress=0, SizeOfRawData=512,
                                                    PointerToRawData=0, Name=b'.text\0')])

                def disassemble(*_args, **_kwargs):
                    paths[changed].write_bytes(b'changed while collecting')
                    return types.SimpleNamespace(stdout='  00400010: nop\n  00400011: ret\n')

                with (patch.object(collector, 'HAPI_SHA256', collector.digest(paths['hapi'].read_bytes())),
                      patch.object(collector, 'PRIOR_REPORTS', (('prior', collector.digest(paths['prior'].read_bytes())),)),
                      patch.object(collector, 'WINDOWS', (('fixture', 0x400010, 0x400012),)),
                      patch.object(collector.pefile, 'PE', return_value=pe),
                      patch.object(collector.subprocess, 'run', side_effect=disassemble)):
                    with self.assertRaisesRegex(ValueError, 'changed during collection'):
                        collector.inspect(paths['hapi'], paths['dumpbin'], root)

    def test_wrong_source_is_rejected_before_disassembly(self):
        with tempfile.TemporaryDirectory() as name:
            source = Path(name) / 'hapi'
            source.write_bytes(b'unrelated artifact')
            with patch.object(collector.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'HAPI identity differs'):
                    collector.inspect(source, Path(name) / 'absent_tool', Path(name))
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
