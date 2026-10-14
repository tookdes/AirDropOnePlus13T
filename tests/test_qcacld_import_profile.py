import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import qcacld_import_profile as qip

class QcacldImportProfileTests(unittest.TestCase):
    def test_checked_profile_materializes_exact_588_rows(self):
        meta,raw,rows=qip.load_profile()
        self.assertEqual(len(rows),588)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '4076858debaaf71d44a4b2af3335f8f405c8d797bb5481015a2e6813ae321190')
        self.assertEqual(sum(meta['provider_counts'].values()),588)
        self.assertEqual([r for r in rows if r[1]=='module_layout'],
                         [['0x4e276f37','module_layout','vmlinux','EXPORT_SYMBOL','']])
        self.assertEqual(meta['captured_provider_export_records'],532)
        self.assertEqual(meta['source_verified_provider_records'],56)

    def test_output_is_derived_symvers_not_binary_patch(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'Module.symvers'
            with patch.object(sys,'argv',['profile','--out',str(out)]):
                self.assertEqual(qip.main(),0)
            self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(),
                             '4076858debaaf71d44a4b2af3335f8f405c8d797bb5481015a2e6813ae321190')
            self.assertNotIn(b'ELF',out.read_bytes()[:16])

    def test_payload_mutation_fails_closed(self):
        original=qip.PARTS
        with tempfile.TemporaryDirectory() as td:
            copies=[]
            for i,p in enumerate(original):
                dst=Path(td)/str(i)
                dst.write_bytes(p.read_bytes())
                copies.append(dst)
            data=bytearray(copies[1].read_bytes())
            data[10]=ord('A') if data[10]!=ord('A') else ord('B')
            copies[1].write_bytes(data)
            with patch.object(qip,'PARTS',copies), self.assertRaises(ValueError):
                qip.load_profile()

    def test_metadata_provider_drift_fails_closed(self):
        meta=json.loads(qip.META.read_text())
        meta['provider_counts']['cnss2']+=1
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'meta.json'; p.write_text(json.dumps(meta))
            with patch.object(qip,'META',p), self.assertRaises(ValueError):
                qip.load_profile()

if __name__=='__main__':
    unittest.main()
