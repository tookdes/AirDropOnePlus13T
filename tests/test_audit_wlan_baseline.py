import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from audit_wlan_baseline import compare_imports

class CompareTests(unittest.TestCase):
    def test_subset_match_but_missing_providers_block_module(self):
        a={'module_layout':0x42,'cld':0x73,'opa':0x88}
        b={'module_layout':0x42,'cld':0x73}
        r=compare_imports(a,b,{'module_layout','cld','opa'},
                          {'module_layout','cld','opa'})
        self.assertEqual(r['matching_versions'],2)
        self.assertTrue(r['crc_subset_matches'])
        self.assertEqual(r['rebuilt_undefined_without_versions'],['opa'])
        self.assertEqual(r['module_completion_gate'],'BLOCKED')
        self.assertFalse(r['loadable_or_firmware_compatible_proven'])

    def test_mismatch_and_new_import_fail(self):
        a={'module_layout':0x42}
        b={'module_layout':0x43,'unexpected':0x55}
        r=compare_imports(a,b,{'module_layout'}, {'module_layout','unexpected'})
        self.assertFalse(r['crc_subset_matches'])
        self.assertEqual(sorted(r['mismatching_versions']),['module_layout'])
        self.assertEqual(r['newly_required_undefined_imports'],['unexpected'])

if __name__=='__main__': unittest.main()
