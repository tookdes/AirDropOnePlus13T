from pathlib import Path
import copy
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from audit_qcacld_callbacks import compare

class CfgCallbackTests(unittest.TestCase):
    def fixture(self):return {'object_bytes':1032,'callbacks':[{'symbol':'before_testmode','offset':432},{'symbol':'after_testmode','offset':472}]}
    def test_matching_slots_are_not_full_abi_proof(self):
        r=compare(self.fixture(),self.fixture());self.assertTrue(r['callback_slot_gate_passed']);self.assertFalse(r['callback_prototypes_and_kcfi_proven'])
    def test_testmode_sized_shift_rejected(self):
        actual=self.fixture();actual['callbacks'][1]['offset']-=16;actual['object_bytes']-=16
        self.assertFalse(compare(actual,self.fixture())['callback_slot_gate_passed'])
    def test_unknown_callback_or_duplicate_slot_rejected(self):
        for mode in ('unknown','duplicate'):
            a=self.fixture()
            if mode=='unknown':a['callbacks'][1]['symbol']='unknown'
            else:a['callbacks'][1]['offset']=432
            self.assertFalse(compare(a,self.fixture())['callback_slot_gate_passed'])
    def test_optional_missing_stock_callback_is_reported_not_called_shifted(self):
        a=self.fixture();a['callbacks'].pop()
        r=compare(a,self.fixture());self.assertTrue(r['callback_slot_gate_passed']);self.assertEqual(r['stock_callbacks_not_initialized'],['after_testmode'])

if __name__=='__main__':unittest.main()
