import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from prepare_stage_a import symversions_from_cmd, compare_fresh, REQUIRED_FRESH, export_db
class PrepareTests(unittest.TestCase):
    def test_symvers_cmd(self):
        self.assertEqual(symversions_from_cmd('# a command\n#SYMVER module_layout 0x4e276f37\n'),{'module_layout':0x4e276f37})
    def test_conflict_not_overwritten(self):
        with self.assertRaises(ValueError):symversions_from_cmd('#SYMVER x 0x1\n#SYMVER x 0x2\n')
    def test_independent_mismatch_fails(self):
        good={n:1 for n in REQUIRED_FRESH};bad=dict(good);bad['module_layout']=2
        with self.assertRaises(ValueError):compare_fresh(bad,good)
    def test_missing_required_fails(self):
        with self.assertRaises(ValueError):compare_fresh({}, {})
    def test_pass_preserves_crc(self):
        good={n:0x42 for n in REQUIRED_FRESH}
        self.assertEqual(set(compare_fresh(good,good).values()),{'0x00000042'})
    @unittest.skipUnless((ROOT/'evidence/stock/exports.json').exists(),'captured exports unavailable')
    def test_recorded_export_database(self):
        rows,_=export_db(ROOT/'evidence/stock');self.assertEqual(len(rows),8795)
        self.assertEqual(rows['module_layout'],0x4e276f37)
if __name__=='__main__':unittest.main()
