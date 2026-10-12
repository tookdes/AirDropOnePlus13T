import sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from module_export_symvers import write_symvers, export_crcs

class ExportSymvers(unittest.TestCase):
    def test_write_symvers_format(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.symvers'
            write_symvers(p,[('ieee80211_alloc_hw_nm',0xa9cce254,'EXPORT_SYMBOL')], 'mac80211')
            self.assertEqual(p.read_text(),'0xa9cce254\tieee80211_alloc_hw_nm\tmac80211\tEXPORT_SYMBOL\t\n')

    def test_stock_files_contain_alloc_hw_nm(self):
        text=(ROOT/'profiles'/'stock-mac80211.exports.symvers').read_text()
        self.assertIn('ieee80211_alloc_hw_nm', text)
        self.assertIn('0xa9cce254', text)
        cfg=(ROOT/'profiles'/'stock-cfg80211.exports.symvers').read_text()
        self.assertIn('cfg80211_vendor_cmd_reply', cfg)

if __name__=='__main__': unittest.main()
