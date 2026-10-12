import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_wireless_stack_smoke import classify, config_is_enabled

class WirelessStackSmoke(unittest.TestCase):
    def test_config_is_enabled_only_y_or_m(self):
        text='# CONFIG_CFG80211 is not set\nCONFIG_MAC80211=m\nCONFIG_RFKILL=y\n'
        self.assertFalse(config_is_enabled(text,'CFG80211'))
        self.assertTrue(config_is_enabled(text,'MAC80211'))
        self.assertTrue(config_is_enabled(text,'RFKILL'))
        self.assertFalse(config_is_enabled('CONFIG_CFG80211=n\n','CFG80211'))

    def test_classify_ieee80211_and_cfg80211(self):
        got=classify(['ieee80211_register_hw','ieee80211_rx_napi',
                      'cfg80211_scan_done','wiphy_register','memcpy'])
        self.assertEqual(got['ieee80211'],['ieee80211_register_hw','ieee80211_rx_napi'])
        self.assertEqual(got['cfg80211'],['cfg80211_scan_done'])
        self.assertEqual(got['wiphy'],['wiphy_register'])
        self.assertEqual(got['other'],['memcpy'])

    def test_kconfig_gate_text_is_present_in_pinned_excerpt_or_docstring(self):
        src=(ROOT/'tools'/'build_wireless_stack_smoke.py').read_text()
        self.assertIn('depends on MAC80211',src)
        self.assertIn('CONFIG_CFG80211',src)
        self.assertIn('wonder.ko',src)
        self.assertIn('TRACE_INCLUDE_PATH',src)
        self.assertNotIn("wireless_out/'Module.symvers'",src)

if __name__=='__main__': unittest.main()
