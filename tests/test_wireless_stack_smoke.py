import json
import sys
import tempfile
from unittest.mock import patch
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import build_wireless_stack_smoke as smoke
from build_wireless_stack_smoke import classify, config_is_enabled, enable_wireless_config

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
        self.assertIn('MAC80211_DEBUGFS',src)
        self.assertNotIn("wireless_out/'Module.symvers'",src)

class WirelessConfigGate(unittest.TestCase):
    def run_config(self, reset_testmode=False, reset_debugfs=False, pm=True):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            src=root/'stage-a'; src.mkdir()
            (src/'.config').write_text('CONFIG_PM='+('y' if pm else 'n')+'\n',encoding='utf-8')
            dst=root/'wireless'
            calls=[]
            def fake_run(cmd, log):
                calls.append(cmd)
                if '--file' in cmd:
                    cfg=Path(cmd[cmd.index('--file')+1])
                    flag=cmd[-1]
                    text=cfg.read_text(encoding='utf-8')
                    lines=[x for x in text.splitlines() if not x.startswith('CONFIG_'+flag+'=')]
                    value='m' if '--module' in cmd else 'y' if '--enable' in cmd else 'n'
                    cfg.write_text('\n'.join(lines)+f'\nCONFIG_{flag}={value}\n',encoding='utf-8')
                elif 'olddefconfig' in cmd and any('NL80211_TESTMODE' in c for c in calls):
                    cfg=dst/'.config'
                    text=cfg.read_text(encoding='utf-8')
                    if reset_testmode:
                        text=text.replace('CONFIG_NL80211_TESTMODE=y','CONFIG_NL80211_TESTMODE=n')
                    if reset_debugfs:
                        text=text.replace('CONFIG_MAC80211_DEBUGFS=n','CONFIG_MAC80211_DEBUGFS=y')
                    cfg.write_text(text,encoding='utf-8')
                return 0
            with patch.object(smoke,'run',side_effect=fake_run):
                result=enable_wireless_config(root/'kernel',src,dst,root/'clang',root/'prepare.log')
            return result, calls

    def test_enables_testmode_and_disables_debugfs_after_first_olddefconfig(self):
        result,calls=self.run_config()
        self.assertTrue(result['enabled']['NL80211_TESTMODE'])
        self.assertFalse(result['enabled']['MAC80211_DEBUGFS'])
        first=next(i for i,c in enumerate(calls) if 'olddefconfig' in c)
        disable=next(i for i,c in enumerate(calls) if '--disable' in c and 'MAC80211_DEBUGFS' in c)
        enable=next(i for i,c in enumerate(calls) if '--enable' in c and 'NL80211_TESTMODE' in c)
        self.assertLess(first,disable)
        self.assertLess(first,enable)
        self.assertIn('modules_prepare',calls[-1])

    def test_rejects_kconfig_resetting_testmode_or_debugfs(self):
        for kwargs in ({'reset_testmode':True},{'reset_debugfs':True},{'pm':False}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                self.run_config(**kwargs)


class WirelessReportGate(unittest.TestCase):
    def run_main(self, ops_passed, crc_mismatch=False):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            out=root/'out'
            def prepare(kernel, source, dest, compiler, log):
                dest.mkdir()
                (dest/'.config').write_text('CONFIG_NL80211_TESTMODE=y\n',encoding='utf-8')
                return {'enabled':{'NL80211_TESTMODE':True,'MAC80211_DEBUGFS':False}}
            module={'make_rc':0,'ko_emitted':True}
            wonder=dict(module,relocatable_object=True,kcfi_enabled=True,
                        kconfig_depends_on_mac80211=True,undefined_count=0)
            argv=['smoke','--kernel',str(root/'kernel'),'--kernel-out',str(root/'stage-a'),
                  '--compiler',str(root/'compiler'),'--target',str(root/'target'),
                  '--out',str(out),'--stock-symvers',str(root/'stock.symvers')]
            with patch.object(sys,'argv',argv), \
                 patch.object(smoke,'enable_wireless_config',side_effect=prepare), \
                 patch.object(smoke,'build_in_tree',return_value=module), \
                 patch.object(smoke,'build_wonder',return_value=wonder), \
                 patch.object(smoke,'audit_path',return_value={'ops_layout_gate_passed':ops_passed}), \
                 patch.object(smoke,'crc_compare',return_value={'compared':True,'mismatched':['bad'] if crc_mismatch else []}), \
                 patch('builtins.print'):
                rc=smoke.main()
            result=json.loads((out/'report.json').read_text(encoding='utf-8'))
            self.assertTrue((out/'ops-layout.json').is_file())
            self.assertTrue((out/'wireless.config').is_file())
            self.assertFalse(result['loadable_proven'])
            self.assertFalse(result['airdrop_available'])
            self.assertEqual(result['module_completion_gate'],'BLOCKED')
            return rc,result

    def test_good_compile_still_does_not_claim_loadability(self):
        rc,result=self.run_main(True)
        self.assertEqual(rc,0)
        self.assertTrue(result['compile_gate_passed'])

    def test_ops_or_stock_crc_mismatch_fails_compile_gate(self):
        for args in ((False,False),(True,True)):
            with self.subTest(args=args):
                rc,result=self.run_main(*args)
                self.assertEqual(rc,1)
                self.assertFalse(result['compile_gate_passed'])


if __name__=='__main__': unittest.main()
