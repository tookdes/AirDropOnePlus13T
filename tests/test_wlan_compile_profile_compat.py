import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_wlan_compile_smoke import profile_kbuild_compat, PROFILE_REQUIRED

class QcacldProfileCompatTests(unittest.TestCase):
    def fixture(self,root:Path):
        cfg=root/'configs'/'sun_gki_peach-v2_defconfig'
        cfg.parent.mkdir(parents=True)
        cfg.write_text(''.join(f'{k}={v}\n' for k,v in PROFILE_REQUIRED.items()),encoding='utf-8')
        beam=root/'core/hdd/src/wlan_hdd_beam_switch.c'
        beam.parent.mkdir(parents=True); beam.write_text('/* fixture */\n',encoding='utf-8')
        (root/'wlan_qcacld3_modules.bzl').write_text(
            '#ifdef OPLUS_FEATURE_WIFI_BEAM_SWITCH\n'
            '    "core/hdd/src/wlan_hdd_beam_switch.c",\n'
            '#endif /* OPLUS_FEATURE_WIFI_BEAM_SWITCH */\n',encoding='utf-8')
        export=root/'cmn/qdf/linux/src/i_qdf_module.h'
        export.parent.mkdir(parents=True)
        export.write_text('#ifdef WLAN_DISABLE_EXPORT_SYMBOL\n#define __qdf_export_symbol(_sym)\n#endif\n')
        (root/'Kbuild').write_text('HDD_OBJS := core/hdd/src/base.o\n'
                                   '$(call add-wlan-objs,hdd,$(HDD_OBJS))\n'
                                   'ccflags-$(CONFIG_WLAN_DISABLE_EXPORT_SYMBOL) += -DWLAN_DISABLE_EXPORT_SYMBOL\n',encoding='utf-8')

    def test_derives_monitor2_and_adds_bazel_only_beam_object_once(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            r=profile_kbuild_compat(root)
            self.assertEqual(r['derived_make_vars'],[
                'CONFIG_WIFI_MONITOR_SUPPORT=y',
                'CONFIG_WLAN_TX_MON_2_0=y',
                'CONFIG_WLAN_DP_LOCAL_PKT_CAPTURE=y',
                'CONFIG_NL80211_TESTMODE=y',
                'CONFIG_WLAN_DISABLE_EXPORT_SYMBOL=y'])
            text=(root/'Kbuild').read_text(encoding='utf-8')
            self.assertEqual(text.count('$(HDD_SRC_DIR)/wlan_hdd_beam_switch.o'),1)
            self.assertNotIn('\\\\n', text)
            self.assertIn('HDD_OBJS += $(HDD_SRC_DIR)/wlan_hdd_beam_switch.o\n', text)
            profile_kbuild_compat(root)
            self.assertEqual((root/'Kbuild').read_text(encoding='utf-8').count(
                '$(HDD_SRC_DIR)/wlan_hdd_beam_switch.o'),1)

    def test_composite_profile_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            cfg=root/'configs'/'sun_gki_peach-v2_defconfig'
            cfg.write_text(cfg.read_text().replace(
                'CONFIG_WIFI_MONITOR_SUPPORT_Y_WLAN_TX_MON_2_0=y',
                'CONFIG_WIFI_MONITOR_SUPPORT_Y_WLAN_TX_MON_2_0=n'))
            with self.assertRaises(ValueError):
                profile_kbuild_compat(root)

    def test_bazel_beam_contract_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            (root/'wlan_qcacld3_modules.bzl').write_text('[]\n')
            with self.assertRaises(ValueError):
                profile_kbuild_compat(root)

    def test_no_export_kbuild_or_header_contract_drift_fails_closed(self):
        for which in ('Kbuild','header'):
            with self.subTest(which=which),tempfile.TemporaryDirectory() as td:
                root=Path(td);self.fixture(root)
                if which=='Kbuild':
                    p=root/'Kbuild';p.write_text(p.read_text().replace('ccflags-$(CONFIG_WLAN_DISABLE_EXPORT_SYMBOL)','wrong'))
                else:(root/'cmn/qdf/linux/src/i_qdf_module.h').write_text('changed')
                with self.assertRaises(ValueError):profile_kbuild_compat(root)

    def test_vendor_testmode_header_and_make_selection_are_both_enabled(self):
        from build_wlan_compile_smoke import VENDOR_KERNEL_CONFIG_DEFINES,PROFILE_KBUILD_DERIVED
        self.assertIn('CONFIG_NL80211_TESTMODE=1',VENDOR_KERNEL_CONFIG_DEFINES)
        self.assertIn('CONFIG_NL80211_TESTMODE=y',PROFILE_KBUILD_DERIVED)
        self.assertIn('CONFIG_WLAN_DISABLE_EXPORT_SYMBOL=y',PROFILE_KBUILD_DERIVED)

if __name__=='__main__':
    unittest.main()
