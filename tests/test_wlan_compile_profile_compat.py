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
        (root/'Kbuild').write_text('HDD_OBJS := core/hdd/src/base.o\n'
                                   '$(call add-wlan-objs,hdd,$(HDD_OBJS))\n',encoding='utf-8')

    def test_derives_monitor2_and_adds_bazel_only_beam_object_once(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); self.fixture(root)
            r=profile_kbuild_compat(root)
            self.assertEqual(r['derived_make_vars'],[
                'CONFIG_WIFI_MONITOR_SUPPORT=y',
                'CONFIG_WLAN_TX_MON_2_0=y',
                'CONFIG_WLAN_DP_LOCAL_PKT_CAPTURE=y'])
            text=(root/'Kbuild').read_text(encoding='utf-8')
            self.assertEqual(text.count('$(HDD_SRC_DIR)/wlan_hdd_beam_switch.o'),1)
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

if __name__=='__main__':
    unittest.main()
