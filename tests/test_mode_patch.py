"""Check the dormancy and public provenance of the first QDF/CDP/WMI port."""
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from validate_mode_patch import validate, touched, PATCH

class ModePatchTests(unittest.TestCase):
    def test_five_scoped_files_and_unchanged_firmware_gate(self):
        result=validate()
        self.assertEqual(len(result['paths']),5)
        self.assertEqual(result['mode'],'dormant')
        self.assertIn(PATCH,(ROOT/'patches/series').read_text().splitlines())
        text=(ROOT/'patches'/PATCH).read_text()
        self.assertIn('WMI_VDEV_TYPE_WIFI_PASSTHRU',text)
        self.assertIn('QDF_PASSTHRU_MODE',text)
        self.assertIn('CDP_VDEV_SET_PASSTHRU_FREQ',text)
        self.assertNotIn('CONFIG_DRIVER_PASSTHRU_MODE=y',text)
        self.assertNotIn('CONFIG_WONDER_SUPPORT=y',text)

    def test_scope_rejects_traversal_and_build_activation(self):
        patch=(ROOT/'patches'/PATCH).read_bytes()
        self.assertEqual(len(touched(patch)),5)
        with self.assertRaises(ValueError):
            touched(patch.replace(b'diff --git a/vendor/qcom/',b'diff --git a/../../vendor/qcom/',1))

if __name__=='__main__': unittest.main()
