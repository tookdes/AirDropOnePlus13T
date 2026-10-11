import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_public_stage_a import profile_load, fresh_verify, layout_header, config_digest

class PublicProfile(unittest.TestCase):
    def setUp(self):
        self.p,self.entries=profile_load(ROOT/'profiles/stage-a.json',ROOT/'profiles/stage-a.exports.symvers')

    def test_profile_genuine_subset(self):
        self.assertEqual(len(self.entries),92)
        self.assertEqual(self.entries['module_layout'],0x4e276f37)
        self.assertEqual(self.entries['of_find_node_opts_by_path'],0x7c497915)

    def test_subset_checksum_rejects_change(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'bad';f.write_text((ROOT/'profiles/stage-a.exports.symvers').read_text().replace('0x4e276f37','0x00000000'))
            with self.assertRaisesRegex(ValueError,'checksum'):
                profile_load(ROOT/'profiles/stage-a.json',f)

    def test_fresh_all_required(self):
        fresh={n:self.entries[n] for n in self.p['fresh_genksyms_symbols']}
        self.assertEqual(len(fresh_verify(fresh,self.p,self.entries)),76)
        fresh.pop('module_layout')
        with self.assertRaisesRegex(ValueError,'missing_fresh'):fresh_verify(fresh,self.p,self.entries)

    def test_fresh_crc_mismatch(self):
        fresh={n:self.entries[n] for n in self.p['fresh_genksyms_symbols']}
        fresh['component_add']^=1
        with self.assertRaisesRegex(ValueError,'crc_mismatch'):fresh_verify(fresh,self.p,self.entries)

    def test_layout_is_captured_not_vivo(self):
        h=layout_header(self.p)
        self.assertIn('OP13T_DEVICE_OF_NODE_OFFSET 768U',h)
        self.assertIn('OP13T_MODULE_SIZE 1536U',h)

    def test_canonical_config_ignores_comment_order_only(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'a';b=Path(d)/'b'
            a.write_text('# title\nCONFIG_FOO=y\n# CONFIG_BAR is not set\n')
            b.write_text('# CONFIG_BAR is not set\nCONFIG_FOO=y\n')
            self.assertEqual(config_digest(a),config_digest(b))
            b.write_text('# CONFIG_BAR is not set\nCONFIG_FOO=m\n')
            self.assertNotEqual(config_digest(a),config_digest(b))

if __name__=='__main__':unittest.main()
