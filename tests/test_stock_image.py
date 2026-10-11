"""Synthetic safety tests plus optional integration against real uploaded inputs."""
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from stock_image import (image_from_boot, embedded_config, EvidenceError,
                         module_exports, export_record, extract, write_symvers)
from layout_from_btf import Btf, BtfError
from test_artifact_tools import fixture_btf

class StockParserTests(unittest.TestCase):
    def test_non_boot_rejected(self):
        for raw in (b'',b'ANDROID!',b'\0'*4096):
            with self.assertRaises(EvidenceError):image_from_boot(raw)
    def test_truncated_kernel_rejected(self):
        raw=bytearray(4096);raw[:8]=b'ANDROID!'
        struct.pack_into('<I',raw,8,4096);struct.pack_into('<I',raw,20,1584);struct.pack_into('<I',raw,40,4)
        with self.assertRaises(EvidenceError):image_from_boot(bytes(raw))
    def test_boot_with_compressed_kernel_is_not_guessed(self):
        raw=bytearray(8192);raw[:8]=b'ANDROID!'
        struct.pack_into('<I',raw,8,4096);struct.pack_into('<I',raw,20,1584);struct.pack_into('<I',raw,40,4)
        with self.assertRaises(EvidenceError):image_from_boot(bytes(raw))
    def test_image_is_readonly(self):
        raw=bytearray(8192);raw[:8]=b'ANDROID!'
        struct.pack_into('<I',raw,8,4096);struct.pack_into('<I',raw,20,1584);struct.pack_into('<I',raw,40,4)
        raw[4152:4156]=b'ARM\x64';struct.pack_into('<Q',raw,4112,8192)
        raw=bytes(raw);image,meta=image_from_boot(raw)
        self.assertEqual(image,raw[4096:]);self.assertEqual(meta['kernel_memory_bytes'],8192)
    def test_missing_config_rejected(self):
        with self.assertRaises(EvidenceError):embedded_config(b'NO_CONFIG')
    def test_bad_export_offsets_rejected(self):
        self.assertIsNone(export_record(b'\0'*100,0))
        self.assertIsNone(export_record(b'\xff'*100,96))
    def test_duplicate_provider_rejected(self):
        row={'name':'x','crc':'0x00000001','namespace':'','provider':'vmlinux','export_type':'EXPORT_SYMBOL'}
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(EvidenceError):write_symvers(Path(d)/'out',[row,row])
    def test_input_cannot_be_output(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(EvidenceError):extract(Path(d),Path(d))
    def test_btf_duplicate_layout_facts_accepted(self):
        b=Btf(fixture_btf());b.structs['device'].append(json.loads(json.dumps(b.structs['device'][0])))
        b.structs['device'][1]['id']=99;b.structs['device'][1]['members'][0]['type_id']=555
        self.assertEqual(b.member_offset('device','driver_data'),8)
        # This must NOT make one() silently select one full type definition.
        with self.assertRaises(BtfError):b.one('device')
    def test_btf_disagreeing_offset_rejected(self):
        b=Btf(fixture_btf());b.structs['device'].append(json.loads(json.dumps(b.structs['device'][0])))
        b.structs['device'][1]['members'][0]['bit_offset']+=8
        with self.assertRaises(BtfError):b.member_offset('device','driver_data')
    def test_btf_disagreeing_size_rejected(self):
        b=Btf(fixture_btf());b.structs['module'].append({'size':1024,'members':[],'id':98})
        with self.assertRaises(BtfError):b.same_size('module')

@unittest.skipUnless(os.environ.get('OP13T_INPUTS'),'set OP13T_INPUTS for real stock integration')
class RealStockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs=Path(os.environ['OP13T_INPUTS']);cls.temp=tempfile.TemporaryDirectory()
        cls.out=Path(cls.temp.name)/'derived';cls.report=extract(cls.inputs,cls.out)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_expected_hash_and_config(self):
        self.assertEqual(self.report['boot']['boot_sha256'],'3672b815e7afc2f6c9807d211bdbbf53757cb8537dcbc80ba5a49ff2b5a8a66e')
        self.assertEqual((self.out/'boot.config').read_bytes(),(self.inputs/'kconfig.txt').read_bytes())
    def test_all_core_crosschecks(self):
        e=self.report['kernel_exports'];self.assertEqual((e['normal_count'],e['gpl_count']),(3343,5452))
        self.assertEqual(e['matched_stock_import_count'],625);self.assertEqual(e['mismatches'],[])
    def test_true_exports_not_imports(self):
        self.assertEqual(self.report['captured_provider_exports'],9078)
        self.assertEqual(self.report['crosschecked_imports'],731)
        self.assertEqual(len(self.report['imports_without_captured_provider']),236)
    def test_actual_btf_layout(self):
        self.assertEqual(self.report['btf']['layouts'],{'OP13T_PLATFORM_DEV_OFFSET':16,
            'OP13T_DEVICE_DRIVER_DATA_OFFSET':152,'OP13T_DEVICE_OF_NODE_OFFSET':768,'OP13T_MODULE_SIZE':1536})
    def test_negative_control_not_used(self):
        from elf_audit import Module
        original=Module((self.inputs/'icnss2.ko').read_bytes()).versions()
        bad=Module((self.inputs/'icnss2_badcrc.ko').read_bytes()).versions()
        self.assertEqual([k for k in original if original[k]!=bad[k]],['debugfs_create_dir'])
        self.assertEqual(self.report['requested_export_checks']['component_add']['crc'],'0x95f9ae5b')
    def test_vendor_export_counts(self):
        self.assertEqual({m['name']:m['export_count'] for m in self.report['stock_modules']},
            {'icnss2.ko':59,'cnss2.ko':74,'cfg80211.ko':150,'qca_cld3_peach.ko':0,'qca_cld3_peach_v2.ko':0})
    def test_captured_provider_metadata(self):
        rows=json.loads((self.out/'exports.json').read_text());byname={r['name']:r for r in rows}
        self.assertEqual(byname['of_find_node_opts_by_path']['crc'],'0x7c497915')
        self.assertEqual(byname['module_layout']['crc'],'0x4e276f37')
        self.assertNotIn('cnss_set_vendor_wonder_priv_data',byname)
        self.assertNotIn('ieee80211_register_hw',byname)
if __name__=='__main__':unittest.main()
