"""Synthetic parser fixtures only. None is a real or deployable kernel module."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from elf_audit import Module, ElfError, audit, merge_stock
from layout_from_btf import Btf, BtfError, generate
from bundle_existing_inputs import bundle, discover
from build_stage_a import config_values

EXPECTED={'module_layout':0x4e276f37,'_printk':0x92997ed8}

def fixture_elf(machine=183, versions=None, corrupt_versions=False):
    """Construct a parser test byte string, not machine code."""
    names=b'\0.shstrtab\0.strtab\0.symtab\0.modinfo\0__versions\0'
    strings=b'\0_printk\0'
    versions=EXPECTED if versions is None else versions
    vers=b''.join(struct.pack('<Q',v)+k.encode().ljust(56,b'\0') for k,v in versions.items())
    if corrupt_versions: vers+=b'x'
    symbol=b'\0'*24+struct.pack('<IBBHQQ',1,0x12,0,0,0,0)
    data=[b'',names,strings,symbol,b'name=synthetic_fixture\0license=GPL\0vermagic=NOT_A_KERNEL\0',vers]
    kinds=[0,3,3,2,1,1]; labels=['','.shstrtab','.strtab','.symtab','.modinfo','__versions']
    offset=64+6*64; sections=[]; chunks=[]
    for i,raw in enumerate(data):
        sections.append(struct.pack('<IIQQQQIIQQ', names.index(labels[i].encode()+b'\0') if i else 0,
            kinds[i],0,0,offset if i else 0,len(raw),2 if i==3 else 0,0,1,24 if i==3 else 0))
        chunks.append(raw); offset+=len(raw)
    ident=b'\x7fELF\x02\x01\x01'+b'\0'*9
    header=ident+struct.pack('<HHIQQQIHHHHHH',1,machine,1,0,0,64,0,64,0,0,64,6,1)
    return header+b''.join(sections)+b''.join(chunks)

def fixture_btf(bitfield=False):
    strings=b'\0platform_device\0dev\0device\0driver_data\0of_node\0module\0'
    def idx(n): return strings.index(n.encode()+b'\0')
    def ty(name,size,members):
        info=(4<<24)|len(members)|(0x80000000 if bitfield else 0)
        data=struct.pack('<III',idx(name),info,size)
        for n,bits in members:
            data+=struct.pack('<III',idx(n),0,bits | (0x08000000 if bitfield else 0))
        return data
    # Intentionally arbitrary offsets, never the target's layout evidence.
    types=ty('platform_device',128,[('dev',64)])+ty('device',64,[('driver_data',64),('of_node',128)])+ty('module',512,[])
    return struct.pack('<HBBIIIII',0xeb9f,1,0,24,0,len(types),len(types),len(strings))+types+strings

class ElfTests(unittest.TestCase):
    def test_synthetic_crc_match_is_not_loadability(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'test.fixture'; p.write_bytes(fixture_elf())
            result=audit(p,EXPECTED)
            self.assertTrue(result['captured_crc_check_passed'])
            self.assertFalse(result['target_loadability_proven'])
    def test_wrong_architecture_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'test.fixture'; p.write_bytes(fixture_elf(machine=62))
            self.assertIn('Not AArch64', ' '.join(audit(p,EXPECTED)['errors']))
    def test_crc_mismatch_and_unknown_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'test.fixture'; p.write_bytes(fixture_elf())
            self.assertIn('CRC mismatch: _printk',audit(p,{'module_layout':EXPECTED['module_layout'],'_printk':1})['errors'])
            self.assertIn('No captured stock CRC evidence: _printk',audit(p,{'module_layout':EXPECTED['module_layout']})['errors'])
    def test_unversioned_strong_import_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'test.fixture'; p.write_bytes(fixture_elf(versions={'module_layout':EXPECTED['module_layout']}))
            self.assertIn('Strong import has no version: _printk',audit(p,EXPECTED)['errors'])
    def test_versions_size_must_be_exact(self):
        with self.assertRaises(ElfError): Module(fixture_elf(corrupt_versions=True)).versions()
    def test_truncated_elf_fails_closed(self):
        raw=fixture_elf()
        for length in (0,20,63,64,len(raw)-1):
            with self.assertRaises(ElfError): Module(raw[:length])
    def test_conflicting_baseline_records_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'baseline.json'
            p.write_text(json.dumps([{'sym':'x','crc':'0x1'},{'sym':'x','crc':'0x2'}]))
            with self.assertRaises(ElfError): merge_stock([],p)
    def test_crc_must_fit_real_32_bit_record(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'baseline.json'
            p.write_text(json.dumps([{'sym':'x','crc':'0x100000000'}]))
            with self.assertRaises(ElfError): merge_stock([],p)
    def test_parser_is_readonly(self):
        raw=fixture_elf(); before=hashlib.sha256(raw).hexdigest()
        Module(raw).describe()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),before)

class BtfTests(unittest.TestCase):
    def test_extract_actual_encoded_offsets(self):
        self.assertEqual(Btf(fixture_btf()).selected(),{'OP13T_PLATFORM_DEV_OFFSET':8,
          'OP13T_DEVICE_DRIVER_DATA_OFFSET':8,'OP13T_DEVICE_OF_NODE_OFFSET':16,'OP13T_MODULE_SIZE':512})
    def test_bitfields_cannot_satisfy_pointer_member(self):
        with self.assertRaises(BtfError): Btf(fixture_btf(True)).selected()
    def test_header_section_bounds_checked(self):
        raw=fixture_btf()
        for cut in (0,10,23,len(raw)-1):
            with self.assertRaises(BtfError): Btf(raw[:cut])
    def test_big_endian_rejected_for_this_target(self):
        raw=bytearray(fixture_btf()); raw[:2]=b'\xeb\x9f'
        with self.assertRaises(BtfError): Btf(bytes(raw))
    def test_generated_header_binds_input_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); b=p/'synthetic.btf'; c=p/'synthetic.config'; o=p/'out.h'
            b.write_bytes(fixture_btf()); c.write_text('CONFIG_TEST=y\n')
            result=generate(b,c,o)
            self.assertEqual(result['raw_btf_sha256'],hashlib.sha256(b.read_bytes()).hexdigest())
            self.assertIn(result['stock_config_file_sha256'],o.read_text())
    def test_kernel_config_disabled_entries(self):
        self.assertEqual(config_values(b'CONFIG_A=y\n# CONFIG_B is not set\n'),{'CONFIG_A':'y','CONFIG_B':'n'})

class BundleTests(unittest.TestCase):
    def test_only_allowlisted_files_and_exact_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); root=p/'inputs'; root.mkdir()
            (root/'kconfig.txt').write_text('CONFIG_TEST=y\n')
            (root/'token.txt').write_text('SECRET_NOT_TO_COPY')
            (root/'icnss2_badcrc.ko').write_bytes(b'experimental-not-stock')
            (root/'amss20.bin').write_bytes(b'firmware fixture')
            result=bundle(root,p/'input.zip')
            with zipfile.ZipFile(p/'input.zip') as z:
                self.assertEqual(set(z.namelist()),{'stock/kconfig.txt','stock/peach/amss20.bin','input-manifest.json'})
                for entry in result['entries']:
                    self.assertEqual(hashlib.sha256(z.read(entry['path'])).hexdigest(),entry['sha256'])
            self.assertFalse(result['device_operations'])
            self.assertIn('boot_a.img',result['missing'])
    def test_differing_duplicate_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); (p/'old').mkdir(); (p/'new').mkdir()
            (p/'old/kconfig.txt').write_text('A'); (p/'new/kconfig.txt').write_text('B')
            with self.assertRaises(ValueError): discover(p)
    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); root=p/'input'; root.mkdir(); (p/'secret').write_text('secret')
            (root/'kconfig.txt').symlink_to(p/'secret')
            self.assertEqual(discover(root),{})
    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); (p/'kconfig.txt').write_text('A'); out=p/'out.zip'; out.write_bytes(b'original')
            with self.assertRaises(ValueError): bundle(p,out)
            self.assertEqual(out.read_bytes(),b'original')
    def test_no_empty_success_archive(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); out=p/'out.zip'
            with self.assertRaises(ValueError): bundle(p,out)
            self.assertFalse(out.exists())

if __name__=='__main__': unittest.main(verbosity=2)
