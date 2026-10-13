import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from elf_audit import Module
from test_artifact_tools import fixture_elf
import build_wonder_kernel_crcs as crcs


class WonderKernelCrcs(unittest.TestCase):
    def test_profile_covers_54_actual_core_exports(self):
        metadata,expected,rows=crcs.load_profile(ROOT/'profiles/stock-wonder-kernel.json',
                                               ROOT/'profiles/stock-wonder-kernel.exports.symvers')
        self.assertEqual(len(expected),54)
        self.assertIn('module_layout',expected)
        self.assertIn('__dev_queue_xmit',expected)
        self.assertIn('netdev_rx_handler_register',expected)
        self.assertTrue(all(r[2]=='vmlinux' for r in rows))

    def test_modified_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'bad.symvers'
            path.write_bytes((ROOT/'profiles/stock-wonder-kernel.exports.symvers').read_bytes()+b'x')
            with self.assertRaises(ValueError):
                crcs.load_profile(ROOT/'profiles/stock-wonder-kernel.json',path)

    def test_fresh_crc_requires_every_expected_symbol_and_matching_value(self):
        for fresh,good in (({'a':1,'b':2},True),({'a':1},False),({'a':1,'b':3},False)):
            with self.subTest(fresh=fresh):
                r=crcs.compare_fresh(fresh,{'a':1,'b':2})
                self.assertEqual(r['fresh_kernel_crc_gate_passed'],good)

    def test_every_strong_import_requires_a_version(self):
        good=crcs.version_coverage(Module(fixture_elf()))
        self.assertTrue(good['all_strong_imports_versioned'])
        bad=crcs.version_coverage(Module(fixture_elf(versions={'module_layout':1})))
        self.assertFalse(bad['all_strong_imports_versioned'])
        self.assertEqual(bad['missing_versions'],['_printk'])

    def test_prepare_writes_only_checked_fresh_values(self):
        _metadata,expected,_rows=crcs.load_profile(ROOT/'profiles/stock-wonder-kernel.json',
                                               ROOT/'profiles/stock-wonder-kernel.exports.symvers')
        with tempfile.TemporaryDirectory() as td:
            out=Path(td); kout=out/'kernel'; kout.mkdir()
            (kout/'Module.symvers').write_text('0x4e276f37\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\t\n',encoding='utf-8')
            def fake_run(args,log):
                for i,obj in enumerate(crcs.KERNEL_OBJECTS):
                    p=Path(obj); cmd=kout/p.parent/('.'+p.name+'.cmd')
                    cmd.parent.mkdir(parents=True,exist_ok=True)
                    cmd.write_text(''.join(f'#SYMVER {name} 0x{crc:08x}\n' for name,crc in expected.items()) if i==0 else '',encoding='utf-8')
            with patch.object(crcs,'run',side_effect=fake_run):
                path,report=crcs.prepare(out/'source',kout,['make'],out)
            self.assertTrue(report['fresh_kernel_crc_gate_passed'])
            self.assertEqual(path.read_bytes(),(ROOT/'profiles/stock-wonder-kernel.exports.symvers').read_bytes())
            self.assertFalse(report['loadable_proven'])
            self.assertEqual(report['additional_exports_for_modpost'],53)
            self.assertNotIn('module_layout',(out/'wonder-kernel-additional.symvers').read_text(encoding='utf-8'))

    def test_duplicate_core_exports_are_omitted_not_shadowed(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'Module.symvers'
            row=['0x00000001','sym','vmlinux','EXPORT_SYMBOL','']
            p.write_text('\t'.join(row)+'\n',encoding='utf-8')
            self.assertEqual(crcs.additional_rows([row],p),[])
            bad=['0x00000002','sym','vmlinux','EXPORT_SYMBOL','']
            with self.assertRaises(ValueError):crcs.additional_rows([bad],p)

    def test_missing_fresh_crc_never_emits_modpost_symvers(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td); kout=out/'kernel'; kout.mkdir()
            (kout/'Module.symvers').write_text('0x4e276f37\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\t\n',encoding='utf-8')
            def fake_run(args,log):
                for obj in crcs.KERNEL_OBJECTS:
                    p=Path(obj); cmd=kout/p.parent/('.'+p.name+'.cmd')
                    cmd.parent.mkdir(parents=True,exist_ok=True)
                    cmd.write_text('',encoding='utf-8')
            with patch.object(crcs,'run',side_effect=fake_run),self.assertRaises(ValueError):
                crcs.prepare(out/'source',kout,['make'],out)
            self.assertFalse((out/'wonder-kernel-checked.symvers').exists())
            report=json.loads((out/'kernel-crc.json').read_text(encoding='utf-8'))
            self.assertFalse(report['fresh_kernel_crc_gate_passed'])
            self.assertEqual(len(report['missing']),54)


if __name__=='__main__':
    unittest.main()
