"""Negative gates for strict qcacld metadata. Fixtures are not real modules."""
from pathlib import Path
import copy
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import prepare_qcacld_modpost as prep
import build_qcacld_kernel_crcs as fresh_core
from audit_qcacld_artifact import check_description, combine_tables, EXPECTED_NEW
from build_wlan_compile_smoke import TARGET_RELEASE, exit_status


def row(name, crc='0x12345678', provider='vmlinux'):
    return [crc, name, provider, 'EXPORT_SYMBOL', '']


class StrictExitTests(unittest.TestCase):
    def test_strict_provider_failure_is_nonzero_even_after_compile_success(self):
        r={'compile_gate_passed':True,'modpost_provider_gate_passed':False}
        self.assertEqual(exit_status(r,True),1)
        self.assertEqual(exit_status(r,False),0)

    def test_compile_failure_always_fails(self):
        self.assertEqual(exit_status({'compile_gate_passed':False,'modpost_provider_gate_passed':True},True),1)

    def test_both_strict_gates_required(self):
        self.assertEqual(exit_status({'compile_gate_passed':True,'modpost_provider_gate_passed':True},True),0)


class FinalElfMetadataTests(unittest.TestCase):
    def fixture(self, candidate=True):
        names={'_printk'} | (EXPECTED_NEW if candidate else set())
        providers={n:row(n,provider='wonder_shim_13t' if n=='cnss_set_vendor_wonder_priv_data' else 'vmlinux') for n in names}
        providers['module_layout']=row('module_layout','0x4e276f37')
        d={'machine':183,'type':1,'sha256':'0'*64,
           'modinfo':{'name':['qca_cld3_peach_v2'],
                      'vermagic':[TARGET_RELEASE+' SMP preempt mod_unload modversions aarch64'],
                      'depends':['wonder_shim_13t' if candidate else '']},
           'versions':{n:f[0] for n,f in providers.items()},
           'undefined_strong':sorted(names),'undefined_weak':[]}
        return d,providers

    def check(self,d,p,candidate=True,size=1536):
        return check_description(d,p,name='qca_cld3_peach_v2',candidate=candidate,module_size=size)

    def test_valid_metadata_is_explicitly_not_loadability(self):
        d,p=self.fixture();r=self.check(d,p)
        self.assertTrue(r['metadata_gate_passed'],r['errors'])
        self.assertFalse(r['loadable_proven'])
        self.assertFalse(r['shared_layouts_and_kcfi_compatibility_proven'])

    def test_unversioned_strong_import(self):
        d,p=self.fixture();del d['versions']['dev_open']
        self.assertIn('Unversioned strong import: dev_open',self.check(d,p)['errors'])

    def test_wrong_crc(self):
        d,p=self.fixture();d['versions']['dev_open']='0xffffffff'
        self.assertIn('CRC mismatch: dev_open',self.check(d,p)['errors'])

    def test_missing_provider(self):
        d,p=self.fixture();del p['dev_open']
        self.assertIn('No provider evidence: dev_open',self.check(d,p)['errors'])

    def test_shim_cannot_be_mislabelled_vmlinux(self):
        d,p=self.fixture();p['cnss_set_vendor_wonder_priv_data'][2]='vmlinux'
        self.assertIn('depends does not match import providers',self.check(d,p)['errors'])

    def test_missing_or_extra_depends(self):
        for depends in ('','wonder_shim_13t,nonexistent','wonder_shim_13t,wonder_shim_13t'):
            d,p=self.fixture();d['modinfo']['depends']=[depends]
            self.assertFalse(self.check(d,p)['metadata_gate_passed'])

    def test_wrong_vermagic_module_size_or_arch(self):
        for change in ('vermagic','size','arch'):
            d,p=self.fixture();size=1536
            if change=='vermagic':d['modinfo']['vermagic']=[TARGET_RELEASE+' wrong-flags']
            if change=='size':size=1535
            if change=='arch':d['machine']=62
            self.assertFalse(self.check(d,p,size=size)['metadata_gate_passed'])

    def test_baseline_cannot_import_wonder_only_symbols(self):
        d,p=self.fixture()
        self.assertIn('Unexpected candidate-only import surface',self.check(d,p,candidate=False)['errors'])

    def test_stale_nonimport_version(self):
        d,p=self.fixture();d['versions']['stale']='0x12345678';p['stale']=row('stale')
        self.assertIn('Version for non-import: stale',self.check(d,p)['errors'])


class ProviderAssemblyTests(unittest.TestCase):
    def test_read_symvers_rejects_malformed_and_duplicate_rows(self):
        bad=('0x100000000\tx\tvmlinux\tEXPORT_SYMBOL\t\n',
             '0x12345678\tx\t\tEXPORT_SYMBOL\t\n',
             '0x12345678\tx\tvmlinux\tEXPORT_NOT_REAL\t\n',
             '0x12345678\tx\tvmlinux\tEXPORT_SYMBOL\tnamespace\n',
             '0x12345678\tx\tvmlinux\tEXPORT_SYMBOL\t\n'*2)
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'rows.symvers'
            for text in bad:
                p.write_text(text,encoding='ascii')
                with self.assertRaises(ValueError):prep.read_symvers(p)

    def test_kernel_conflicts_include_provider_and_export_class(self):
        for index,value in ((0,'0xffffffff'),(2,'wrong_provider'),(3,'EXPORT_SYMBOL_GPL')):
            expected=row('x');old=expected.copy();old[index]=value
            with self.assertRaises(ValueError):prep.missing_against([expected],{'x':old})

    def test_cross_table_conflict_is_not_last_writer_wins(self):
        with tempfile.TemporaryDirectory() as td:
            a=Path(td)/'a';b=Path(td)/'b'
            prep.write(a,[row('x')]);prep.write(b,[row('x',provider='wrong')])
            with self.assertRaises(ValueError):combine_tables([a,b])

    def test_provider_prepare_rejects_bad_fresh_or_shim_evidence(self):
        cases=('success','fresh_false','fresh_missing','fresh_conflict','shim_wrong_crc','shim_wrong_provider','shim_extra_export')
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as td:
                root=Path(td);kout=root/'kernel-out';kout.mkdir();out=root/'out'
                base=[row('module_layout','0x4e276f37')]
                prep.write(kout/'Module.symvers',base)
                core=[row('dev_open','0x2db1f9fe'),row('dev_close','0x3d8d1736'),row('get_random_u32','0xd36dc10c')]
                if case=='fresh_conflict':prep.write(kout/'Module.symvers',base+[row('dev_open','0xffffffff')])
                def fresh(*args):
                    checked=core[:-1] if case=='fresh_missing' else core
                    prep.write(out/'qcacld-kernel-checked.symvers',checked)
                    path=out/'qcacld-kernel-additional.symvers';prep.write(path,checked)
                    return path,{'fresh_kernel_crc_gate_passed':case!='fresh_false','matched':{f[1]:f[0] for f in core}}
                exp={'name':'cnss_set_vendor_wonder_priv_data','crc':'0xd7585ffc','provider':'wonder_shim_13t',
                     'export_type':'EXPORT_SYMBOL','namespace':'','provider_sha256':'a'*64}
                if case=='shim_wrong_crc':exp['crc']='0xffffffff'
                if case=='shim_wrong_provider':exp['provider']='vmlinux'
                exports=[exp,copy.deepcopy(exp)] if case=='shim_extra_export' else [exp]
                with patch.object(prep,'load_profile',return_value=({},b'',base)),patch.object(prep,'prepare_kernel',side_effect=fresh),patch.object(prep,'module_exports',return_value=exports):
                    if case=='success':
                        r=prep.prepare(root,kout,root,root/'shim.ko',out)
                        self.assertEqual(r['candidate_extra_provider_rows'],4)
                    else:
                        with self.assertRaises(ValueError):prep.prepare(root,kout,root,root/'shim.ko',out)


class FreshCoreCrcTests(unittest.TestCase):
    def fixture(self, root, case):
        kout=root/'kernel';out=root/'out';out.mkdir();kout.mkdir()
        expected={'dev_close':0x3d8d1736,'dev_open':0x2db1f9fe,'get_random_u32':0xd36dc10c}
        rows=[row(n,f'0x{v:08x}') for n,v in expected.items()]
        prep.write(kout/'Module.symvers',[row('dev_open','0xffffffff')] if case=='existing_conflict' else [])
        for obj in fresh_core.OBJECTS:
            f=Path(obj);cmd=kout/f.parent/('.'+f.name+'.cmd');cmd.parent.mkdir(parents=True,exist_ok=True)
            values=({'get_random_u32':expected['get_random_u32']} if 'random' in obj else
                    {'dev_close':expected['dev_close'],'dev_open':expected['dev_open']})
            if case=='missing' and 'random' in obj:values={}
            if case=='mismatch' and 'random' in obj:values['get_random_u32']=1
            if case=='cross_object_conflict' and 'random' in obj:values['dev_open']=1
            cmd.write_text(''.join(f'#SYMVER {n} 0x{v:08x}\n' for n,v in values.items()),encoding='ascii')
        return kout,out,expected,rows

    def test_fresh_object_gate_accepts_exact_regeneration_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);kout,out,expected,rows=self.fixture(root,'success')
            with patch.object(fresh_core,'load_profile',return_value=({'exports_sha256':'a'*64},expected,rows)),patch.object(fresh_core,'run') as run:
                _,r=fresh_core.prepare(root,kout,['make'],out)
                self.assertTrue(r['fresh_kernel_crc_gate_passed']);self.assertFalse(r['loadable_proven'])
                run.assert_called_once_with(['make',*fresh_core.OBJECTS],out/'qcacld-kernel-crc-build.log')

    def test_missing_mismatch_conflicting_objects_or_existing_export_fail(self):
        for case in ('missing','mismatch','cross_object_conflict','existing_conflict'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as td:
                root=Path(td);kout,out,expected,rows=self.fixture(root,case)
                with patch.object(fresh_core,'load_profile',return_value=({'exports_sha256':'a'*64},expected,rows)),patch.object(fresh_core,'run'),self.assertRaises(ValueError):
                    fresh_core.prepare(root,kout,['make'],out)


if __name__=='__main__':unittest.main()
