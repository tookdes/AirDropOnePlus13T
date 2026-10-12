import json, sys, tempfile, unittest, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from package_stage_a_ksu import package, REQUIRED_KO

class PackageStageA(unittest.TestCase):
    def _result(self, ok=True):
        mods={n:{'errors':[] if ok else ['fail'],'captured_crc_check_passed':ok}
              for n in REQUIRED_KO}
        return {'build_and_offline_abi_gates_passed':ok,'airdrop_available':False,
                'modules':mods}

    def _tree(self, d:Path, ok=True):
        verified=d/'verified'; verified.mkdir(parents=True)
        for n in REQUIRED_KO:
            (verified/n).write_bytes(b'ko-'+n.encode())
        (verified/'SHA256SUMS').write_text(
            ''.join(__import__('hashlib').sha256((verified/n).read_bytes()).hexdigest()+'  '+n+'\n'
                    for n in REQUIRED_KO))
        result=d/'stage-a-result.json'
        result.write_text(json.dumps(self._result(ok))+'\n')
        return verified, result

    def test_package_contains_probes_not_wlan(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); verified, result=self._tree(d)
            z=d/'probe.zip'
            m=package(verified, result, z)
            self.assertFalse(m['airdrop_available'])
            self.assertTrue(m['diagnostics_only_default'])
            names=set(zipfile.ZipFile(z).namelist())
            self.assertTrue({'hello_13t.ko','wonder_shim_13t.ko','module.prop',
                             'customize.sh','META-INF/com/google/android/update-binary'} <= names)
            self.assertNotIn('qca_cld3_peach_v2.ko', names)
            self.assertNotIn('wonder.ko', names)

    def test_refuse_failed_gates_and_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); verified, result=self._tree(d, ok=False)
            with self.assertRaisesRegex(ValueError,'ABI gates'):
                package(verified, result, d/'a.zip')
            verified, result=self._tree(d/'ok')
            out=d/'ok.zip'; package(verified, result, out)
            with self.assertRaisesRegex(ValueError,'overwrite'):
                package(verified, result, out)

if __name__=='__main__': unittest.main()
