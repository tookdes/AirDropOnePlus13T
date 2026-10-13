"""Compile actual shim bodies with mocks; no target kernel or device operations."""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class ShimLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('cc'):
            raise unittest.SkipTest('Host C compiler unavailable')
        cls.tmp=tempfile.TemporaryDirectory()
        directory=Path(cls.tmp.name)
        src=(ROOT/'shim/wonder_shim_13t.c').read_text()
        stripped=re.sub(r'^#include .*\n','',src,flags=re.M)
        unit=((ROOT/'tests/fixtures/shim_host_prefix.h').read_text()+ '\n'+stripped+'\n'+
              (ROOT/'tests/fixtures/shim_host_main.c').read_text())
        file=directory/'shim_mock.c'; file.write_text(unit)
        cls.exe=directory/'shim_mock'
        cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
             '-fsanitize=undefined','-fno-sanitize-recover=all',str(file),'-o',str(cls.exe)]
        subprocess.run(cmd,check=True,capture_output=True,text=True)
        cls.results=[]
        cls.sha=hashlib.sha256(src.encode()).hexdigest()
    @classmethod
    def tearDownClass(cls):
        (ROOT/'evidence/shim-host-regression.json').write_text(json.dumps({
            'source_sha256':cls.sha,'compiler':'host cc with UBSan',
            'scope':'Actual shim bodies; mocked, sequential kernel services; no target ABI, concurrency, or radio proof',
            'results':cls.results},indent=2)+'\n')
        cls.tmp.cleanup()
    def run_case(self,*args):
        result=subprocess.run([str(self.exe),*map(str,args)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        self.results.append({'case':list(args),'stdout':result.stdout.strip(),'exit':result.returncode})
    def test_readonly_default_has_no_side_effects(self): self.run_case('readonly')
    def test_missing_nodes_release_other_reference(self):
        for i in (0,1):
            with self.subTest(node=i): self.run_case('missing',i)
    def test_bound_nodes_are_rejected_without_leaks(self):
        for i in (0,1):
            with self.subTest(node=i): self.run_case('occupied',i)
    def test_zero_phandle_rejected(self): self.run_case('zero_phandle')
    def test_foreign_property_is_not_modified(self): self.run_case('existing_property')
    def test_each_allocation_failure_cleans_owned_resources(self):
        for i in range(1,6):
            with self.subTest(allocation=i): self.run_case('alloc_fail',i)
    def test_each_device_registration_failure_cleans_up(self):
        for i in (1,2):
            with self.subTest(device=i): self.run_case('device_fail',i)
    def test_failed_property_add_is_unpublished_and_freed(self): self.run_case('property_fail')
    def test_component_failure_is_returned_and_callbacks_cleared(self): self.run_case('component_fail')
    def test_failed_module_pin_is_not_reported_success(self): self.run_case('pin_fail')
    def test_registration_idempotence_and_full_teardown(self): self.run_case('lifecycle')
    def test_software_ops_registers_stub_without_radio(self): self.run_case('software_ops')

if __name__=='__main__': unittest.main(verbosity=2)
