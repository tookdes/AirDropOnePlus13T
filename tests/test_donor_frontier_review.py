"""Pinned hunk decisions and nested-workspace application must fail closed."""
from pathlib import Path
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from review_donor_frontier import canonical, copyright_only, hunks, minimize, sha
from candidate_donor_slice import patch_environment, FRONTIER_PROFILE_SHA256, EXPECTED_PATHS_SHA256
ROOT=Path(__file__).resolve().parents[1]
PATH='vendor/file.c'
PATCH=b'diff --git a/vendor/file.c b/vendor/file.c\nindex 1111111..2222222 100644\n--- a/vendor/file.c\n+++ b/vendor/file.c\n@@ -1,3 +1,3 @@\n-Copyright (c) old\n+Copyright (c) new\n \n /* fixed */\n@@ -10,3 +10,3 @@\n /* code */\n-int old;\n+int passthru;\n /* end */\n'


def fixture():
    _,blocks=hunks(PATCH)
    e={'path':PATH,'canonical_diff_sha256':sha(canonical(PATCH)),
       'hunk_sha256':[sha(canonical(h)) for h in blocks],'action':'keep',
       'drop_copyright_hunks':[sha(canonical(blocks[0]))],'rationale':'fixture'}
    return {'schema':1,'release_ready':False,'expected_retained_path_count':1,'paths':[e]}


class FrontierTests(unittest.TestCase):
    def test_exact_pruning_only_removes_copyright_hunk(self):
        rows,r=minimize([(PATH,PATCH)],fixture())
        self.assertNotIn(b'Copyright',rows[0][1]);self.assertIn(b'+int passthru;',rows[0][1])
        self.assertEqual(r['input_hunks'],2);self.assertEqual(r['retained_hunks'],1)
        self.assertFalse(r['production_review_complete']);self.assertFalse(r['release_ready'])

    def test_index_abbreviation_is_not_hunk_drift(self):
        changed=PATCH.replace(b'1111111..2222222',b'111111111..222222222')
        self.assertEqual(minimize([(PATH,PATCH)],fixture()),minimize([(PATH,changed)],fixture()))

    def test_cosmetic_hunk_function_label_is_not_source_drift(self):
        labeled=PATCH.replace(b'@@ -10,3 +10,3 @@\n',b'@@ -10,3 +10,3 @@ function_name(void)\n')
        a,_=minimize([(PATH,PATCH)],fixture());b,_=minimize([(PATH,labeled)],fixture())
        self.assertEqual(canonical(a[0][1]),canonical(b[0][1]))

    def test_functional_hunk_cannot_be_pruned_as_copyright(self):
        p=fixture();p['paths'][0]['drop_copyright_hunks']=[p['paths'][0]['hunk_sha256'][1]]
        with self.assertRaises(ValueError):minimize([(PATH,PATCH)],p)

    def test_changed_hunk_or_context_rejected(self):
        for changed in (PATCH.replace(b'int passthru',b'int broken'),PATCH.replace(b'@@ -10,3 +10,3 @@',b'@@ -11,3 +11,3 @@')):
            with self.assertRaises(ValueError):minimize([(PATH,changed)],fixture())

    def test_unknown_duplicate_or_reordered_paths_rejected(self):
        with self.assertRaises(ValueError):minimize([(PATH,PATCH),(PATH,PATCH)],fixture())
        with self.assertRaises(ValueError):minimize([('vendor/wrong.c',PATCH)],fixture())

    def test_drop_requires_explicit_decision_and_correct_count(self):
        p=fixture();p['paths'][0]['action']='drop';p['expected_retained_path_count']=0
        rows,r=minimize([(PATH,PATCH)],p);self.assertEqual(rows,[]);self.assertEqual(r['retained_hunks'],0)
        p['paths'][0]['rationale']=''
        with self.assertRaises(ValueError):minimize([(PATH,PATCH)],p)

    def test_profile_hash_and_frontier_decisions_are_pinned(self):
        raw=(ROOT/'profiles/qcacld-minimized-frontier.json').read_bytes()
        self.assertEqual(sha(raw),FRONTIER_PROFILE_SHA256)
        p=json.loads(raw);self.assertEqual(len(p['paths']),44)
        self.assertEqual(p['original_path_set_sha256'],EXPECTED_PATHS_SHA256)
        self.assertEqual(sum(e['action']=='keep' for e in p['paths']),40)
        self.assertFalse(p['production_review_complete'])
        for e in p['paths']:self.assertTrue(e['rationale']);self.assertTrue(e['hunk_sha256'])

    def test_nested_output_applies_locally_instead_of_silently_skipping(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);subprocess.run(['git','init','-q',str(root)],check=True)
            out=root/'nested'/'candidate';(out/'vendor').mkdir(parents=True)
            p=out/'vendor/file.c';p.write_bytes(b'Copyright (c) old\n\n/* fixed */\n'+b'padding\n'*6+b'/* code */\nint old;\n/* end */\n')
            subprocess.run(['git','apply','-'],cwd=out,env=patch_environment(out),input=PATCH,check=True,capture_output=True)
            self.assertIn(b'int passthru;',p.read_bytes())
            self.assertFalse((root/'vendor/file.c').exists())


if __name__=='__main__':unittest.main()
