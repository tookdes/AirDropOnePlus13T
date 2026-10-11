"""Host-only tests. Fixtures do not prove stock-kernel compatibility."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import audit_inventory as inv
import check_crc as crc


def command(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], stderr=subprocess.STDOUT).decode().strip()


def make_repo(path, files):
    path.mkdir()
    command(path, 'init', '-q')
    command(path, 'config', 'user.name', 'Fixture')
    command(path, 'config', 'user.email', 'fixture@example.invalid')
    for name, value in files.items():
        p = path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)
    command(path, 'add', '.')
    command(path, 'commit', '-qm', 'test fixture')
    return command(path, 'rev-parse', 'HEAD')


class LexicalTests(unittest.TestCase):
    def test_macro_alias_and_nested_conditions(self):
        text = '#if OUTER\n#ifdef DRIVER_PASSTHRU_MODE\n#ifdef CONFIG_WONDER_SUPPORT\nint x;\n#endif\n#else\nint y;\n#endif\n#endif\n'
        ranges, errors = inv.conditional_ranges(text)
        self.assertFalse(errors)
        self.assertEqual([(r['start'], r['end']) for r in ranges], [(2, 8), (3, 5)])
        self.assertEqual(ranges[1]['ancestors'], [1, 2])
        self.assertEqual(ranges[0]['branches'], [6])

    def test_elif_and_continuation(self):
        text = '#if BASE\n#elif defined(CONFIG_WONDER_SUPPORT) || \\\n defined(DRIVER_PASSTHRU_MODE)\nint x;\n#endif\n'
        ranges, errors = inv.conditional_ranges(text)
        self.assertFalse(errors)
        self.assertEqual((ranges[0]['start'], ranges[0]['end']), (1, 5))
        self.assertEqual(ranges[0]['branches'], [2])

    def test_unbalanced_rejected_as_warning(self):
        self.assertEqual(len(inv.conditional_ranges('#endif\n#ifdef DRIVER_PASSTHRU_MODE\n')[1]), 2)

    def test_call_candidates_ignore_comments_and_strings(self):
        text = 'real(v); /* fake(x) */ const char *s="other(y)"; // nope(z)\nif (x) live();'
        names = set(inv.CALL.findall(inv.strip_c_comments_and_strings(text))) - inv.KEYWORDS
        self.assertEqual(names, {'real', 'live'})

    def test_diff_counts(self):
        self.assertEqual(inv.diff_counts('a\nb\n', 'a\nc\nd\n'), {'added': 2, 'deleted': 1, 'churn': 3})

    def test_git_objects_cover_sparse_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            target, donor = base / 't', base / 'd'
            common = 'vendor/qcom/opensource/wlan/'
            ts = make_repo(target, {common + 'same.c': '/* wonder */\n', common + 'changed.c': 'int old;\n', 'README': 'target'})
            ds = make_repo(donor, {common + 'same.c': '/* wonder */\n', common + 'changed.c': '#ifdef DRIVER_PASSTHRU_MODE\nint new;\n#endif\n', common + 'new.c': '/* passthrough */\n', inv.SEED: 'int seed(void) { return helper(); }\n'})
            command(donor, 'sparse-checkout', 'init', '--no-cone')
            command(donor, 'sparse-checkout', 'set', '/README')
            self.assertFalse((donor / (common + 'new.c')).exists())
            result = inv.scan(target, donor, base / 'result', {'op13t': {'commit': ts}, 'op15': {'commit': ds}})
            self.assertEqual(result['file_count'], 3)
            self.assertFalse(result['full_semantic_closure'])
            records = {x['path']: x for x in json.loads((base / 'result/files.json').read_text())}
            self.assertEqual(records[common + 'same.c']['file_status'], 'A-file-byte-identical')
            self.assertEqual(records[common + 'changed.c']['file_status'], 'B-file-different-API-review-required')
            self.assertEqual(records[common + 'new.c']['file_status'], 'C-file-absent-in-target')
            with self.assertRaises(RuntimeError):
                inv.scan(target, donor, base / 'wrong', {'op13t': {'commit': '0' * 40}, 'op15': {'commit': ds}})
            self.assertFalse((base / 'wrong').exists())


class CrcTests(unittest.TestCase):
    def test_match_and_missing_and_mismatch(self):
        self.assertTrue(crc.compare({'a': 1}, {'a': 1})['passed'])
        self.assertFalse(crc.compare({'a': 1}, {})['passed'])
        self.assertEqual(crc.compare({'a': 1}, {'a': 2})['mismatch'][0]['actual'], '0x00000002')

    def test_baseline_validation(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'baseline.json'
            p.write_text('[{"sym":"a","crc":"0x1"},{"sym":"a","crc":"0x1"}]')
            with self.assertRaises(ValueError):
                crc.load_expected(p)
            p.write_text('[]')
            with self.assertRaises(ValueError):
                crc.load_expected(p)

    def test_symvers_conflicting_duplicates(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'symvers'
            p.write_text('0x00000001 a vmlinux EXPORT_SYMBOL\n0x00000002 a vmlinux EXPORT_SYMBOL\n')
            with self.assertRaises(ValueError):
                crc.load_symvers([p])
            p.write_text('0x00000001 a vmlinux EXPORT_SYMBOL\n')
            self.assertEqual(crc.load_symvers([p, p]), {'a': 1})

    def test_stock_evidence_readonly(self):
        p = ROOT / 'evidence/stock_icnss2_versions.json'
        before = p.read_bytes()
        baseline = crc.load_expected(p)
        self.assertEqual(len(baseline), 313)
        self.assertEqual(baseline['of_find_node_opts_by_path'], 0x7c497915)
        self.assertEqual(baseline['module_layout'], 0x4e276f37)
        self.assertEqual(p.read_bytes(), before)


class SourceTests(unittest.TestCase):
    def test_five_exact_donor_blobs(self):
        report = json.loads((ROOT / 'evidence/patch-validation.json').read_text())
        for item in report['source_files']:
            data = (ROOT / 'upstream/op15-excerpts' / item['path']).read_bytes()
            self.assertEqual(inv.blob_hash(data), item['git_blob'], item['path'])
            self.assertEqual(len(data.splitlines()), item['lines'])

    def test_header_contract_identity(self):
        target = ROOT / 'upstream/op13t-excerpts/vendor/oplus/kernel/wifi/wonder/include/wonder/wondertap.h'
        donor = ROOT / 'upstream/op15-excerpts/vendor/qcom/opensource/wlan/qca-wifi-host-cmn/qdf/linux/src/wondertap.h'
        self.assertEqual(target.read_bytes(), donor.read_bytes())

    def test_no_build_activation_in_series(self):
        touched = set()
        for name in (ROOT / 'patches/series').read_text().splitlines():
            text = (ROOT / 'patches' / name).read_text()
            for line in text.splitlines():
                if line.startswith('diff --git a/'):
                    touched.add(line.split(' b/', 1)[1])
        self.assertEqual(len(touched), 6)
        self.assertFalse(any('defconfig' in p or p.endswith('Kbuild') for p in touched))


if __name__ == '__main__':
    unittest.main(verbosity=2)
