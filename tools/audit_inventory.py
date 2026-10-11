#!/usr/bin/env python3
"""Pinned whole-tree lexical inventory, NOT semantic dependency-closure proof.

Reads Git objects (including files outside sparse checkouts). Produces every
text match for passthru/passthrough/wonder, same-path diffs, preprocessor ranges,
and exact diff counts. It does NOT select or apply driver patches and does NOT
call any phone tool. Full-file diff counts are NOT feature-only patch estimates.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEATURE = re.compile(r'passthru|passthrough|wonder', re.I)
CPP = re.compile(r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)')
CALL = re.compile(r'\b([A-Za-z_][A-Za-z_0-9]*)\s*\(')
KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'typeof',
            '__typeof__', '_Static_assert', 'static_assert', 'defined'}
SEED = 'vendor/qcom/opensource/wlan/qcacld-3.0/core/hdd/src/wlan_hdd_wondertap.c'

def git(repo: Path, *args: str, ok_codes: tuple[int, ...] = (0,)) -> bytes:
    cp = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    if cp.returncode not in ok_codes:
        raise RuntimeError(cp.stderr.decode(errors='replace').strip() or str(args))
    return cp.stdout

def blob_hash(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def tree(repo: Path, revision: str) -> tuple[dict[str, str], list[str]]:
    blobs, submodules = {}, []
    for entry in git(repo, 'ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
        if not entry:
            continue
        meta, raw_path = entry.split(b'\t', 1)
        _mode, kind, sha = meta.decode().split()
        path = raw_path.decode('utf-8')
        if kind == 'blob':
            blobs[path] = sha
        elif kind == 'commit':
            submodules.append(path)
    return blobs, submodules

def read_blob(repo: Path, sha: str) -> bytes:
    raw = git(repo, 'cat-file', 'blob', sha)
    if blob_hash(raw) != sha:
        raise RuntimeError('Object digest mismatch: ' + sha)
    return raw

def matched_paths(repo: Path, revision: str) -> set[str]:
    data = git(repo, 'grep', '-I', '-l', '-z', '-i', '-E',
               '-e', 'passthru|passthrough|wonder', revision, '--',
               ok_codes=(0, 1))
    prefix = (revision + ':').encode()
    paths = set()
    for item in data.split(b'\0'):
        if not item:
            continue
        if not item.startswith(prefix):
            raise RuntimeError('Unexpected git grep filename: ' + repr(item))
        paths.add(item[len(prefix):].decode('utf-8'))
    return paths

def conditional_ranges(text: str) -> tuple[list[dict], list[str]]:
    """Record balanced CPP ranges and branches without evaluating macros.

    Supports line-continuation conditions; ranges are lexical, not a C AST.
    Comments and macro expansion may still require manual review.
    """
    stack, ranges, errors = [], [], []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i + 1
        logical = lines[i]
        while logical.rstrip().endswith('\\') and i + 1 < len(lines):
            logical = logical.rstrip()[:-1] + ' ' + lines[i + 1].lstrip()
            i += 1
        match = CPP.match(logical)
        if match:
            kind, expression = match.groups()
            if kind in ('if', 'ifdef', 'ifndef'):
                stack.append({'start': start, 'conditions': [logical.strip()],
                              'ancestors': [s['start'] for s in stack],
                              'branches': []})
            elif kind in ('elif', 'else'):
                if not stack:
                    errors.append(f'Orphan #{kind} at {start}')
                else:
                    stack[-1]['conditions'].append(logical.strip())
                    stack[-1]['branches'].append(start)
            else:
                if not stack:
                    errors.append(f'Orphan #endif at {start}')
                else:
                    item = stack.pop()
                    item['end'] = i + 1
                    item['feature_condition'] = any(FEATURE.search(x) for x in item['conditions'])
                    if item['feature_condition']:
                        ranges.append(item)
        i += 1
    errors += [f'Unclosed #if at {s["start"]}' for s in stack]
    return sorted(ranges, key=lambda r: r['start']), errors

def strip_c_comments_and_strings(text: str) -> str:
    # This is deliberately a lexical work-list extractor, not a C parser.
    rx = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    return rx.sub(lambda m: '\n' * m.group().count('\n') + ' ', text)

def diff_counts(before: str, after: str) -> dict[str, int]:
    added = deleted = 0
    for kind, i, j, a, b in difflib.SequenceMatcher(
            None, before.splitlines(), after.splitlines(), autojunk=False).get_opcodes():
        if kind in ('replace', 'delete'):
            deleted += j - i
        if kind in ('replace', 'insert'):
            added += b - a
    return {'added': added, 'deleted': deleted, 'churn': added + deleted}

def scan(target: Path, donor: Path, out: Path, locks: dict) -> dict:
    repos = {'op13t': target, 'op15': donor}
    trees, submodules, matched = {}, {}, {}
    for name, repo in repos.items():
        expected = locks[name]['commit']
        got = git(repo, 'rev-parse', 'HEAD').decode().strip()
        if got != expected:
            raise RuntimeError(f'{name}: expected {expected}, found {got}')
        trees[name], submodules[name] = tree(repo, expected)
        matched[name] = matched_paths(repo, expected)
    out.mkdir(parents=True, exist_ok=False)
    (out / 'diffs').mkdir()
    records, hits, conditions, warnings = [], [], [], []
    for path in sorted(matched['op13t'] | matched['op15']):
        texts, shas = {}, {}
        for name, repo in repos.items():
            sha = trees[name].get(path)
            shas[name] = sha
            if not sha:
                texts[name] = ''
                continue
            data = read_blob(repo, sha)
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                warnings.append({'path': path, 'repo': name, 'reason': 'Non-UTF8: manual review required'})
                text = data.decode('utf-8', errors='replace')
            texts[name] = text
            for lineno, line in enumerate(text.splitlines(), 1):
                if FEATURE.search(line):
                    hits.append({'repo': name, 'path': path, 'line': lineno, 'text': line})
            ranges, errors = conditional_ranges(text)
            conditions += [{'repo': name, 'path': path, **r} for r in ranges]
            warnings += [{'repo': name, 'path': path, 'reason': e} for e in errors]
        if shas['op13t'] is None:
            status = 'C-file-absent-in-target'
        elif shas['op15'] is None:
            status = 'target-only'
        elif shas['op13t'] == shas['op15']:
            status = 'A-file-byte-identical'
        else:
            status = 'B-file-different-API-review-required'
        counts = diff_counts(texts['op13t'], texts['op15'])
        diffname = hashlib.sha256(path.encode()).hexdigest()[:20] + '.diff'
        diff = ''.join(difflib.unified_diff(texts['op13t'].splitlines(True),
                                         texts['op15'].splitlines(True),
                                         fromfile='op13t/' + path,
                                         tofile='op15/' + path))
        if diff:
            (out / 'diffs' / diffname).write_text(diff)
        records.append({'path': path, 'file_status': status, 'blob_sha': shas,
                        'whole_file_diff': counts, 'diff': 'diffs/' + diffname if diff else None,
                        'semantic_classification': 'not-assessed'})
    calls = []
    if SEED in trees['op15']:
        src = read_blob(donor, trees['op15'][SEED]).decode()
        names = sorted(set(CALL.findall(strip_c_comments_and_strings(src))) - KEYWORDS)
        for name in names:
            # Presence is not proof of compatible definition or a callable API.
            raw = git(target, 'grep', '-I', '-l', '-z', '-w', '-F', '-e', name,
                      locks['op13t']['commit'], '--', 'vendor/qcom/opensource/wlan',
                      ok_codes=(0, 1))
            calls.append({'name': name, 'target_text_presence': bool(raw),
                          'requires_definition_and_signature_review': True})
    summary = {'status': 'LEXICAL_INVENTORY_ONLY', 'pins': locks,
               'file_count': len(records), 'hit_count': len(hits),
               'conditional_count': len(conditions), 'submodules_not_scanned': submodules,
               'full_semantic_closure': False, 'kernel_build_passed': False,
               'deployable': False, 'whole_file_diff_is_NOT_feature_patch_size': True,
               'warnings': warnings}
    for name, obj in [('summary', summary), ('files', records), ('hits', hits),
                      ('conditionals', conditions), ('call_review_queue', calls)]:
        (out / (name + '.json')).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')
    table = ['# Whole-tree lexical inventory', '',
             'Not semantic closure. B is a whole-file difference, not a proven API mismatch.',
             'Full-file churn includes unrelated upstream changes; do not use it as the backport estimate.', '',
             '| File | File status | Whole-file + / - |', '|---|---|---|']
    table += [f'| `{r["path"]}` | {r["file_status"]} | +{r["whole_file_diff"]["added"]} / -{r["whole_file_diff"]["deleted"]} |' for r in records]
    (out / 'file_inventory.md').write_text('\n'.join(table) + '\n')
    return summary

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--donor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    locks = json.loads((ROOT / 'upstream.lock.json').read_text())
    print(json.dumps(scan(args.target, args.donor, args.output, locks), indent=2))

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
