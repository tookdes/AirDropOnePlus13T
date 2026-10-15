#!/usr/bin/env python3
"""Deterministic donor-hunk inventory/minimization, never a release approval.

Only an exact reviewed path/hunk profile may transform the disposable candidate.
The broad 44-path compile frontier remains separately reproducible.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(diff: bytes) -> bytes:
    # Git abbreviates object IDs differently in shallow/complete repositories.
    # Hunk contents, paths, modes and context remain byte-pinned.
    result=[]
    for line in diff.splitlines(keepends=True):
        if line.startswith(b'index '):continue
        if line.startswith(b'@@ '):
            # GitHub's C parser and local Git label the same hunk differently.
            # Labels are presentation only. Preserve ranges and ALL code/context.
            match=re.fullmatch(br'(@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@)[^\n]*\n',line)
            if not match:raise ValueError('Malformed unified hunk header')
            line=match[1]+b'\n'
        result.append(line)
    return b''.join(result)


def hunks(diff: bytes) -> tuple[bytes, list[bytes]]:
    chunks = re.split(br'(?=^@@ )', diff, flags=re.M)
    if len(chunks) < 2 or not chunks[0].startswith(b'diff --git '):
        raise ValueError('Expected one text diff with hunks')
    if chunks[0].count(b'diff --git ') != 1 or any(b'\ndiff --git ' in c for c in chunks[1:]):
        raise ValueError('Expected a single-file diff')
    return chunks[0], chunks[1:]


def copyright_only(hunk: bytes) -> bool:
    changed = [line[1:] for line in hunk.splitlines() if line[:1] in (b'+', b'-')]
    return bool(changed) and all(b'Copyright (c)' in line for line in changed)


def select_patch(path: str, diff: bytes, entry: dict) -> bytes:
    if entry['path'] != path or sha(canonical(diff)) != entry['canonical_diff_sha256']:
        raise ValueError('Pinned donor diff drift: '+path)
    preamble, blocks = hunks(diff)
    if [sha(canonical(h)) for h in blocks] != entry['hunk_sha256']:
        raise ValueError('Pinned donor hunk drift: '+path)
    if entry['action'] not in ('keep', 'drop') or not entry.get('rationale'):
        raise ValueError('Missing explicit frontier decision')
    if entry['action'] == 'drop':
        return b''
    drops = set(entry.get('drop_copyright_hunks', []))
    known = {sha(canonical(h)) for h in blocks}
    if not drops <= known or any(sha(canonical(h)) in drops and not copyright_only(h) for h in blocks):
        raise ValueError('Only standalone copyright-only hunks may be pruned within a kept file')
    selected = [h for h in blocks if sha(canonical(h)) not in drops]
    return canonical(preamble)+b''.join(selected) if selected else b''


def minimize(rows: list[tuple[str, bytes]], profile: dict) -> tuple[list[tuple[str, bytes]], dict]:
    if profile.get('schema') != 1 or profile.get('release_ready') is not False:
        raise ValueError('Unreviewed frontier profile schema/safety')
    if len({p for p, _ in rows}) != len(rows):
        raise ValueError('Duplicate candidate paths')
    entries = profile['paths']
    if [e['path'] for e in entries] != [p for p, _ in rows]:
        raise ValueError('Frontier path/order drift')
    output, dropped, pruned = [], [], []
    before_hunks = after_hunks = 0
    for (path, diff), entry in zip(rows, entries):
        _, blocks = hunks(diff); before_hunks += len(blocks)
        chosen = select_patch(path, diff, entry)
        if chosen:
            _, kept = hunks(chosen); after_hunks += len(kept)
            output.append((path, chosen))
            pruned.extend({'path': path, 'hunk_sha256': h} for h in entry.get('drop_copyright_hunks', []))
        else:
            dropped.append({'path': path, 'rationale': entry['rationale']})
    if len(output) != profile['expected_retained_path_count']:
        raise ValueError('Unexpected minimized path count')
    return output, {'input_paths': len(rows), 'retained_paths': len(output),
                    'input_hunks': before_hunks, 'retained_hunks': after_hunks,
                    'dropped_paths': dropped, 'pruned_copyright_hunks': pruned,
                    'retained_patch_sha256': sha(b''.join(d for _, d in output)),
                    'review_status': 'INITIAL_GROUPED_SOURCE_REVIEW',
                    'production_review_complete': False, 'release_ready': False,
                    'loadable_proven': False, 'rf_proven': False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--diff', type=Path, required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    try:
        diff = a.diff.read_bytes()
        chunks = re.split(br'(?=^diff --git )', diff, flags=re.M)
        by_path = {}
        for chunk in chunks:
            if not chunk.startswith(b'diff --git '):
                continue
            path = chunk.splitlines()[0].partition(b' b/')[2].decode('ascii')
            if path in by_path:
                raise ValueError('Duplicate diff path')
            by_path[path] = chunk
        profile = json.loads(a.profile.read_text(encoding='utf-8'))
        rows = [(e['path'], by_path[e['path']]) for e in profile['paths']]
        selected, report = minimize(rows, profile)
        a.out.mkdir(parents=True, exist_ok=False)
        (a.out/'minimized-frontier.patch').write_bytes(b''.join(d for _, d in selected))
        (a.out/'review-report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    except (OSError, ValueError, KeyError) as exc:
        print(str(exc)); return 1
    print(json.dumps(report, indent=2)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
