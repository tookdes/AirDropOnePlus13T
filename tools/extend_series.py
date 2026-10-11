#!/usr/bin/env python3
"""Rebuild the seed plus a hash-pinned generic Wonder correctness patch."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path
from audit_inventory import blob_hash
from build_seed_series import ROOT, build, run
REL = 'vendor/oplus/kernel/wifi/wonder/wondertap.c'
BLOB = '00b979928229a77c2bbbc8a8f29d7e6bf0cd7b0c'
NAME = '0004-wonder-initialization-and-locking.patch'

def once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError('Pinned source context is not unique: ' + repr(old[:100]))
    return text.replace(old, new, 1)

def fix(text: str) -> str:
    text = once(text, '\tstruct wondertap_init_params params;',
                '\tstruct wondertap_init_params params = {0};')
    text = once(text, '\tint retry;\n\n\tmutex_lock(&wondertap->lock);',
                '\tint retry;\n\n\tif (!wondertap || !_params)\n\t\treturn -EINVAL;\n\n\tmutex_lock(&wondertap->lock);')
    old = '\t\tif (_params->rate_adaptation_enable) {\n\t\t\tparams.rate_adaptation_enable = _params->rate_adaptation_enable;'
    new = ('\t\t/* Only these capability flags are initialized by wonder_start().\n'
           '\t\t * Retry limits and reserved fields must remain zero, not stack data.\n'
           '\t\t */\n'
           '\t\tparams.amsdu_enable = _params->amsdu_enable;\n'
           '\t\tparams.ampdu_enable = _params->ampdu_enable;\n'
           '\t\tparams.rate_adaptation_enable = _params->rate_adaptation_enable;\n'
           '\t\tif (params.rate_adaptation_enable) {')
    text = once(text, old, new)
    text = once(text, '\t\t\tif (retry < 5) {', '\t\t\tif (retry < 3) {')
    text = once(text, 'Retrying in 1 second...', 'Retrying in 400 ms...')
    text = once(text, '\t\t\treturn wondertap_ops->set_tx_rate_mask(wondertap->vendor_handle, params);',
                '\t\t\tret = wondertap_ops->set_tx_rate_mask(wondertap->vendor_handle, params);')
    return text

def extend() -> dict:
    raw = (ROOT/'upstream/op13t-excerpts'/REL).read_bytes()
    if blob_hash(raw) != BLOB:
        raise ValueError('Target generic Wonder source hash mismatch')
    build()
    modified = fix(raw.decode()).encode()
    dest = ROOT/'module/staged-source'/REL
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(modified)
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        run(repo, 'init', '-q')
        run(repo, 'config', 'user.name', 'op13t-wonder source workbench')
        run(repo, 'config', 'user.email', 'noreply@localhost')
        run(repo, 'config', 'commit.gpgsign', 'false')
        p = repo/REL
        p.parent.mkdir(parents=True)
        p.write_bytes(raw)
        run(repo, 'add', '.')
        run(repo, 'commit', '-qm', 'Fixture: exact target generic Wonder source, not a full kernel')
        base = run(repo, 'rev-parse', 'HEAD').decode().strip()
        p.write_bytes(modified)
        run(repo, 'add', '.')
        run(repo, 'commit', '-qm', 'wonder: initialize vendor parameters and release rate-mask mutex\n\n'
            'The mac80211 caller initializes only three capability bits. Do not\n'
            'copy its uninitialized retry/reserved fields. Initialize the vendor\n'
            'parameter block, preserve those three flags, and use cached settings.\n'
            'Return through unlock after the rate-mask callback, on success or failure.\n'
            'Do not sleep after the final init attempt; log the actual backoff.\n\n'
            'Target source: 6a196f79f77acd55cf302e1696c038e4cad99254.\n'
            'Host mocks reproduce original defects; not a target-kernel build.')
        patch = run(repo, 'format-patch', '--no-signature', '--stdout', base)
        patch_path = ROOT/'patches'/NAME
        patch_path.write_bytes(patch)
        stats = run(repo, 'diff', '--numstat', base, 'HEAD').decode().strip()
        run(repo, 'reset', '--hard', base)
        run(repo, 'apply', '--check', '--index', str(patch_path))
        run(repo, 'apply', '--index', str(patch_path))
        assert p.read_bytes() == modified
        run(repo, 'apply', '-R', '--index', str(patch_path))
        assert p.read_bytes() == raw
        assert not run(repo, 'status', '--porcelain')
    series = ROOT/'patches/series'
    series.write_text(series.read_text()+NAME+'\n')
    result = {'patch':NAME, 'preimage_git_blob': BLOB, 'postimage_git_blob':blob_hash(modified),
              'numstat':stats, 'apply_and_reverse':'PASS',
              'scope':'Exact touched-file fixture; not complete source tree or target build'}
    (ROOT/'evidence/generic-patch-validation.json').write_text(json.dumps(result, indent=2)+'\n')
    return result
if __name__ == '__main__':
    print(json.dumps(extend(), indent=2))
