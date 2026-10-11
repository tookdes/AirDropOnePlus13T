#!/usr/bin/env python3
"""Reproduce dormant-source import patches from verified snapshots.

Uses a minimal source fixture, not a complete OnePlus kernel checkout.
All touched target paths were individually confirmed absent at the pinned ref.
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from audit_inventory import blob_hash

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'vendor/qcom/opensource/wlan/'
FILES = {
    PREFIX+'qca-wifi-host-cmn/qdf/inc/qdf_wondertap.h': '30ca36501e64f2ed5e885d3d5b30acd4b6b6da5e',
    PREFIX+'qca-wifi-host-cmn/qdf/linux/src/i_qdf_wondertap.h': '6eff4950742490d01bb7b9c1034f8fa01296ef9c',
    PREFIX+'qca-wifi-host-cmn/qdf/linux/src/wondertap.h': '9b03aa77703413e87dece1bc1d39369088808f88',
    PREFIX+'qcacld-3.0/core/hdd/inc/wlan_hdd_wondertap.h': '8dbed1cff51b256a9532d22b3f468c60aa22f7e6',
    PREFIX+'qcacld-3.0/core/hdd/src/wlan_hdd_wondertap.c': 'd1a69c4a103abd991c8649475174581a546efcdc',
}
C_PATH = PREFIX+'qcacld-3.0/core/hdd/src/wlan_hdd_wondertap.c'
CANONICAL = 'vendor/oplus/kernel/wifi/wonder/include/wonder/wondertap.h'

def harden(text: str) -> str:
    for msg in ('Set fixed tx rate for wondertap failed:%d', 'Set GI for wondertap failed:%d'):
        old = '\tif (ret)\n\t\thdd_err("' + msg + '", ret);'
        new = '\tif (ret) {\n\t\thdd_err("' + msg + '", ret);\n\t\treturn ret;\n\t}'
        if text.count(old) != 1:
            raise ValueError('Unexpected donor error path: ' + msg)
        text = text.replace(old, new, 1)
    old = '\t\thdd_err("Command not allowed in mode:%d", hdd_get_conparam());\n\t\tgoto destroy_sync;'
    new = '\t\thdd_err("Command not allowed in mode:%d", hdd_get_conparam());\n\t\terrno = -EOPNOTSUPP;\n\t\tgoto destroy_sync;'
    if text.count(old) != 1:
        raise ValueError('Unexpected mission-mode gate')
    return text.replace(old, new, 1)

def run(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env.update(GIT_AUTHOR_DATE='2026-10-11T00:00:00+00:00',
               GIT_COMMITTER_DATE='2026-10-11T00:00:00+00:00')
    cp = subprocess.run(['git', '-C', str(repo), *args], capture_output=True, env=env)
    if cp.returncode:
        raise RuntimeError(cp.stderr.decode(errors='replace'))
    return cp.stdout

def build() -> dict:
    source = ROOT/'upstream/op15-excerpts'
    records = []
    for path, want in FILES.items():
        raw = (source/path).read_bytes()
        if blob_hash(raw) != want:
            raise ValueError('Donor blob mismatch: ' + path)
        records.append({'path': path, 'git_blob': want, 'lines': len(raw.splitlines()),
                        'target_status': '404 at pinned target commit',
                        'donor_commit': '5ab2a689ff87d7d28c511f1762cf41c1b90d965a'})
    canonical = (ROOT/'upstream/op13t-excerpts'/CANONICAL).read_bytes()
    if blob_hash(canonical) != FILES[PREFIX+'qca-wifi-host-cmn/qdf/linux/src/wondertap.h']:
        raise ValueError('Target generic contract differs')
    patches = ROOT/'patches'
    patches.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        run(repo, 'init', '-q')
        run(repo, 'config', 'user.name', 'op13t-wonder source workbench')
        run(repo, 'config', 'user.email', 'noreply@localhost')
        run(repo, 'config', 'commit.gpgsign', 'false')
        run(repo, 'config', 'core.autocrlf', 'false')
        p = repo/CANONICAL
        p.parent.mkdir(parents=True)
        p.write_bytes(canonical)
        run(repo, 'add', '.')
        run(repo, 'commit', '-qm', 'Test fixture: verified 13T generic contract; NOT a full upstream tree')
        base = run(repo, 'rev-parse', 'HEAD').decode().strip()
        groups = [list(FILES)[:3], list(FILES)[3:]]
        messages = [
            'qdf: import WonderTap interface headers without enabling passthru\n\n'
            'Source: OnePlusOSS sm8850, commit 5ab2a689ff87d7d28c511f1762cf41c1b90d965a.\n'
            'Target: OnePlusOSS sm8750, commit 6a196f79f77acd55cf302e1696c038e4cad99254.\n'
            'All three headers retain their upstream bytes and license notices.\n'
            'The interface contract is byte-identical to the target generic Wonder header.\n'
            'No Kbuild or defconfig changes; not a working backport.\n',
            'hdd: stage donor WonderTap bridge as dormant source\n\n'
            'Source: OnePlusOSS sm8850, commit 5ab2a689ff87d7d28c511f1762cf41c1b90d965a.\n'
            'Target: OnePlusOSS sm8750, commit 6a196f79f77acd55cf302e1696c038e4cad99254.\n'
            'Both files preserve upstream bytes and license notices.\n'
            'Dependency closure, target adaptation and full module build are NOT complete.\n'
            'Do not add the object to Kbuild or enable DRIVER_PASSTHRU_MODE yet.\n',
            'hdd: preserve WonderTap setup failures instead of reporting success\n\n'
            'Return immediately when fixed-rate or SGI WMI configuration fails.\n'
            'Previously a later successful command overwrote the earlier error.\n'
            'Set -EOPNOTSUPP before cleanup when the driver is not in mission mode.\n'
            'Previously errno could remain zero from context validation.\n'
            'This is a narrow error-propagation fix, NOT complete cleanup/SSR hardening.\n'
        ]
        for paths, message in zip(groups, messages[:2]):
            for path in paths:
                dest = repo/path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((source/path).read_bytes())
            run(repo, 'add', '.')
            run(repo, 'commit', '-qm', message)
        p = repo/C_PATH
        p.write_text(harden(p.read_text()))
        run(repo, 'add', '.')
        run(repo, 'commit', '-qm', messages[2])
        raw_names = run(repo, 'format-patch', '--no-signature', '-o', str(patches), base).decode().splitlines()
        final_names = ['0001-qdf-wondertap-headers.patch',
                       '0002-hdd-wondertap-dormant-import.patch',
                       '0003-hdd-propagate-setup-errors.patch']
        for generated, name in zip(raw_names, final_names):
            Path(generated).replace(patches/name)
        (patches/'series').write_text('\n'.join(final_names)+'\n')
        final_blob = p.read_bytes()
        expected_tree = run(repo, 'rev-parse', 'HEAD^{tree}').decode().strip()
        aggregate = run(repo, 'diff', '--numstat', base, 'HEAD').decode()
        per_patch = {}
        for name in final_names:
            per_patch[name] = run(repo, 'apply', '--numstat', str(patches/name)).decode()
        run(repo, 'reset', '--hard', base)
        checks = []
        for name in final_names:
            run(repo, 'apply', '--check', '--index', str(patches/name))
            run(repo, 'apply', '--index', str(patches/name))
            checks.append({'patch': name, 'apply_check_on_touched_path_fixture': 'passed'})
        if run(repo, 'write-tree').decode().strip() != expected_tree:
            raise RuntimeError('Replayed tree does not match generated tree')
        for name in reversed(final_names):
            run(repo, 'apply', '-R', '--check', '--index', str(patches/name))
            run(repo, 'apply', '-R', '--index', str(patches/name))
        if run(repo, 'status', '--porcelain'):
            raise RuntimeError('Reverse application did not restore fixture')
    out = ROOT/'module/staged-source'/C_PATH
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(final_blob)
    summary = {'status': 'DORMANT_SOURCE_SEED_NOT_DEPLOYABLE', 'source_files': records,
               'patch_checks': checks, 'reverse_application': 'passed',
               'validation_scope': 'minimal fixture containing verified touched paths, not full kernel tree',
               'patch_numstat': per_patch, 'aggregate_numstat': aggregate,
               'full_kernel_build': 'NOT_RUN', 'full_dependency_closure': 'NOT_COMPLETE'}
    (ROOT/'evidence/patch-validation.json').write_text(json.dumps(summary, indent=2)+'\n')
    return summary

if __name__ == '__main__':
    print(json.dumps(build(), indent=2))
