#!/usr/bin/env python3
"""Validate the pinned, dormant QDF/CDP/WMI mode patch without activating firmware.

With --target, use an exact OnePlus 13T vendor source checkout and test
application and reverse application on a temporary touched-path fixture.
The original checkout and any device files are never modified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from build_seed_series import ROOT

PATCH = '0005-qdf-dp-wmi-passthru-mode-primitives.patch'
TARGET = '6a196f79f77acd55cf302e1696c038e4cad99254'
SHA256 = '7b0dffd94f3692274da38706f25a5cb070ac693933d6c8f2c685c96faff4d70c'

def touched(patch: bytes) -> list[str]:
    paths = []
    for line in patch.decode('utf8').splitlines():
        if line.startswith('diff --git a/'):
            a, b = line.split(' b/',1)
            path=a[len('diff --git a/'):]
            if path != b:
                raise ValueError('Patch renames or swaps scope: '+line)
            if path.startswith('/') or '..' in Path(path).parts or not path.startswith('vendor/qcom/opensource/wlan/'):
                raise ValueError('Out-of-scope mode patch: '+path)
            paths.append(path)
    if len(paths) != 5 or len(set(paths)) != 5:
        raise ValueError('Expected exactly five mode primitives files')
    if any('Kbuild' in p or 'defconfig' in p or 'Kconfig' in p for p in paths):
        raise ValueError('Build activation forbidden in dormant patch')
    return paths

def validate(target: Path | None = None) -> dict:
    patch_path=ROOT/'patches'/PATCH
    patch=patch_path.read_bytes()
    paths=touched(patch)
    if hashlib.sha256(patch).hexdigest() != SHA256:
        raise ValueError('Pinned mode-patch SHA256 mismatch')
    output={'patch':PATCH,'sha256':hashlib.sha256(patch).hexdigest(),
            'paths':paths,'mode':'dormant','source_target_commit':TARGET}
    if target is None:
        output['validation']='static only (pass --target for pinned source apply/reverse)'
        return output
    head=subprocess.check_output(['git','-C',str(target),'rev-parse','HEAD'],text=True).strip()
    if head != TARGET:
        raise ValueError('Wrong target source commit; refusing to validate against arbitrary tree')
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        for rel in paths:
            src=target/rel
            if not src.is_file() or src.is_symlink():
                raise ValueError('Missing or unsafe target source: '+rel)
            expected=subprocess.check_output(['git','-C',str(target),'rev-parse','HEAD:'+rel],text=True).strip()
            observed=subprocess.check_output(['git','hash-object',str(src)],text=True).strip()
            if expected != observed:
                raise ValueError('Target source has local edits: '+rel)
            dst=root/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
        originals={rel:(root/rel).read_bytes() for rel in paths}
        for opts in [['--check'],[],['--reverse','--check'],['--reverse']]:
            cp=subprocess.run(['git','apply',*opts,str(patch_path)],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if cp.returncode:
                raise ValueError('Patch application/reversal failed: '+cp.stderr.decode(errors='replace'))
        if any((root/rel).read_bytes()!=data for rel,data in originals.items()):
            raise ValueError('Reversing patch did not recover the target source')
    output['validation']='pinned target source: forward + reverse PASS'
    return output

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--target',type=Path)
    a=p.parse_args();print(json.dumps(validate(a.target),indent=2))
