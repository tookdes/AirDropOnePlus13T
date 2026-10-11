#!/usr/bin/env python3
"""Reproduce a *compile-only* OnePlus-15 WLAN donor-introduction slice.

The source seed remains separate from 60 diff candidates. The candidate slice
includes unrelated vendor synchronization edits and is NEVER a device release.
The stock and donor checkouts are read-only; the output tree is new.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

TARGET = '6a196f79f77acd55cf302e1696c038e4cad99254'
INTRO = '307d23721d20e21b8160b9ba9c3cb50911ff8c00'
INTRO_PARENT = '7fb7abf097a18c6e2ad2fb9d18876b095898e87f'
PREFIX = 'vendor/qcom/opensource/wlan/'
EXPECTED_PATH_COUNT = 60
EXPECTED_PATHS_SHA256 = 'd6839cb032c99d1192d87be33c00fc607df5d786b09e5b6c4a2aa276722b0959'

def cmd(*args: str, cwd: Path | None = None, check=True) -> bytes:
    cp = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
    if check and cp.returncode:
        raise RuntimeError('command failed: ' + ' '.join(args) + '\n' +
                           cp.stderr.decode(errors='replace')[:600])
    return cp.stdout

def touched(diff: bytes) -> set[str]:
    paths=set()
    for line in diff.decode(errors='strict').splitlines():
        if not line.startswith('diff --git a/'):
            continue
        a,sep,b=line.partition(' b/')
        path=a.removeprefix('diff --git a/')
        if not sep or path != b or not path.startswith('vendor/') or '..' in Path(path).parts:
            raise ValueError('Unexpected patch path: ' + line)
        paths.add(path)
    return paths

def donor_diff(donor: Path, rel: str) -> bytes:
    return cmd('git','-C',str(donor),'diff','--no-ext-diff','--binary',
               INTRO_PARENT,INTRO,'--',rel)

def source_candidates(donor: Path) -> list[tuple[str,bytes]]:
    # Explicit exact tree IDs. A shallow public-source fetch can retrieve the
    # introduction and its parent without changing HEAD.
    for commit in (INTRO,INTRO_PARENT):
        cmd('git','-C',str(donor),'cat-file','-e',commit+'^{commit}')
    names=cmd('git','-C',str(donor),'diff','--name-only',INTRO_PARENT,
              INTRO,'--',PREFIX).decode().splitlines()
    return [(rel,donor_diff(donor,rel)) for rel in names]

def fixture_candidates(path: Path) -> list[tuple[str,bytes]]:
    # Offline fixture from the *same* two donor commits, for regression tests.
    rows=json.loads(path.read_text())
    return [(r['path'],Path(r['patch']).read_bytes()) for r in rows]

def reproduce(target: Path, output: Path, seed: Path,
              candidates: list[tuple[str,bytes]]) -> dict:
    if cmd('git','-C',str(target),'rev-parse','HEAD').decode().strip()!=TARGET:
        raise ValueError('The target must be the pinned OnePlus 13T source SHA')
    if output.exists():
        raise ValueError('Refusing to overwrite any existing tree')
    if not (target/PREFIX).is_dir():
        raise ValueError('Missing Qualcomm target source')
    (output/PREFIX).parent.mkdir(parents=True,exist_ok=True)
    shutil.copytree(target/PREFIX,output/PREFIX,symlinks=True)
    # Headers for external IPA integration are part of the same target repo.
    dataipa='vendor/qcom/opensource/dataipa'
    shutil.copytree(target/dataipa, output/dataipa, symlinks=True)
    # OPlus generic Wonder is separate from the Qualcomm tree.
    wonder='vendor/oplus/kernel/wifi/wonder/wondertap.c'
    (output/wonder).parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(target/wonder,output/wonder)
    series=[n for n in (seed/'patches/series').read_text().splitlines() if n and not n.startswith('#')]
    if len(series) != 7:
        raise ValueError('Expected seven pinned review patches')
    reserved=set()
    for name in series:
        patch=(seed/'patches'/name).read_bytes()
        reserved.update(touched(patch))
        cp=subprocess.run(['git','apply','--check','-'],cwd=output,input=patch,capture_output=True)
        if cp.returncode:
            raise ValueError('Seed patch failed: '+name+' '+cp.stderr.decode(errors='replace'))
        cp=subprocess.run(['git','apply','-'],cwd=output,input=patch,capture_output=True)
        if cp.returncode:
            raise ValueError('Seed patch application failed: '+name)
    accepted=[]; skipped=[]; content=[]
    for rel,patch in candidates:
        if not rel.startswith(PREFIX) or '..' in Path(rel).parts:
            raise ValueError('Unapproved candidate path: '+rel)
        if not patch or touched(patch)!={rel}:
            raise ValueError('Candidate diff scope mismatch: '+rel)
        if rel in reserved or (output/rel).is_symlink():
            skipped.append(rel);continue
        cp=subprocess.run(['git','apply','--check','-'],cwd=output,input=patch,capture_output=True)
        if cp.returncode:
            skipped.append(rel);continue
        cp=subprocess.run(['git','apply','-'],cwd=output,input=patch,capture_output=True)
        if cp.returncode:
            raise ValueError('Checked candidate failed during application: '+rel)
        accepted.append(rel)
        content.append(patch)
    digest=hashlib.sha256(('\n'.join(accepted)+'\n').encode()).hexdigest()
    if len(accepted)!=EXPECTED_PATH_COUNT or digest!=EXPECTED_PATHS_SHA256:
        raise ValueError(f'Candidate frontier drift: {len(accepted)} {digest}; refusing to publish')
    report={'target_sha':TARGET,'donor_intro':INTRO,'donor_parent':INTRO_PARENT,
            'release_ready':False,'compile_only':True,'seven_seed_patches':series,
            'candidate_paths':accepted,'skipped_count':len(skipped),
            'accepted_path_set_sha256':digest,
            'selected_diff_sha256':hashlib.sha256(b''.join(content)).hexdigest(),
            'note':'File-wide donor sync candidates contain unrelated changes: NOT a reviewed production patch series'}
    (output/'backport-candidate.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--target',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seed',type=Path,default=Path(__file__).resolve().parents[1])
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--donor',type=Path)
    group.add_argument('--offline-fixture',type=Path)
    args=parser.parse_args()
    rows=source_candidates(args.donor) if args.donor else fixture_candidates(args.offline_fixture)
    report=reproduce(args.target,args.output,args.seed,rows)
    print(json.dumps({'selected':len(report['candidate_paths']),
                      'paths_sha256':report['accepted_path_set_sha256'],
                      'compile_only':True},indent=2))
if __name__=='__main__':
    main()
