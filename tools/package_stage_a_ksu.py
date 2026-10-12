#!/usr/bin/env python3
"""Assemble a KernelSU *probe* zip from Stage A verified ARM64 modules.

The zip is refused unless both .ko files, SHA256SUMS and a passing
stage-a-result.json are present. It never packages qcacld, wonder.ko,
firmware, or an AirDrop installer.
"""
from __future__ import annotations
import argparse, hashlib, json, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_KO = ('hello_13t.ko', 'wonder_shim_13t.ko')
TEMPLATE = (
    'module.prop',
    'customize.sh',
    'post-fs-data.sh',
    'service.sh',
    'NOT_AIRDROP',
    'META-INF/com/google/android/update-binary',
    'META-INF/com/google/android/updater-script',
)

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def load_result(path: Path) -> dict:
    r = json.loads(path.read_text())
    if r.get('build_and_offline_abi_gates_passed') is not True:
        raise ValueError('Stage A ABI gates did not pass')
    if r.get('airdrop_available') is True:
        raise ValueError('Refusing a result that claims AirDrop')
    mods = r.get('modules') or {}
    for name in REQUIRED_KO:
        info = mods.get(name)
        if not info or info.get('errors'):
            raise ValueError('Module failed offline checks: '+name)
        if info.get('captured_crc_check_passed') is not True:
            raise ValueError('CRC gate missing/failed: '+name)
    return r

def verify_kos(verified: Path, sums: Path) -> None:
    listed = {}
    for line in sums.read_text().splitlines():
        digest, name = line.split()
        listed[name] = digest
    for name in REQUIRED_KO:
        f = verified/name
        if not f.is_file():
            raise ValueError('Missing verified module: '+name)
        if sha(f) != listed.get(name):
            raise ValueError('SHA256 mismatch: '+name)

def package(verified: Path, result: Path, out: Path) -> dict:
    load_result(result)
    verify_kos(verified, verified/'SHA256SUMS')
    if out.exists():
        raise ValueError('Refusing to overwrite existing zip')
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for rel in TEMPLATE:
            src = ROOT/'ksu-test'/rel
            if not src.is_file():
                raise ValueError('Missing package template: '+rel)
            z.write(src, rel)
        for name in REQUIRED_KO:
            z.write(verified/name, name)
        z.write(verified/'SHA256SUMS', 'SHA256SUMS')
        z.write(result, 'stage-a-result.json')
    manifest = {
        'schema': 1,
        'zip_sha256': sha(out),
        'modules': {n: sha(verified/n) for n in REQUIRED_KO},
        'airdrop_available': False,
        'autoload': False,
        'diagnostics_only_default': True,
        'note': 'KernelSU probe zip. Manual insmod after reboot. Not AirDrop.',
    }
    (out.parent/(out.name+'.json')).write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--verified', type=Path, required=True)
    p.add_argument('--result', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    try:
        m = package(a.verified.resolve(), a.result.resolve(), a.out.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc))
        return 1
    print(json.dumps(m, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
