#!/usr/bin/env python3
"""Package an existing evidence directory. No ADB, shell, network or device operations.

Copies only allowlisted evidence names; skips symlinks and rejects different
files with the same selected name. Original evidence is never modified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import zipfile
from pathlib import Path

NAMES={'kconfig.txt','config.gz','boot_a.img','qca_cld3_peach_v2.ko',
       'qca_cld3_peach.ko','cnss2.ko','cfg80211.ko','icnss2.ko','mac80211.ko',
       'icnss2_versions.json','vmlinux.btf','dt-evidence.txt'}
FIRMWARE=re.compile(r'^(?:amss[^/]*\.(?:bin|mbn|elf|b[0-9]{2})|bdwlan[^/]*\.(?:bin|elf)|Data\.msc|m3[^/]*\.(?:bin|elf))$',re.I)

def sha(path:Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def discover(root:Path) -> dict[str,Path]:
    root=root.resolve(strict=True)
    if not root.is_dir(): raise ValueError('Input must be an existing directory')
    result={}
    for directory,dirs,files in os.walk(root,followlinks=False):
        parent=Path(directory)
        dirs[:]=[d for d in dirs if not (parent/d).is_symlink() and d not in {'.git','node_modules','.venv'}]
        if len(parent.relative_to(root).parts)>=6: dirs[:]=[]
        for name in files:
            p=parent/name
            if p.is_symlink() or not p.is_file(): continue
            if name in NAMES:
                key='stock/'+name
            elif FIRMWARE.fullmatch(name):
                key='stock/peach/'+name
            else: continue
            if key in result and sha(result[key])!=sha(p):
                raise ValueError('Different candidate files for '+key+'; use a narrower input directory')
            result.setdefault(key,p)
    return result

def bundle(root:Path, output:Path) -> dict:
    selected=discover(root)
    if not selected: raise ValueError('No allowlisted evidence found; no archive created')
    if output.exists(): raise ValueError('Refusing to overwrite existing output')
    missing=[]
    if not any('stock/'+x in selected for x in ('kconfig.txt','config.gz')): missing.append('kconfig.txt or config.gz')
    for x in ('qca_cld3_peach_v2.ko','cnss2.ko','cfg80211.ko','icnss2.ko','boot_a.img'):
        if 'stock/'+x not in selected: missing.append(x)
    if 'stock/peach/amss20.bin' not in selected: missing.append('peach/amss20.bin')
    record={'schema':1,'origin':'Provided existing directory; not a new live capture',
            'missing':missing,'entries':[],'device_operations':False,
            'warning':'Contains proprietary firmware/kernel binaries; do not publish publicly'}
    for name,path in sorted(selected.items()):
        record['entries'].append({'path':name,'sha256':sha(path),'size':path.stat().st_size})
    output.parent.mkdir(parents=True,exist_ok=True)
    created=False
    try:
        with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            created=True
            for row in record['entries']:
                path=selected[row['path']]
                # Read and hash the exact bytes written, detecting changed evidence.
                digest=hashlib.sha256(); total=0
                with path.open('rb') as src, z.open(row['path'],'w',force_zip64=True) as dest:
                    for chunk in iter(lambda:src.read(1024*1024),b''):
                        digest.update(chunk); total+=len(chunk); dest.write(chunk)
                if digest.hexdigest()!=row['sha256'] or total!=row['size']:
                    raise ValueError('Evidence changed while archiving: '+row['path'])
            z.writestr('input-manifest.json',json.dumps(record,indent=2)+'\n')
    except Exception:
        if created: output.unlink(missing_ok=True)
        raise
    return record
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path); p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    try: print(json.dumps(bundle(a.directory,a.out),indent=2))
    except (OSError,ValueError) as exc: raise SystemExit(str(exc))
