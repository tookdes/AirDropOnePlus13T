#!/usr/bin/env python3
"""Freshly regenerate the three kernel CRCs introduced by the qcacld backport."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from prepare_stage_a import COMMON, run, symversions_from_cmd
from build_wonder_kernel_crcs import additional_rows

ROOT=Path(__file__).resolve().parents[1]
OBJECTS=('net/core/dev.o','drivers/char/random.o')

def load_profile()->tuple[dict,dict[str,int],list[list[str]]]:
    meta=json.loads((ROOT/'profiles/qcacld-backport-kernel.json').read_text())
    raw=(ROOT/'profiles/qcacld-backport-kernel.exports.symvers').read_bytes()
    if meta.get('schema')!=1 or meta.get('kernel_commit')!=COMMON or meta.get('kernel_objects')!=list(OBJECTS):
        raise ValueError('Unreviewed qcacld kernel CRC profile')
    if hashlib.sha256(raw).hexdigest()!=meta.get('exports_sha256'):
        raise ValueError('qcacld kernel CRC profile checksum mismatch')
    rows=[];expected={}
    for line in raw.decode('ascii').splitlines():
        f=line.split('\t')
        if len(f)!=5 or f[2]!='vmlinux' or f[3]!='EXPORT_SYMBOL' or f[4] or f[1] in expected:
            raise ValueError('Malformed qcacld kernel CRC row')
        expected[f[1]]=int(f[0],16);rows.append(f)
    if set(expected)!= {'dev_close','dev_open','get_random_u32'} or len(rows)!=meta['export_count']:
        raise ValueError('Incomplete candidate-only kernel CRC profile')
    return meta,expected,rows

def prepare(kernel:Path,kout:Path,make:list[str],out:Path)->tuple[Path,dict]:
    meta,expected,rows=load_profile()
    log=out/'qcacld-kernel-crc-build.log';log.write_text('',encoding='utf-8')
    run(make+list(OBJECTS),log)
    fresh={}
    for obj in OBJECTS:
        p=Path(obj);cmd=kout/p.parent/('.'+p.name+'.cmd')
        for name,crc in symversions_from_cmd(cmd.read_text(encoding='utf-8')).items():
            if name in fresh and fresh[name]!=crc: raise ValueError('Conflicting fresh CRC: '+name)
            fresh[name]=crc
    missing=sorted(set(expected)-set(fresh))
    mismatch={n:{'fresh':f'0x{fresh[n]:08x}','stock':f'0x{expected[n]:08x}'}
              for n in expected if n in fresh and fresh[n]!=expected[n]}
    report={'fresh_kernel_crc_gate_passed':not missing and not mismatch,
            'missing':missing,'mismatched':mismatch,'kernel_objects':list(OBJECTS),
            'profile_sha256':meta['exports_sha256'],'loadable_proven':False}
    if not report['fresh_kernel_crc_gate_passed']:
        (out/'qcacld-kernel-crc.json').write_text(json.dumps(report,indent=2)+'\n')
        raise ValueError('Candidate-only fresh kernel CRC gate failed')
    checked=out/'qcacld-kernel-checked.symvers'
    checked.write_text(''.join(f'0x{fresh[f[1]]:08x}\t'+'\t'.join(f[1:])+'\n' for f in rows))
    extra=additional_rows(rows,kout/'Module.symvers')
    add=out/'qcacld-kernel-additional.symvers'
    add.write_text(''.join('\t'.join(f)+'\n' for f in extra))
    report['additional_exports_for_modpost']=len(extra)
    report['matched']={n:f'0x{fresh[n]:08x}' for n in sorted(expected)}
    (out/'qcacld-kernel-crc.json').write_text(json.dumps(report,indent=2)+'\n')
    return add,report
