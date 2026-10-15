#!/usr/bin/env python3
"""Materialize the derived stock qcacld import/provider profile.

The profile is metadata parsed from the captured factory qca_cld3_peach_v2.ko.
It is NOT a module patch and cannot make a mismatched module compatible.
Every byte/count/provider identity is pinned and checked before use.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
META=ROOT/'profiles/stock-qcacld-peach-v2.imports.json'
PARTS=[ROOT/f'profiles/stock-qcacld-peach-v2.imports.symvers.gz.b64.part{i}'
       for i in range(4)]

def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def load_profile()->tuple[dict,bytes,list[list[str]]]:
    meta=json.loads(META.read_text(encoding='utf-8'))
    if meta.get('schema')!=1:
        raise ValueError('Unsupported qcacld import profile schema')
    encoded=''.join(''.join(p.read_text(encoding='ascii').split()) for p in PARTS).encode('ascii')
    if sha(encoded)!=meta['payload_base64_sha256']:
        raise ValueError('qcacld compressed profile payload checksum mismatch')
    try:
        raw=gzip.decompress(base64.b64decode(encoded,validate=True))
    except Exception as exc:
        raise ValueError('qcacld compressed profile cannot be decoded') from exc
    if sha(raw)!=meta['symvers_sha256']:
        raise ValueError('qcacld symvers checksum mismatch after decompression')
    try:
        lines=raw.decode('ascii').splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError('qcacld symvers is not ASCII') from exc
    rows=[]
    names=set()
    for no,line in enumerate(lines,1):
        fields=line.split('\t')
        if len(fields)!=5 or not fields[0].startswith('0x') or len(fields[0])!=10:
            raise ValueError(f'Invalid qcacld symvers row {no}')
        int(fields[0][2:],16)
        if not fields[1] or fields[1] in names:
            raise ValueError(f'Duplicate/empty qcacld symbol at row {no}')
        if fields[3] not in ('EXPORT_SYMBOL','EXPORT_SYMBOL_GPL'):
            raise ValueError(f'Unexpected export class at row {no}')
        if fields[4]:
            raise ValueError(f'Unexpected namespace at row {no}')
        names.add(fields[1]); rows.append(fields)
    if len(rows)!=meta['import_crc_count']:
        raise ValueError('qcacld import count mismatch')
    counts=Counter(r[2] for r in rows)
    if dict(counts)!=meta['provider_counts']:
        raise ValueError('qcacld provider count/profile mismatch: '+json.dumps(dict(counts),sort_keys=True))
    module_layout=[r for r in rows if r[1]=='module_layout']
    if module_layout!=[['0x4e276f37','module_layout','vmlinux','EXPORT_SYMBOL','']]:
        raise ValueError('Unexpected stock module_layout CRC/profile')
    if meta['captured_provider_export_records']+meta['source_verified_provider_records']!=len(rows):
        raise ValueError('qcacld evidence accounting does not sum to import count')
    evidence_path=ROOT/'profiles'/meta['additional_provider_evidence_file']
    if evidence_path.name!='stock-qcacld-peach-v2.provider-evidence.json':
        raise ValueError('Unexpected provider evidence filename')
    evidence_raw=evidence_path.read_bytes()
    if sha(evidence_raw)!=meta['additional_provider_evidence_sha256']:
        raise ValueError('Additional provider evidence checksum mismatch')
    evidence=json.loads(evidence_raw)
    if (evidence.get('schema')!=1 or evidence.get('previously_captured_export_records')!=532 or
            evidence.get('newly_captured_export_records')!=56 or
            evidence.get('total_captured_export_records')!=588 or
            meta['captured_provider_export_records']!=588 or meta['source_verified_provider_records']!=0):
        raise ValueError('Unexpected actual provider evidence accounting')
    expected={r[2]:set() for r in rows if r[2] not in ('vmlinux','cnss2','cfg80211')}
    for r in rows:
        if r[2] in expected: expected[r[2]].add(r[1])
    found={}
    for r in evidence['providers']:
        provider=r['provider']; symbols=r['symbols']
        if (provider in found or len(r['module_sha256'])!=64 or
                any(c not in '0123456789abcdef' for c in r['module_sha256']) or
                r['evidence_kind'] not in ('captured_provider_module_exports','captured_vendor_boot_member_exports') or
                r['matched_import_count']!=len(symbols) or len(symbols)!=len(set(symbols))):
            raise ValueError('Malformed additional provider evidence')
        found[provider]=set(symbols)
    if found!=expected:
        raise ValueError('Additional provider evidence symbol/provider mismatch')
    return meta,raw,rows

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    meta,raw,rows=load_profile()
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(raw)
    print(json.dumps({
      'stock_module_sha256':meta['stock_module_sha256'],
      'symvers_sha256':meta['symvers_sha256'],
      'import_crc_count':len(rows),
      'provider_counts':meta['provider_counts'],
      'output':str(a.out) if a.out else None,
      'loadable_proven':False,
    },indent=2))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
