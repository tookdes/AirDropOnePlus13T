#!/usr/bin/env python3
"""Compare compiled qcacld cfg80211 callback slots with captured stock metadata."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elf_audit import Module
from audit_rf_backend import cfg_callbacks
ROOT=Path(__file__).resolve().parents[1]


def compare(actual: dict, expected: dict) -> dict:
    rows=actual['callbacks'];stock={r['symbol']:r['offset'] for r in expected['callbacks']}
    symbols=[r['symbol'] for r in rows];offsets=[r['offset'] for r in rows]
    errors=[]
    if len(symbols)!=len(set(symbols)) or len(offsets)!=len(set(offsets)):
        errors.append('Duplicate callback symbol/slot')
    if actual['object_bytes']!=expected['object_bytes']:
        errors.append('cfg80211_ops object size mismatch')
    for r in rows:
        if r['symbol'] not in stock:errors.append('Unreviewed callback: '+r['symbol'])
        elif stock[r['symbol']]!=r['offset']:
            errors.append(f"Callback slot mismatch: {r['symbol']} actual=0x{r['offset']:x} stock=0x{stock[r['symbol']]:x}")
    return {'callback_count':len(rows),'object_bytes':actual['object_bytes'],
            'expected_object_bytes':expected['object_bytes'],'errors':errors,
            'stock_callbacks_not_initialized':sorted(set(stock)-set(symbols)),
            'callback_slot_gate_passed':not errors,'loadable_proven':False,
            'callback_prototypes_and_kcfi_proven':False}


def audit(path: Path) -> dict:
    profile=ROOT/'profiles/stock-qcacld-cfg80211-callbacks.json'
    raw=profile.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='09ad4e09060b91c8c2eadd5a434304176f3d25d0eb733745918cda9673abcf08':
        raise ValueError('Captured cfg80211 callback profile checksum mismatch')
    expected=json.loads(raw)
    mod=Module(path.read_bytes())
    report=compare(cfg_callbacks(mod),expected)
    report.update(module_sha256=mod.sha256,profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest())
    return report


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('module',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args()
    try:r=audit(a.module)
    except (OSError,ValueError,KeyError) as exc:print(str(exc));return 1
    text=json.dumps(r,indent=2)+'\n'
    if a.out:a.out.write_text(text,encoding='utf-8')
    print(text);return 0 if r['callback_slot_gate_passed'] else 1


if __name__=='__main__':raise SystemExit(main())
