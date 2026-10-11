#!/usr/bin/env python3
"""Compare rebuilt qcacld to the *captured* factory module without editing either.

A build using KBUILD_MODPOST_WARN may still contain unresolved imports and MUST
NOT be installed. Count those separately from CRC matches. Never invent CRCs,
firmware capabilities, symbol provider identities, or KCFI approval.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from elf_audit import Module

def compare_imports(stock: dict[str,int], rebuilt: dict[str,int],
                    stock_imports: set[str], rebuilt_imports: set[str]) -> dict:
    shared=stock.keys() & rebuilt.keys()
    mismatches={n:{'stock':f'0x{stock[n]:08x}', 'rebuilt':f'0x{rebuilt[n]:08x}'}
                for n in sorted(shared) if stock[n]!=rebuilt[n]}
    newly_required=sorted(rebuilt_imports-stock_imports)
    unversioned=sorted(rebuilt_imports-rebuilt.keys())
    return {
        'stock_versions':len(stock), 'rebuilt_versions':len(rebuilt),
        'shared_versions':len(shared), 'matching_versions':len(shared)-len(mismatches),
        'mismatching_versions':mismatches,
        'stock_only_versioned':sorted(stock.keys()-rebuilt.keys()),
        'rebuilt_only_versioned':sorted(rebuilt.keys()-stock.keys()),
        'newly_required_undefined_imports':newly_required,
        'rebuilt_undefined_without_versions':unversioned,
        'crc_subset_matches':not mismatches,
        'loadable_or_firmware_compatible_proven':False,
        'module_completion_gate':'BLOCKED' if unversioned or newly_required or mismatches else 'NOT_VERIFIED',
    }

def imports(m:Module)->set[str]:
    return {s['name'] for s in m.symbols() if s['binding']==1 and s['index']==0 and s['name']}

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock',type=Path,required=True)
    p.add_argument('--rebuilt',type=Path,required=True)
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    stock=Module(args.stock.read_bytes()); rebuilt=Module(args.rebuilt.read_bytes())
    if stock.machine!=183 or rebuilt.machine!=183:
        raise ValueError('Only ARM64 factory and ARM64 rebuilt kernel modules are supported')
    result=compare_imports(stock.versions(),rebuilt.versions(),imports(stock),imports(rebuilt))
    text=json.dumps(result,indent=2)+'\n'
    if args.output:
        args.output.write_text(text)
    print(text)
    return 0 if result['crc_subset_matches'] and not result['newly_required_undefined_imports'] else 1

if __name__=='__main__':
    raise SystemExit(main())
