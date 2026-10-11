#!/usr/bin/env python3
"""Compare real Module.symvers files with captured stock CRCs. Never writes CRCs."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

CRC = re.compile(r'^0x[0-9a-fA-F]{1,8}$')

def load_expected(path: Path) -> dict[str, int]:
    result = {}
    for item in json.loads(path.read_text()):
        sym, crc = item['sym'], item['crc']
        if sym in result or not CRC.fullmatch(crc):
            raise ValueError(f'Invalid or duplicate baseline: {sym}')
        result[sym] = int(crc, 16)
    if not result:
        raise ValueError('Empty baseline')
    return result

def load_symvers(paths: list[Path]) -> dict[str, int]:
    result = {}
    for path in paths:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            cols = line.split()
            if len(cols) < 4 or not CRC.fullmatch(cols[0]):
                raise ValueError(f'Malformed Module.symvers line {path}:{lineno}')
            crc, sym = int(cols[0], 16), cols[1]
            if sym in result and result[sym] != crc:
                raise ValueError(f'Conflicting CRC for {sym}')
            result[sym] = crc
    return result

def compare(expected: dict[str, int], actual: dict[str, int]) -> dict:
    missing = sorted(expected.keys() - actual.keys())
    mismatch = [{'symbol': k, 'expected': f'0x{v:08x}', 'actual': f'0x{actual[k]:08x}'}
                for k, v in sorted(expected.items()) if k in actual and actual[k] != v]
    return {'expected': len(expected), 'compared': len(expected) - len(missing),
            'missing': missing, 'mismatch': mismatch,
            'passed': not missing and not mismatch,
            'scope': 'Captured CRCs only; not exported-symbol, KCFI, layout or firmware validation'}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--symvers', type=Path, action='append', required=True)
    args = parser.parse_args()
    result = compare(load_expected(args.baseline), load_symvers(args.symvers))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit(str(exc)) from exc
