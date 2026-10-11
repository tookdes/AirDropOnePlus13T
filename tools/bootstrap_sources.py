#!/usr/bin/env python3
"""Fetch pinned public sources. No kernel build or device operations."""
from __future__ import annotations
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=ROOT / 'upstream')
    args = parser.parse_args()
    locks = json.loads((ROOT / 'upstream.lock.json').read_text())
    args.destination.mkdir(parents=True, exist_ok=True)
    for name in ('op13t', 'op15'):
        lock = locks[name]
        dest = args.destination / name
        if not dest.exists():
            dest.mkdir()
            run('git', 'init', '-q', str(dest))
            run('git', '-C', str(dest), 'remote', 'add', 'origin',
                'https://github.com/' + lock['repository'] + '.git')
        if not (dest / '.git').exists():
            raise SystemExit(f'Refusing non-repository directory: {dest}')
        remote = run('git', '-C', str(dest), 'remote', 'get-url', 'origin')
        if remote != 'https://github.com/' + lock['repository'] + '.git':
            raise SystemExit(f'Refusing unexpected remote at {dest}: {remote}')
        if run('git', '-C', str(dest), 'status', '--porcelain'):
            raise SystemExit(f'Refusing dirty tree: {dest}')
        run('git', '-C', str(dest), 'fetch', '--depth=1', 'origin', lock['commit'])
        run('git', '-C', str(dest), 'checkout', '--detach', lock['commit'])
        got = run('git', '-C', str(dest), 'rev-parse', 'HEAD')
        if got != lock['commit']:
            raise SystemExit(f'Pinned commit mismatch: {name}')
        print(f'{name}: {got}')

if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.output or str(exc)) from exc
