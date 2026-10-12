#!/usr/bin/env python3
"""Write Module.symvers rows from a REL ARM64 kernel module's ksymtab+kcrctab."""
from __future__ import annotations
import argparse, struct
from pathlib import Path
from elf_audit import Module, ElfError

def _rela_name(mod: Module, ksymsec: str) -> str:
    needle = '.rela_' + ksymsec
    hits = [n for n in mod.sections if n == needle or n.startswith(needle + '+')]
    if not hits:
        raise ElfError('No relocation section for '+ksymsec)
    return hits[0]

def ksymtab_names(mod: Module, ksymsec: str) -> list[str]:
    k = mod.sections[ksymsec]
    raw = mod.take(*mod.sections[_rela_name(mod, ksymsec)][4:6])
    if len(raw) % 24:
        raise ElfError('Unexpected RELA entry size')
    syms = mod.symbols()
    slot = k[5] // 12
    names = [''] * slot
    for off in range(0, len(raw), 24):
        r_offset, r_info, _addend = struct.unpack_from('<QqQ', raw, off)
        if r_offset % 12 or r_offset // 12 >= slot:
            continue
        names[r_offset // 12] = syms[r_info >> 32]['name']
    if any(not n for n in names):
        raise ElfError('Unnamed ksymtab slot in '+ksymsec)
    return names

def export_crcs(mod: Module) -> list[tuple[str, int, str]]:
    rows = []
    pairs = []
    if '__ksymtab' in mod.sections:
        pairs.append(('__ksymtab', '__kcrctab', 'EXPORT_SYMBOL'))
    if '__ksymtab_gpl' in mod.sections:
        pairs.append(('__ksymtab_gpl', '__kcrctab_gpl', 'EXPORT_SYMBOL_GPL'))
    for tab, crcsec, kind in pairs:
        names = ksymtab_names(mod, tab)
        raw = mod.section(crcsec)
        if len(raw) != 4 * len(names):
            raise ElfError(crcsec+' count mismatch')
        crcs = struct.unpack('<'+'I'*len(names), raw)
        for name, crc in zip(names, crcs):
            rows.append((name, crc, kind))
    return rows

def write_symvers(path: Path, rows: list[tuple[str, int, str]], provider: str) -> None:
    lines = [f'0x{crc:08x}\t{name}\t{provider}\t{kind}\t\n' for name, crc, kind in rows]
    path.write_text(''.join(lines))

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('module', type=Path)
    p.add_argument('--provider', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    mod = Module(a.module.read_bytes())
    rows = export_crcs(mod)
    if a.out.exists():
        raise ValueError('Refusing to overwrite '+str(a.out))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    write_symvers(a.out, rows, a.provider)
    print(f'{a.provider} {len(rows)} exports -> {a.out}')
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        raise SystemExit(str(exc))
