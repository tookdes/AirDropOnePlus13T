#!/usr/bin/env python3
"""Read uncompressed ELF64-LE kernel modules. Never modifies CRCs or binaries."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

class ElfError(ValueError):
    pass

class Module:
    def __init__(self, data: bytes):
        self.data = data
        self.sha256 = hashlib.sha256(data).hexdigest()
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
            raise ElfError('Expected an uncompressed ELF64 little-endian file')
        fields = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        self.type, self.machine = fields[:2]
        if self.type != 1:
            raise ElfError('Expected ET_REL, not an executable or firmware blob')
        off, entrysize, count, names_idx = fields[5], fields[10], fields[11], fields[12]
        if not count or entrysize != 64 or names_idx >= count:
            raise ElfError('Invalid or unsupported section table')
        self.take(off, count * entrysize)
        headers = [struct.unpack_from('<IIQQQQIIQQ', data, off+i*entrysize) for i in range(count)]
        names = self.take(headers[names_idx][4], headers[names_idx][5])
        self.sections = {}
        self.headers = headers
        for h in headers:
            name = self.string(names, h[0])
            if name in self.sections:
                raise ElfError('Duplicate section name: '+name)
            if h[1] != 8:  # SHT_NOBITS has no file data.
                self.take(h[4], h[5])
            self.sections[name] = h

    def take(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > len(self.data) or length > len(self.data)-offset:
            raise ElfError('Section exceeds file bounds')
        return self.data[offset:offset+length]

    @staticmethod
    def string(data: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(data):
            raise ElfError('String offset out of bounds')
        end = data.find(b'\0', offset)
        if end < 0:
            raise ElfError('Missing string terminator')
        try:
            return data[offset:end].decode('ascii')
        except UnicodeDecodeError as exc:
            raise ElfError('Non-ASCII ELF string') from exc

    def section(self, name: str) -> bytes:
        if name not in self.sections:
            raise ElfError('Missing section: '+name)
        h = self.sections[name]
        if h[1] == 8:
            raise ElfError('Cannot read NOBITS as file content')
        return self.take(h[4], h[5])

    def modinfo(self) -> dict[str, list[str]]:
        values = {}
        for record in self.section('.modinfo').split(b'\0'):
            if not record:
                continue
            text = record.decode('utf-8')
            if '=' not in text:
                raise ElfError('Malformed .modinfo')
            key, val = text.split('=', 1)
            values.setdefault(key, []).append(val)
        return values

    def versions(self) -> dict[str, int]:
        data = self.section('__versions')
        if not data or len(data) % 64:
            raise ElfError('Expected nonempty basic MODVERSIONS entries, 64 bytes each')
        result = {}
        for offset in range(0, len(data), 64):
            crc, = struct.unpack_from('<Q', data, offset)
            sym = self.string(data[offset+8:offset+64], 0)
            if not sym or sym in result or crc > 0xffffffff:
                raise ElfError('Invalid or duplicate MODVERSIONS record')
            result[sym] = crc
        return result

    def symbols(self) -> list[dict]:
        h = self.sections.get('.symtab')
        if not h or h[9] != 24 or h[5] % 24 or h[6] >= len(self.headers):
            raise ElfError('Invalid or missing .symtab')
        sh = self.headers[h[6]]
        strings = self.take(sh[4], sh[5])
        records = []
        for off in range(h[4], h[4]+h[5], 24):
            name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', self.data, off)
            records.append({'name':self.string(strings,name),'binding':info>>4,
                            'type':info&15,'index':index})
        return records

    def describe(self) -> dict:
        versions = self.versions()
        symbols = self.symbols()
        return {'sha256':self.sha256,'machine':self.machine,'type':self.type,
                'modinfo':self.modinfo(),
                'versions':{k:f'0x{v:08x}' for k,v in sorted(versions.items())},
                'undefined_strong':sorted(s['name'] for s in symbols if s['index']==0 and s['binding']==1 and s['name']),
                'undefined_weak':sorted(s['name'] for s in symbols if s['index']==0 and s['binding']==2 and s['name']),
                'kcfi_symbols':[s['name'] for s in symbols if s['name'].startswith('__kcfi_typeid_')],
                'kcfi_traps_present':'.kcfi_traps' in self.sections,
                'kcfi_note':'Presence or absence of these markers alone does not prove KCFI compatibility'}

def merge_stock(paths: list[Path], baseline: Path | None = None) -> dict[str,int]:
    result = {}
    def add(sym, crc):
        if not isinstance(sym, str) or not sym or not sym.isascii() or "\0" in sym:
            raise ElfError('Invalid captured stock symbol name')
        if type(crc) is not int or not 0 <= crc <= 0xffffffff:
            raise ElfError('Captured CRC is outside its 32-bit range: '+sym)
        if sym in result and result[sym] != crc:
            raise ElfError('Conflicting captured stock CRC: '+sym)
        result[sym] = crc
    if baseline:
        for row in json.loads(baseline.read_text()):
            add(row['sym'], int(row['crc'],16))
    for path in paths:
        module = Module(path.read_bytes())
        if module.machine != 183:
            raise ElfError('Stock baseline is not ARM64: '+str(path))
        for sym,crc in module.versions().items():
            add(sym,crc)
    return result

def audit(path: Path, expected: dict[str,int]) -> dict:
    mod=Module(path.read_bytes()); desc=mod.describe(); versions=mod.versions()
    errors=[]
    if mod.machine!=183: errors.append('Not AArch64 (e_machine != 183)')
    if 'module_layout' not in versions: errors.append('Missing module_layout CRC')
    for sym in desc['undefined_strong']:
        if sym not in versions: errors.append('Strong import has no version: '+sym)
    for sym,crc in versions.items():
        if sym not in expected: errors.append('No captured stock CRC evidence: '+sym)
        elif expected[sym] != crc: errors.append('CRC mismatch: '+sym)
    desc['errors']=errors
    desc['captured_crc_check_passed']=not errors
    desc['target_loadability_proven']=False
    desc['not_covered']=['KCFI call-site type agreement','target struct layout','trimmed export availability',
                         'GPL/namespaced export policy','firmware','live insmod/rmmod']
    return desc

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('module',type=Path)
    p.add_argument('--baseline',type=Path)
    p.add_argument('--stock-module',type=Path,action='append',default=[])
    p.add_argument('--inspect-only',action='store_true')
    args=p.parse_args()
    result=(Module(args.module.read_bytes()).describe() if args.inspect_only else
            audit(args.module,merge_stock(args.stock_module,args.baseline)))
    print(json.dumps(result,indent=2))
    return 0 if args.inspect_only or result['captured_crc_check_passed'] else 1
if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,ValueError,KeyError,struct.error) as exc: raise SystemExit(str(exc))
