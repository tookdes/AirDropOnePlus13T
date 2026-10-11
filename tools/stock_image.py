#!/usr/bin/env python3
"""Read-only extraction of this project's stock ARM64 boot evidence.

Boot v3/v4 -> uncompressed ARM64 Image -> IKCONFIG, BTF, actual exports.
No ELF patching, no CRC substitution and no module loading. Import CRCs are
cross-checks, never substitutes for an export entry. Image table placement is
checked against the pinned 6.6 vmlinux.lds.h and independent stock modules.
"""
from __future__ import annotations
import argparse
import array
import gzip
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from elf_audit import Module, ElfError, merge_stock
from layout_from_btf import Btf, BtfError, generate

STOCK_MODULES = ('icnss2.ko', 'cnss2.ko', 'cfg80211.ko',
                 'qca_cld3_peach.ko', 'qca_cld3_peach_v2.ko')
ANCHORS = ('_printk', 'module_layout', 'component_add', 'of_find_node_opts_by_path')
IDENT = re.compile(rb'[A-Za-z_][A-Za-z0-9_]*\Z')
NS = re.compile(rb'[A-Za-z0-9_]*\Z')

class EvidenceError(ValueError): pass

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def image_from_boot(boot: bytes) -> tuple[bytes, dict]:
    if len(boot) < 4096 or boot[:8] != b'ANDROID!':
        raise EvidenceError('Not an Android boot image')
    version = struct.unpack_from('<I', boot, 40)[0]
    size = struct.unpack_from('<I', boot, 8)[0]
    hsize = struct.unpack_from('<I', boot, 20)[0]
    if version not in (3, 4) or hsize != {3:1580, 4:1584}[version]:
        raise EvidenceError('Only canonical boot header v3/v4 is supported')
    if size < 64 or 4096 + size > len(boot):
        raise EvidenceError('Truncated kernel payload')
    image = boot[4096:4096+size]
    if image[56:60] != b'ARM\x64':
        raise EvidenceError('Need an uncompressed ARM64 Image; no format guessing')
    memsize = struct.unpack_from('<Q', image, 16)[0]
    if memsize < size or memsize > 1024**3:
        raise EvidenceError('Invalid ARM64 image memory size')
    return image, {'boot_header_version':version, 'kernel_file_offset':4096,
                   'kernel_bytes':size, 'kernel_memory_bytes':memsize,
                   'boot_sha256':sha(boot), 'image_sha256':sha(image)}

def embedded_config(image: bytes) -> tuple[bytes, dict]:
    begin = image.find(b'IKCFG_ST')
    end = image.find(b'IKCFG_ED', begin+8)
    if begin < 0 or end <= begin+8:
        raise EvidenceError('Embedded IKCONFIG not found')
    raw = gzip.decompress(image[begin+8:end])
    if not raw.startswith(b'#') or b'CONFIG_ARM64=y\n' not in raw:
        raise EvidenceError('Embedded config is not the expected ARM64 config')
    return raw, {'image_offset':begin+8, 'compressed_bytes':end-begin-8,
                 'bytes':len(raw), 'sha256':sha(raw)}

def embedded_btf(image: bytes) -> tuple[bytes, dict]:
    valid = []
    for match in re.finditer(b'\x9f\xeb\x01\x00\x18\x00\x00\x00', image):
        offset = match.start()
        if offset+24 > len(image): continue
        _, _, _, hlen, toff, tlen, soff, slen = struct.unpack_from('<HBBIIIII', image, offset)
        size = hlen+max(toff+tlen, soff+slen)
        if offset+size > len(image): continue
        raw = image[offset:offset+size]
        try:
            parsed = Btf(raw)
            layouts = parsed.selected()
        except (ValueError, struct.error):
            continue
        valid.append((raw, {'image_offset':offset, 'bytes':size, 'sha256':sha(raw),
                            'type_count':parsed.type_count, 'layouts':layouts,
                            'layout_variant_ids':{n:[s['id'] for s in parsed.structs[n]]
                                for n in ('platform_device','device','module')}}))
    if len(valid) != 1:
        raise EvidenceError('Need exactly one structurally valid core BTF block')
    return valid[0]

def cstring(data: bytes, offset: int, limit: int=192) -> bytes | None:
    if not 0 <= offset < len(data): return None
    end = data.find(b'\0', offset, min(len(data), offset+limit))
    return data[offset:end] if end >= 0 else None

def export_record(image: bytes, offset: int) -> dict | None:
    if offset < 0 or offset+12 > len(image): return None
    value, name, namespace = struct.unpack_from('<iii', image, offset)
    nameoff, nsoff = offset+4+name, offset+8+namespace
    text, ns = cstring(image, nameoff), cstring(image, nsoff)
    if not text or not IDENT.fullmatch(text) or ns is None or not NS.fullmatch(ns):
        return None
    return {'name':text.decode('ascii'), 'namespace':ns.decode('ascii'),
            'record_offset':offset, 'value_image_offset':offset+value,
            'name_offset':nameoff, 'namespace_offset':nsoff}

def kernel_exports(image: bytes, imports: dict[str,int]) -> tuple[list[dict], dict]:
    targets: dict[int,str] = {}
    for name in ANCHORS:
        for hit in re.finditer(rb'(?<=\x00)'+name.encode()+b'\0', image):
            targets[hit.start()] = name
    words = array.array('i')
    if words.itemsize != 4: raise EvidenceError('Host must provide 32-bit array ints')
    words.frombytes(image[:len(image)//4*4])
    if sys.byteorder != 'little': words.byteswap()
    candidates = set()
    for i, rel in enumerate(words):
        offset = i*4
        if offset+rel in targets and export_record(image, offset-4):
            candidates.add(offset-4)
    del words
    bounds = set()
    for off in candidates:
        start, end = off, off+12
        while export_record(image, start-12): start -= 12
        while export_record(image, end): end += 12
        if end-start >= 128*12: bounds.add((start,end))
    if len(bounds) != 1:
        raise EvidenceError('Ambiguous or absent PREL32 export table')
    start, end = bounds.pop()
    records = [export_record(image, o) for o in range(start,end,12)]
    names = [r['name'] for r in records]
    if len(set(names)) != len(names) or not set(ANCHORS).issubset(names):
        raise EvidenceError('Invalid export table anchors or duplicate names')
    # The pinned linker script places two individually sorted export tables,
    # then two corresponding u32 CRC tables, then the shared string table.
    splits = [i for i in range(1,len(names)) if names[i] <= names[i-1]]
    if len(splits) != 1:
        raise EvidenceError('Cannot prove normal/GPL table boundary')
    split = splits[0]
    strings_start = min(min(r['name_offset'],r['namespace_offset']) for r in records)
    crc_end = end+4*len(records)
    if crc_end != strings_start or crc_end > len(image):
        raise EvidenceError('CRC/table/string geometry does not match pinned linker script')
    matched = []
    for i, r in enumerate(records):
        crc = struct.unpack_from('<I',image,end+4*i)[0]
        r.update(crc=f'0x{crc:08x}', crc_offset=end+4*i,
                 export_type='EXPORT_SYMBOL' if i<split else 'EXPORT_SYMBOL_GPL',
                 provider='vmlinux')
        if r['name'] in imports:
            if crc != imports[r['name']]:
                raise EvidenceError('Stock import disagrees with boot export: '+r['name'])
            matched.append(r['name'])
    if len(matched) < 32 or not {'_printk','module_layout'}.issubset(matched):
        raise EvidenceError('Insufficient independent import/export cross-checks')
    return records, {'ksymtab_offset':start,'normal_count':split,
                     'gpl_count':len(records)-split,'export_count':len(records),
                     'kcrctab_offset':end,'strings_offset':strings_start,
                     'matched_stock_import_count':len(matched),
                     'matched_stock_imports':matched,
                     'mismatches':[], 'format':'ARM64 PREL32 / absolute u32 CRC'}

def module_exports(path: Path) -> list[dict]:
    mod = Module(path.read_bytes())
    if mod.machine != 183: raise EvidenceError('Not an AArch64 stock module')
    h = mod.sections['.symtab']; sh = mod.headers[h[6]]
    strings = mod.take(sh[4], sh[5]); syms=[]
    for o in range(h[4],h[4]+h[5],24):
        name, info, other, idx, value, size=struct.unpack_from('<IBBHQQ',mod.data,o)
        syms.append({'name':mod.string(strings,name),'index':idx,'value':value})
    result=[]
    for section, crcsection, etype in (('__ksymtab','__kcrctab','EXPORT_SYMBOL'),
                                      ('__ksymtab_gpl','__kcrctab_gpl','EXPORT_SYMBOL_GPL')):
        if section not in mod.sections: continue
        kh=mod.sections[section]; ki=mod.headers.index(kh)
        if kh[5] % 12: raise EvidenceError('Unexpected module export record width')
        crcdata=mod.section(crcsection)
        if len(crcdata) != kh[5]//12*4: raise EvidenceError('Module export/CRC counts differ')
        reloc={}
        for rh in mod.headers:
            if rh[1]!=4 or rh[7]!=ki: continue
            if rh[9]!=24 or rh[5]%24: raise EvidenceError('Unexpected RELA record width')
            for o in range(rh[4],rh[4]+rh[5],24):
                roff,rinfo,addend=struct.unpack_from('<QQq',mod.data,o)
                if (rinfo & 0xffffffff)!=261: raise EvidenceError('Export relocation is not R_AARCH64_PREL32')
                si=rinfo>>32
                if si>=len(syms) or roff in reloc: raise EvidenceError('Invalid or duplicate export relocation')
                reloc[roff]=(syms[si],addend)
        def read_rel_string(roff):
            if roff not in reloc: raise EvidenceError('Missing export string relocation')
            sym,add=reloc[roff]
            if not 0<sym['index']<len(mod.headers): raise EvidenceError('Export string section invalid')
            sh=mod.headers[sym['index']]
            return mod.string(mod.take(sh[4],sh[5]),sym['value']+add)
        group=[]
        for off in range(0,kh[5],12):
            name,namespace=read_rel_string(off+4),read_rel_string(off+8)
            if not IDENT.fullmatch(name.encode()) or not NS.fullmatch(namespace.encode()):
                raise EvidenceError('Malformed module export name/namespace')
            crc=struct.unpack_from('<I',crcdata,off//12*4)[0]
            group.append({'name':name,'namespace':namespace,'crc':f'0x{crc:08x}',
                          'export_type':etype,'provider':path.stem,
                          'section':section,'record_offset':off,
                          'provider_sha256':mod.sha256})
        if [r['name'] for r in group] != sorted(r['name'] for r in group):
            raise EvidenceError('Module export order is not sorted')
        result+=group
    return result

def write_symvers(path: Path, records: list[dict]) -> None:
    names = [r['name'] for r in records]
    if len(names)!=len(set(names)): raise EvidenceError('Duplicate providers in export evidence')
    path.write_text(''.join(f"{r['crc']}\t{r['name']}\t{r['provider']}\t{r['export_type']}\t{r['namespace']}\n"
                           for r in sorted(records,key=lambda r:r['name'])))

def extract(inputs: Path, output: Path, layout_header: Path | None=None) -> dict:
    inputs=inputs.resolve(); output=output.resolve()
    if inputs==output or output.is_relative_to(inputs) or inputs.is_relative_to(output):
        raise EvidenceError('Input and output directories must not overlap')
    output.mkdir(parents=True,exist_ok=True)
    manifest=[]
    for p in sorted(inputs.iterdir()):
        if p.is_symlink(): raise EvidenceError('Evidence symlinks are not accepted')
        if p.is_file():
            data=p.read_bytes()
            kind=('stock_module' if p.name in STOCK_MODULES else
                  'deliberately_modified_negative_control' if p.name in ('icnss2_badcrc.ko','icnss2_bogusvm.ko') else
                  'supporting_input')
            manifest.append({'name':p.name,'bytes':len(data),'sha256':sha(data),'role':kind})
    mods=[inputs/n for n in STOCK_MODULES]
    imports=merge_stock(mods, inputs/'icnss2_versions.json')
    boot=(inputs/'boot_a.img').read_bytes(); image,bootinfo=image_from_boot(boot)
    cfg,cfginfo=embedded_config(image)
    if cfg != (inputs/'kconfig.txt').read_bytes():
        raise EvidenceError('Captured config differs from boot IKCONFIG')
    btf,btfinfo=embedded_btf(image)
    core,exportinfo=kernel_exports(image,imports)
    extra=[]; summaries=[]
    for p in mods:
        m=Module(p.read_bytes()); exports=module_exports(p); extra+=exports
        summaries.append({'name':p.name,'sha256':m.sha256,'import_count':len(m.versions()),
                          'export_count':len(exports),'modinfo':m.modinfo()})
    all_exports=core+extra
    byname={r['name']:r for r in all_exports}
    if len(byname)!=len(all_exports):raise EvidenceError('Conflicting stock export providers')
    cross=0
    for name,crc in imports.items():
        if name in byname:
            if int(byname[name]['crc'],16)!=crc: raise EvidenceError('Provider/import CRC conflict: '+name)
            cross+=1
    for fname,data in [('Image',image),('vmlinux.btf',btf),('boot.config',cfg)]:
        (output/fname).write_bytes(data)
    write_symvers(output/'vmlinux.exports.symvers',core)
    write_symvers(output/'captured-providers.exports.symvers',all_exports)
    (output/'exports.json').write_text(json.dumps(all_exports,indent=2)+'\n')
    (output/'import-crc-union.json').write_text(json.dumps(
        [{'sym':n,'crc':f'0x{c:08x}'} for n,c in sorted(imports.items())],indent=2)+'\n')
    (output/'input-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    if layout_header:generate(output/'vmlinux.btf',inputs/'kconfig.txt',layout_header)
    needs=['component_add','component_del','component_master_add_with_match','component_master_del',
           'component_bind_all','component_unbind_all','component_match_add_release','of_find_node_opts_by_path',
           'of_add_property','of_remove_property','of_find_device_by_node','platform_device_alloc',
           'platform_device_add','platform_device_unregister','platform_device_put',
           'try_module_get','module_put','cnss_set_vendor_wonder_priv_data',
           'ieee80211_alloc_hw_nm','ieee80211_register_hw','ieee80211_rx_napi']
    report={'schema':1,'boot':bootinfo,'config':cfginfo,'config_byte_equal':True,'btf':btfinfo,
            'kernel_exports':exportinfo,'stock_modules':summaries,'import_union_count':len(imports),
            'captured_provider_exports':len(all_exports),'crosschecked_imports':cross,
            'imports_without_captured_provider':sorted(set(imports)-byname.keys()),
            'requested_export_checks':{n:byname.get(n) for n in needs},
            'negative_controls_excluded':True,'target_build_executed':False,'phone_accessed':False,
            'scope':'Read-only shipping-image evidence. Actual exports only in symvers; unknown providers not invented.'}
    (output/'extraction-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('inputs',type=Path)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--layout-header',type=Path)
    a=p.parse_args()
    try:r=extract(a.inputs,a.output,a.layout_header)
    except (OSError,ValueError,struct.error) as exc:p.exit(1,str(exc)+'\n')
    print(json.dumps({k:r[k] for k in ('boot','config_byte_equal','btf','import_union_count',
                                       'captured_provider_exports','crosschecked_imports')},indent=2))
if __name__=='__main__':main()
