#!/usr/bin/env python3
"""Read-only stock RF interface inventory. Never loads modules or modifies ELF/CRCs.

An interface inventory is not firmware/RF proof. In particular, monitor RX,
management TX, and Ethernet offload are not a bidirectional raw-data backend.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from elf_audit import Module, ElfError
from audit_mac80211_ops import full_symbols
from layout_from_btf import Btf
from stock_image import module_exports

VENDOR_SIZE = 56  # Reference includes ANDROID_KABI_RESERVE(1).
VENDOR_RAW_POLICY = (1 << 64) - 61  # (long)-ENODATA, not -1.
VENDOR_ID = 0x1374


def object_symbol(mod: Module, name: str, size: int | None = None) -> dict:
    hits = [s for s in full_symbols(mod) if s['name'] == name and s['type'] == 1
            and (size is None or s['size'] == size)]
    if len(hits) != 1:
        raise ElfError('Missing or ambiguous object: ' + name)
    s = hits[0]
    if not 0 < s['index'] < len(mod.headers) or not s['size']:
        raise ElfError('Invalid object: ' + name)
    h = mod.headers[s['index']]
    if h[1] == 8 or s['value'] > h[5] or s['size'] > h[5] - s['value']:
        raise ElfError('Object is outside file-backed section: ' + name)
    return s


def object_relocations(mod: Module, target: dict) -> list[dict]:
    """Resolve ABS64 data/function/section references in one bounded object."""
    syms = full_symbols(mod)
    if mod.sections['.symtab'][1] != 2:
        raise ElfError('Expected SHT_SYMTAB for object relocations')
    symtab_index = mod.headers.index(mod.sections['.symtab'])
    functions = {}
    objects = {}
    for s in syms:
        if s['type'] == 2 and s['size']:
            functions.setdefault((s['index'], s['value']), []).append(s)
        if s['type'] == 1 and s['size']:
            objects.setdefault((s['index'], s['value']), []).append(s)
    rows = []
    seen = set()
    for h in mod.headers:
        if h[1] not in (4, 9) or h[7] != target['index']:
            continue
        if h[1] != 4 or h[9] != 24 or h[5] % 24 or h[6] != symtab_index:
            raise ElfError('Invalid RELA section for object')
        for p in range(h[4], h[4] + h[5], 24):
            place, info, addend = struct.unpack_from('<QQq', mod.data, p)
            end = target['value'] + target['size']
            if place < target['value'] and place + 8 > target['value']:
                raise ElfError('Relocation partially overlaps object start')
            if not target['value'] <= place < end:
                continue
            offset = place - target['value']
            if offset % 8 or offset + 8 > target['size'] or offset in seen or info & 0xffffffff != 257:
                raise ElfError('Unaligned, duplicate, out-of-range or non-ABS64 relocation')
            seen.add(offset)
            idx = info >> 32
            if idx >= len(syms):
                raise ElfError('Relocation symbol outside symtab')
            ref = syms[idx]
            if not 0 < ref['index'] < len(mod.headers):
                raise ElfError('Relocation references undefined/special symbol')
            section = mod.headers[ref['index']]
            address = ref['value'] + addend
            if not 0 <= address < section[5]:
                raise ElfError('Relocation address outside referenced section')
            name = ref['name']
            is_function = bool(section[2] & 4)
            if is_function:
                if section[1] == 8:
                    raise ElfError('Callback points to executable NOBITS section')
                if ref['type'] == 2 and addend == 0:
                    fn = ref
                else:
                    hits = functions.get((ref['index'], address), [])
                    if len(hits) != 1:
                        raise ElfError('Cannot resolve executable relocation uniquely')
                    fn = hits[0]
                if not fn['name'] or not fn['size'] or fn['size'] > section[5] - address:
                    raise ElfError('Invalid callback function')
                name = fn['name']
            elif ref['type'] == 3:
                hits = objects.get((ref['index'], address), [])
                name = hits[0]['name'] if len(hits) == 1 else f'SECTION_{ref["index"]}+0x{address:x}'
            rows.append({'offset': offset, 'symbol': name, 'function': is_function,
                         'referenced_section_index': ref['index'], 'addend': addend})
    return sorted(rows, key=lambda r: r['offset'])


def netdev_table(mod: Module, name: str, size: int, xmit_offset: int) -> dict:
    target = object_symbol(mod, name, size)
    if not 0 <= xmit_offset <= size - 8 or xmit_offset % 8:
        raise ElfError('Invalid ndo_start_xmit offset')
    h = mod.headers[target['index']]
    raw = mod.take(h[4] + target['value'], target['size'])
    if any(raw):
        raise ElfError('Unexpected nonzero unrelocated net_device_ops bytes')
    rows = object_relocations(mod, target)
    if any(not r['function'] for r in rows):
        raise ElfError('net_device_ops points to non-executable data')
    return {'symbol': name, 'size': size,
            'callbacks': [{'offset': r['offset'], 'symbol': r['symbol']} for r in rows],
            'ndo_start_xmit': [r['symbol'] for r in rows if r['offset'] == xmit_offset]}


def vendor_names(text: str) -> dict[int, list[str]]:
    match = re.search(r'enum\s+qca_nl80211_vendor_subcmds\s*\{(.*?)\};', text, re.S)
    if not match:
        raise ElfError('Missing QCA vendor subcommand enum')
    body = re.sub(r'/\*.*?\*/', '', match.group(1), flags=re.S)
    body = re.sub(r'//[^\n]*', '', body)
    result = {}
    for name, value in re.findall(r'\b((?:QCA|OPLUS)_NL80211_VENDOR_SUBCMD_[A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*[,\n]', body):
        number = int(value, 0) if value.lower().startswith('0x') else int(value, 10)
        result.setdefault(number, []).append(name)
    if not result:
        raise ElfError('No literal QCA vendor subcommands parsed')
    return result


def vendor_commands(mod: Module, names: dict[int, list[str]]) -> dict:
    target = object_symbol(mod, 'hdd_wiphy_vendor_commands')
    if target['size'] % VENDOR_SIZE:
        raise ElfError('Vendor command array does not match 56-byte reference layout')
    h = mod.headers[target['index']]
    raw = mod.take(h[4] + target['value'], target['size'])
    rows = object_relocations(mod, target)
    relocated = {r['offset']: r for r in rows}
    commands = []
    for off in range(0, target['size'], VENDOR_SIZE):
        vendor, subcmd, flags = struct.unpack_from('<III', raw, off)
        doit, dumpit, policy = struct.unpack_from('<QQQ', raw, off + 16)
        maxattr = struct.unpack_from('<I', raw, off + 40)[0]
        if any(raw[off + 12:off + 16]) or any(raw[off + 44:off + 56]):
            raise ElfError('Unexpected vendor padding/KABI reserve bytes')
        if vendor != VENDOR_ID or flags & ~7 or doit or dumpit:
            raise ElfError('Vendor table prefix/pointer layout validation failed')
        callbacks = {}
        for field, slot in (('doit', 16), ('dumpit', 24)):
            ref = relocated.get(off + slot)
            if ref:
                if not ref['function']:
                    raise ElfError('Vendor handler is not executable')
                callbacks[field] = ref['symbol']
        if not callbacks:
            raise ElfError('Vendor command has no resolved handler')
        policy_ref = relocated.get(off + 32)
        if policy_ref and (policy_ref['function'] or policy):
            raise ElfError('Vendor policy is executable or has conflicting raw pointer bytes')
        if policy not in (0, VENDOR_RAW_POLICY):
            raise ElfError('Unexpected unrelocated vendor policy pointer')
        if any(r['offset'] // VENDOR_SIZE == off // VENDOR_SIZE
               and r['offset'] % VENDOR_SIZE not in (16, 24, 32) for r in rows):
            raise ElfError('Unexpected relocation in vendor record')
        commands.append({'vendor_id': vendor, 'subcmd': subcmd, 'names': names.get(subcmd, []),
                         'flags': flags, **callbacks,
                         'policy': policy_ref['symbol'] if policy_ref else
                         ('RAW_DATA' if policy == VENDOR_RAW_POLICY else None),
                         'maxattr': maxattr})
    ids = [(c['vendor_id'], c['subcmd']) for c in commands]
    if len(ids) != len(set(ids)):
        raise ElfError('Duplicate vendor/subcommand record')
    return {'object_bytes': target['size'], 'entry_bytes': VENDOR_SIZE,
            'layout_scope': 'Reference 56-byte layout including KABI reserve validated against every captured entry and pointer relocation; not complete wiphy ABI proof.',
            'count': len(commands), 'commands': commands,
            'unmapped_subcmds': [c['subcmd'] for c in commands if not c['names']]}


def cfg_callbacks(mod: Module) -> dict:
    target = object_symbol(mod, 'wlan_hdd_cfg80211_ops')
    h = mod.headers[target['index']]
    if any(mod.take(h[4] + target['value'], target['size'])):
        raise ElfError('Unexpected nonzero cfg80211_ops data')
    rows = object_relocations(mod, target)
    if any(not r['function'] for r in rows):
        raise ElfError('cfg80211_ops points to non-executable data')
    return {'object_bytes': target['size'],
            'callbacks': [{'offset': r['offset'], 'symbol': r['symbol']} for r in rows]}



# Exact fingerprint of the captured 13T cfg80211 management-frame guard.
# This is deliberately not a heuristic disassembler or a universal kernel rule.
MGMT_GUARD_WORDS = {
    0x00: 0xd503233f,  # paciasp
    0x04: 0xa9bb7bfd,  # stp x29, x30, [sp, #-0x50]!
    0x08: 0xf9000bf9,  # str x25, [sp, #0x10]
    0x0c: 0xa9025ff8,  # stp x24, x23, [sp, #0x20]
    0x10: 0xa90357f6,  # stp x22, x21, [sp, #0x30]
    0x14: 0xa9044ff4,  # stp x20, x19, [sp, #0x40]
    0x18: 0x910003fd,  # mov x29, sp
    0x1c: 0xf9400028,  # ldr x8, [x1]
    0x20: 0xf9402508,  # ldr x8, [x8, #0x48] (mgmt_stypes)
    0x24: 0xb40001e8,  # cbz x8, +0x60 (-EOPNOTSUPP)
    0x28: 0xf9400009,  # ldr x9, [x0]
    0x2c: 0xaa0003f6,  # mov x22, x0
    0x30: 0xf9410529,  # ldr x9, [x9, #0x208] (mgmt_tx)
    0x34: 0xb4000169,  # cbz x9, +0x60 (-EOPNOTSUPP)
    0x38: 0xf9400c49,  # ldr x9, [x2, #0x18] (params->len)
    0x3c: 0xaa0203f4,  # mov x20, x2
    0x40: 0xf100653f,  # cmp x9, #25
    0x44: 0x540000a3,  # b.lo +0x58 (-EINVAL)
    0x48: 0xf9400a99,  # ldr x25, [x20, #0x10] (params->buf)
    0x4c: 0x79400329,  # ldrh w9, [x25] (frame control)
    0x50: 0x721e053f,  # tst w9, #0x000c (frame type mask)
    0x54: 0x54000180,  # b.eq +0x84 (management path)
    0x58: 0x128002b8,  # mov w24, #-22
    0x5c: 0x14000002,  # b +0x64 (return path)
    0x60: 0x12800bd8,  # mov w24, #-95 (unavailable-callback path)
    0x64: 0x2a1803e0,  # mov w0, w24
    0x68: 0xa9444ff4,  # ldp x20, x19, [sp, #0x40]
    0x6c: 0xf9400bf9,  # ldr x25, [sp, #0x10]
    0x70: 0xa94357f6,  # ldp x22, x21, [sp, #0x30]
    0x74: 0xa9425ff8,  # ldp x24, x23, [sp, #0x20]
    0x78: 0xa8c57bfd,  # ldp x29, x30, [sp], #0x50
    0x7c: 0xd50323bf,  # autiasp
    0x80: 0xd65f03c0,  # ret
}


def management_tx_guard(mod: Module) -> dict:
    """Verify the known stock data-frame rejection path; fail on other builds."""
    if mod.machine != 183:
        raise ElfError('Management TX guard requires an AArch64 module')
    if mod.sections.get('.symtab', (0, 0))[1] != 2:
        raise ElfError('Expected SHT_SYMTAB for management TX guard')
    hits = [s for s in full_symbols(mod) if s['name'] == 'cfg80211_mlme_mgmt_tx'
            and s['type'] == 2 and s['size']]
    if len(hits) != 1:
        raise ElfError('Missing or ambiguous cfg80211 management TX function')
    fn = hits[0]
    if not 0 < fn['index'] < len(mod.headers):
        raise ElfError('Management TX function is undefined/special')
    h = mod.headers[fn['index']]
    if h[1] == 8 or not h[2] & 4 or fn['value'] > h[5] or fn['size'] > h[5] - fn['value']:
        raise ElfError('Management TX function is outside executable file data')
    if fn['value'] % 4 or fn['size'] < 0x88:
        raise ElfError('Truncated or unaligned management TX function')
    raw = mod.take(h[4] + fn['value'], fn['size'])
    for offset, word in MGMT_GUARD_WORDS.items():
        if struct.unpack_from('<I', raw, offset)[0] != word:
            raise ElfError(f'Unknown management TX guard at +0x{offset:x}; do not infer raw TX capability')
    # Reject text fixups in the fingerprint/return path. Kernel loading must not
    # rewrite instructions on which this specific offline conclusion depends.
    for rel in mod.headers:
        if rel[1] not in (4, 9) or rel[7] != fn['index']:
            continue
        if rel[1] != 4 or rel[9] != 24 or rel[5] % 24:
            raise ElfError('Invalid management TX text RELA section')
        for pos in range(rel[4], rel[4] + rel[5], 24):
            place = struct.unpack_from('<Q', mod.data, pos)[0]
            if fn['value'] <= place < fn['value'] + 0x84:
                raise ElfError('Management TX guard has text relocations')
    return {'module_sha256': mod.sha256, 'symbol': fn['name'],
            'function_section_offset': fn['value'], 'function_bytes': fn['size'],
            'fingerprint_scope': 'Exact captured 13T instruction sequence only, not arbitrary cfg80211 builds.',
            'minimum_frame_bytes': 25, 'frame_type_mask': 12,
            'accepted_frame_type': 0, 'non_management_result': -22,
            'data_frame_tx_rejected': True,
            'return_scope': 'Non-management frames return -22 when the callback is available; unavailable callbacks return -95 before reaching the frame guard.',
            'verified_instruction_words': {f'0x{k:x}': f'0x{v:08x}' for k, v in MGMT_GUARD_WORDS.items()}}


def audit(qcacld: Path, cnss: Path, stock_btf: Path, vendor_header: Path,
          cfg80211: Path | None = None) -> dict:
    qca = Module(qcacld.read_bytes())
    bridge = Module(cnss.read_bytes())
    if qca.machine != 183 or bridge.machine != 183:
        raise ElfError('Expected captured AArch64 modules')
    btf = Btf(stock_btf.read_bytes())
    size = btf.same_size('net_device_ops')
    xmit = btf.member_offset('net_device_ops', 'ndo_start_xmit')
    normal = netdev_table(qca, 'wlan_drv_ops', size, xmit)
    monitor = netdev_table(qca, 'wlan_mon_drv_ops', size, xmit)
    if normal['ndo_start_xmit'] != ['hdd_hard_start_xmit']:
        raise ElfError('Station TX positive control does not match stock BTF slot')
    qexports = module_exports(qcacld)
    cexports = module_exports(cnss)
    qsymbols = full_symbols(qca)
    bridge_symbols = full_symbols(bridge)
    related = sorted({s['name'] for s in qsymbols + bridge_symbols
                      if re.search(r'wonder|passthru|passthrough', s['name'], re.I)})
    needed = ('hdd_open_adapter', 'hdd_start_adapter', 'ucfg_dp_passthrough_register_txrx_ops',
              'cnss_set_vendor_wonder_priv_data')
    exported = {r['name'] for r in qexports + cexports}
    defined = {s['name'] for mod, symbols in ((qca, qsymbols), (bridge, bridge_symbols))
               for s in symbols if s['type'] == 2 and 0 < s['index'] < len(mod.headers)
               and mod.headers[s['index']][2] & 4 and s['size']}
    return {'schema': 2, 'status': 'OFFLINE_RF_INTERFACE_INVENTORY_COMPLETE_RUNTIME_RF_GATE_NOT_PASSED',
            'vendor_header_sha256': hashlib.sha256(vendor_header.read_bytes()).hexdigest(),
            'management_tx_guard': management_tx_guard(Module(cfg80211.read_bytes())) if cfg80211 else None,
            'qcacld_sha256': qca.sha256, 'cnss_sha256': bridge.sha256, 'stock_btf_sha256': btf.sha256,
            'net_device_ops_size': size, 'ndo_start_xmit_offset': xmit,
            'normal_station_positive_control': normal, 'stock_monitor': monitor,
            'qcacld_actual_export_count': len(qexports), 'cnss_actual_export_count': len(cexports),
            'wonder_passthru_symbol_names': related,
            'donor_helper_visibility': [{'function': n, 'defined': n in defined, 'exported': n in exported} for n in needed],
            'cfg80211_callbacks': cfg_callbacks(qca),
            'vendor_commands': vendor_commands(qca, vendor_names(vendor_header.read_text(encoding='utf-8-sig'))),
            'normal_monitor_ndo_start_xmit_present': bool(monitor['ndo_start_xmit']),
            'normal_monitor_raw_tx_available': None if monitor['ndo_start_xmit'] else False,
            'module_only_donor_backend_entrypoint_exported': 'cnss_set_vendor_wonder_priv_data' in exported,
            'radio_gate_passed': False, 'firmware_passthru_capability': 'NOT_PROVEN',
            'no_phone_operations_or_binary_writes': True,
            'limitations': ['Inventory is not complete absence-of-all-possible-vendor-paths proof.',
                            'Command names, management TX presence or a non-null ndo_start_xmit are not raw data TX proof.',
                            'No firmware services, RF reception/transmission, channel coexistence or AirDrop test.']}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qcacld', type=Path, required=True)
    p.add_argument('--cnss', type=Path, required=True)
    p.add_argument('--stock-btf', type=Path, required=True)
    p.add_argument('--vendor-header', type=Path, required=True)
    p.add_argument('--cfg80211', type=Path, help='Optional captured cfg80211.ko; verifies the exact 13T management-frame guard')
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    # Refuse to overwrite any evidence input with a report.
    inputs = (args.qcacld, args.cnss, args.stock_btf, args.vendor_header)
    evidence_inputs = inputs + ((args.cfg80211,) if args.cfg80211 else ())
    if args.out.suffix.lower() != '.json':
        raise ElfError('Report output must be a JSON file')
    if args.out.resolve() in {s.resolve() for s in evidence_inputs} or any(
            args.out.exists() and s.exists() and args.out.samefile(s) for s in evidence_inputs):
        raise ElfError('Report output overlaps an evidence input')
    result = audit(*inputs, cfg80211=args.cfg80211)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('status', 'qcacld_actual_export_count',
                                          'normal_monitor_raw_tx_available', 'radio_gate_passed')}, indent=2))
    print('Captured vendor commands:', result['vendor_commands']['count'])
    print('Unmapped IDs:', result['vendor_commands']['unmapped_subcmds'])
    print('Report:', args.out)
    # Success means extraction completed, never RF readiness.
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, struct.error) as exc:
        raise SystemExit(str(exc))
