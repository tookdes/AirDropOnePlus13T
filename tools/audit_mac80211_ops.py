#!/usr/bin/env python3
"""Read-only ARM64 Wonder callback-slot audit; never changes module bytes/CRCs.

Offsets are for the pinned 13T mac80211.h with CONFIG_PM=y,
CONFIG_MAC80211_DEBUGFS=n and CONFIG_NL80211_TESTMODE=y. Stock alloc_hw_nm
checks wake_tx_queue at 0x2f0; stock mac80211 has testmode cmd/dump functions.
This checks initialized callbacks, not the entire driver ABI or live safety.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from elf_audit import Module, ElfError

# (ieee80211_ops member, pinned Wonder callback, byte offset)
EXPECTED_CALLBACKS = (
    ('tx', 'wonder_tx', 0x000),
    ('start', 'wonder_start', 0x008),
    ('stop', 'wonder_stop', 0x010),
    ('add_interface', 'wonder_add_interface', 0x030),
    ('remove_interface', 'wonder_remove_interface', 0x040),
    ('config', 'wonder_config', 0x048),
    ('configure_filter', 'wonder_configure_filter', 0x080),
    ('set_rts_threshold', 'wonder_set_rts_threshold', 0x100),
    ('sta_add', 'wonder_sta_add', 0x108),
    ('sta_remove', 'wonder_sta_remove', 0x110),
    ('sta_notify', 'wonder_sta_notify', 0x118),
    ('sta_set_txpwr', 'wonder_sta_set_txpwr', 0x120),
    ('sta_pre_rcu_remove', 'wonder_sta_pre_rcu_remove', 0x130),
    ('sta_rate_tbl_update', 'wonder_sta_rate_tbl_update', 0x140),
    ('sta_statistics', 'wonder_sta_statistics', 0x148),
    ('tx_last_beacon', 'wonder_tx_last_beacon', 0x178),
    ('ampdu_action', 'wonder_ampdu_action', 0x180),
    ('flush', 'wonder_flush', 0x1b0),
    ('flush_sta', 'wonder_flush_sta', 0x1b8),
    ('channel_switch', 'wonder_channel_switch', 0x1c0),
    ('wake_tx_queue', 'wonder_wake_tx_queue', 0x2f0),
    ('start_nan', 'wonder_start_nan', 0x300),
    ('stop_nan', 'wonder_stop_nan', 0x308),
    ('add_nan_func', 'wonder_add_nan_func', 0x318),
    ('del_nan_func', 'wonder_del_nan_func', 0x320),
    ('can_aggregate_in_amsdu', 'wonder_amsdu_sanity', 0x328),
)


def compile_time_assertions() -> str:
    """Validate the compiler's actual header layout before emitting any .ko."""
    return '\n/* Pinned stock callback offsets; not proof of live safety. */\n' + ''.join(
        f'_Static_assert(__builtin_offsetof(struct ieee80211_ops, {member}) == '
        f'0x{offset:x}, "stock ieee80211_ops.{member} offset mismatch");\n'
        for member, _callback, offset in EXPECTED_CALLBACKS)


def full_symbols(mod: Module) -> list[dict]:
    # Reuse the generic parser's structural checks, but also need st_value/size.
    mod.symbols()
    h = mod.sections['.symtab']
    sh = mod.headers[h[6]]
    strings = mod.take(sh[4], sh[5])
    result = []
    for off in range(h[4], h[4] + h[5], 24):
        name, info, _other, index, value, size = struct.unpack_from('<IBBHQQ', mod.data, off)
        result.append({'name': mod.string(strings, name), 'type': info & 15,
                       'index': index, 'value': value, 'size': size})
    return result


def callback_relocations(mod: Module) -> tuple[int, list[dict]]:
    if mod.machine != 183:
        raise ElfError('Expected an AArch64 module')
    syms = full_symbols(mod)
    hits = [s for s in syms if s['name'] == 'wonder_mac80211_ops']
    if len(hits) != 1:
        raise ElfError('Expected exactly one wonder_mac80211_ops object')
    target = hits[0]
    if target['type'] != 1 or not 0 < target['index'] < len(mod.headers):
        raise ElfError('Invalid wonder_mac80211_ops object symbol')
    section = mod.headers[target['index']]
    start, size = target['value'], target['size']
    if not size or size % 8 or start > section[5] or size > section[5] - start or section[1] == 8:
        raise ElfError('Invalid wonder_mac80211_ops range')
    raw = mod.take(section[4] + start, size)
    if any(raw):
        raise ElfError('Nonzero unrelocated callback-table bytes')
    symtab_index = mod.headers.index(mod.sections['.symtab'])
    rows = []
    seen = set()
    for h in mod.headers:
        if h[1] not in (4, 9) or h[7] != target['index']:
            continue
        if h[1] != 4 or h[9] != 24 or h[5] % 24 or h[6] != symtab_index:
            raise ElfError('Invalid callback RELA section')
        for off in range(h[4], h[4] + h[5], 24):
            offset, info, addend = struct.unpack_from('<QQq', mod.data, off)
            if not start <= offset < start + size:
                continue
            relative = offset - start
            if relative % 8 or relative in seen or (info & 0xffffffff) != 257:
                raise ElfError('Invalid, duplicate or non-ABS64 callback relocation')
            seen.add(relative)
            symindex = info >> 32
            if symindex >= len(syms):
                raise ElfError('Callback relocation symbol out of bounds')
            ref = syms[symindex]
            if not 0 < ref['index'] < len(mod.headers) or ref['type'] not in (2, 3):
                raise ElfError('Callback relocation does not reference a defined function/section')
            function_section = mod.headers[ref['index']]
            address = ref['value'] + addend
            if not function_section[2] & 4 or not 0 <= address < function_section[5]:
                raise ElfError('Callback points outside executable code')
            if ref['type'] == 2 and addend == 0:
                functions = [ref]
            else:
                functions = [s for s in syms if s['index'] == ref['index'] and
                             s['value'] == address and s['type'] == 2]
            if len(functions) != 1 or not functions[0]['name'] or not functions[0]['size']:
                raise ElfError('Cannot uniquely resolve callback relocation to a function')
            if functions[0]['size'] > function_section[5] - address:
                raise ElfError('Callback function exceeds executable section')
            rows.append({'offset': f'0x{relative:x}', 'symbol': functions[0]['name']})
    return size, sorted(rows, key=lambda row: int(row['offset'], 16))


def audit_ops(mod: Module) -> dict:
    size, rows = callback_relocations(mod)
    expected = {callback: f'0x{offset:x}' for _member, callback, offset in EXPECTED_CALLBACKS}
    found = {}
    errors = []
    for row in rows:
        name, offset = row['symbol'], row['offset']
        if name in found:
            errors.append('Callback appears more than once: ' + name)
        found[name] = offset
        if name not in expected:
            errors.append('Unexpected callback: ' + name)
        elif offset != expected[name]:
            errors.append(f'{name}: expected {expected[name]}, found {offset}')
    for name in expected:
        if name not in found:
            errors.append('Missing callback: ' + name)
    return {'ops_symbol': 'wonder_mac80211_ops', 'ops_size': f'0x{size:x}',
            'callbacks': rows, 'expected_callbacks': expected, 'errors': errors,
            'ops_layout_gate_passed': not errors, 'loadable_proven': False,
            'scope': 'Initialized callback slots only; not complete struct/KCFI or live safety proof.'}


def audit_path(path: Path) -> dict:
    try:
        return audit_ops(Module(path.read_bytes()))
    except (OSError, ElfError, struct.error) as exc:
        return {'ops_layout_gate_passed': False, 'errors': [str(exc)], 'loadable_proven': False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('module', type=Path)
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    result = audit_path(args.module)
    text = json.dumps(result, indent=2) + '\n'
    if args.out:
        args.out.write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if result['ops_layout_gate_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
