"""Synthetic ELF fixtures; never real/loadable kernel modules."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from elf_audit import Module, ElfError
from audit_mac80211_ops import EXPECTED_CALLBACKS, audit_ops, audit_path, compile_time_assertions


def fixture(section_refs=True, shift=0, missing=None, unexpected=False,
            relocation_type=257, duplicate=False, bad_symbol=False,
            undefined=False, function_addend=0, nonzero=False, truncated=False,
            machine=183, bad_link=False, no_ops=False, bad_size=False):
    labels = ['', '.shstrtab', '.strtab', '.symtab', '.text', '.rodata', '.rela.rodata']
    names = b'\0' + b''.join(n.encode()+b'\0' for n in labels[1:])
    callbacks = [(callback, offset + (shift if offset >= 0x1b0 else 0))
                 for _member, callback, offset in EXPECTED_CALLBACKS if callback != missing]
    if unexpected:
        callbacks.append(('unexpected_callback', 0x350))
    strings = bytearray(b'\0')
    def name_id(name):
        value = len(strings)
        strings.extend(name.encode()+b'\0')
        return value
    symbols = [b'\0'*24, struct.pack('<IBBHQQ', 0, 3, 0, 4, 0, 0)]
    # The table starts inside .rodata, not at section offset zero.
    base, size = 0x20, 0x3d8
    if not no_ops:
        symbols.append(struct.pack('<IBBHQQ', name_id('wonder_mac80211_ops'), 0x11,
                                   0, 5, base, 0 if bad_size else size))
    relas = []
    for i, (name, offset) in enumerate(callbacks):
        address = (i+1)*16
        symidx = len(symbols)
        symbols.append(struct.pack('<IBBHQQ', name_id(name), 0x12, 0,
                                   0 if undefined else 4, address, 8))
        ref = 1 if section_refs else symidx
        if bad_symbol:
            ref = 0xffff
        addend = address if section_refs else function_addend
        relas.append(struct.pack('<QQq', base+offset, (ref << 32)|relocation_type, addend))
    if duplicate:
        relas.append(relas[0])
    rodata = bytearray(base+size+8)
    if nonzero:
        rodata[base] = 1
    data = [b'', names, bytes(strings), b''.join(symbols),
            b'\0'*((len(callbacks)+2)*16), bytes(rodata), b''.join(relas)]
    if truncated:
        data[6] += b'x'
    kinds = [0, 3, 3, 2, 1, 1, 4]
    chunks = []
    headers = []
    offset = 64 + len(labels)*64
    for i, raw in enumerate(data):
        link = 2 if i == 3 else (2 if bad_link else 3) if i == 6 else 0
        info = 5 if i == 6 else 0
        flags = 6 if i == 4 else 2 if i == 5 else 0
        headers.append(struct.pack('<IIQQQQIIQQ',
            names.index(labels[i].encode()+b'\0') if i else 0,
            kinds[i], flags, 0, offset if i else 0, len(raw), link, info, 1,
            24 if i in (3,6) else 0))
        chunks.append(raw)
        offset += len(raw)
    ident = b'\x7fELF\x02\x01\x01'+b'\0'*9
    header = ident+struct.pack('<HHIQQQIHHHHHH',1,machine,1,0,0,64,0,64,0,0,64,len(labels),1)
    return header+b''.join(headers)+b''.join(chunks)


class OpsLayoutAudit(unittest.TestCase):
    def test_section_addends_resolve_callbacks_and_relative_offsets(self):
        r = audit_ops(Module(fixture()))
        self.assertTrue(r['ops_layout_gate_passed'])
        self.assertFalse(r['loadable_proven'])
        self.assertEqual(len(r['callbacks']), 26)
        self.assertIn({'offset':'0x2f0','symbol':'wonder_wake_tx_queue'}, r['callbacks'])

    def test_direct_function_relocations(self):
        self.assertTrue(audit_ops(Module(fixture(section_refs=False)))['ops_layout_gate_passed'])

    def test_missing_testmode_slots_fail(self):
        r = audit_ops(Module(fixture(shift=-0x10)))
        self.assertFalse(r['ops_layout_gate_passed'])
        self.assertIn('wonder_wake_tx_queue: expected 0x2f0, found 0x2e0',r['errors'])

    def test_debugfs_shift_fails(self):
        r = audit_ops(Module(fixture(shift=0x18)))
        self.assertFalse(r['ops_layout_gate_passed'])

    def test_missing_and_unexpected_callbacks_fail(self):
        for kwargs in ({'missing':'wonder_start'}, {'unexpected':True}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(audit_ops(Module(fixture(**kwargs)))['ops_layout_gate_passed'])

    def test_malformed_relocations_and_objects_are_rejected(self):
        cases = [{'relocation_type':258}, {'duplicate':True}, {'bad_symbol':True},
                 {'undefined':True}, {'section_refs':False,'function_addend':1},
                 {'nonzero':True}, {'truncated':True}, {'machine':62},
                 {'bad_link':True}, {'no_ops':True}, {'bad_size':True}]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ElfError):
                audit_ops(Module(fixture(**kwargs)))

    def test_compile_assertions_cover_every_audited_callback(self):
        text = compile_time_assertions()
        self.assertEqual(text.count('_Static_assert'), len(EXPECTED_CALLBACKS))
        for member, callback, offset in EXPECTED_CALLBACKS:
            self.assertIn(f'ieee80211_ops, {member}) == 0x{offset:x}', text)

    def test_path_failure_is_a_failed_gate_not_an_exception(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'missing.ko'
            r=audit_path(p)
            self.assertFalse(r['ops_layout_gate_passed'])
            self.assertTrue(r['errors'])
            p.write_bytes(b'not ELF')
            self.assertFalse(audit_path(p)['ops_layout_gate_passed'])


if __name__ == '__main__':
    unittest.main()
