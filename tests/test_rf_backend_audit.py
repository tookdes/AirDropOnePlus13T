import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_audit import Module, ElfError
from audit_rf_backend import (VENDOR_RAW_POLICY, object_symbol, object_relocations,
                              netdev_table, vendor_commands, vendor_names, management_tx_guard, MGMT_GUARD_WORDS, main)


def fixture(*, vendor=False, entries=1, policy=None, flags=3, vendor_id=0x1374,
            duplicate_id=False, no_handler=False, xmit=False, nonzero=False,
            duplicate_relocation=False, relocation_type=257, bad_symbol=False,
            undefined=False, section_refs=False, function_addend=0, bad_link=False,
            truncated_rela=False, reserve=False, pointer=False, data_policy=False,
            extra_object=False, duplicate_object=False, size_override=None,
            management=False, policy_conflict=False, wrong_symtab_kind=False, executable_bss=False):
    labels = ['', '.shstrtab', '.strtab', '.symtab', '.text', '.rodata', '.rela.rodata']
    shnames = b'\0' + b''.join(s.encode() + b'\0' for s in labels[1:])
    strings = bytearray(b'\0')
    def n(name):
        off = len(strings)
        strings.extend(name.encode() + b'\0')
        return off
    syms = [b'\0' * 24, struct.pack('<IBBHQQ', 0, 3, 0, 4, 0, 0)]
    base = 0x20
    size = 56 * entries if vendor else 0x2c0
    name = 'cfg80211_mlme_mgmt_tx' if management else 'hdd_wiphy_vendor_commands' if vendor else 'wlan_mon_drv_ops'
    if management:
        size = 0x90
    syms.append(struct.pack('<IBBHQQ', n(name), 0x12 if management else 0x11, 0, 4 if management else 5, base,
                            size if size_override is None else size_override))
    if duplicate_object:
        syms.append(struct.pack('<IBBHQQ', n(name), 0x11, 0, 5, base, size))
    if extra_object:
        syms.append(struct.pack('<IBBHQQ', n(name), 0x11, 0, 5, base, 144))
    raw = bytearray(base + size + 64)
    relas = []
    fcount = 0
    def callback(name, slot):
        nonlocal fcount
        fcount += 1
        address = fcount * 16
        idx = len(syms)
        syms.append(struct.pack('<IBBHQQ', n(name), 0x12, 0,
                                0 if undefined else 4, address, 8))
        ref = 0xffff if bad_symbol else 1 if section_refs else idx
        addend = address if section_refs else function_addend
        relas.append(struct.pack('<QQq', base + slot, (ref << 32) | relocation_type, addend))
    if vendor:
        for i in range(entries):
            slot = base + i * 56
            struct.pack_into('<III', raw, slot, vendor_id,
                             11 if duplicate_id else 11 + i, flags)
            struct.pack_into('<Q', raw, slot + 32,
                             VENDOR_RAW_POLICY if policy is None else policy)
            if reserve:
                raw[slot + 48] = 1
            if pointer:
                raw[slot + 16] = 1
            if not no_handler:
                callback('handler_' + str(i), i * 56 + 16)
        if data_policy:
            struct.pack_into('<Q', raw, base + 32, VENDOR_RAW_POLICY if policy_conflict else 0)
            address = base + size + 16
            idx = len(syms)
            syms.append(struct.pack('<IBBHQQ', n('test_policy'), 0x11, 0, 5, address, 16))
            relas.append(struct.pack('<QQq', base + 32, (idx << 32) | 257, 0))
    elif not management:
        callback('hdd_mon_open', 0x10)
        callback('hdd_stop', 0x18)
        if xmit:
            callback('hdd_hard_start_xmit', 0x20)
        if nonzero:
            raw[base] = 1
    if duplicate_relocation:
        relas.append(relas[0])
    rela = b''.join(relas) + (b'x' if truncated_rela else b'')
    text = bytearray(base + size if management else (fcount + 3) * 16)
    if management:
        for offset, word in MGMT_GUARD_WORDS.items():
            struct.pack_into('<I', text, base + offset, word)
    data = [b'', shnames, bytes(strings), b''.join(syms), bytes(text), bytes(raw), rela]
    kinds = [0, 3, 3, 1 if wrong_symtab_kind else 2, 8 if executable_bss else 1, 1, 4]
    headers = []
    off = 64 + 7 * 64
    for i, value in enumerate(data):
        link = 2 if i == 3 else (2 if bad_link else 3) if i == 6 else 0
        headers.append(struct.pack('<IIQQQQIIQQ', shnames.index(labels[i].encode() + b'\0') if i else 0,
                                   kinds[i], 6 if i == 4 else 2 if i == 5 else 0,
                                   0, off if i else 0, len(value), link,
                                   5 if i == 6 else 0, 1, 24 if i in (3, 6) else 0))
        off += len(value)
    ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    hdr = ident + struct.pack('<HHIQQQIHHHHHH', 1, 183, 1, 0, 0, 64, 0, 64, 0, 0, 64, 7, 1)
    return Module(hdr + b''.join(headers) + b''.join(data))


class RfBackendAuditTests(unittest.TestCase):
    def test_monitor_missing_tx_and_positive_control_with_tx(self):
        r = netdev_table(fixture(), 'wlan_mon_drv_ops', 0x2c0, 0x20)
        self.assertEqual(r['ndo_start_xmit'], [])
        self.assertEqual(len(r['callbacks']), 2)
        r = netdev_table(fixture(xmit=True), 'wlan_mon_drv_ops', 0x2c0, 0x20)
        self.assertEqual(r['ndo_start_xmit'], ['hdd_hard_start_xmit'])

    def test_section_function_relocations(self):
        r = netdev_table(fixture(section_refs=True), 'wlan_mon_drv_ops', 0x2c0, 0x20)
        self.assertEqual(r['callbacks'][0], {'offset': 16, 'symbol': 'hdd_mon_open'})

    def test_duplicate_name_selected_by_verified_struct_size(self):
        mod = fixture(extra_object=True)
        with self.assertRaises(ElfError):
            object_symbol(mod, 'wlan_mon_drv_ops')
        self.assertEqual(object_symbol(mod, 'wlan_mon_drv_ops', 0x2c0)['size'], 0x2c0)

    def test_malformed_callback_evidence_is_rejected(self):
        for args in ({'nonzero': True}, {'duplicate_object': True}, {'duplicate_relocation': True},
                     {'relocation_type': 258}, {'bad_symbol': True}, {'undefined': True},
                     {'function_addend': 1}, {'bad_link': True}, {'truncated_rela': True},
                     {'size_override': 0}, {'size_override': 0xfffff},
                     {'wrong_symtab_kind': True}, {'executable_bss': True}):
            with self.subTest(args=args), self.assertRaises(ElfError):
                netdev_table(fixture(**args), 'wlan_mon_drv_ops', 0x2c0, 0x20)

    def test_invalid_member_offset_is_rejected(self):
        for off in (-1, 3, 0x2c0):
            with self.subTest(offset=off), self.assertRaises(ElfError):
                netdev_table(fixture(), 'wlan_mon_drv_ops', 0x2c0, off)

    def test_vendor_kabi_stride_and_raw_data_sentinel(self):
        r = vendor_commands(fixture(vendor=True, entries=2), {11: ['DFS'], 12: ['NAN']})
        self.assertEqual(r['entry_bytes'], 56)
        self.assertEqual(r['count'], 2)
        self.assertEqual(r['unmapped_subcmds'], [])
        self.assertEqual(r['commands'][0]['doit'], 'handler_0')
        self.assertEqual(r['commands'][1]['subcmd'], 12)
        self.assertEqual(r['commands'][0]['policy'], 'RAW_DATA')
        self.assertEqual(VENDOR_RAW_POLICY, (1 << 64) - 61)

    def test_vendor_data_policy_and_unknown_id_are_preserved(self):
        r = vendor_commands(fixture(vendor=True, data_policy=True), {})
        self.assertEqual(r['commands'][0]['policy'], 'test_policy')
        self.assertEqual(r['unmapped_subcmds'], [11])

    def test_old_wrong_stride_invalid_padding_and_fake_callbacks_fail(self):
        cases = ({'size_override': 48}, {'reserve': True}, {'vendor_id': 1}, {'flags': 8},
                 {'pointer': True}, {'policy': 0xffffffffffffffff}, {'no_handler': True},
                 {'entries': 2, 'duplicate_id': True}, {'duplicate_relocation': True},
                 {'bad_link': True}, {'bad_symbol': True}, {'undefined': True})
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ElfError):
                vendor_commands(fixture(vendor=True, **args), {})

    def test_qca_and_oplus_names_are_parsed_without_type_enum_pollution(self):
        text = '''enum unrelated { QCA_NL80211_VENDOR_SUBCMD_NOT_COMMAND = 1, };
        enum qca_nl80211_vendor_subcmds {
            QCA_NL80211_VENDOR_SUBCMD_DFS = 11,
            QCA_NL80211_VENDOR_SUBCMD_ALIAS = 11,
            QCA_NL80211_VENDOR_SUBCMD_HEX = 0x16,
            OPLUS_NL80211_VENDOR_SUBCMD_ACL = 1001,
            /* QCA_NL80211_VENDOR_SUBCMD_IGNORED = 999, */
        };'''
        r = vendor_names(text)
        self.assertEqual(r[11], ['QCA_NL80211_VENDOR_SUBCMD_DFS', 'QCA_NL80211_VENDOR_SUBCMD_ALIAS'])
        self.assertEqual(r[22], ['QCA_NL80211_VENDOR_SUBCMD_HEX'])
        self.assertEqual(r[1001], ['OPLUS_NL80211_VENDOR_SUBCMD_ACL'])
        self.assertNotIn(1, r)
        self.assertNotIn(999, r)

    def test_missing_vendor_enum_fails_closed(self):
        for text in ('', 'enum qca_nl80211_vendor_subcmds {};'):
            with self.subTest(text=text), self.assertRaises(ElfError):
                vendor_names(text)

    def test_no_output_can_overwrite_evidence_or_non_json_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'input.json'
            p.write_text('evidence', encoding='utf-8')
            argv = ['audit', '--qcacld', str(p), '--cnss', str(p), '--stock-btf', str(p),
                    '--vendor-header', str(p), '--out', str(p)]
            with patch.object(sys, 'argv', argv), patch('audit_rf_backend.audit') as action:
                with self.assertRaises(ElfError):
                    main()
                action.assert_not_called()
            self.assertEqual(p.read_text(encoding='utf-8'), 'evidence')
            argv[-1] = str(Path(td) / 'module.ko')
            with patch.object(sys, 'argv', argv), self.assertRaises(ElfError):
                main()


    def test_conflicting_vendor_policy_bytes_are_rejected(self):
        with self.assertRaises(ElfError):
            vendor_commands(fixture(vendor=True, data_policy=True, policy_conflict=True), {})

    def test_partial_relocation_overlaps_are_rejected(self):
        mod = fixture()
        raw = bytearray(mod.data)
        h = mod.sections['.rela.rodata']
        struct.pack_into('<Q', raw, h[4], 0x20 - 4)
        with self.assertRaises(ElfError):
            netdev_table(Module(bytes(raw)), 'wlan_mon_drv_ops', 0x2c0, 0x20)

    def test_exact_stock_management_guard_is_not_data_frame_injection(self):
        r = management_tx_guard(fixture(management=True))
        self.assertTrue(r['data_frame_tx_rejected'])
        self.assertEqual(r['minimum_frame_bytes'], 25)
        self.assertEqual(r['non_management_result'], -22)
        self.assertEqual(r['frame_type_mask'], 12)
        self.assertIn('Exact captured 13T', r['fingerprint_scope'])

    def test_every_guard_word_must_match(self):
        mod = fixture(management=True)
        text = mod.sections['.text']
        for offset in MGMT_GUARD_WORDS:
            with self.subTest(offset=offset), self.assertRaises(ElfError):
                data = bytearray(mod.data)
                data[text[4] + 0x20 + offset] ^= 1
                management_tx_guard(Module(bytes(data)))

    def test_management_guard_wrong_arch_missing_or_bad_function_fails(self):
        with self.assertRaises(ElfError):
            management_tx_guard(fixture())
        with self.assertRaises(ElfError):
            management_tx_guard(fixture(management=True, size_override=0x80))
        for args in ({'wrong_symtab_kind': True}, {'executable_bss': True}):
            with self.subTest(args=args), self.assertRaises(ElfError):
                management_tx_guard(fixture(management=True, **args))
        mod = fixture(management=True)
        data = bytearray(mod.data)
        struct.pack_into('<H', data, 18, 62)
        with self.assertRaises(ElfError):
            management_tx_guard(Module(bytes(data)))
        sym = mod.sections['.symtab'][4] + 2 * 24
        for pos, fmt, value in ((sym + 6, '<H', 0), (sym + 8, '<Q', 0x21),
                                (sym + 16, '<Q', 0xfffff)):
            data = bytearray(mod.data)
            struct.pack_into(fmt, data, pos, value)
            with self.subTest(pos=pos), self.assertRaises(ElfError):
                management_tx_guard(Module(bytes(data)))

    def test_optional_cfg_evidence_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / 'input'
            inp.write_bytes(b'x')
            cfg = Path(td) / 'cfg.json'
            cfg.write_bytes(b'protected')
            argv = ['audit', '--qcacld', str(inp), '--cnss', str(inp), '--stock-btf', str(inp),
                    '--vendor-header', str(inp), '--cfg80211', str(cfg), '--out', str(cfg)]
            with patch.object(sys, 'argv', argv), patch('audit_rf_backend.audit') as action:
                with self.assertRaises(ElfError):
                    main()
                action.assert_not_called()
            self.assertEqual(cfg.read_bytes(), b'protected')

    def test_output_hardlink_to_evidence_is_protected(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'input'
            p.write_bytes(b'protected')
            out = Path(td) / 'report.json'
            os.link(p, out)
            argv = ['audit', '--qcacld', str(p), '--cnss', str(p), '--stock-btf', str(p),
                    '--vendor-header', str(p), '--out', str(out)]
            with patch.object(sys, 'argv', argv), patch('audit_rf_backend.audit') as action:
                with self.assertRaises(ElfError):
                    main()
                action.assert_not_called()
            self.assertEqual(p.read_bytes(), b'protected')

    def test_cli_success_means_inventory_not_radio_readiness(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'input'
            p.write_bytes(b'x')
            out = Path(td) / 'out.json'
            argv = ['audit', '--qcacld', str(p), '--cnss', str(p), '--stock-btf', str(p),
                    '--vendor-header', str(p), '--out', str(out)]
            report = {'status': 'INVENTORY', 'qcacld_actual_export_count': 0,
                      'normal_monitor_raw_tx_available': False, 'radio_gate_passed': False,
                      'vendor_commands': {'count': 0, 'unmapped_subcmds': []}}
            with patch.object(sys, 'argv', argv), patch('audit_rf_backend.audit', return_value=report):
                self.assertEqual(main(), 0)
            self.assertFalse(json.loads(out.read_text(encoding='utf-8'))['radio_gate_passed'])


if __name__ == '__main__':
    unittest.main()
