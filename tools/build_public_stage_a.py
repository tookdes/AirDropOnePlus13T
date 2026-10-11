#!/usr/bin/env python3
"""Reproduce Stage A from public source plus a narrowly scoped stock ABI profile.

No raw boot/config/BTF/firmware is uploaded. The profile is derived offline from
actual stock exports and BTF, not synthesized to fit a newly compiled module.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from build_stage_a import config_values, TARGET_RELEASE
from elf_audit import Module, audit
from prepare_stage_a import CORE_OBJECTS, COMMON, CLANG_COMMIT, run, symversions_from_cmd

ROOT = Path(__file__).resolve().parents[1]
MODULE_NAMES = ('hello_13t.ko', 'wonder_shim_13t.ko')
LAYOUT_KEYS = {'OP13T_PLATFORM_DEV_OFFSET', 'OP13T_DEVICE_DRIVER_DATA_OFFSET',
               'OP13T_DEVICE_OF_NODE_OFFSET', 'OP13T_MODULE_SIZE'}

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def config_digest(path: Path) -> str:
    return sha(json.dumps(config_values(path.read_bytes()), sort_keys=True,
                          separators=(',', ':')).encode())

def profile_load(profile_path: Path, exports_path: Path) -> tuple[dict, dict[str, int]]:
    p = json.loads(profile_path.read_text())
    if (p.get('schema') != 1 or p.get('kernel_commit') != COMMON or
            p.get('compiler_commit') != CLANG_COMMIT or p.get('target_release') != TARGET_RELEASE):
        raise ValueError('Unreviewed target profile')
    if p.get('config_overrides') != {'CONFIG_TRIM_UNUSED_KSYMS': 'y',
                                    'CONFIG_UNUSED_KSYMS_WHITELIST': '"abi_symbollist.raw"'}:
        raise ValueError('Unreviewed configuration overrides')
    if set(p['layouts']) != LAYOUT_KEYS or any(type(v) is not int or v < 0 for v in p['layouts'].values()):
        raise ValueError('Malformed target layout profile')
    if not p['layouts']['OP13T_MODULE_SIZE']:
        raise ValueError('Zero-sized struct module')
    raw = exports_path.read_bytes()
    if sha(raw) != p['selected_exports_sha256']:
        raise ValueError('Captured export subset checksum mismatch')
    entries = {}
    for line in raw.decode('ascii').splitlines():
        f = line.split('\t')
        if (len(f) != 5 or f[2] != 'vmlinux' or f[3] not in ('EXPORT_SYMBOL', 'EXPORT_SYMBOL_GPL')
                or not re.fullmatch(r'0x[0-9a-f]{8}', f[0])
                or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', f[1]) or f[1] in entries
                or not re.fullmatch(r'[A-Za-z_0-9]*', f[4])):
            raise ValueError('Malformed captured export record')
        entries[f[1]] = int(f[0], 16)
    if len(entries) != p['selected_exports_count'] or len(entries) != 92:
        raise ValueError('Incomplete captured export subset')
    fresh = p['fresh_genksyms_symbols']
    if len(fresh) != 76 or len(set(fresh)) != 76 or not set(fresh) <= entries.keys():
        raise ValueError('Incomplete independent genksyms coverage')
    for key in ('compiler_sha256', 'config_canonical_sha256', 'stock_boot_sha256',
                'stock_btf_sha256', 'stock_config_sha256'):
        if not re.fullmatch(r'[a-f0-9]{64}', p[key]):
            raise ValueError('Malformed profile hash: ' + key)
    return p, entries

def fresh_verify(fresh: dict[str, int], profile: dict, expected: dict[str, int]) -> dict[str, str]:
    required = set(profile['fresh_genksyms_symbols'])
    missing = sorted(required - fresh.keys())
    mismatches = sorted(n for n, v in fresh.items() if n in expected and expected[n] != v)
    if missing or mismatches:
        raise ValueError(json.dumps({'missing_fresh': missing, 'crc_mismatch': mismatches}))
    return {n: f'0x{fresh[n]:08x}' for n in sorted(required)}

def layout_header(profile: dict) -> str:
    return ('/* Derived from captured stock BTF; full ABI compatibility is not implied. */\n'
            '#ifndef OP13T_TARGET_LAYOUT_GENERATED_H\n#define OP13T_TARGET_LAYOUT_GENERATED_H\n' +
            ''.join(f'#define {k} {v}U\n' for k, v in sorted(profile['layouts'].items())) +
            f'#define OP13T_LAYOUT_BTF_SHA256 "{profile["stock_btf_sha256"]}"\n'
            f'#define OP13T_LAYOUT_CONFIG_SHA256 "{profile["stock_config_sha256"]}"\n#endif\n')

def clean_source(source: Path) -> None:
    got = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if got != COMMON:
        raise ValueError('Wrong kernel common revision')
    status = subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True)
    if status.strip():
        raise ValueError('Kernel common checkout must be clean')

def build(source: Path, compiler: Path, output: Path, profile_path: Path, exports_path: Path) -> dict:
    profile, expected = profile_load(profile_path, exports_path)
    clean_source(source)
    version = subprocess.check_output([str(compiler/'clang'), '--version'], text=True)
    if not all(word in version for word in ('18.0.0', 'r510928', '11368308')):
        raise ValueError('Wrong compiler identity')
    if sha((compiler/'clang').read_bytes()) != profile['compiler_sha256']:
        raise ValueError('Compiler binary checksum differs from validated build')
    if output.exists():
        raise ValueError('Output directory already exists; refusing stale result reuse')
    output.mkdir(parents=True)
    out = output/'kernel-out'
    log = output/'build.log'
    make = ['make', '-C', str(source), 'O='+str(out), 'ARCH=arm64',
            'LLVM='+str(compiler)+'/', 'LLVM_IAS=1', 'KERNELRELEASE='+TARGET_RELEASE, '-j2']
    run(make+['gki_defconfig'], log)
    run([str(source/'scripts/config'), '--file', str(out/'.config'),
         '--enable', 'TRIM_UNUSED_KSYMS', '--set-str', 'UNUSED_KSYMS_WHITELIST', 'abi_symbollist.raw'], log)
    run(make+['olddefconfig'], log)
    got_config = config_digest(out/'.config')
    if got_config != profile['config_canonical_sha256']:
        raise ValueError('Reconstructed configuration is not the stock configuration: '+got_config)
    run(make+['modules_prepare'], log)
    run(make+list(CORE_OBJECTS), log)
    fresh = {}
    for obj in CORE_OBJECTS:
        p = Path(obj)
        part = symversions_from_cmd((out/p.parent/('.'+p.name+'.cmd')).read_text())
        for name, crc in part.items():
            if name in fresh and fresh[name] != crc:
                raise ValueError('Conflicting fresh CRC: '+name)
            fresh[name] = crc
    verified_fresh = fresh_verify(fresh, profile, expected)
    # Genuine stock-export CRCs are exposed to modpost only after independent
    # kernel compilation and whole-configuration checks. Never rewrite a .ko.
    shutil.copyfile(exports_path, out/'Module.symvers')
    modsrc = output/'module-source'
    shutil.copytree(ROOT/'shim', modsrc, ignore=shutil.ignore_patterns(
        '*.ko', '*.o', '*.o.d', '*.mod*', '.*.cmd', 'Module.symvers', 'modules.order', 'target_layout.generated.*'))
    (modsrc/'include/target_layout.generated.h').write_text(layout_header(profile))
    run(make+['M='+str(modsrc), 'BUILD_WONDER_SHIM=1', 'modules'], log)
    modules = {}
    for name in MODULE_NAMES:
        file = modsrc/name
        result = audit(file, expected)
        m = Module(file.read_bytes())
        info = m.modinfo()
        required_magic = TARGET_RELEASE+' SMP preempt mod_unload modversions aarch64'
        if info.get('vermagic') != [required_magic]:
            result['errors'].append('Target vermagic mismatch')
        section = m.sections.get('.gnu.linkonce.this_module')
        if not section or section[5] != profile['layouts']['OP13T_MODULE_SIZE']:
            result['errors'].append('this_module layout size mismatch')
        # Pinned Kbuild intentionally omits CC_FLAGS_CFI from generated .mod.o
        # metadata (scripts/Makefile.modfinal:30). Require KCFI on driver code.
        for obj in (name[:-3]+'.o',):
            command = (modsrc/('.'+obj+'.cmd')).read_text()
            if '-fsanitize=kcfi' not in command or re.search(r'-fno-sanitize=[^\s;]*(?:kcfi|all)', command):
                result['errors'].append('Missing or disabled KCFI compile flag: '+obj)
        result['captured_crc_check_passed'] = not result['errors']
        result['profile_core_exports_checked'] = True
        result['not_covered'] = ['Runtime KCFI call-sites', 'current phone boot identity',
                                 'live insmod/rmmod', 'Wi-Fi driver and firmware', 'AirDrop']
        modules[name] = result
    result = {'schema':1, 'kernel_commit':COMMON, 'compiler_version':version,
              'compiler_sha256':profile['compiler_sha256'], 'target_release':TARGET_RELEASE,
              'profile_sha256':sha(profile_path.read_bytes()),
              'configuration_sha256':got_config, 'fresh_genksyms_count':len(verified_fresh),
              'fresh_genksyms_matches':verified_fresh, 'modules':modules,
              'build_and_offline_abi_gates_passed':all(not m['errors'] for m in modules.values()),
              'live_insmod':'NOT_RUN', 'airdrop_available':False,
              'raw_stock_evidence_used_in_this_build':False,
              'stock_evidence_source':'Derived checked-in ABI profile; original boot/BTF were parsed offline'}
    (output/'stage-a-result.json').write_text(json.dumps(result, indent=2)+'\n')
    if not result['build_and_offline_abi_gates_passed']:
        raise ValueError('Built modules failed offline checks; see stage-a-result.json')
    dest = output/'verified'
    dest.mkdir()
    for name in MODULE_NAMES:
        shutil.copyfile(modsrc/name, dest/name)
    shutil.copyfile(modsrc/'Module.symvers', dest/'Module.symvers')
    (dest/'SHA256SUMS').write_text(''.join(sha((dest/n).read_bytes())+'  '+n+'\n' for n in MODULE_NAMES))
    return result

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel-source', type=Path, required=True)
    p.add_argument('--clang-dir', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--profile', type=Path, default=ROOT/'profiles/stage-a.json')
    p.add_argument('--exports', type=Path, default=ROOT/'profiles/stage-a.exports.symvers')
    a = p.parse_args()
    try:
        r = build(a.kernel_source.resolve(), a.clang_dir.resolve(), a.out.resolve(), a.profile, a.exports)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(str(exc))
        return 1
    print(json.dumps(r, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
