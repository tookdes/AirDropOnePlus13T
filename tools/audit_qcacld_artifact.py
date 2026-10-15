#!/usr/bin/env python3
"""Freeze/audit the SAME strict qcacld build. No phone commands or ELF writes.

PASSED_OFFLINE means version/provider metadata closure, never runtime ABI/RF.
This is a diagnostic evidence directory, not a flashable/KernelSU package.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from elf_audit import Module
from prepare_qcacld_modpost import read_symvers
from build_wlan_compile_smoke import TARGET_RELEASE
from stock_image import module_exports

EXPECTED_NEW = {'cnss_set_vendor_wonder_priv_data', 'dev_close', 'dev_open', 'get_random_u32'}
REQUIRED_CONFIG = ('CONFIG_MODVERSIONS=y', 'CONFIG_MODULE_UNLOAD=y', 'CONFIG_CFI_CLANG=y')


def combine_tables(paths: list[Path]) -> dict[str, list[str]]:
    result = {}
    for path in paths:
        for name, row in read_symvers(path).items():
            if name in result and result[name] != row:
                raise ValueError('Conflicting provider evidence: ' + name)
            result[name] = row
    return result


def check_description(desc: dict, providers: dict[str, list[str]], *,
                      name: str, candidate: bool, module_size: int) -> dict:
    """Pure checks kept separate so negative cases need no giant ELF fixture."""
    errors = []
    info, versions = desc['modinfo'], desc['versions']
    strong, weak = set(desc['undefined_strong']), set(desc['undefined_weak'])
    if desc['machine'] != 183 or desc['type'] != 1:
        errors.append('Expected AArch64 ET_REL')
    expected_vermagic = TARGET_RELEASE + ' SMP preempt mod_unload modversions aarch64'
    if info.get('vermagic') != [expected_vermagic]:
        errors.append('Unexpected full vermagic')
    if info.get('name') != [name]:
        errors.append('Unexpected module name')
    if module_size != 1536:
        errors.append('Unexpected struct module size')
    if versions.get('module_layout') != '0x4e276f37':
        errors.append('Unexpected module_layout CRC')
    for symbol in sorted(strong - set(versions)):
        errors.append('Unversioned strong import: ' + symbol)
    for symbol, crc in versions.items():
        row = providers.get(symbol)
        if row is None:
            errors.append('No provider evidence: ' + symbol)
        elif crc != row[0]:
            errors.append('CRC mismatch: ' + symbol)
        if symbol not in strong | weak | {'module_layout'}:
            errors.append('Version for non-import: ' + symbol)
    # Module dependencies must reflect real export providers, not just stock order.
    expected_deps = {providers[s][2].replace('-', '_') for s in versions
                     if s in providers and providers[s][2] != 'vmlinux'}
    dep_values = info.get('depends', [])
    actual_deps = [s.replace('-', '_') for s in dep_values[0].split(',') if s] if len(dep_values) == 1 else []
    if len(actual_deps) != len(set(actual_deps)) or set(actual_deps) != expected_deps:
        errors.append('depends does not match import providers')
    if name == 'qca_cld3_peach_v2':
        extras = strong & EXPECTED_NEW
        if extras != (EXPECTED_NEW if candidate else set()):
            errors.append('Unexpected candidate-only import surface')
    return {'sha256': desc['sha256'], 'module': name, 'strong_import_count': len(strong),
            'weak_import_count': len(weak), 'version_count': len(versions),
            'vermagic': info.get('vermagic'), 'depends': info.get('depends'),
            'struct_module_bytes': module_size, 'errors': errors,
            'metadata_gate_passed': not errors, 'loadable_proven': False,
            'shared_layouts_and_kcfi_compatibility_proven': False}


def audit_module(path: Path, providers: dict, *, name: str, candidate: bool) -> tuple[dict, set[str]]:
    mod = Module(path.read_bytes())
    desc = mod.describe()
    section = mod.sections.get('.gnu.linkonce.this_module')
    report = check_description(desc, providers, name=name, candidate=candidate,
                               module_size=section[5] if section else 0)
    if name == 'qca_cld3_peach_v2' and module_exports(path):
        report['errors'].append('Unexpected qcacld exports')
        report['metadata_gate_passed'] = False
    return report, set(desc['undefined_strong'])


def freeze(stage_a: Path, providers: Path, smoke: Path, candidate_tree: Path,
           compiler: Path, revision: str, out: Path) -> dict:
    if out.exists():
        raise ValueError('Refusing to overwrite evidence directory')
    out.mkdir(parents=True)
    # Fixed allow-list: no private captures, arbitrary directory recursion, or installers.
    inputs = {
        'modules/baseline/qca_cld3_peach_v2.ko': smoke/'baseline/src/qca_cld3_peach_v2.ko',
        'modules/candidate/qca_cld3_peach_v2.ko': smoke/'candidate/src/qca_cld3_peach_v2.ko',
        'modules/wonder_shim_13t.ko': stage_a/'verified/wonder_shim_13t.ko',
        'kernel/config': stage_a/'kernel-out/.config',
        'kernel/Module.symvers': stage_a/'kernel-out/Module.symvers',
        'kernel/autoconf.h': stage_a/'kernel-out/include/generated/autoconf.h',
        'reports/compile.json': smoke/'report.json',
        'reports/candidate.json': candidate_tree/'backport-candidate.json',
        'reports/providers.json': providers/'qcacld-modpost-providers.json',
        'reports/fresh-core.json': providers/'qcacld-kernel-crc.json',
        'providers/baseline.symvers': providers/'qcacld-baseline-providers.symvers',
        'providers/candidate.symvers': providers/'qcacld-candidate-providers.symvers',
        'providers/fresh-core.symvers': providers/'qcacld-kernel-checked.symvers',
        'logs/baseline.log': smoke/'baseline/build.log',
        'logs/candidate.log': smoke/'candidate/build.log',
    }
    files = []
    for rel, src in inputs.items():
        if not src.is_file() or src.is_symlink():
            raise ValueError('Missing/unsafe same-build evidence: ' + rel)
        dst = out/rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        files.append({'path': rel, 'bytes': dst.stat().st_size,
                      'sha256': hashlib.sha256(dst.read_bytes()).hexdigest()})
    config = (out/'kernel/config').read_text(encoding='utf-8')
    if not set(REQUIRED_CONFIG) <= set(config.splitlines()):
        raise ValueError('Required module/KCFI config not enabled')
    compile_report = json.loads((out/'reports/compile.json').read_text())
    if not (compile_report.get('compile_gate_passed') is True and
            compile_report.get('modpost_provider_gate_passed') is True and
            compile_report.get('module_completion_gate') == 'PASSED_OFFLINE' and
            all(compile_report.get(label, {}).get('strict_modpost') is True for label in ('baseline', 'candidate'))):
        raise ValueError('Strict compile/provider gate not passed')
    provider_report = json.loads((out/'reports/providers.json').read_text())
    shim = out/'modules/wonder_shim_13t.ko'
    exports = module_exports(shim)
    if len(exports) != 1 or {k: exports[0][k] for k in provider_report['shim_export']} != provider_report['shim_export']:
        raise ValueError('Archived shim is not the checked same-build export')
    audits, imports = {}, {}
    for label in ('baseline', 'candidate'):
        rows = combine_tables([out/'kernel/Module.symvers', out/f'providers/{label}.symvers'])
        audits[label], imports[label] = audit_module(out/f'modules/{label}/qca_cld3_peach_v2.ko',
            rows, name='qca_cld3_peach_v2', candidate=label == 'candidate')
    # The shim itself uses the very same base kernel symvers, not stock consumer guesses.
    kernel_rows = combine_tables([out/'kernel/Module.symvers'])
    audits['shim'], _ = audit_module(shim, kernel_rows, name='wonder_shim_13t', candidate=False)
    # Keep raw modules immutable; publish explicit debug-only derivatives for
    # bounded downloads. All SHF_ALLOC bytes, versions and imports must survive.
    derivatives = []
    for label in ('baseline', 'candidate'):
        original = out/f'modules/{label}/qca_cld3_peach_v2.ko'
        derivative = out/f'compact/{label}/qca_cld3_peach_v2.ko'
        derivative.parent.mkdir(parents=True)
        subprocess.run([str(compiler/'llvm-objcopy'), '--strip-debug', str(original), str(derivative)], check=True)
        old, new = Module(original.read_bytes()), Module(derivative.read_bytes())
        if old.versions() != new.versions() or old.modinfo() != new.modinfo():
            raise ValueError('Debug stripping changed module ABI metadata')
        old_imports = sorted((r['name'], r['binding'], r['type']) for r in old.symbols() if r['index'] == 0)
        new_imports = sorted((r['name'], r['binding'], r['type']) for r in new.symbols() if r['index'] == 0)
        if old_imports != new_imports:
            raise ValueError('Debug stripping changed imports')
        old_alloc = {n: h for n, h in old.sections.items() if h[2] & 2}
        new_alloc = {n: h for n, h in new.sections.items() if h[2] & 2}
        if set(old_alloc) != set(new_alloc):
            raise ValueError('Debug stripping changed allocated section set')
        for n, h in old_alloc.items():
            if h[5] != new_alloc[n][5] or h[1] != new_alloc[n][1] or (h[1] != 8 and old.section(n) != new.section(n)):
                raise ValueError('Debug stripping changed allocated bytes: '+n)
        rel = derivative.relative_to(out).as_posix()
        files.append({'path': rel, 'bytes': derivative.stat().st_size, 'sha256': new.sha256})
        derivatives.append({'path': rel, 'original_sha256': old.sha256, 'sha256': new.sha256,
                            'transformation': 'llvm-objcopy --strip-debug; raw original retained',
                            'all_allocated_section_bytes_identical': True,
                            'versions_modinfo_and_imports_identical': True,
                            'binary_crc_patching': False, 'loadable_proven': False})
    difference_ok = imports['candidate'] - imports['baseline'] == EXPECTED_NEW and not imports['baseline'] - imports['candidate']
    report = {'schema': 1, 'source_revision': revision,
              'compiler_sha256': hashlib.sha256((compiler/'clang').read_bytes()).hexdigest(),
              'compiler_toolchain_commit': '18bfb7fbd697a1ad710fd0581a4ac9f3db385f71',
              'compiler_version': subprocess.check_output([str(compiler/'clang'), '--version'], text=True).strip(),
              'source_pins': {'common': '5a0ffb447c1dbd82e8e3af7a98c4a629f4b6d143',
                              'vendor': '6a196f79f77acd55cf302e1696c038e4cad99254',
                              'donor_intro': '307d23721d20e21b8160b9ba9c3cb50911ff8c00'},
              'files': files, 'debug_stripped_derivatives': derivatives, 'modules': audits, 'final_elf_import_delta_passed': difference_ok,
              'final_elf_metadata_gate_passed': difference_ok and all(r['metadata_gate_passed'] for r in audits.values()),
              'loadable_proven': False, 'release_ready': False, 'firmware_compatible_proven': False,
              'rf_proven': False, 'installer': False}
    (out/'manifest.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stage-a', 'providers', 'smoke', 'candidate-tree', 'compiler', 'out'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--source-revision', required=True)
    a = p.parse_args()
    try:
        report = freeze(a.stage_a, a.providers, a.smoke, a.candidate_tree, a.compiler, a.source_revision, a.out)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('Strict artifact freeze failed: '+str(exc))
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report['final_elf_metadata_gate_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
