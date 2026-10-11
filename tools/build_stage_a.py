#!/usr/bin/env python3
"""Build only Stage A/A2 against a prepared and independently verified target kernel tree.

Not a full qcacld backport builder. Never loads a module, writes device firmware,
changes CRCs, or packages an installable AirDrop release.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from elf_audit import audit, merge_stock
from layout_from_btf import generate
ROOT=Path(__file__).resolve().parents[1]
COMMON_COMMIT='5a0ffb447c1dbd82e8e3af7a98c4a629f4b6d143'
TARGET_RELEASE='6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k'
REQUIRED={'CONFIG_ARM64':'y','CONFIG_MODVERSIONS':'y','CONFIG_CFI_CLANG':'y',
          'CONFIG_LTO_NONE':'y','CONFIG_RANDSTRUCT_NONE':'y','CONFIG_MODULE_UNLOAD':'y'}

def config_values(raw:bytes) -> dict[str,str]:
    if raw[:2]==b'\x1f\x8b': raw=gzip.decompress(raw)
    values={}
    for line in raw.decode().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            k,v=line.split('=',1); values[k]=v
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[2:-11]]='n'
    return values

def preflight(source:Path, output:Path, config:Path, clang:Path):
    expected=config_values(config.read_bytes()); actual=config_values((output/'.config').read_bytes())
    for key,val in REQUIRED.items():
        if expected.get(key)!=val: raise ValueError('Captured config violates required constraint: '+key)
    # LOCALVERSION is separately recorded; it does not excuse other config differences.
    differing=sorted(k for k in set(expected)|set(actual)
                     if k!='CONFIG_LOCALVERSION' and expected.get(k,'n')!=actual.get(k,'n'))
    if differing: raise ValueError('Build .config differs from captured config: '+', '.join(differing[:30]))
    commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if commit!=COMMON_COMMIT: raise ValueError('Kernel source commit is not the captured release base')
    if subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True).strip():
        raise ValueError('Kernel source tree must be clean before Stage A build')
    if (output/'include/config/kernel.release').read_text().strip()!=TARGET_RELEASE:
        raise ValueError('Prepared kernel release is not the captured target')
    if not (output/'Module.symvers').is_file(): raise ValueError('A verified Module.symvers is required')
    version=subprocess.check_output([str(clang/'clang'),'--version'],text=True)
    if not all(x in version for x in ('18.0.0','r510928','11368308')):
        raise ValueError('Expected Android clang 18.0.0 r510928')
    for exe in ('ld.lld','llvm-ar','llvm-nm','llvm-objcopy','llvm-strip'):
        if not (clang/exe).is_file(): raise ValueError('Missing toolchain binary: '+exe)
    return {'source_commit':commit,'compiler':version,
            'compiler_sha256':hashlib.sha256((clang/'clang').read_bytes()).hexdigest(),
            'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest(),
            'symvers_sha256':hashlib.sha256((output/'Module.symvers').read_bytes()).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel-source',type=Path,required=True)
    p.add_argument('--kernel-out',type=Path,required=True)
    p.add_argument('--stock-config',type=Path,required=True)
    p.add_argument('--clang-dir',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--btf',type=Path,help='Build diagnostics-default shim as well; requires captured BTF')
    p.add_argument('--stock-module',type=Path,action='append',default=[])
    p.add_argument('--captured-exports',type=Path,help='stock_image.py output directory; requires independent prepare proof')
    p.add_argument('--prepare-proof',type=Path)
    a=p.parse_args()
    source=a.kernel_source.resolve(); output=a.kernel_out.resolve(); clang=a.clang_dir.resolve()
    record=preflight(source,output,a.stock_config,clang)
    if a.captured_exports:
        from prepare_stage_a import export_db, REQUIRED_FRESH
        if not a.prepare_proof: raise ValueError('Captured exports require prepare-proof.json')
        expected_exports, export_report=export_db(a.captured_exports)
        proof=json.loads(a.prepare_proof.read_text())
        if proof['source_commit']!=COMMON_COMMIT or proof['stock_symvers_sha256']!=record['symvers_sha256']:
            raise ValueError('Prepare proof does not bind this source/output')
        if proof['compiler_sha256']!=record['compiler_sha256'] or proof['config_sha256']!=record['config_sha256']:
            raise ValueError('Prepare proof does not bind this compiler/config')
        if not REQUIRED_FRESH.issubset(proof['fresh_genksyms_matches']):
            raise ValueError('Missing independent genksyms coverage')
        for name,value in proof['fresh_genksyms_matches'].items():
            if expected_exports.get(name)!=int(value,16):raise ValueError('Bad fresh genksyms proof')
        record['prepare_proof']=proof
    if a.out.exists(): raise ValueError('Use a new output directory; refusing to overwrite build evidence')
    a.out.mkdir(parents=True)
    work=a.out.resolve()/'src'; shutil.copytree(ROOT/'shim',work,
        ignore=shutil.ignore_patterns('*.o','*.ko','*.cmd','.*.cmd','*.o.d','*.mod*','Module.symvers','modules.order','target_layout.generated.*'))
    if a.btf: record['layout']=generate(a.btf,a.stock_config,work/'include/target_layout.generated.h')
    cmd=['make','-C',str(source),'O='+str(output),'M='+str(work),'ARCH=arm64',
         'LLVM='+str(clang)+'/', 'KERNELRELEASE='+TARGET_RELEASE, 'LLVM_IAS=1','BUILD_WONDER_SHIM='+('1' if a.btf else '0'),'-j2','modules']
    # Do not inherit an environment that silently weakens compiler/module checks.
    env=os.environ.copy()
    for key in ('KCFLAGS','KCPPFLAGS','CFLAGS_MODULE','KBUILD_MODPOST_WARN','KBUILD_EXTRA_SYMBOLS',
                'KBUILD_MODPOST_NOFINAL','KCONFIG_CONFIG','LLVM','ARCH','CROSS_COMPILE',
                'MAKEFLAGS','MFLAGS','CC','CXX','LD','AR','AS','NM','KBUILD_OUTPUT','KBUILD_EXTMOD'):
        env.pop(key,None)
    with (a.out/'build.log').open('w') as log:
        status=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,env=env).returncode
    record.update(command=cmd,build_exit=status,live_insmod='NOT_RUN',radio_operations=False)
    record['modules']={}
    if status==0:
        try:
            expected=(expected_exports if a.captured_exports else
                      merge_stock(a.stock_module,ROOT/'evidence/stock_icnss2_versions.json'))
        except (OSError,ValueError,KeyError) as exc:
            record['audit_error']=str(exc)
        else:
            for name in ['hello_13t.ko']+(['wonder_shim_13t.ko'] if a.btf else []):
                try:
                    result=audit(work/name,expected)
                    from elf_audit import Module
                    mod=Module((work/name).read_bytes())
                    if mod.modinfo().get('vermagic', [''])[0].split(' ',1)[0]!=TARGET_RELEASE:
                        result['errors'].append('Module release does not match captured target')
                    if a.captured_exports:
                        section=mod.sections.get('.gnu.linkonce.this_module')
                        if not section or section[5]!=export_report['btf']['layouts']['OP13T_MODULE_SIZE']:
                            result['errors'].append('this_module size disagrees with captured BTF')
                        stem=name[:-3]
                        cmdfile=work/('.'+stem+'.o.cmd')
                        command=cmdfile.read_text()
                        if '-fsanitize=kcfi' not in command or '-fno-sanitize=kcfi' in command:
                            result['errors'].append('Missing or overridden KCFI compile flag')
                        result['captured_crc_check_passed']=not result['errors']
                        result['core_export_availability_checked']=True
                        result['not_covered']=[x for x in result['not_covered'] if x!='trimmed export availability']
                        result['not_covered'].append('whether the phone still runs the recorded boot image')
                    record['modules'][name]=result
                except (OSError,ValueError,KeyError) as exc:
                    record['modules'][name]={'captured_crc_check_passed':False,
                                             'target_loadability_proven':False,'error':str(exc)}
    passed=bool(status==0 and record['modules'] and
                all(x['captured_crc_check_passed'] for x in record['modules'].values()))
    record['build_and_offline_abi_gates_passed']=passed
    if passed:
        verified=a.out/'verified';verified.mkdir()
        for name in record['modules']:
            shutil.copyfile(work/name,verified/name)
        if (work/'Module.symvers').is_file():
            shutil.copyfile(work/'Module.symvers',verified/'Module.symvers')
    (a.out/'stage-a-result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
    return 0 if passed else 1

if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,ValueError,subprocess.CalledProcessError) as exc: raise SystemExit(str(exc))
