#!/usr/bin/env python3
"""Prepare the exact ARM64 header environment and independently regenerate CRCs.

Module.symvers comes from actual stock boot exports, never invented CRCs.
Compile real kernel translation units and compare fresh genksyms output first.
No target kernel is flashed and no phone is contacted.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from build_stage_a import config_values
ROOT=Path(__file__).resolve().parents[1]
COMMON='5a0ffb447c1dbd82e8e3af7a98c4a629f4b6d143'
CLANG_COMMIT='18bfb7fbd697a1ad710fd0581a4ac9f3db385f71'
CLANG_NAME='clang-r510928'
CLANG_REPO='https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86'
CORE_OBJECTS=('kernel/module/version.o','drivers/base/platform.o',
              'drivers/base/component.o','drivers/of/base.o')
REQUIRED_FRESH={'module_layout','component_add','component_del',
                'platform_device_alloc','of_find_node_opts_by_path'}
UNTRUSTED_ENV=('KCFLAGS','KCPPFLAGS','CFLAGS_MODULE','CFLAGS_KERNEL','LDFLAGS_MODULE',
 'KBUILD_MODPOST_WARN','KBUILD_EXTRA_SYMBOLS','KBUILD_MODPOST_NOFINAL','KCONFIG_CONFIG',
 'KCONFIG_ALLCONFIG','LLVM','ARCH','CROSS_COMPILE','CC','CXX','LD','AR','AS','NM',
 'OBJCOPY','OBJDUMP','STRIP','MAKEFLAGS','MFLAGS','KBUILD_SRC','KBUILD_OUTPUT','KBUILD_EXTMOD')

def digest(p:Path):return hashlib.sha256(p.read_bytes()).hexdigest()
def clean_env():
    env=os.environ.copy()
    for k in UNTRUSTED_ENV:env.pop(k,None)
    env['LC_ALL']='C';return env

def run(args:list[str], log:Path, *, cwd:Path|None=None):
    with log.open('a') as f:
        f.write('\n$ '+' '.join(args)+'\n');f.flush()
        r=subprocess.run(args,cwd=cwd,env=clean_env(),stdout=f,stderr=subprocess.STDOUT)
    if r.returncode:raise RuntimeError(f'Command failed ({r.returncode}); see {log}')

def checkout(url:str, commit:str, path:Path, log:Path, sparse:str|None=None):
    if not (path/'.git').exists():
        if path.exists() and any(path.iterdir()):raise ValueError('Refusing nonempty non-git directory')
        path.mkdir(parents=True,exist_ok=True)
        run(['git','init','-q',str(path)],log)
        run(['git','-C',str(path),'remote','add','origin',url],log)
    origin=subprocess.check_output(['git','-C',str(path),'remote','get-url','origin'],text=True).strip()
    if origin!=url:raise ValueError('Wrong source remote: '+str(path))
    if subprocess.check_output(['git','-C',str(path),'status','--porcelain'],text=True).strip():
        raise ValueError('Refusing dirty source checkout: '+str(path))
    if sparse:
        run(['git','-C',str(path),'sparse-checkout','init','--cone'],log)
        run(['git','-C',str(path),'sparse-checkout','set',sparse],log)
    run(['git','-C',str(path),'fetch','--filter=blob:none','--depth=1','origin',commit],log)
    run(['git','-C',str(path),'checkout','--detach',commit],log)
    got=subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
    if got!=commit:raise ValueError('Source revision mismatch')

def export_db(evidence:Path):
    report=json.loads((evidence/'extraction-report.json').read_text())
    if digest(evidence/'boot.config')!=report['config']['sha256']:
        raise ValueError('Captured config checksum mismatch')
    if digest(evidence/'vmlinux.btf')!=report['btf']['sha256']:
        raise ValueError('Captured BTF checksum mismatch')
    rows=json.loads((evidence/'exports.json').read_text())
    core={r['name']:r for r in rows if r['provider']=='vmlinux'}
    raw=(evidence/'vmlinux.exports.symvers').read_text()
    parsed={}
    for line in raw.splitlines():
        f=line.split('\t')
        if len(f)!=5 or f[2]!='vmlinux' or f[1] in parsed:raise ValueError('Malformed core export table')
        r=core.get(f[1])
        if not r or [r['crc'],r['name'],r['provider'],r['export_type'],r['namespace']]!=f:
            raise ValueError('Export metadata disagrees with symvers')
        parsed[f[1]]=int(f[0],16)
    if len(parsed)!=report['kernel_exports']['export_count'] or len(parsed)!=len(core):
        raise ValueError('Core export count mismatch')
    return parsed,report

def symversions_from_cmd(text:str)->dict[str,int]:
    result={}
    for sym,crc in re.findall(r'^#SYMVER\s+(\S+)\s+(0x[0-9a-fA-F]+)\s*$',text,re.M):
        if sym in result and result[sym]!=int(crc,16):raise ValueError('Conflicting fresh CRC')
        result[sym]=int(crc,16)
    return result

def compare_fresh(fresh:dict[str,int], expected:dict[str,int]):
    missing=sorted(REQUIRED_FRESH-fresh.keys())
    missing_stock=sorted(REQUIRED_FRESH-expected.keys())
    mismatch={n:{'fresh':f'0x{v:08x}','stock':f'0x{expected[n]:08x}'}
              for n,v in fresh.items() if n in expected and v!=expected[n]}
    if missing or missing_stock or mismatch:
        raise ValueError(json.dumps({'missing_required_crc':missing,'missing_stock_crc':missing_stock,'mismatches':mismatch}))
    return {n:f'0x{v:08x}' for n,v in sorted(fresh.items()) if n in expected}

def prepare(work:Path,evidence:Path,fetch:bool)->dict:
    work=work.resolve();work.mkdir(parents=True,exist_ok=True);log=work/'prepare.log'
    source=work/'common';tc=work/'toolchain'
    if fetch:
        checkout('https://github.com/OnePlusOSS/android_kernel_common_oneplus_sm8750.git',COMMON,source,log)
        checkout(CLANG_REPO,CLANG_COMMIT,tc,log,CLANG_NAME)
    actual=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if actual!=COMMON:raise ValueError('Kernel revision mismatch')
    if subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True).strip():
        raise ValueError('Kernel source must be clean')
    compiler=tc/CLANG_NAME/'bin';version=subprocess.check_output([str(compiler/'clang'),'--version'],text=True)
    if not all(s in version for s in ('11368308','r510928','18.0.0')):
        raise ValueError('Compiler is not the captured Android r510928 build 11368308')
    for t in ('ld.lld','llvm-ar','llvm-nm','llvm-objcopy','llvm-strip'):
        if not (compiler/t).is_file():raise ValueError('Missing tool: '+t)
    expected,report=export_db(evidence)
    out=work/'kernel-out'
    if out.exists():raise ValueError('Use a new workspace; refusing to overwrite prepared build output')
    out.mkdir();shutil.copyfile(evidence/'boot.config',out/'.config')
    make=['make','-C',str(source),'O='+str(out),'ARCH=arm64','LLVM='+str(compiler)+'/', 'LLVM_IAS=1','-j2']
    run(make+['olddefconfig'],log)
    before=config_values((evidence/'boot.config').read_bytes());after=config_values((out/'.config').read_bytes())
    diff={k:[before.get(k,'n'),after.get(k,'n')] for k in set(before)|set(after)
          if k!='CONFIG_LOCALVERSION' and before.get(k,'n')!=after.get(k,'n')}
    if diff:
        (work/'config-differences.json').write_text(json.dumps(diff,indent=2)+'\n')
        raise ValueError('Prepared config differs from captured config; no silent ABI/config substitutions')
    run(make+['modules_prepare'],log)
    run(make+list(CORE_OBJECTS),log)
    fresh={}
    for obj in CORE_OBJECTS:
        p=Path(obj);cmd=out/p.parent/('.'+p.name+'.cmd')
        got=symversions_from_cmd(cmd.read_text())
        for n,v in got.items():
            if n in fresh and fresh[n]!=v:raise ValueError('Conflicting generated symbol versions')
            fresh[n]=v
    checked=compare_fresh(fresh,expected)
    # Only after independent genksyms comparison expose captured export data.
    # Never rewrite a built module's __versions section.
    shutil.copyfile(evidence/'vmlinux.exports.symvers',out/'Module.symvers')
    proof={'schema':1,'source_commit':COMMON,'compiler_commit':CLANG_COMMIT,'compiler_version':version,
           'compiler_sha256':digest(compiler/'clang'),'boot_sha256':report['boot']['boot_sha256'],
           'config_sha256':digest(evidence/'boot.config'),'stock_symvers_sha256':digest(out/'Module.symvers'),
           'fresh_genksyms_matches':checked,'fresh_genksyms_count':len(checked),
           'symvers_origin':'actual boot export tables; NOT synthesized from imports',
           'full_kernel_link':False,'phone_accessed':False}
    (work/'prepare-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    return proof

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--evidence',type=Path,default=ROOT/'evidence/stock');p.add_argument('--fetch',action='store_true')
    a=p.parse_args()
    try:r=prepare(a.workspace,a.evidence,a.fetch)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        a.workspace.mkdir(parents=True,exist_ok=True)
        (a.workspace/'prepare-failure.json').write_text(json.dumps({'error':str(exc),'target_build_complete':False},indent=2)+'\n')
        p.exit(1,str(exc)+'\n')
    print(json.dumps(r,indent=2))
if __name__=='__main__':main()
