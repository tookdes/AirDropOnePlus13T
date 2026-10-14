#!/usr/bin/env python3
"""Prepare fail-closed qcacld modpost provider tables from checked evidence."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from prepare_stage_a import run
from build_stage_a import TARGET_RELEASE
from build_qcacld_kernel_crcs import prepare as prepare_kernel
from qcacld_import_profile import load_profile
from stock_image import module_exports

def read_symvers(path:Path)->dict[str,list[str]]:
    result={}
    for no,line in enumerate(path.read_text(encoding='utf-8').splitlines(),1):
        f=line.split('\t')
        if len(f)!=5 or f[1] in result or not f[1]:
            raise ValueError(f'Invalid/duplicate symvers row {path}:{no}')
        int(f[0],16); result[f[1]]=f
    return result

def missing_against(rows:list[list[str]], existing:dict[str,list[str]])->list[list[str]]:
    extra=[]
    for f in rows:
        old=existing.get(f[1])
        if old is None: extra.append(f)
        elif old!=f: raise ValueError('Provider/CRC conflict with kernel Module.symvers: '+f[1])
    return extra

def write(path:Path,rows:list[list[str]])->None:
    names=[f[1] for f in rows]
    if len(names)!=len(set(names)): raise ValueError('Duplicate provider symbol in '+str(path))
    path.write_text(''.join('\t'.join(f)+'\n' for f in sorted(rows,key=lambda x:x[1])),encoding='ascii')

def prepare(kernel:Path,kout:Path,compiler:Path,shim:Path,out:Path)->dict:
    out.mkdir(parents=True,exist_ok=False)
    _,_,stock_rows=load_profile()
    existing=read_symvers(kout/'Module.symvers')
    stock_extra=missing_against(stock_rows,existing)

    make=['make','-C',str(kernel),'O='+str(kout),'ARCH=arm64',
          'LLVM='+str(compiler)+'/', 'LLVM_IAS=1',
          'KERNELRELEASE='+TARGET_RELEASE,'-j2']
    core_path,core_report=prepare_kernel(kernel,kout,make,out)
    core_rows=list(read_symvers(core_path).values())

    exports=module_exports(shim)
    matches=[r for r in exports if r['name']=='cnss_set_vendor_wonder_priv_data']
    if len(matches)!=1 or len(exports)!=1:
        raise ValueError('Unexpected Stage-A shim export surface')
    r=matches[0]
    if (r['crc']!='0xd7585ffc' or r['provider']!='wonder_shim_13t' or
            r['export_type']!='EXPORT_SYMBOL' or r['namespace']!=''):
        raise ValueError('Stage-A shim provider ABI changed')
    shim_row=[r['crc'],r['name'],r['provider'],r['export_type'],r['namespace']]

    baseline=out/'qcacld-baseline-providers.symvers'
    candidate=out/'qcacld-candidate-providers.symvers'
    write(baseline,stock_extra)
    # New core rows were independently regenerated immediately above.
    merged={f[1]:f for f in stock_extra}
    for f in core_rows+[shim_row]:
        if f[1] in merged and merged[f[1]]!=f:
            raise ValueError('Conflicting candidate provider: '+f[1])
        merged[f[1]]=f
    write(candidate,list(merged.values()))

    report={
      'stock_import_count':len(stock_rows),
      'stock_rows_already_in_kernel_symvers':len(stock_rows)-len(stock_extra),
      'baseline_extra_provider_rows':len(stock_extra),
      'candidate_extra_provider_rows':len(merged),
      'fresh_candidate_kernel_crc_gate_passed':core_report['fresh_kernel_crc_gate_passed'],
      'fresh_candidate_kernel_crcs':core_report['matched'],
      'shim_export':{k:r[k] for k in ('name','crc','provider','export_type','namespace','provider_sha256')},
      'expected_candidate_only_symbols':['cnss_set_vendor_wonder_priv_data','dev_close','dev_open','get_random_u32'],
      'binary_crc_patching':False,'module_completion_proven':False,
    }
    (out/'qcacld-modpost-providers.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--kernel-out',type=Path,required=True)
    p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--shim',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    try:r=prepare(a.kernel,a.kernel_out,a.compiler,a.shim,a.out)
    except (OSError,ValueError,RuntimeError) as exc:
        print(str(exc));return 1
    print(json.dumps(r,indent=2));return 0
if __name__=='__main__': raise SystemExit(main())
