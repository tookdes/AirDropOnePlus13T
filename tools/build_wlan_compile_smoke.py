#!/usr/bin/env python3
"""Compile-only qcacld smoke against the pinned 13T GKI environment.

This deliberately permits modpost warnings because dependent vendor Module.symvers
are not public in this workflow. It does NOT declare the produced module loadable.
Compilation, relocatable link, Wonder object selection and candidate-only undefined
imports are the only gates here.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess
from pathlib import Path

TARGET_RELEASE='6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k'
PROFILE='sun_gki_peach-v2'
MODNAME='qca_cld3_peach_v2'
OPLUS_DEFINES=[
 'OPLUS_FEATURE_WIFI_BDF','OPLUS_FEATURE_WIFI_MAC','OPLUS_FEATURE_WIFI_FTM',
 'OPLUS_FEATURE_WIFI_DCS_SWITCH','OPLUS_BUG_STABILITY',
 'OPLUS_FEATURE_WIFI_VENDOR_FT','OPLUS_FEATURE_CONN_POWER_MONITOR',
 'OPLUS_FEATURE_WIFI_BEAM_SWITCH','OPLUS_FEATURE_SOFTAP_DCS_SWITCH',
]

def run(cmd:list[str], log:Path, env:dict[str,str]|None=None)->int:
    with log.open('a') as f:
        f.write('\n$ '+' '.join(cmd)+'\n');f.flush()
        p=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,env=env)
        return p.returncode

def undefined(nm:Path,obj:Path)->set[str]:
    if not obj.exists(): return set()
    out=subprocess.check_output([str(nm),'-u',str(obj)],text=True,errors='replace')
    got=set()
    for line in out.splitlines():
        m=re.search(r'\bU\s+(\S+)$',line.strip())
        if m: got.add(m.group(1))
    return got

def build(label:str, kernel:Path, kout:Path, compiler:Path, root:Path,
          out:Path, passthru:bool)->dict:
    cld=root/'vendor/qcom/opensource/wlan/qcacld-3.0'
    if not cld.is_dir(): raise ValueError(f'{label}: missing qcacld source')
    out.mkdir(parents=True,exist_ok=False)
    log=out/'build.log'
    # Build out-of-tree objects beside copied source, never edit the pinned git checkout.
    work=out/'src'
    shutil.copytree(cld,work,symlinks=True)
    # sibling symlinks in qcacld point outside this directory; recreate the public
    # sibling layout used by the original tree.
    wlan=root/'vendor/qcom/opensource/wlan'
    for name in ('qca-wifi-host-cmn','fw-api','platform'):
        src=wlan/name; dst=out/name
        if src.exists(): shutil.copytree(src,dst,symlinks=True)
    data=root/'vendor/qcom/opensource/dataipa'
    if data.exists(): shutil.copytree(data,out/'dataipa',symlinks=True)
    # Point qcacld's standard relative symlinks at the copied siblings.
    for name,target in [('cmn','../qca-wifi-host-cmn'),('api','../fw-api')]:
        p=work/name
        if p.exists() or p.is_symlink(): p.unlink()
        p.symlink_to(target)

    kcflags=' '.join('-D'+x for x in OPLUS_DEFINES)
    override=''
    if passthru:
        override='CONFIG_DRIVER_PASSTHRU_MODE=y CONFIG_WONDER_SUPPORT=y'
    cmd=['make','-C',str(kernel),'O='+str(kout),'ARCH=arm64',
         'LLVM='+str(compiler)+'/', 'LLVM_IAS=1',
         'KERNELRELEASE='+TARGET_RELEASE,'-j2',
         'M='+str(work),'WLAN_ROOT='+str(work),'MODNAME='+MODNAME,
         'CONFIG_QCA_CLD_WLAN=m','CONFIG_QCA_CLD_WLAN_PROFILE='+PROFILE,
         'KBUILD_MODPOST_WARN=1','KCFLAGS='+kcflags]
    if override: cmd.append('WLAN_CFG_OVERRIDE='+override)
    cmd.append('modules')
    rc=run(cmd,log)
    obj=work/(MODNAME+'.o'); ko=work/(MODNAME+'.ko')
    nm=compiler/'llvm-nm'
    und=sorted(undefined(nm,obj if obj.exists() else ko))
    wonder_obj=work/'core/hdd/src/wlan_hdd_wondertap.o'
    wonder_cmd=work/'core/hdd/src/.wlan_hdd_wondertap.o.cmd'
    cmdtext=wonder_cmd.read_text(errors='replace') if wonder_cmd.exists() else ''
    return {
      'label':label,'passthru':passthru,'make_rc':rc,
      'relocatable_object':obj.exists(),'ko_emitted':ko.exists(),
      'undefined_count':len(und),'undefined':und,
      'wonder_object_selected':wonder_obj.exists(),
      'wonder_compile_cmd_present':wonder_cmd.exists(),
      'wonder_macro_enabled':'-DDRIVER_PASSTHRU_MODE' in cmdtext,
      'wonder_kcfi_enabled':'-fsanitize=kcfi' in cmdtext,
      'release_ready':False,'loadable_proven':False,
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--kernel',type=Path,required=True)
    ap.add_argument('--kernel-out',type=Path,required=True)
    ap.add_argument('--compiler',type=Path,required=True)
    ap.add_argument('--baseline',type=Path,required=True)
    ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=False)
    b=build('baseline',a.kernel,a.kernel_out,a.compiler,a.baseline,a.out/'baseline',False)
    c=build('candidate',a.kernel,a.kernel_out,a.compiler,a.candidate,a.out/'candidate',True)
    report={'baseline':b,'candidate':c,
      'candidate_only_undefined':sorted(set(c['undefined'])-set(b['undefined'])),
      'baseline_only_undefined':sorted(set(b['undefined'])-set(c['undefined'])),
      'compile_gate_passed': b['make_rc']==0 and c['make_rc']==0 and
         b['relocatable_object'] and c['relocatable_object'] and
         c['wonder_object_selected'] and c['wonder_macro_enabled'] and c['wonder_kcfi_enabled'],
      'module_completion_gate':'BLOCKED',
      'note':'KBUILD_MODPOST_WARN is compile diagnostics only; dependent vendor symbol closure is a later hard gate.'}
    (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['compile_gate_passed'] else 1
if __name__=='__main__': raise SystemExit(main())
