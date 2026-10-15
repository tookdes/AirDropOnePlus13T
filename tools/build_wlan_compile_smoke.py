#!/usr/bin/env python3
"""Compile-only qcacld smoke against the pinned 13T GKI environment.

Strict mode requires checked providers and fails on either compilation or
provider-closure failure. Diagnostic mode may emit unresolved-symbol warnings.
Neither mode establishes runtime loadability, firmware compatibility, or RF.
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

OPLUS_SYSTEM_HEADERS = ('boot_mode.h', 'oplus_midplat.h', 'oplus_project.h',
                        'oplus_project_data_ocdt.h')

# The public GKI common-tree config (gki_defconfig) omits vendor kernel configs
# that the stock 13T vendor modules are built with, while the stock boot image
# (captured config) is GKI-only and also omits them: CONFIG_ARM_SMMU is "not set"
# and IPA3/IOMMU-util live in the vendor module tree. The qcacld/dataipa sources
# switch on these via IS_ENABLED(CONFIG_*); selecting the vendor build's branch
# is required for a compile-only reproduction. These -D flags only steer header
# selection in the copied public sources; they never alter the checked-in ABI
# profile, the stock kernel config, or the emitted (non-loadable) objects.
VENDOR_KERNEL_CONFIG_DEFINES = ['CONFIG_IPA3=1', 'CONFIG_ARM_SMMU=1']

# The pinned profile is consumed differently by the shipping Bazel build and
# this diagnostic Kbuild path. Bazel keys the monitor-2.0 source set from
# CONFIG_WIFI_MONITOR_SUPPORT_Y_WLAN_TX_MON_2_0, while Kbuild tests the derived
# CONFIG_WLAN_TX_MON_2_0 variable directly. Derive the latter only after
# proving the exact pinned profile enables the corresponding composite keys.
PROFILE_REQUIRED = {
 'CONFIG_WIFI_MONITOR_SUPPORT': 'y',
 'CONFIG_WIFI_MONITOR_SUPPORT_Y_WLAN_TX_MON_2_0': 'y',
 'CONFIG_WLAN_DP_LOCAL_PKT_CAPTURE': 'y',
 'CONFIG_WLAN_TX_MON_2_0_Y_WLAN_DP_LOCAL_PKT_CAPTURE': 'y',
}
PROFILE_KBUILD_DERIVED = [
 'CONFIG_WIFI_MONITOR_SUPPORT=y',
 'CONFIG_WLAN_TX_MON_2_0=y',
 'CONFIG_WLAN_DP_LOCAL_PKT_CAPTURE=y',
]

def profile_kbuild_compat(work: Path) -> dict:
    cfg=work/'configs'/(PROFILE+'_defconfig')
    if not cfg.is_file(): raise ValueError('Missing pinned qcacld profile: '+str(cfg))
    values={}
    for line in cfg.read_text(errors='strict').splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            k,v=line.split('=',1); values[k]=v.strip()
    bad={k:{'expected':v,'actual':values.get(k)} for k,v in PROFILE_REQUIRED.items()
         if values.get(k)!=v}
    if bad: raise ValueError('Pinned monitor profile drift: '+json.dumps(bad,sort_keys=True))

    # OPlus ships this source in wlan_qcacld3_modules.bzl under the already
    # pinned OPLUS_FEATURE_WIFI_BEAM_SWITCH define. Traditional Kbuild lacks
    # that source selection, so add it only inside the disposable build copy.
    beam='core/hdd/src/wlan_hdd_beam_switch.c'
    bzl=work/'wlan_qcacld3_modules.bzl'
    if not (work/beam).is_file() or not bzl.is_file():
        raise ValueError('Missing pinned OPlus beam-switch source metadata')
    bzl_text=bzl.read_text(errors='strict')
    if '#ifdef OPLUS_FEATURE_WIFI_BEAM_SWITCH' not in bzl_text or ('"'+beam+'"') not in bzl_text:
        raise ValueError('Beam-switch Bazel source contract drifted')
    kbuild=work/'Kbuild'; text=kbuild.read_text(errors='strict')
    obj='$(HDD_SRC_DIR)/wlan_hdd_beam_switch.o'
    hdd_anchor='$(call add-wlan-objs,hdd,$(HDD_OBJS))'
    if obj not in text:
        if text.count(hdd_anchor)!=1: raise ValueError('Unexpected HDD Kbuild anchor')
        text=text.replace(hdd_anchor,
            '# Diagnostic Kbuild parity with pinned Bazel OPlus source selection\n'
            'HDD_OBJS += '+obj+'\n\n'+hdd_anchor)
        kbuild.write_text(text)
    return {'profile':PROFILE,'derived_make_vars':PROFILE_KBUILD_DERIVED,
            'beam_switch_object':obj,'source_selection':'pinned Bazel to disposable Kbuild parity'}

def oplus_system_shim(baseline: Path, out: Path) -> Path:
    """Expose the pinned 13T OPlus system headers under the kernel's
    ``soc/oplus/system`` include path.

    The public OnePlusOSS common tree no longer ships ``include/soc/oplus``; the
    exact headers live in the pinned vendor module tree. Only the four headers
    the qcacld/cmn/cnss2 source actually includes are staged, read from the
    immutable target checkout so the smoke cannot drift from the stock ABI.
    """
    src = baseline/'vendor/oplus/kernel/boot/include'
    if not src.is_dir():
        raise ValueError('Missing OPlus system headers: '+str(src))
    dst = out/'oplus-system-headers'/'soc'/'oplus'/'system'
    dst.mkdir(parents=True, exist_ok=True)
    missing = [h for h in OPLUS_SYSTEM_HEADERS if not (src/h).is_file()]
    if missing:
        raise ValueError('Incomplete OPlus system headers: '+', '.join(missing))
    for h in OPLUS_SYSTEM_HEADERS:
        shutil.copy2(src/h, dst/h)
    return out/'oplus-system-headers'

def build(label:str, kernel:Path, kout:Path, compiler:Path, root:Path,
          out:Path, passthru:bool, plus_inc:Path,
          extra_symvers:Path|None=None, strict_modpost:bool=False)->dict:
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

    compat=profile_kbuild_compat(work)

    # The GKI config promotes warnings to errors (CONFIG_WERROR), and qcacld
    # adds -Wmissing-prototypes itself. The stock source is known to carry a
    # few non-static helper definitions without prototypes (e.g. an OPlus
    # qdf_nbuf_clear_dhcp_bc_flags); upstream works around these with ad-hoc
    # forward declarations, not by treating them as build failures. Demote only
    # this diagnostic so the compile-only smoke keeps every other -Werror.
    kcflags=' '.join('-D'+x for x in OPLUS_DEFINES)+' -I'+str(plus_inc)
    kcflags+=' '+' '.join('-D'+x for x in VENDOR_KERNEL_CONFIG_DEFINES)
    kcflags+=' -Wno-error=missing-prototypes'
    override=''
    if passthru:
        override='CONFIG_DRIVER_PASSTHRU_MODE=y CONFIG_WONDER_SUPPORT=y'
    cmd=['make','-C',str(kernel),'O='+str(kout),'ARCH=arm64',
         'LLVM='+str(compiler)+'/', 'LLVM_IAS=1',
         'KERNELRELEASE='+TARGET_RELEASE,'-j2',
         'M='+str(work),'WLAN_ROOT='+str(work),'MODNAME='+MODNAME,
         'CONFIG_QCA_CLD_WLAN=m','CONFIG_QCA_CLD_WLAN_PROFILE='+PROFILE,
         'CONFIG_IPA_OUT_OF_TREE=y',
         *compat['derived_make_vars'],
         'KCFLAGS='+kcflags]
    if strict_modpost:
        if not extra_symvers or not extra_symvers.is_file():
            raise ValueError(label+': strict modpost requires checked provider symvers')
        cmd.append('KBUILD_EXTRA_SYMBOLS='+str(extra_symvers.resolve()))
    else:
        cmd.append('KBUILD_MODPOST_WARN=1')
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
      'kbuild_profile_compat':compat,
      'strict_modpost':strict_modpost,
      'extra_symvers':str(extra_symvers) if extra_symvers else None,
      'modpost_provider_gate_passed':strict_modpost and rc==0 and ko.exists(),
      'release_ready':False,'loadable_proven':False,
    }

def exit_status(report: dict, strict_modpost: bool) -> int:
    """A standalone strict invocation must enforce the provider gate too."""
    return 0 if (report['compile_gate_passed'] and
                 (not strict_modpost or report['modpost_provider_gate_passed'])) else 1


def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--kernel',type=Path,required=True)
    ap.add_argument('--kernel-out',type=Path,required=True)
    ap.add_argument('--compiler',type=Path,required=True)
    ap.add_argument('--baseline',type=Path,required=True)
    ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--baseline-symvers',type=Path)
    ap.add_argument('--candidate-symvers',type=Path)
    ap.add_argument('--strict-modpost',action='store_true')
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=False)
    if a.strict_modpost and (not a.baseline_symvers or not a.candidate_symvers):
        raise ValueError('--strict-modpost requires both provider symvers files')
    plus_inc=oplus_system_shim(a.baseline,a.out)
    b=build('baseline',a.kernel,a.kernel_out,a.compiler,a.baseline,a.out/'baseline',False,plus_inc,
            a.baseline_symvers,a.strict_modpost)
    c=build('candidate',a.kernel,a.kernel_out,a.compiler,a.candidate,a.out/'candidate',True,plus_inc,
            a.candidate_symvers,a.strict_modpost)
    candidate_only=sorted(set(c['undefined'])-set(b['undefined']))
    baseline_only=sorted(set(b['undefined'])-set(c['undefined']))
    expected_new=['cnss_set_vendor_wonder_priv_data','dev_close','dev_open','get_random_u32']
    compile_ok=b['make_rc']==0 and c['make_rc']==0 and b['relocatable_object'] and c['relocatable_object'] and \
         c['wonder_object_selected'] and c['wonder_macro_enabled'] and c['wonder_kcfi_enabled']
    provider_ok=compile_ok and a.strict_modpost and b['modpost_provider_gate_passed'] and c['modpost_provider_gate_passed'] and \
         candidate_only==expected_new and not baseline_only
    report={'baseline':b,'candidate':c,
      'candidate_only_undefined':candidate_only,
      'baseline_only_undefined':baseline_only,
      'expected_candidate_only_undefined':expected_new,
      'compile_gate_passed':compile_ok,
      'modpost_provider_gate_passed':provider_ok,
      'module_completion_gate':'PASSED_OFFLINE' if provider_ok else 'BLOCKED',
      'note':('Strict modpost resolved every undefined symbol from checked provider tables.'
              if provider_ok else 'Provider closure is not yet a loadability claim.')}
    (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return exit_status(report,a.strict_modpost)
if __name__=='__main__': raise SystemExit(main())
