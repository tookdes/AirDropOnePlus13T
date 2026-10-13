#!/usr/bin/env python3
"""Compile-only cfg80211, mac80211 and Wonder against the pinned 13T GKI tree.

Stock boot config has CONFIG_CFG80211 not set; the captured device ships an
out-of-tree cfg80211.ko and mac80211.ko. Wonder.ko Kconfig depends on
MAC80211, so this smoke enables those two configs on a *copy* of the Stage A
kernel-out, builds the in-tree wireless modules, then builds the pinned 13T
Wonder sources. It does NOT claim CRC match with the captured cfg80211.ko,
live loadability, or an AirDrop installer.
"""
from __future__ import annotations
import argparse, json, re, shutil, subprocess
from pathlib import Path
from elf_audit import Module
from audit_mac80211_ops import audit_path, compile_time_assertions

TARGET_RELEASE='6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k'
WONDER_REL=Path('vendor/oplus/kernel/wifi/wonder')
WIRELESS_MODULES=(
    ('cfg80211','net/wireless','cfg80211.ko'),
    ('mac80211','net/mac80211','mac80211.ko'),
)

def run(cmd:list[str], log:Path)->int:
    with log.open('a') as f:
        f.write('\n$ '+' '.join(cmd)+'\n');f.flush()
        return subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT).returncode

def undefined(nm:Path,obj:Path)->set[str]:
    if not obj.exists(): return set()
    out=subprocess.check_output([str(nm),'-u',str(obj)],text=True,errors='replace')
    got=set()
    for line in out.splitlines():
        m=re.search(r'\bU\s+(\S+)$',line.strip())
        if m: got.add(m.group(1))
    return got

def config_is_enabled(text:str, name:str)->bool:
    return bool(re.search(rf'^CONFIG_{re.escape(name)}=[ym]$', text, re.M))

def classify(names:list[str])->dict[str,list[str]]:
    buckets={'ieee80211':[],'cfg80211':[],'wiphy':[],'other':[]}
    for n in names:
        if n.startswith('ieee80211_') or n.startswith('ieee80211x_'):
            buckets['ieee80211'].append(n)
        elif n.startswith('cfg80211_'):
            buckets['cfg80211'].append(n)
        elif n.startswith('wiphy_'):
            buckets['wiphy'].append(n)
        else:
            buckets['other'].append(n)
    return buckets

def make_cmd(kernel:Path, kout:Path, compiler:Path)->list[str]:
    return ['make','-C',str(kernel),'O='+str(kout),'ARCH=arm64',
            'LLVM='+str(compiler)+'/','LLVM_IAS=1',
            'KERNELRELEASE='+TARGET_RELEASE,'-j2']

def enable_wireless_config(kernel:Path, kout_src:Path, kout_dst:Path,
                           compiler:Path, log:Path)->dict:
    if not (kout_src/'.config').is_file():
        raise ValueError('Missing Stage A kernel-out .config')
    if kout_dst.exists():
        raise ValueError('Refusing to overwrite wireless kernel-out')
    shutil.copytree(kout_src, kout_dst, symlinks=True)
    cfg=kout_dst/'.config'
    script=kernel/'scripts'/'config'
    for name in ('CFG80211','MAC80211'):
        rc=run([str(script),'--file',str(cfg),'--module',name], log)
        if rc: raise RuntimeError('scripts/config failed for '+name)
    rc=run(make_cmd(kernel,kout_dst,compiler)+['olddefconfig'], log)
    if rc: raise RuntimeError('olddefconfig failed after enabling wireless')
    # Stock ops omit the three DEBUGFS callbacks but include the two TESTMODE
    # callbacks. DEBUGFS=n alone leaves wake_tx_queue at 0x2e0, not stock 0x2f0.
    rc=run([str(script),'--file',str(cfg),'--disable','MAC80211_DEBUGFS'], log)
    if rc: raise RuntimeError('scripts/config failed for MAC80211_DEBUGFS')
    rc=run([str(script),'--file',str(cfg),'--enable','NL80211_TESTMODE'], log)
    if rc: raise RuntimeError('scripts/config failed for NL80211_TESTMODE')
    rc=run(make_cmd(kernel,kout_dst,compiler)+['olddefconfig'], log)
    if rc: raise RuntimeError('olddefconfig failed after setting stock wireless ops config')
    text=cfg.read_text(errors='replace')
    enabled={n:config_is_enabled(text,n) for n in ('CFG80211','MAC80211','RFKILL')}
    enabled['MAC80211_DEBUGFS']=config_is_enabled(text,'MAC80211_DEBUGFS')
    enabled['NL80211_TESTMODE']=config_is_enabled(text,'NL80211_TESTMODE')
    enabled['PM']=config_is_enabled(text,'PM')
    if not enabled['CFG80211'] or not enabled['MAC80211']:
        raise ValueError('Wireless configs did not remain enabled: '+json.dumps(enabled))
    if enabled['MAC80211_DEBUGFS']:
        raise ValueError('MAC80211_DEBUGFS must stay disabled to match stock ops layout')
    if not enabled['NL80211_TESTMODE'] or not enabled['PM']:
        raise ValueError('NL80211_TESTMODE and PM must stay enabled to match stock ops layout')
    rc=run(make_cmd(kernel,kout_dst,compiler)+['modules_prepare'], log)
    if rc: raise RuntimeError('modules_prepare failed after enabling wireless')
    return {'enabled':enabled,'kernel_out':str(kout_dst)}

def build_in_tree(label:str, rel:str, ko_name:str, kernel:Path, kout:Path,
                  compiler:Path, out:Path)->dict:
    out.mkdir(parents=True, exist_ok=False)
    log=out/'build.log'
    # Out-of-tree O= builds resolve TRACE_INCLUDE_PATH to ./trace.h. Copy the
    # in-tree wireless sources beside kernel-out so that include works.
    src=kernel/rel
    work=kout/rel
    if not src.is_dir():
        raise ValueError('Missing in-tree wireless sources: '+str(src))
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(src, work, symlinks=True)
    cmd=make_cmd(kernel,kout,compiler)+['M='+str(work),'KBUILD_MODPOST_WARN=1','modules']
    rc=run(cmd,log)
    ko=work/ko_name
    obj=work/(ko_name[:-3]+'.o')
    nm=compiler/'llvm-nm'
    und=sorted(undefined(nm, obj if obj.exists() else ko))
    return {'label':label,'make_rc':rc,'ko_emitted':ko.exists(),
            'relocatable_object':obj.exists(),'undefined_count':len(und),
            'undefined':und,'release_ready':False,'loadable_proven':False}

def parse_symvers(path:Path)->dict[str,int]:
    rows={}
    for line in path.read_text().splitlines():
        f=line.split('\t')
        if len(f)<2: continue
        rows[f[1]]=int(f[0],16)
    return rows

def crc_compare(wonder_ko:Path, stock_symvers:list[Path])->dict:
    if not wonder_ko.is_file():
        return {'compared':False,'matched':[],'mismatched':[],'missing_import':[]}
    imp=Module(wonder_ko.read_bytes()).versions()
    stock={}
    for p in stock_symvers:
        stock.update(parse_symvers(p))
    matched=[]; mismatched=[]; missing=[]
    for name,crc in sorted(imp.items()):
        if name=='module_layout':
            continue
        if name not in stock:
            missing.append(name); continue
        if stock[name]==crc: matched.append(name)
        else: mismatched.append({'name':name,'wonder':f'0x{crc:08x}','stock':f'0x{stock[name]:08x}'})
    return {'compared':True,'matched':matched,'mismatched':mismatched,
            'missing_import':missing,
            'alloc_hw_nm': next((x for x in mismatched if x['name']=='ieee80211_alloc_hw_nm'), None)}

def build_wonder(kernel:Path, kout:Path, compiler:Path, src:Path,
                 extra_symvers:list[Path], out:Path)->dict:
    if not (src/'mac80211.c').is_file() or not (src/'Kconfig').is_file():
        raise ValueError('Missing pinned Wonder sources under '+str(src))
    kconfig=(src/'Kconfig').read_text(errors='replace')
    if 'depends on MAC80211' not in kconfig:
        raise ValueError('Wonder Kconfig no longer depends on MAC80211')
    out.mkdir(parents=True, exist_ok=False)
    log=out/'build.log'
    work=out/'src'
    shutil.copytree(src, work, symlinks=True)
    series=Path(__file__).resolve().parents[1]/'patches'/'wonder'
    if series.is_dir():
        for patch in sorted(series.glob('*.patch')):
            cp=subprocess.run(['git','apply','--check','-'],cwd=work,input=patch.read_bytes(),capture_output=True)
            if cp.returncode:
                raise ValueError('Wonder patch failed: '+patch.name+' '+cp.stderr.decode(errors='replace'))
            cp=subprocess.run(['git','apply','-'],cwd=work,input=patch.read_bytes(),capture_output=True)
            if cp.returncode:
                raise ValueError('Wonder patch apply failed: '+patch.name)
    mac=work/'mac80211.c'
    mac.write_text(mac.read_text(encoding='utf-8')+compile_time_assertions(), encoding='utf-8')
    # The pinned Makefile.include appends a canoe product Module.symvers that
    # is not part of this public smoke. Keep only the wireless-stack symbols.
    include=work/'Makefile.include'
    if include.exists():
        include.write_text('# Public compile-only smoke: product Module.symvers omitted.\n')
    extra=' '.join(str(p) for p in extra_symvers if p.is_file())
    cmd=make_cmd(kernel,kout,compiler)+[
        'M='+str(work),'KBUILD_MODPOST_WARN=1',
        'KCFLAGS=-I'+str(work/'include')]
    if extra: cmd.append('KBUILD_EXTRA_SYMBOLS='+extra)
    cmd.append('modules')
    rc=run(cmd,log)
    ko=work/'wonder.ko'; obj=work/'wonder.o'
    main_cmd=work/'.main.o.cmd'
    cmdtext=main_cmd.read_text(errors='replace') if main_cmd.exists() else ''
    nm=compiler/'llvm-nm'
    und=sorted(undefined(nm, obj if obj.exists() else ko))
    return {
        'label':'wonder','make_rc':rc,'ko_emitted':ko.exists(),
        'relocatable_object':obj.exists(),'undefined_count':len(und),
        'undefined':und,'undefined_classified':classify(und),
        'kcfi_enabled':'-fsanitize=kcfi' in cmdtext,
        'kconfig_depends_on_mac80211':True,
        'release_ready':False,'loadable_proven':False,
    }

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--kernel',type=Path,required=True)
    ap.add_argument('--kernel-out',type=Path,required=True)
    ap.add_argument('--compiler',type=Path,required=True)
    ap.add_argument('--target',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--stock-symvers',type=Path,action='append',default=[])
    a=ap.parse_args(); a.out.mkdir(parents=True, exist_ok=False)
    log=a.out/'prepare.log'
    log.write_text('')
    wireless_out=a.out/'wireless-kernel-out'
    cfg=enable_wireless_config(a.kernel.resolve(), a.kernel_out.resolve(),
                               wireless_out, a.compiler.resolve(), log)
    modules={}
    for label,rel,ko in WIRELESS_MODULES:
        modules[label]=build_in_tree(label,rel,ko,a.kernel.resolve(),
                                     wireless_out,a.compiler.resolve(),
                                     a.out/label)
    extra=[]
    stock=[p.resolve() for p in a.stock_symvers]
    extra.extend(stock)
    if not stock:
        extra.extend([wireless_out/'net'/'wireless'/'Module.symvers',
                      wireless_out/'net'/'mac80211'/'Module.symvers'])
    wonder=build_wonder(a.kernel.resolve(), wireless_out, a.compiler.resolve(),
                        a.target.resolve()/WONDER_REL, extra, a.out/'wonder')
    ko=a.out/'wonder'/'src'/'wonder.ko'
    crc=crc_compare(ko, stock) if stock else {'compared':False}
    ops=audit_path(ko)
    (a.out/'ops-layout.json').write_text(json.dumps(ops,indent=2)+'\n', encoding='utf-8')
    (a.out/'wireless.config').write_bytes((wireless_out/'.config').read_bytes())
    report={
        'schema':1,'target_release':TARGET_RELEASE,'config':cfg,
        'modules':modules,'wonder':wonder,
        'compile_gate_passed': all(m['make_rc']==0 and m['ko_emitted']
                                   for m in modules.values()) and
            wonder['make_rc']==0 and (wonder['ko_emitted'] or wonder['relocatable_object']) and
            wonder['kcfi_enabled'] and wonder['kconfig_depends_on_mac80211'] and
            ops['ops_layout_gate_passed'] and (not stock or not crc['mismatched']),
        'module_completion_gate':'BLOCKED',
        'stock_crc':crc,'ops_layout':ops,
        'stock_cfg80211_crc_compared':bool(stock),
        'airdrop_available':False,'loadable_proven':False,
        'note':'Compile-only. Stock wireless export CRCs may be applied via KBUILD_EXTRA_SYMBOLS. Initialized ieee80211_ops slots are statically checked; complete ABI/KCFI and live insmod remain later hard gates.'
    }
    (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    summary={k:report[k] for k in ('compile_gate_passed','module_completion_gate',
                                   'airdrop_available','loadable_proven',
                                   'stock_cfg80211_crc_compared')}
    summary.update({'cfg80211_ko':modules['cfg80211']['ko_emitted'],
                    'mac80211_ko':modules['mac80211']['ko_emitted'],
                    'wonder_ko':wonder['ko_emitted'],
                    'wonder_kcfi':wonder['kcfi_enabled'],
                    'wonder_undefined':wonder['undefined_count'],
                    'wonder_ops_layout':ops['ops_layout_gate_passed']})
    print(json.dumps(summary, indent=2))
    return 0 if report['compile_gate_passed'] else 1

if __name__=='__main__': raise SystemExit(main())
