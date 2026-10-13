#!/usr/bin/env python3
"""Generate every Wonder core-import CRC from real pinned kernel objects.

Captured export metadata is only a comparison baseline. A checked fresh CRC
for every required kernel export is mandatory before passing it to modpost.
No raw private boot/BTF/module evidence is read by this public CI builder.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from elf_audit import Module
from prepare_stage_a import COMMON, run, symversions_from_cmd

ROOT = Path(__file__).resolve().parents[1]
KERNEL_OBJECTS = (
    'kernel/module/version.o', 'drivers/base/platform.o',
    'drivers/base/component.o', 'drivers/of/base.o',
    'kernel/softirq.o', 'kernel/panic.o', 'kernel/params.o',
    'kernel/printk/printk.o', 'kernel/locking/mutex.o',
    'kernel/rcu/tree.o', 'kernel/sched/core.o', 'kernel/workqueue.o',
    'kernel/time/timer.o', 'kernel/time/jiffies.o',
    'drivers/base/core.o', 'drivers/of/platform.o', 'drivers/char/random.o',
    'arch/arm64/kernel/alternative.o', 'lib/nlattr.o', 'lib/kstrtox.o',
    'fs/debugfs/inode.o', 'fs/libfs.o', 'net/core/dev.o',
    'net/core/dev_addr_lists.o', 'net/core/skbuff.o',
    'net/core/net_namespace.o', 'mm/vmalloc.o',
)


def load_profile(profile: Path, symvers: Path) -> tuple[dict, dict[str, int], list[list[str]]]:
    metadata=json.loads(profile.read_text(encoding='utf-8'))
    stage=json.loads((ROOT/'profiles/stage-a.json').read_text(encoding='utf-8'))
    raw=symvers.read_bytes()
    if metadata.get('schema') != 1 or metadata.get('kernel_commit') != COMMON or \
            metadata.get('stock_boot_sha256') != stage['stock_boot_sha256'] or \
            hashlib.sha256(raw).hexdigest() != metadata.get('exports_sha256'):
        raise ValueError('Unverified Wonder kernel export profile')
    rows=[]; expected={}
    for line in raw.decode('ascii').splitlines():
        fields=line.split('\t')
        if len(fields)!=5 or fields[2]!='vmlinux' or fields[1] in expected or \
                fields[3] not in ('EXPORT_SYMBOL','EXPORT_SYMBOL_GPL'):
            raise ValueError('Invalid Wonder kernel export row')
        crc=int(fields[0],16)
        if not 0<=crc<=0xffffffff:
            raise ValueError('Invalid Wonder kernel export CRC')
        expected[fields[1]]=crc; rows.append(fields)
    if len(expected) != metadata.get('export_count') or len(expected)!=54 or 'module_layout' not in expected:
        raise ValueError('Incomplete Wonder kernel export profile')
    return metadata,expected,rows


def compare_fresh(fresh: dict[str,int], expected: dict[str,int]) -> dict:
    missing=sorted(set(expected)-set(fresh))
    mismatched=[{'symbol':name,'fresh':f'0x{fresh[name]:08x}','stock':f'0x{crc:08x}'}
                for name,crc in sorted(expected.items()) if name in fresh and fresh[name]!=crc]
    return {'fresh_kernel_crc_gate_passed':not missing and not mismatched,
            'matched':[name for name in sorted(expected) if name in fresh and fresh[name]==expected[name]],
            'missing':missing,'mismatched':mismatched}


def additional_rows(rows: list[list[str]], existing: Path) -> list[list[str]]:
    known={}
    for line in existing.read_text(encoding='utf-8').splitlines():
        fields=line.split('\t')
        if len(fields)!=5 or fields[1] in known:
            raise ValueError('Invalid preexisting kernel Module.symvers')
        known[fields[1]]=fields
    extra=[]
    for fields in rows:
        previous=known.get(fields[1])
        if previous is None:
            extra.append(fields)
        elif previous != fields:
            raise ValueError('Preexisting kernel export conflicts with freshly checked metadata: '+fields[1])
    return extra


def prepare(kernel: Path, kout: Path, make: list[str], out: Path) -> tuple[Path, dict]:
    profile=ROOT/'profiles/stock-wonder-kernel.json'
    baseline=ROOT/'profiles/stock-wonder-kernel.exports.symvers'
    metadata,expected,rows=load_profile(profile,baseline)
    log=out/'kernel-crc-build.log'
    log.write_text('',encoding='utf-8')
    run(make+list(KERNEL_OBJECTS),log)
    fresh={}
    for obj in KERNEL_OBJECTS:
        p=Path(obj)
        cmd=kout/p.parent/('.'+p.name+'.cmd')
        for name,crc in symversions_from_cmd(cmd.read_text(encoding='utf-8')).items():
            if name in fresh and fresh[name]!=crc:
                raise ValueError('Conflicting independently generated CRC: '+name)
            fresh[name]=crc
    report=compare_fresh(fresh,expected)
    report.update({'profile_sha256':hashlib.sha256(profile.read_bytes()).hexdigest(),
                   'export_subset_sha256':metadata['exports_sha256'],
                   'kernel_objects':list(KERNEL_OBJECTS),'loadable_proven':False})
    (out/'kernel-crc.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    if not report['fresh_kernel_crc_gate_passed']:
        raise ValueError('Fresh kernel import CRC gate failed; see kernel-crc.json')
    # Every value comes from fresh genksyms output, not an unchecked baseline.
    extra=additional_rows(rows,kout/'Module.symvers')
    path=out/'wonder-kernel-checked.symvers'
    path.write_bytes(''.join(f'0x{fresh[f[1]]:08x}\t'+ '\t'.join(f[1:])+'\n' for f in rows).encode('ascii'))
    # Do not feed core exports already in kernel-out/Module.symvers to modpost
    # a second time. No existing CRC is replaced or silently shadowed.
    (out/'wonder-kernel-additional.symvers').write_bytes(''.join('\t'.join(f)+'\n' for f in extra).encode('ascii'))
    report['additional_exports_for_modpost']=len(extra)
    (out/'kernel-crc.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return path,report


def version_coverage(module: Module) -> dict:
    strong=sorted(s['name'] for s in module.symbols() if s['name'] and s['index']==0 and s['binding']==1)
    versions=module.versions()
    missing=sorted(set(strong)-set(versions))
    return {'all_strong_imports_versioned':not missing,'strong_import_count':len(strong),
            'version_count':len(versions),'missing_versions':missing}
