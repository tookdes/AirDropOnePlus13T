#!/usr/bin/env python3
"""Extract selected layouts from captured raw BTF using the pinned 6.6 BTF format.

This reads evidence; it does not guess offsets or declare full ABI compatibility.
Reference: common@5a0ffb447c1dbd82e8e3af7a98c4a629f4b6d143/include/uapi/linux/btf.h
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

class BtfError(ValueError): pass

class Btf:
    def __init__(self, raw: bytes):
        if len(raw)<24: raise BtfError('Truncated BTF header')
        magic,version,flags,hlen,toff,tlen,soff,slen=struct.unpack_from('<HBBIIIII',raw)
        if magic!=0xeb9f or version!=1 or flags or hlen<24:
            raise BtfError('Expected raw little-endian BTF version 1')
        if hlen>len(raw) or toff+tlen>len(raw)-hlen or soff+slen>len(raw)-hlen:
            raise BtfError('BTF sections exceed captured file')
        if max(toff,soff)<min(toff+tlen,soff+slen):
            raise BtfError('Overlapping BTF type/string sections')
        self.strings=raw[hlen+soff:hlen+soff+slen]
        if not self.strings or self.strings[0]!=0: raise BtfError('Invalid BTF string table')
        types=raw[hlen+toff:hlen+toff+tlen]
        self.structs={}; pos=0; tid=1
        fixed={0:0,1:4,2:0,3:12,7:0,8:0,9:0,10:0,11:0,12:0,14:4,16:0,17:4,18:0}
        repeated={4:12,5:12,6:8,13:8,15:12,19:12}
        while pos<len(types):
            if len(types)-pos<12: raise BtfError('Truncated BTF type')
            noff,info,size=struct.unpack_from('<III',types,pos); pos+=12
            if info & 0x60ff0000: raise BtfError('Reserved BTF info bits are set')
            kind=(info>>24)&0x1f; vlen=info&0xffff; kflag=info>>31
            if kind in repeated: length=repeated[kind]*vlen
            elif kind in fixed: length=fixed[kind]
            else: raise BtfError('Unsupported BTF kind: '+str(kind))
            if length>len(types)-pos: raise BtfError('Truncated BTF type payload')
            name=self.string(noff)
            if kind==4:
                members=[]
                for idx in range(vlen):
                    mname,mtype,moff=struct.unpack_from('<III',types,pos+idx*12)
                    bit_size=moff>>24 if kflag else 0
                    bit_offset=moff&0xffffff if kflag else moff
                    if bit_offset>size*8 or (bit_size and bit_offset+bit_size>size*8):
                        raise BtfError('Member offset exceeds struct')
                    members.append({'name':self.string(mname),'type_id':mtype,
                                    'bit_offset':bit_offset,'bit_size':bit_size})
                self.structs.setdefault(name,[]).append({'id':tid,'size':size,'members':members})
            pos+=length; tid+=1
        self.type_count=tid-1
        self.sha256=hashlib.sha256(raw).hexdigest()

    def string(self, offset: int) -> str:
        if offset>=len(self.strings): raise BtfError('BTF string offset out of bounds')
        end=self.strings.find(b'\0',offset)
        if end<0: raise BtfError('Unterminated BTF string')
        return self.strings[offset:end].decode('utf-8')

    def one(self, name: str) -> dict:
        values=self.structs.get(name,[])
        if len(values)!=1: raise BtfError('Missing or ambiguous struct: '+name)
        if not values[0]['size']: raise BtfError('Zero-sized struct: '+name)
        return values[0]

    def same_size(self, name: str) -> int:
        values=self.structs.get(name,[])
        sizes={v['size'] for v in values}
        if len(sizes)!=1 or not next(iter(sizes)):
            raise BtfError('Missing or inconsistent struct sizes: '+name)
        return next(iter(sizes))

    def member_offset(self, name: str, member: str) -> int:
        # Validate this exact layout fact across ALL duplicate named variants.
        # Do not pick the first record or claim field types are equivalent.
        variants=self.structs.get(name,[])
        if not variants: raise BtfError('Missing struct: '+name)
        offsets=set()
        for variant in variants:
            matches=[m for m in variant['members'] if m['name']==member]
            if len(matches)!=1: raise BtfError('Missing or ambiguous member: '+name+'.'+member)
            m=matches[0]
            if m['bit_size'] or m['bit_offset']%8:
                raise BtfError('Expected byte-aligned, non-bitfield member')
            offsets.add(m['bit_offset']//8)
        if len(offsets)!=1: raise BtfError('Conflicting member offsets: '+name+'.'+member)
        return offsets.pop()

    def selected(self) -> dict[str,int]:
        return {'OP13T_PLATFORM_DEV_OFFSET':self.member_offset('platform_device','dev'),
                'OP13T_DEVICE_DRIVER_DATA_OFFSET':self.member_offset('device','driver_data'),
                'OP13T_DEVICE_OF_NODE_OFFSET':self.member_offset('device','of_node'),
                'OP13T_MODULE_SIZE':self.same_size('module')}

def generate(btf_path:Path, config_path:Path, output:Path) -> dict:
    btf=Btf(btf_path.read_bytes()); values=btf.selected()
    config_sha=hashlib.sha256(config_path.read_bytes()).hexdigest()
    record={'raw_btf_sha256':btf.sha256,'stock_config_file_sha256':config_sha,
            'type_count':btf.type_count,'values':values,
            'scope':'Selected captured struct sizes/offsets only; does not prove entire ABI'}
    header=('/* Generated from captured raw BTF. Do not hand-edit. */\n'
            '#ifndef OP13T_TARGET_LAYOUT_GENERATED_H\n#define OP13T_TARGET_LAYOUT_GENERATED_H\n'
            f'#define OP13T_LAYOUT_BTF_SHA256 "{btf.sha256}"\n'
            f'#define OP13T_LAYOUT_CONFIG_SHA256 "{config_sha}"\n'+
            ''.join(f'#define {key} {value}U\n' for key,value in values.items())+'#endif\n')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(header)
    output.with_suffix('.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('btf',type=Path); p.add_argument('--stock-config',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True); a=p.parse_args()
    try: print(json.dumps(generate(a.btf,a.stock_config,a.out),indent=2))
    except (OSError,ValueError,struct.error) as exc: raise SystemExit(str(exc))
