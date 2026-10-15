"""Independent test-only emitter of the two reviewed transformations. No input files are included."""
import struct, hashlib, json
from pathlib import Path
HELPER=bytes.fromhex('e90302aa2a054091297a0bd5290101913f010aeba3ffff549f3f03d500011fd6')
SPECS={
 'boot':dict(version='10.0.26100.9278', alloc=[0x4844,0x48a4,0x5520,0x556c], free=[0x55e0,0x6570,0x67a0,0x6e68], prp=[0xb654,0xb838,0x1fe64,0x239fc,0x38c88], helper=0x3a0f0, table_size=5368, iat_index=28),
 'recovery':dict(version='10.0.26100.1', alloc=[0x3324,0x3384,0x6fc8,0x712c,0x9e70,0xa06c,0xd9bc,0xdbf0], free=[0x4c98,0x567c,0x6b64,0xa024,0xa810,0xab88,0xaf1c,0xb0e8,0xdf30],prp=[0x94fc,0x96e0,0x1ce18,0x2086c,0x34ab0],helper=0x36770,table_size=4788,iat_index=0)
}
def reference_emit(src,spec):
 # Parse PE offsets independently of the production parser.
 b=bytearray(src);u16=lambda at:struct.unpack_from('<H',src,at)[0];u32=lambda at:struct.unpack_from('<I',src,at)[0]
 pe=u32(0x3c);assert src[pe:pe+4]==b'PE\0\0' and u16(pe+4)==0xaa64
 opt=pe+24;sh=opt+u16(pe+20);sections=[]
 for i in range(u16(pe+6)):
  at=sh+40*i;vs,rva,rs,raw=struct.unpack_from('<IIII',src,at+8);sections.append((at,vs,rva,rs,raw))
 def off(rva,n=4):
  matches=[raw+rva-base for _,_,base,size,raw in sections if base<=rva and rva+n<=base+size]
  assert len(matches)==1;return matches[0]
 def setword(rva,old,new):
  at=off(rva);assert u32(at)==old;struct.pack_into('<I',b,at,new)
 for reg,sites in ((6,spec['alloc']),(4,spec['free'])):
  for rva in sites:setword(rva,0x52800020|reg,0x52800000|reg)
 h=spec['helper'];at=off(h,len(HELPER));assert not any(src[at:at+len(HELPER)])
 section=next(s for s in sections if s[2]<=h<h+len(HELPER)<=s[2]+s[3])
 assert h>=section[2]+section[1]
 b[at:at+len(HELPER)]=HELPER
 struct.pack_into('<I',b,section[0]+8,h+len(HELPER)-section[2])
 for site in spec['prp']:setword(site,0xd63f0100,0x94000000|(((h-site)//4)&0x3ffffff))
 lc=off(u32(opt+112+10*8));relative=u32(lc+0xe0);idx=u16(lc+0xe4)
 begin=sections[idx-1][4]+relative
 version,size=struct.unpack_from('<II',src,begin);assert version==1 and size==spec['table_size']
 pos=begin+8;end=pos+size;records=[];removed=[]
 while pos<end:
  sym,length=struct.unpack_from('<QI',src,pos);payload=src[pos+12:pos+12+length];pos+=12+length
  if sym==8:
   at=0;blocks=[]
   while at<len(payload):
    page,n=struct.unpack_from('<II',payload,at);out=[]
    for e in range(at+8,at+n,4):
     word=struct.unpack_from('<I',payload,e)[0];site=page+(word&1023)*4
     if site in spec['prp']:
      assert word>>17==spec['iat_index'] and (word>>11)&31==8 and (word>>16)&1==0 and (word>>10)&1==1
      removed.append(site)
     else:out.append(payload[e:e+4])
    if out:blocks.append(struct.pack('<II',page,8+4*len(out))+b''.join(out))
    at+=n
   payload=b''.join(blocks)
  records.append(struct.pack('<QI',sym,len(payload))+payload)
 assert pos==end and sorted(removed)==sorted(spec['prp'])
 new=b''.join(records);b[begin:end]=struct.pack('<II',1,len(new))+new+b'\0'*(size-len(new))
 cert_dir=opt+112+4*8;cert,size=struct.unpack_from('<II',src,cert_dir)
 assert cert+size==len(src) and size>0
 del b[cert:];b[cert_dir:cert_dir+8]=b'\0'*8;b[opt+64:opt+68]=b'\0'*4
 acc=sum(int.from_bytes(b[x:x+2],'little') for x in range(0,len(b),2))
 while acc>>16:acc=(acc&65535)+(acc>>16)
 struct.pack_into('<I',b,opt+64,acc+len(b))
 return bytes(b)
