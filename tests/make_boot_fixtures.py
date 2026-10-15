"""Create tiny synthetic registry hives for native libhivex tests.
No Windows hive or Microsoft executable is redistributed.
"""
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))


def minimal():
    data=bytearray(8192)
    data[:4]=b'regf'
    struct.pack_into('<IIQIIIIIII',data,4,1,1,0x01da000000000000,1,3,0,1,0x20,4096,1)
    data[4096:4100]=b'hbin'
    struct.pack_into('<II',data,4100,0,4096)
    struct.pack_into('<Q',data,4116,0x01da000000000000)
    root=4096+0x20
    struct.pack_into('<i',data,root,-88)
    n=root+4
    data[n:n+2]=b'nk'
    struct.pack_into('<H',data,n+2,0x2c)
    struct.pack_into('<Q',data,n+4,0x01da000000000000)
    struct.pack_into('<I',data,n+16,0xffffffff)
    for at in (28,32,40,48): struct.pack_into('<I',data,n+at,0xffffffff)
    struct.pack_into('<I',data,n+44,0x78)
    struct.pack_into('<HH',data,n+72,4,0)
    data[n+76:n+80]=b'ROOT'
    sk=4096+0x78
    struct.pack_into('<i',data,sk,-56)
    data[sk+4:sk+6]=b'sk'
    struct.pack_into('<IIII',data,sk+8,0x78,0x78,1,28)
    # Self-relative security descriptor with an empty ACL, sufficient for hives
    # used only as native parser fixtures. This is not a Windows image ACL.
    struct.pack_into('<BBHIIII',data,sk+24,1,0,0x8004,0,0,0,20)
    struct.pack_into('<BBHHH',data,sk+44,2,0,8,0,0)
    struct.pack_into('<i',data,4096+0xb0,4096-0xb0)
    checksum=0
    for at in range(0,508,4): checksum ^= struct.unpack_from('<I',data,at)[0]
    struct.pack_into('<I',data,508,checksum or 1)
    return bytes(data)


def create(root):
    import hivex
    from pi5_studio.boot_hives import node
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    seed=root/'minimal.hive';seed.write_bytes(minimal())
    def setval(h,p,k,t,v): h.node_set_value(node(h,p,True),{'key':k,'t':t,'value':v})
    def dw(h,p,k,v): setval(h,p,k,4,struct.pack('<I',v))
    def sz(h,p,k,v,t=1): setval(h,p,k,t,(v+'\0').encode('utf-16-le'))
    h=hivex.Hivex(str(seed),write=True)
    dw(h,'Select','Current',1);dw(h,'Select','Default',1)
    for number in (1,2):
        cs=f'ControlSet{number:03d}'
        svc=cs+r'\Services\stornvme'
        dw(h,svc,'Type',1);dw(h,svc,'Start',0)
        dw(h,svc+r'\StartOverride','0',3)
        sz(h,svc,'Group','SCSI miniport')
        sz(h,svc,'ImagePath',r'\SystemRoot\System32\drivers\stornvme.sys',2)
        node(h,cs+r'\Services\partmgr',True);node(h,cs+r'\Services\mountmgr',True)
    sz(h,'PreserveMe','String','unchanged fixture')
    h.commit(str(root/'SYSTEM'))
    h=hivex.Hivex(str(seed),write=True)
    sz(h, r'Microsoft\Windows\CurrentVersion', 'DevicePath', r'%SystemRoot%\inf', 2)
    sz(h, 'PreserveMe', 'String', 'unchanged software')
    h.commit(str(root/'SOFTWARE'))
    h=hivex.Hivex(str(seed),write=True)
    loader=r'Objects\{7619dcc9-fafe-11d9-b411-000476eba25f}'
    dw(h,loader+r'\Description','Type',0x10200003)
    setval(h,loader+r'\Elements\26000022','Element',3,b'\x01')
    setval(h,loader+r'\Elements\12000002','Element',1,(r'\Windows\System32\Boot\winload.efi'+'\0').encode('utf-16-le'))
    mgr=r'Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}'
    dw(h,mgr+r'\Description','Type',0x10100002)
    sz(h,'PreserveMe','String','unchanged fixture')
    h.commit(str(root/'BCD'))
    # Cover the real REG_SZ representation as the default fixture, the older
    # binary fixture separately, and a BIOS store that EFI media must omit.
    sz(h,loader+r'\Elements\12000002','Element',r'\Windows\System32\Boot\winload.efi',3)
    h.commit(str(root/'BCD-BINARY'))
    sz(h,loader+r'\Elements\12000002','Element',r'\Windows\System32\Boot\winload.exe',1)
    h.commit(str(root/'BCD-BIOS'))


if __name__=='__main__':
    create(sys.argv[1])
