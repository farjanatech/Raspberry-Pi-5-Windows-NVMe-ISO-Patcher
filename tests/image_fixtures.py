"""Synthetic image fixtures; no Windows inputs or physical disks."""
from pathlib import Path
import shutil, struct, subprocess
from pi5_studio import image_tools as bt
from test_pi5_nvme_tool import fixture

def listing(files):
    return ('\n\n'.join('Path = '+p+'\nSize = '+str(n)+'\nFolder = -' for p,n in files)+'\n\n').encode()

def native_ready():
    if not all(shutil.which(x) for x in ('7z','wimlib-imagex','xorriso','openssl','osslsigncode','mformat','mmd','mcopy')):
        return False
    return subprocess.run(['/usr/bin/python3','-c','import hivex'],capture_output=True).returncode==0


def run(*args):
    result = subprocess.run([str(x) for x in args], capture_output=True)
    if result.returncode:
        raise RuntimeError('Native fixture command failed: '+repr(args)+'\n'+result.stderr.decode('utf-8', 'replace'))
    return result.stdout


def synthetic_iso(root):
    from tests.test_native_tools import capture
    source,inf,profile,_=fixture()
    tree=root/'image'
    (tree/'Windows/System32/drivers').mkdir(parents=True)
    (tree/'Windows/System32/config').mkdir()
    (tree/'Windows/INF').mkdir(parents=True)
    (tree/'Windows/System32/drivers/stornvme.sys').write_bytes(source)
    (tree/'Windows/INF/stornvme.inf').write_bytes(inf)
    run('/usr/bin/python3',Path(__file__).with_name('make_boot_fixtures.py'),root/'hives')
    shutil.copyfile(root/'hives/SYSTEM',tree/'Windows/System32/config/SYSTEM')
    (tree/'setup.exe').write_bytes(b'Original synthetic Setup marker')
    media=root/'media';(media/'sources').mkdir(parents=True)
    capture(tree,media/'sources/boot.wim','Synthetic PE - not Windows')
    capture(tree,media/'sources/install.wim','Synthetic Pro - not Windows')
    (media/'efi/boot').mkdir(parents=True)
    (media/'efi/microsoft/boot').mkdir(parents=True)
    (media/'boot').mkdir()
    # Fake EFI app header for file-level testing only; not executable boot code.
    pe=bt.core.PE(source);efi=bytearray(source)
    struct.pack_into('<H',efi,pe.optional+68,10)
    (media/'efi/boot/bootaa64.efi').write_bytes(efi)
    for path, fixture_name in (('efi/microsoft/boot/bcd', 'BCD'), ('boot/bcd', 'BCD-BIOS')):
        shutil.copyfile(root/'hives'/fixture_name,media/path)
    (media/'boot/boot.sdi').write_bytes(b'NOT A REAL SDI - native tool fixture')
    fat=media/'efi/microsoft/boot/efisys.bin'
    run('mformat','-i',fat,'-C','-f','2880','::')
    run('mmd','-i',fat,'::/efi');run('mmd','-i',fat,'::/efi/boot')
    run('mcopy','-i',fat,media/'efi/boot/bootaa64.efi','::/efi/boot/bootaa64.efi')
    iso=root/'synthetic.iso'
    run('xorriso','-as','mkisofs','-iso-level','3','-J','-R','-e','efi/microsoft/boot/efisys.bin','-no-emul-boot','-o',iso,media)
    return iso,profile
