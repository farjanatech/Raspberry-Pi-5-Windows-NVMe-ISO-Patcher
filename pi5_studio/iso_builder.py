"""Original Windows ARM64 ISO to driver-prepared ISO on Linux.

Microsoft Setup is preserved. No Pi firmware, custom setup launcher, USB
writer or disk partitioning is included. Exact-profile patching and local
SYS/INF/CAT signing remain the same as previous Studio releases.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import uuid

import pi5_nvme_tool as core
from . import __version__
from .backend import (Cancellation, Cancelled, GIB, MIB, Runner, Session, StudioError,
                      atomic_json, digest, file_identity, stamp, wim_images)
from .image_tools import entries, need, prerequisites, quoted, ROOT, SYSTEM_PYTHON
from .packages import build_collection, native_versions, safe_path

CONTROLLER_ID = r'PCI\VEN_1E4B&DEV_1202'


def copy_file(source, target, cancel):
    """Bounded, cancellable copies of large WIMs into new working files."""
    cancel.check()
    identity = file_identity(source)
    with Path(source).open('rb') as incoming, Path(target).open('xb') as outgoing:
        while True:
            cancel.check()
            block = incoming.read(4*MIB)
            if not block:
                break
            need(shutil.disk_usage(target.parent).free >= len(block)+128*MIB,
                 'Workspace is nearly full. Choose a larger output drive.')
            outgoing.write(block)
    need(file_identity(source) == identity, 'A working input changed during copying')


def publish_iso(pending, output):
    """Atomic no-replace publication, including exFAT output drives."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is not None:
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(pending), -100, os.fsencode(output), 1) == 0:
            return
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(output))
    # Older libc fallback; it still never overwrites an existing path.
    os.link(pending, output)
    pending.unlink()


class LoggedRunner(Runner):
    def run(self, argv, **kwargs):
        try:
            result = super().run(argv, **kwargs)
            self.log('Exit status: 0')
            if result:
                codec = 'utf-16' if result.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8'
                self.log(result[-65536:].decode(codec, 'replace'))
            return result
        except Exception as exc:
            self.log('Command stopped: '+str(exc))
            raise


def boot_index(wim):
    with Path(wim).open('rb') as stream:
        header = stream.read(208)
    need(len(header) == 208 and header[:8] == b'MSWIM\0\0\0', 'Invalid boot WIM header')
    return struct.unpack_from('<I', header, 0x78)[0]


def source_members(data):
    members = {k: v for k, v in entries(data).items() if not k.startswith('[boot]/')}
    for name in ('sources/boot.wim', 'efi/boot/bootaa64.efi', 'efi/microsoft/boot/bcd',
                 'boot/boot.sdi', 'setup.exe', 'sources/setup.exe'):
        need(name in members, 'Use a complete original Windows ARM64 ISO; missing '+name)
    need(not any(k.startswith(('pi5studio/', '$winpedriver$/')) or k in ('autounattend.xml', 'unattend.xml')
                 for k in members), 'Use an original ISO without a previous custom installer or answer file')
    efisys = next((k for k in ('efi/microsoft/boot/efisys_noprompt.bin', 'efi/microsoft/boot/efisys.bin')
                   if k in members), None)
    need(efisys, 'The original Microsoft EFI boot image is missing')
    return members, efisys


class Build:
    def __init__(self, cancel=None, notify=lambda percent, text: None):
        self.cancel = cancel or Cancellation()
        self.notify = notify
        self.root = None
        self.report = {}
        self.runner = LoggedRunner(self.cancel, self.log)
        self.package_by_environment = {}

    def log(self, text):
        if self.root:
            with (self.root / 'build.log').open('a', encoding='utf-8') as stream:
                stream.write(stamp() + ' ' + text + '\n')

    def stage(self, percent, message):
        self.cancel.check()
        self.log(message)
        self.notify(percent, message)

    def save(self):
        if self.root:
            atomic_json(self.root / 'build-report.json', self.report)

    def extract(self, wim, index, member, dest, limit=128*MIB):
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.runner.run([self.tools['wimlib'], 'extract', str(wim), str(index), member,
                         '--to-stdout', '--no-globs'], output=dest, limit=limit)

    def iso_extract(self, iso, member, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.runner.run([self.tools['7zip'], 'x', '-so', '-bd', '-y', '-spd', '--', str(iso), member['path']],
                        output=dest, limit=max(1, member['size']))
        need(dest.stat().st_size == member['size'], 'ISO member size mismatch: ' + member['path'])

    def collect(self, name, wim, index):
        folder = self.root / 'collection' / name / 'original-inputs'
        self.extract(wim, index, '/Windows/System32/drivers/stornvme.sys', folder/'stornvme.sys', 64*MIB)
        self.extract(wim, index, '/Windows/INF/stornvme.inf', folder/'stornvme.inf', 4*MIB)

    def setup_snapshot(self, wim, folder):
        """Record original startup content and absence without assuming a shell layout."""
        snapshot = {}
        for index in (1, 2):
            # Inventory first: extraction, corruption and I/O errors must never
            # be mistaken for an optional file being absent.
            listing = self.runner.run([self.tools['wimlib'], 'dir', str(wim), str(index)])
            members = {line.replace('\\', '/').casefold()
                       for line in listing.decode('utf-8', 'strict').splitlines()}
            need('/' in members and '/windows/system32' in members, 'Invalid boot image file listing')
            for member in ('/Windows/System32/startnet.cmd', '/Windows/System32/winpeshl.ini',
                           '/sources/setup.exe'):
                present = member.casefold() in members
                need(present or not (index == 2 and member == '/sources/setup.exe'),
                     'Original Microsoft Setup executable is missing from boot image 2: '+member)
                if present:
                    path = self.root/folder/(str(index)+'-'+Path(member).name)
                    self.extract(wim, index, member, path)
                    snapshot[index, member] = digest(path, self.cancel)
                else:
                    snapshot[index, member] = None
                    self.log(f'Boot image {index}: {member} is absent; preserving the original layout')
        return snapshot

    def verify_setup(self, wim, original):
        current = self.setup_snapshot(wim, 'setup-readback')
        for (index, member), expected in original.items():
            need(current[index, member] == expected,
                 f'Original Microsoft Setup file changed in boot image {index}: {member}')

    def require_programs(self, wim, index, names):
        for name in names:
            target = self.root/'program-check'/name
            self.extract(wim, index, '/Windows/System32/'+name, target, 128*MIB)
            pe = core.PE(target.read_bytes())
            need(pe.machine in (core.MACHINE_ARM64, 0xA641, 0xA64E),
                 'A required installation program is not ARM64: '+name)
            target.unlink()

    def package(self, environment):
        return self.root / 'signed/packages' / self.package_by_environment[environment]['package_name']

    def preflight_hives(self, wim, index, environment):
        modes = [('SYSTEM', 'system'), ('SOFTWARE', 'software')]
        if environment.startswith('install-'):
            modes.append(('BCD-Template', 'template'))
        for name, mode in modes:
            original = self.root/'hives'/(environment+'.'+name)
            self.extract(wim, index, '/Windows/System32/config/'+name, original)
            command = ([SYSTEM_PYTHON, str(ROOT/'pi5_studio/driver_hives.py')] if mode == 'software' else
                       [SYSTEM_PYTHON, str(ROOT/'pi5_studio/boot_hives.py'), mode])
            result = json.loads(self.runner.run(command+[str(original), '--check-only']))
            self.report.setdefault('hive_preflight', []).append(dict(environment=environment, **result))

    def update_image(self, wim, index, environment, extra=None, trust_packages=()):
        """Inject only an alternate driver, checked hive and explicit payloads."""
        layer = self.root / 'layers' / environment
        driver = layer / 'Windows/System32/drivers/pi5nvme.sys'
        driver.parent.mkdir(parents=True)
        package = self.package(environment)
        copy_file(package/'pi5nvme.sys', driver, self.cancel)
        original = self.root / 'hives' / (environment+'.SYSTEM')
        target = layer / 'Windows/System32/config/SYSTEM'
        target.parent.mkdir(parents=True)
        result = json.loads(self.runner.run([SYSTEM_PYTHON, str(ROOT/'pi5_studio/boot_hives.py'),
                                             'system', str(original), str(target)]))
        self.report.setdefault('hives', []).append(dict(environment=environment, **result))
        pkgdir = layer/'Windows/Drivers/Pi5NVMe'
        pkgdir.mkdir(parents=True)
        for name in ('pi5nvme.sys', 'pi5nvme.inf', 'pi5nvme.cat', 'local-test-certificate.cer'):
            copy_file(package/name, pkgdir/name, self.cancel)
        software = self.root/'hives'/(environment+'.SOFTWARE')
        software_out = layer/'Windows/System32/config/SOFTWARE'
        result = json.loads(self.runner.run([SYSTEM_PYTHON, str(ROOT/'pi5_studio/driver_hives.py'),
                                             str(software), str(software_out),
                                             str(package/'local-test-certificate.cer'),
                                             *[str(p/'local-test-certificate.cer') for p in trust_packages]]))
        self.report['hives'].append(dict(environment=environment, **result))
        if environment.startswith('install-'):
            template = self.root/'hives'/(environment+'.BCD-Template')
            template_out = layer/'Windows/System32/config/BCD-Template'
            result = json.loads(self.runner.run([SYSTEM_PYTHON, str(ROOT/'pi5_studio/boot_hives.py'),
                                                 'template', str(template), str(template_out)]))
            self.report['hives'].append(dict(environment=environment, **result))
        for name, value in (extra or {}).items():
            dest = layer/name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, Path):
                copy_file(value, dest, self.cancel)
            else:
                dest.write_bytes(value)
        command = self.root / ('update-'+environment+'.txt')
        changed_hives = ('SYSTEM', 'SOFTWARE', 'BCD-Template') if environment.startswith('install-') else ('SYSTEM', 'SOFTWARE')
        command.write_text('add '+quoted(layer)+' /\n'+''.join(
            'delete --force '+quoted('/Windows/System32/config/'+hive+suffix)+'\n'
            for hive in changed_hives for suffix in ('.LOG', '.LOG1', '.LOG2')), encoding='utf-8')
        self.runner.run([self.tools['wimlib'], 'update', str(wim), str(index), '--check', '--threads=2'], stdin_path=command)
        # Read every changed file out of the WIM, including nested recovery WIMs.
        check = self.root/'readback'
        check.mkdir(exist_ok=True)
        for n, path in enumerate(sorted(p for p in layer.rglob('*') if p.is_file())):
            readback = check/(environment+'-'+str(n))
            self.extract(wim, index, '/'+path.relative_to(layer).as_posix(), readback, max(path.stat().st_size, 1))
            need(digest(readback, self.cancel) == digest(path, self.cancel), 'Integrated file readback differs')
            readback.unlink()
        stock = check/(environment+'-stock')
        self.extract(wim, index, '/Windows/System32/drivers/stornvme.sys', stock, 64*MIB)
        original_driver = self.root/'collection'/environment/'original-inputs/stornvme.sys'
        need(digest(stock, self.cancel) == digest(original_driver, self.cancel), 'Inbox driver was unexpectedly changed')
        stock.unlink()
        shutil.rmtree(layer)

    def run(self, source, output, *, profiles=None):
        need(sys.platform == 'linux', 'Build your ISO on Raspberry Pi OS or another 64-bit Linux desktop')
        source, output = safe_path(Path(source)), safe_path(Path(output))
        need(source.suffix.lower() == '.iso' and output.suffix.lower() == '.iso', 'Choose input and output .iso paths')
        need(output.parent.is_dir() and not output.exists() and source != output,
             'Choose a new output filename; an existing ISO is never overwritten')
        # Reject paths the WIM command-file grammar cannot represent before
        # extraction/signing, rather than failing at the first image update.
        quoted(output)
        identity = file_identity(source)
        self.root = output.parent / ('.'+output.stem+'-build-'+uuid.uuid4().hex[:10])
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.report = dict(schema=2, studio_version=__version__, build_id=uuid.uuid4().hex,
                           created_utc=stamp(), status='BUILDING', source_iso=str(source), output_iso=str(output),
                           original_iso_modified=False, installation_iso=True, windows_installation_verified=False,
                           target_controller=CONTROLLER_ID, custom_firmware_included=False,
                           custom_setup_included=False, private_keys_in_iso=False,
                           driver_integration='BOOT_SERVICE_AND_SIGNED_PNP_PRELOAD',
                           native_driver_store_serviced_at_build=False,
                           testsigning='ISO_BOOT_BCD_AND_WINDOWS_BCD_TEMPLATE',
                           wor_flashing_and_hardware_verified=False)
        pending = self.root/'output.iso.partial'
        published = False
        self.save()
        try:
            self.stage(1, 'Checking image-building tools')
            self.tools = prerequisites(self.runner)
            self.report['signing_tools'] = native_versions()
            self.stage(3, 'Reading the original Windows ARM64 ISO')
            assets, efisys = source_members(self.runner.run([
                self.tools['7zip'], 'l', '-slt', '-ba', '-bd', '--', str(source)]))
            def inspection_progress(stage, percent, detail):
                self.log(detail)
                if percent >= 0:
                    if percent == 100:
                        detail = 'Windows images inspected; checking original Setup files'
                    self.notify(3+int(percent*7/100), detail)
            session = Session(self.cancel, inspection_progress, runner=self.runner)
            session.inspect(source, self.root)
            self.report['source_sha256'] = session.data['source_sha256']
            install_images = [x for x in session.images if x.kind == 'install']
            boot_images = [x for x in session.images if x.kind == 'boot']
            need([x.index for x in boot_images] == [1, 2] and boot_index(session.media['boot']) == 2,
                 'Use original Microsoft media with WinPE at index 1 and bootable Setup at index 2')
            need(1 <= len(install_images) <= 31, 'Supported installation image count is 1 to 31')
            required = 3*sum(p.stat().st_size for p in session.media.values()) + 8*GIB
            need(shutil.disk_usage(self.root).free >= required, f'Building this ISO needs approximately {required/GIB:.0f} GiB free')
            startup = self.setup_snapshot(session.media['boot'], 'setup-originals')
            self.report['microsoft_setup_originals'] = [
                dict(image_index=index, path=member, present=value is not None, sha256=value)
                for (index, member), value in startup.items()]
            self.save()
            original_bcd = self.root/'original-BCD'
            self.iso_extract(source, assets['efi/microsoft/boot/bcd'], original_bcd)
            self.report['bcd_preflight'] = json.loads(self.runner.run([
                SYSTEM_PYTHON, str(ROOT/'pi5_studio/boot_hives.py'), 'bcd', str(original_bcd), '--check-only']))
            original_loader = self.root/'original-loader.efi'
            self.iso_extract(source, assets['efi/boot/bootaa64.efi'], original_loader)
            loader = core.PE(original_loader.read_bytes())
            need(loader.machine == core.MACHINE_ARM64 and loader.subsystem == 10, 'Original EFI loader is not ARM64')
            self.stage(10, 'Collecting compatible drivers for Setup, Windows and recovery')
            (self.root/'collection').mkdir()
            for image in boot_images:
                self.collect('boot-'+str(image.index), session.media['boot'], image.index)
            recoveries, recovery_cache = {}, {}
            for image in install_images:
                self.collect('install-'+str(image.index), session.media['install'], image.index)
                recovery = self.root/'recovery'/f'{image.index}.wim'
                self.extract(session.media['install'], image.index, '/Windows/System32/Recovery/winre.wim', recovery, 4*GIB)
                recovery_hash = digest(recovery, self.cancel)
                if recovery_hash in recovery_cache:
                    recovery.unlink()
                    recovery = recovery_cache[recovery_hash]
                else:
                    recovery_cache[recovery_hash] = recovery
                metadata = wim_images(self.runner.run([self.tools['wimlib'], 'info', str(recovery), '--xml']), 'recovery')
                need(len(metadata) == 1 and metadata[0].architecture == 'ARM64', 'Each edition must have one ARM64 recovery image')
                self.collect('recovery-'+str(image.index), recovery, 1)
                recoveries[image.index] = recovery
            environments = [('boot-'+str(i.index), session.media['boot'], i.index) for i in boot_images]
            environments += [('install-'+str(i.index), session.media['install'], i.index) for i in install_images]
            environments += [('recovery-'+str(i.index), recoveries[i.index], 1) for i in install_images]
            for n, (environment, image_file, index) in enumerate(environments):
                self.stage(10+int(n*9/len(environments)), 'Checking registry compatibility: '+environment)
                self.preflight_hives(image_file, index, environment)
            self.save()
            self.stage(20, 'Patching and signing the compatible drivers automatically')
            result = build_collection(self.root/'collection', self.root/'signed', self.root/'private-keys',
                                      CONTROLLER_ID, profiles=profiles, check_cancel=self.cancel.check,
                                      progress=lambda p, t: self.stage(20+p//6, t))
            shutil.rmtree(self.root/'private-keys')
            self.report['packages'] = result['packages']
            for package in result['packages']:
                verification = json.loads((self.root/'signed/packages'/package['package_name']/'verification.json').read_text())
                self.log('Package verification: '+json.dumps(verification))
                for env in package['environments']:
                    self.package_by_environment[env] = package
            # Setup's automatic driver discovery must not choose a package from
            # a different Windows build. Normal multi-edition ISOs share one pair.
            install_packages = {self.package_by_environment['install-'+str(i.index)]['package_name'] for i in install_images}
            need(len(install_packages) == 1, 'All Windows editions must use the same NVMe package for automatic Setup discovery')
            setup_package = self.package('install-'+str(install_images[0].index))
            media = self.root/'media';media.mkdir()
            for name, member in assets.items():
                if name not in ('sources/boot.wim', 'sources/install.wim', 'sources/install.esd', 'efi/microsoft/boot/bcd'):
                    self.iso_extract(source, member, media/name)
            bcd = media/'efi/microsoft/boot/bcd'
            bcd.parent.mkdir(parents=True, exist_ok=True)
            self.report['bcd'] = json.loads(self.runner.run([SYSTEM_PYTHON, str(ROOT/'pi5_studio/boot_hives.py'),
                                                            'bcd', str(original_bcd), str(bcd)]))
            (media/'sources').mkdir(exist_ok=True)
            boot = media/'sources/boot.wim';install = media/'sources/install.wim'
            self.stage(38, 'Preparing drivers while preserving Microsoft Setup')
            copy_file(session.media['boot'], boot, self.cancel)
            for image in boot_images:
                extras = {}
                for name in ('pi5nvme.sys', 'pi5nvme.inf', 'pi5nvme.cat', 'local-test-certificate.cer'):
                    # Standard Setup discovers X:\$WinPEDriver$; WoR receives
                    # package files in its driver folder without a new launcher.
                    extras['$WinPEDriver$/Pi5NVMe/'+name] = setup_package/name
                    extras['drivers/Pi5NVMe/'+name] = setup_package/name
                self.update_image(boot, image.index, 'boot-'+str(image.index), extras, (setup_package,))
            need(boot_index(boot) == 2, 'Microsoft Setup boot index changed')
            self.verify_setup(boot, startup)
            self.report['microsoft_setup_readback_verified'] = True
            prepared_recoveries = set()
            for n, image in enumerate(install_images):
                self.stage(42+int(n*30/len(install_images)), 'Preparing '+image.name+' and its recovery image')
                recovery = recoveries[image.index]
                if recovery not in prepared_recoveries:
                    self.update_image(recovery, 1, 'recovery-'+str(image.index))
                    self.runner.run([self.tools['wimlib'], 'verify', str(recovery)])
                    prepared_recoveries.add(recovery)
                self.runner.run([self.tools['wimlib'], 'export', str(session.media['install']), str(image.index), str(install),
                                 '--compress=LZX', '--threads=2', '--check'])
                self.update_image(install, n+1, 'install-'+str(image.index),
                                  {'Windows/System32/Recovery/winre.wim': recovery})
            shutil.rmtree(session.root)
            self.stage(75, 'Verifying the prepared Windows images')
            for wim in (boot, install):
                self.runner.run([self.tools['wimlib'], 'verify', str(wim)])
            self.report['install_image_format'] = 'sources/install.wim'
            self.stage(82, 'Writing the finished installation ISO')
            self.runner.run([self.tools['xorriso'], '-as', 'mkisofs', '-iso-level', '3', '-J', '-joliet-long', '-R',
                             '-V', 'PI5_WINDOWS', '-e', efisys, '-no-emul-boot', '--boot-catalog-hide',
                             '-o', str(pending), str(media)])
            self.stage(90, 'Checking the finished ISO contents')
            final_files = entries(self.runner.run([self.tools['7zip'], 'l', '-slt', '-ba', '-bd', '--', str(pending)]))
            expected = {p.relative_to(media).as_posix().lower(): p for p in media.rglob('*') if p.is_file()}
            actual = {k: v for k, v in final_files.items() if not k.startswith('[boot]/')}
            need(set(actual) == set(expected), 'Final ISO member set differs')
            for n, (name, path) in enumerate(sorted(expected.items())):
                temp = self.root/'readback'/('iso-'+str(n))
                self.iso_extract(pending, actual[name], temp)
                need(digest(temp, self.cancel) == digest(path, self.cancel), 'Final ISO readback differs: '+name)
                temp.unlink()
            need(file_identity(source) == identity and digest(source, self.cancel) == self.report['source_sha256'],
                 'The source ISO changed during the build')
            self.report.update(status='DRIVER_PREPARED_ISO_BUILT', iso_sha256=digest(pending, self.cancel),
                               iso_bytes=pending.stat().st_size, final_iso_readback_verified=True,
                               editions=[x.as_dict() for x in install_images], finished_utc=stamp())
            self.cancel.check()
            self.save()
            # Both paths are on the output filesystem. A competing build or
            # user-created destination is never replaced.
            publish_iso(pending, output)
            published = True
            self.report['log_directory'] = str(self.root)
            self.save()
            # The only deliverable is the ISO. Keep the log and report, remove
            # our own working copies after publication, never the source ISO.
            cleanup_warnings = []
            for path in self.root.iterdir():
                if path.name in ('build.log', 'build-report.json'):
                    continue
                try:
                    if path.is_dir() and not path.is_symlink():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                except OSError as exc:
                    cleanup_warnings.append(str(exc))
            if cleanup_warnings:
                self.report['cleanup_warnings'] = cleanup_warnings
                self.log('Temporary file cleanup: '+json.dumps(cleanup_warnings))
                self.save()
            self.log('ISO ready. Background log and build report saved.')
            self.notify(100, 'ISO ready. Background log and build report saved.')
            return self.report
        except Exception as exc:
            followup_errors = []
            if (self.root/'private-keys').is_dir():
                try:
                    shutil.rmtree(self.root/'private-keys')
                except OSError as cleanup_error:
                    followup_errors.append('Private-key cleanup failed: '+str(cleanup_error))
            self.report.update(status='CANCELLED' if isinstance(exc, Cancelled) else 'FAILED', error=str(exc))
            # Once atomically published, the verified ISO is kept even if a
            # later report write fails. Never delete an existing user artifact.
            self.report['verified_output_published'] = published
            for label, action in (('Build report', self.save), ('Build log', lambda: self.log(str(exc)))):
                try:
                    action()
                except OSError as write_error:
                    followup_errors.append(label+' could not be saved: '+str(write_error))
            message = str(exc)+'\nLog folder: '+str(self.root)
            if published:
                message += '\nThe verified ISO was already saved: '+str(output)
            if followup_errors:
                message += '\n'+'\n'.join(followup_errors)
            raise StudioError(message) from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('iso', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    Build(notify=lambda p, s: print(f'[{p}%] {s}', flush=True)).run(args.iso, args.output)


if __name__ == '__main__':
    main()
