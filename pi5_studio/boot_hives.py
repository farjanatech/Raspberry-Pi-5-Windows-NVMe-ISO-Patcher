"""Offline driver boot configuration and test-signing edits; source hives stay unchanged."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

TESTSIGNING = "16000049"
DRIVER_IMAGE = r"System32\drivers\pi5nvme.sys"


class HiveError(Exception):
    pass


def require(value, message):
    if not value:
        raise HiveError(message)


def clean_hive(path):
    require(path.is_file() and not path.is_symlink(), "Hive must be a regular, nonsymlink file")
    size = path.stat().st_size
    require(8192 <= size <= 128 * 1024**2, "Hive size is outside the supported range")
    with path.open('rb') as stream:
        header = stream.read(4096)
    require(header[:4] == b'regf', "Not a Windows registry hive")
    require(header[4:8] == header[8:12], "Dirty hive: transaction log replay is required; not guessed")
    checksum = 0
    for at in range(0, 508, 4):
        checksum ^= struct.unpack_from('<I', header, at)[0]
    if checksum == 0: checksum = 1
    if checksum == 0xffffffff: checksum = 0xfffffffe
    require(checksum == struct.unpack_from('<I', header, 508)[0], "Hive header checksum mismatch")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def node(h, path, create=False):
    current = h.root()
    for part in path.split('\\'):
        child = h.node_get_child(current, part)
        if not child and create:
            child = h.node_add_child(current, part)
        require(child, "Required registry path missing: " + path)
        current = child
    return current


def get(h, path, key, optional=False):
    n = node(h, path)
    v = h.node_get_value(n, key)
    if not v and optional: return None
    require(v, "Required registry value missing: " + path + '\\' + key)
    t, data = h.value_value(v)
    return t, bytes(data)


def dword(value):
    require(value is not None and value[0] == 4 and len(value[1]) == 4, "Expected REG_DWORD")
    return struct.unpack('<I', value[1])[0]


def text(value):
    require(value is not None and value[0] in (1, 2), "Expected registry string")
    try:
        result = value[1].decode('utf-16-le').rstrip('\0')
    except UnicodeError as exc:
        raise HiveError('Malformed registry string') from exc
    require('\0' not in result, "Embedded NUL in registry string")
    return result


def plan_system(h):
    controls = [h.node_name(n) for n in h.node_children(h.root())
                if re.fullmatch(r'ControlSet\d{3}', h.node_name(n), re.I)]
    require(1 <= len(controls) <= 16, 'No supported ControlSet layout found')
    for key in ('Current', 'Default'):
        selected = dword(get(h, 'Select', key))
        require(f'ControlSet{selected:03d}'.lower() in [n.lower() for n in controls],
                'Select references a missing control set')
    changes = []
    for control in controls:
        service = control + r'\Services\stornvme'
        require(dword(get(h, service, 'Type')) == 1, 'stornvme is not a kernel driver service')
        require(dword(get(h, service, 'Start')) in (0, 1, 2, 3), 'Disabled or unfamiliar stornvme service')
        require(text(get(h, service, 'Group')).lower() == 'scsi miniport', 'Unexpected NVMe load-order group')
        old = text(get(h, service, 'ImagePath')).replace('/', '\\').lower().lstrip('\\')
        require(old in (r'system32\drivers\stornvme.sys', r'systemroot\system32\drivers\stornvme.sys',
                        r'%systemroot%\system32\drivers\stornvme.sys'),
                'Unexpected or already customized stornvme ImagePath')
        changes.extend([(service, 'ImagePath', 2, (DRIVER_IMAGE+'\0').encode('utf-16-le')),
                        (service, 'Start', 4, struct.pack('<I', 0))])
        overrides = h.node_get_child(node(h, service), 'StartOverride')
        if overrides:
            for v in h.node_values(overrides):
                key = h.value_key(v)
                require(re.fullmatch(r'\d+', key) and dword(h.value_value(v)) in range(5),
                        'Unknown NVMe StartOverride; no override is guessed')
                changes.append((service+r'\StartOverride', key, 4, struct.pack('<I', 0)))
    return changes


def bcd_loader_path(value):
    """Read the EFI application path without rewriting its registry representation.

    Real Windows media stores this element as REG_SZ (1). Older Studio fixtures
    used REG_BINARY (3) containing the same UTF-16LE string; retain that explicit
    compatibility, but never coerce arbitrary registry types or guess a loader.
    """
    require(value is not None, 'BCD EFI application path is missing')
    kind, raw = value
    require(kind in (1, 3),
            f'BCD EFI application path has registry type {kind}; expected REG_SZ (1) or legacy REG_BINARY (3)')
    require(2 <= len(raw) <= 1024 and len(raw) % 2 == 0,
            'BCD EFI application path has an invalid UTF-16LE byte length')
    try:
        decoded = raw.decode('utf-16-le')
    except UnicodeError as exc:
        raise HiveError('BCD EFI application path is not valid UTF-16LE') from exc
    require(decoded.endswith('\0'), 'BCD EFI application path has no terminating NUL')
    path = decoded[:-1]
    require(path and not any(ord(c) < 32 or ord(c) == 127 for c in path),
            'BCD EFI application path contains an embedded NUL or control character')
    allowed = (r'\windows\system32\boot\winload.efi', r'\windows\system32\winload.efi')
    require(path.lower() in allowed,
            f'This image requires an EFI WinPE loader; found {path!r} (registry type {kind})')
    return path


def plan_bcd(h, template=False):
    objects = node(h, 'Objects')
    changes, loaders = [], 0
    for n in h.node_children(objects):
        name = h.node_name(n)
        require(re.fullmatch(r'\{[0-9a-fA-F-]{36}\}', name), 'Unexpected BCD object name')
        base = 'Objects\\'+name
        kind = dword(get(h, base+r'\Description', 'Type'))
        if kind == 0x10200003:  # Windows OS loader, NOT an arbitrary BCD object.
            if not template:
                winpe = get(h, base+r'\Elements\26000022', 'Element')
                require(winpe == (3, b'\x01'), 'BCD OS loader is not explicitly a WinPE loader')
            path = get(h, base+r'\Elements\12000002', 'Element')
            bcd_loader_path(path)
            loaders += 1
        elif kind != 0x10100002:  # Windows Boot Manager
            continue
        changes.append((base+'\\Elements\\'+TESTSIGNING, 'Element', 3, b'\x01'))
    require(loaders > 0, 'No EFI WinPE boot entry found; BCD not changed')
    return changes


def edit(source, output, mode):
    import hivex  # distribution binding; intentionally not a PyPI dependency
    require(mode in ('system', 'bcd', 'template'), 'Unsupported hive operation')
    source, output = Path(source).absolute(), Path(output).absolute()
    require(source.resolve() != output.resolve(), 'Output may not replace the input hive')
    require(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'Choose a NEW hive output')
    before = clean_hive(source)
    h = hivex.Hivex(str(source), write=True)
    changes = plan_system(h) if mode == 'system' else plan_bcd(h, template=mode == 'template')
    for path, key, t, value in changes:
        h.node_set_value(node(h, path, create=True), {'key': key, 't': t, 'value': value})
    h.commit(str(output))
    h = None
    clean_hive(output)
    result = hivex.Hivex(str(output))
    for path, key, t, value in changes:
        require(get(result, path, key) == (t, value), 'Committed hive readback did not match')
    require(clean_hive(source) == before, 'Source hive changed during processing')
    return {'mode': mode, 'source_sha256': before, 'output_sha256': clean_hive(output),
            'readback_verified': True, 'changes': [{'path': p, 'key': k, 'type': t, 'hex': v.hex()}
                                                 for p,k,t,v in changes]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['system', 'bcd', 'template'])
    p.add_argument('source', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    try:
        print(json.dumps(edit(a.source, a.output, a.mode), indent=2))
    except (HiveError, ImportError, RuntimeError, OSError, ValueError) as exc:
        p.exit(2, 'Offline hive edit stopped: '+str(exc)+'\n')


if __name__ == '__main__':
    main()
