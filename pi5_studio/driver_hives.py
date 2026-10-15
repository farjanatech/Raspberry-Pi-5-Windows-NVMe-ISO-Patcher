"""Preload the signed package using Windows DevicePath and certificate stores.

Only extracted image hives are opened. No host trust store is modified and no
startup command, answer file or setup executable is installed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pi5_studio import boot_hives as hives

DRIVER_PATH = r'%SystemRoot%\Drivers\Pi5NVMe'
VERSION_KEY = r'Microsoft\Windows\CurrentVersion'


def certificate_blob(der):
    # CERT_CERT_PROP_ID / reserved=1 / byte count, as produced by Windows'
    # CertSerializeCertificateStoreElement. DER was verified by the signer.
    hives.require(128 <= len(der) <= 65536 and der[0] == 0x30,
                  'Invalid DER certificate supplied by the signing stage')
    return struct.pack('<III', 32, 1, len(der)) + der


def plan_software(hive, certificates):
    value = hives.get(hive, VERSION_KEY, 'DevicePath')
    hives.require(value[0] == 2, 'Windows DevicePath must be REG_EXPAND_SZ')
    paths = hives.text(value).split(';')
    hives.require(any(p.lower() == r'%systemroot%\inf' for p in paths),
                  'Windows DevicePath does not contain its original INF directory')
    hives.require(DRIVER_PATH.lower() not in [p.lower() for p in paths],
                  'Use an original ISO; this image already contains the Pi5 driver path')
    changes = [(VERSION_KEY, 'DevicePath', 2,
                (';'.join(paths + [DRIVER_PATH])+'\0').encode('utf-16-le'))]
    for certificate in dict.fromkeys(certificates):
        thumbprint = hashlib.sha1(certificate).hexdigest().upper()
        for store in ('ROOT', 'TrustedPublisher'):
            changes.append((rf'Microsoft\SystemCertificates\{store}\Certificates\{thumbprint}',
                            'Blob', 3, certificate_blob(certificate)))
    return changes


def edit(source, output, certificates):
    import hivex
    source, output = Path(source), Path(output)
    hives.require(source.resolve() != output.resolve() and not output.exists()
                  and not output.is_symlink(), 'Hive output must be a new file')
    before = hives.clean_hive(source)
    hive = hivex.Hivex(str(source), write=True)
    changes = plan_software(hive, [Path(p).read_bytes() for p in certificates])
    for path, key, kind, value in changes:
        hive.node_set_value(hives.node(hive, path, True), dict(key=key, t=kind, value=value))
    hive.commit(str(output))
    hive = None
    hives.clean_hive(output)
    result = hivex.Hivex(str(output))
    for path, key, kind, value in changes:
        hives.require(hives.get(result, path, key) == (kind, value), 'Driver preload readback differs')
    hives.require(hives.clean_hive(source) == before, 'Original SOFTWARE hive changed')
    return dict(mode='software', source_sha256=before, output_sha256=hives.clean_hive(output),
                readback_verified=True, device_path=DRIVER_PATH,
                certificates_sha256=[hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in certificates])


def inspect(source):
    """Check the original DevicePath and hive without needing signing keys."""
    import hivex
    source = Path(source)
    before = hives.clean_hive(source)
    hive = hivex.Hivex(str(source))
    plan_software(hive, [])
    hives.require(hives.clean_hive(source) == before, 'Source SOFTWARE hive changed during inspection')
    return dict(mode='software', source_sha256=before, preflight_verified=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('certificates', type=Path, nargs='*')
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    if args.check_only:
        if args.output is not None or args.certificates:
            parser.error('--check-only does not accept an output or certificates')
        print(json.dumps(inspect(args.source)))
    else:
        if args.output is None or not args.certificates:
            parser.error('An output path and at least one certificate are required')
        print(json.dumps(edit(args.source, args.output, args.certificates)))
