"""Verify the reviewed source snapshot; never uploads files or accesses inputs."""
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {'.sys', '.inf', '.cat', '.cer', '.pem', '.key', '.pfx', '.exe', '.dll',
             '.iso', '.wim', '.esd', '.swm', '.img', '.zip', '.7z', '.dmp'}


def verify():
    data = json.loads((ROOT/'SOURCE_MANIFEST.json').read_text(encoding='utf-8'))
    assert data['schema'] == 1 and data['files'], 'Invalid source manifest'
    for name, expected in data['files'].items():
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and '..' not in relative.parts and '\\' not in name and ':' not in name
        assert relative.suffix.lower() not in FORBIDDEN and not relative.name.startswith('.env'), name
        path = ROOT/relative
        assert not any(p.is_symlink() for p in (path, *path.parents)), name
        content = path.read_bytes()
        if path.suffix == '.sh': assert b'\r' not in content, 'Shell script must use LF: '+name
        assert hashlib.sha256(content).hexdigest() == expected, 'Source checksum differs: '+name
    return len(data['files'])


if __name__ == '__main__':
    print('Verified', verify(), 'source files. No Windows inputs, firmware or private keys are included.')
