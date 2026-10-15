"""Exact-input static ports, not Windows/Pi hardware approvals.

No Microsoft files are bundled. See docs/DRIVER_PROVENANCE.md. The original
helper/approach is attributed to damian5466's nvme/build.py; the upstream
26100.9539 profile remains unchanged in the core.
"""
import copy
import struct
from pi5_nvme_tool import BUILTIN_PROFILE


def _port(version, hashes, alloc, release, calls, helper, table_size, iat, guid, contexts):
    p = copy.deepcopy(BUILTIN_PROFILE)
    p.update(id=f'local-arm64-{version}-static-v1', source_version='10.0.' + version,
             source_sha256=hashes[0], inf_sha256=hashes[1], output_sha256=hashes[2],
             provenance='https://github.com/farjanatech/Raspberry-Pi-5-Windows-NVMe-ISO-Patcher/blob/v2.1.1/docs/DRIVER_PROVENANCE.md',
             runtime_evidence='Static review and reproducible build on user-supplied real input only. Windows loading, Pi 5 I/O and boot NOT TESTED.',
             inf_date='10/12/2026')
    p['edits'] = [dict(rva=r, before=struct.pack('<I', 0x52800020 | reg).hex(),
                       after=struct.pack('<I', 0x52800000 | reg).hex())
                  for reg, sites in ((6, alloc), (4, release)) for r in sites]
    p['helper']['rva'] = helper
    p['calls'] = [dict(rva=r, before='00013fd6') for r in calls]
    p['relocation'].update(table_size=table_size, iat_index=iat)
    p['review'] = dict(level='REAL_INPUT_STATIC_ONLY', date='2026-10-12',
                       allocation_edit_count=len(alloc), release_edit_count=len(release),
                       prp_redirect_count=len(calls),
                       original_pdb=[dict(pdb_name='stornvme.pdb', guid=guid, age=1, symbol_key=guid+'1')],
                       context_sha256=[dict(rva=r-96, length=124, sha256=h) for r,h in zip(calls, contexts)],
                       limitations=['No Microsoft signature-chain validation was performed here.',
                                    'A reproducible output is not evidence of correct DMA behavior.',
                                    'Retains the upstream fixed 4 KiB / 64-byte cache-line helper assumptions.',
                                    'Unsigned output is NOT a complete installable driver package.'])
    return p


ADDITIONAL_PROFILES = [
    _port('26100.9278', (
        'dd01b8ac34120dcc8ce451d7ff70cab4aeeddc9bdaaa55bc098d009891e583e6',
        'fb822b46e9defc1bd196852a890ad18d1ca8c980e1370f683c89d5ab0de4fea2',
        'b0e57c872083c704d000a64b384b28b742356cf76b4377e3913b3b6f2fcb8251'),
        [0x4844,0x48A4,0x5520,0x556C], [0x55E0,0x6570,0x67A0,0x6E68],
        [0xB654,0xB838,0x1FE64,0x239FC,0x38C88], 0x3A0F0, 5368, 28,
        '1C4CEA08EA1370ABD12231F4310BD520', [
            '59037ace5329f54a3d96c32a7c4a98e54d2dd75cb1259e913d7b425db258b19a',
            '2671b1dff55b2649bf71c955ef4ac8feeac49f0999f9b558b9a168f30af9c2b8',
            '83185e42142c061917209042acc43889a62aca313524740442f5df2410636c3d',
            '40bc01ed5e199cedaca3932af0d244b6826e049423b3aefe1e7aeb24756ca7db',
            'c8c4e2ed8a70a2d50659ca6cd7585cb748f4412175ce087ee1ea3f7871e9c7a1']),
    _port('26100.1', (
        '97f70142be8c7e06274aee03d87b9b6e70fa2a9d505455fba356ad9b882d46ee',
        'b84c61c50731a446fc44a70deb9da9a046c6eeace16041978bfec53ee25db30e',
        'b325085fa2e6d18c65c8cb800b5eb3e721b59b08d6eb2adc35f3d0a4c33d3866'),
        [0x3324,0x3384,0x6FC8,0x712C,0x9E70,0xA06C,0xD9BC,0xDBF0],
        [0x4C98,0x567C,0x6B64,0xA024,0xA810,0xAB88,0xAF1C,0xB0E8,0xDF30],
        [0x94FC,0x96E0,0x1CE18,0x2086C,0x34AB0], 0x36770, 4788, 0,
        'E11C23B6D9F2AC37B415AE2184815C90', [
            '04b1552ba82620afa7a6065eae0b054246b5fd108b7d2d7d984771a08e91fb6f',
            '64e23e32da5c6be6dc15b78fe6112083324c263997c5a89a10f88d3c5b79a61c',
            '51e5e90f7fd62be706a4688b3ef35b8b64dbf6a3d329dcb2b90e3ec034b61dee',
            '829abfb967ac0eeb6de0ff7fb98b93b5967d42f66cc2bccfba05e4bbfc24752d',
            '983053e42a47228f3c83c1c68879fe405d8eae23ee94897f7961b34b51324508'])
]
