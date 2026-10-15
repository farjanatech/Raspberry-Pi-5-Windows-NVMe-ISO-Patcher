"""Bounded archive and native image-tool helpers for the ISO builder."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import uuid
import zipfile

import pi5_nvme_tool as core
import linux_test_sign as signer
from .backend import (Cancellation, Cancelled, GIB, MIB, Runner, Session, StudioError,
                      atomic_json, checked_path, digest, file_identity, safe_archive_path, stamp, wim_images)
from . import __version__

ROOT = Path(__file__).resolve().parent.parent
SYSTEM_PYTHON = '/usr/bin/python3'
def need(ok, message):
    if not ok: raise StudioError(message)


def prerequisites(runner=None):
    tools = {n: shutil.which(n) for n in ('xorriso', 'openssl', 'osslsigncode')}
    tools.update({'7zip': shutil.which('7zz') or shutil.which('7z'), 'wimlib': shutil.which('wimlib-imagex')})
    need(all(tools.values()), 'Install xorriso, openssl, osslsigncode, 7zip and wimtools; rerun the desktop installer.')
    (runner or Runner(Cancellation())).run([SYSTEM_PYTHON, '-c', 'import hivex'], timeout=15)
    return tools


def entries(data):
    """Bounded 7-Zip records. Never extract an archive wholesale."""
    need(len(data) <= 16*MIB, 'Archive listing too large')
    result, row = {}, {}
    for line in data.decode('utf-8', 'strict').splitlines()+['']:
        if line.strip():
            if ' = ' in line:
                k,v = line.split(' = ',1)
                need(k not in row, 'Ambiguous archive listing')
                row[k] = v
        elif row:
            path = row.get('Path','').replace('\\','/')
            if path and row.get('Folder') != '+' and not row.get('Attributes','').startswith('D'):
                # 7z may emit a '/' directory record without Folder on some formats.
                if path not in ('/', '.'):
                    path = safe_archive_path(path)
                    low = path.lower()
                    need(low not in result, 'Case-insensitive duplicate archive member: '+path)
                    need(not row.get('Symbolic Link') and not row.get('Hard Link'), 'Archive links are not accepted')
                    try: size = int(row['Size'])
                    except (KeyError, ValueError) as exc: raise StudioError('Invalid member size') from exc
                    need(0 <= size <= 64*GIB, 'Out-of-range member size')
                    result[low] = {'path':path,'size':size}
            row = {}
    return result


def quoted(value):
    # wimlib command-file grammar, NOT shell quoting. Reject ambiguous characters.
    value = str(value)
    need(not any(c in value for c in ('"', '\n', '\r', '\0', '\\')), 'Unsupported quote/backslash in WIM staging path')
    return '"'+value+'"'
