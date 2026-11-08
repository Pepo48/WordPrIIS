#!/usr/bin/env python3
"""Check the actual distribution boundary, not a copy of its file-selection logic."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
from zipfile import ZipFile
root = Path(__file__).resolve().parent.parent
subprocess.run([sys.executable, str(root/'scripts/package.py')], check=True)
with ZipFile(root/'.artifacts/wordpriis-tools.zip') as z:
    assert z.testzip() is None
    names = set(z.namelist())
    assert {'wordpress-iis.ps1','config/releases.json','modules/Common.ps1','scripts/Invoke-WindowsDiagnostics.ps1','scripts/wordpriis-bootstrap-profile.php','TESTSUITE.md'} <= names
    assert not any(p.startswith(('.artifacts/','config/local')) or p.endswith(('.etl','.pfx','.key')) for p in names)
    manifest = json.loads(z.read('bundle-manifest.json'))
    assert set(manifest['files']) == names - {'bundle-manifest.json'}
    assert all(hashlib.sha256(z.read(p)).hexdigest() == digest for p,digest in manifest['files'].items())
subprocess.run([sys.executable, str(root/'tests/privacy.py')], check=True)
print('Package: 5 assertions passed.')
