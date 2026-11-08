#!/usr/bin/env python3
"""Check the actual distribution boundary, not a copy of its file-selection logic."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import os
from zipfile import ZipFile
root = Path(__file__).resolve().parent.parent
# Exercise the real exclusion policy with a harmless synthetic detailed-report file.
fd, probe = tempfile.mkstemp(prefix='production-fixture-profile-', suffix='.json', dir=root/'docs/verification-results')
try:
    with os.fdopen(fd, 'w') as stream:
        json.dump({'profiles': [{'synthetic': True}]}, stream)
    subprocess.run([sys.executable, str(root/'scripts/package.py')], check=True)
finally:
    Path(probe).unlink()

with ZipFile(root/'.artifacts/wordpriis-tools.zip') as z:
    assert z.testzip() is None
    names = set(z.namelist())
    assert {'wordpress-iis.ps1','config/releases.json','modules/Common.ps1','scripts/Invoke-WindowsDiagnostics.ps1','scripts/wordpriis-bootstrap-profile.php','TESTSUITE.md'} <= names
    assert not any(p.startswith(('.artifacts/','config/local')) or p.endswith(('.etl','.pfx','.key')) for p in names)
    assert not any(re.fullmatch(r'docs/verification-results/production-.*-profile-.*\.json', p) for p in names)
    assert all('profiles' not in json.loads(z.read(p)) for p in names if p.startswith('docs/verification-results/') and p.endswith('.json') and isinstance(json.loads(z.read(p)), dict))
    manifest = json.loads(z.read('bundle-manifest.json'))
    assert set(manifest['files']) == names - {'bundle-manifest.json'}
    assert all(hashlib.sha256(z.read(p)).hexdigest() == digest for p,digest in manifest['files'].items())
subprocess.run([sys.executable, str(root/'tests/privacy.py')], check=True)
print('Package: 7 assertions passed.')
