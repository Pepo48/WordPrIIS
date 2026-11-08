#!/usr/bin/env python3
"""Private standalone toolkit; never include local configuration, logs, credentials or release archives."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib
import json
import re
root = Path(__file__).resolve().parent.parent
output = root / '.artifacts/wordpriis-tools.zip'
output.parent.mkdir(exist_ok=True)
files = [root / name for name in ['wordpress-iis.ps1','README.md','TESTSUITE.md','CHANGELOG.md']]
for folder in ['modules','scripts','tests','container','docs']:
    files += [p for p in (root/folder).rglob('*') if p.is_file() and p.suffix in {'.ps1','.php','.py','.sh','.md','.json'} and '__pycache__' not in p.parts and not (folder == 'docs' and p.parent.name == 'verification-results' and re.fullmatch(r'production-.*-profile-.*\.json', p.name))]
files += [root/'container/Containerfile']
files += [root/'config'/name for name in ['example.json','existing-site.example.json','releases.json']]
files = sorted(set(files))
manifest = {'version':'2026-11-08','scope':'Private operations toolkit; not a WordPress plugin','files':{p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
with ZipFile(output,'w',ZIP_DEFLATED) as archive:
    for p in files:
        archive.write(p,p.relative_to(root).as_posix())
    archive.writestr('bundle-manifest.json',json.dumps(manifest,indent=2)+'\n')
print(output)
