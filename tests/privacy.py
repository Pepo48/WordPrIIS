#!/usr/bin/env python3
"""Prevent reintroducing private deployment identifiers into source and bundles."""
from pathlib import Path
from zipfile import ZipFile
import hashlib
import re

ROOT = Path(__file__).resolve().parent.parent
# Fingerprints avoid preserving the original site/account identifiers in the regression itself.
DENIED = frozenset({'614f68375c865c76f73f706bfcdfe923380046da2dfaa2e878c4b19bf7710f83', 'f3a49ade714ce4a9e237429623a29eac5a5144a44f8a7a5b135d16522292e478', 'f986ad37691680cb1a0bb5040070cd98fadf2e8466cee880a17917a50b614539', 'f0908a7c799308091c42099e9792fa39268fe8b8999bb4e35c744cd2d88438cc', '9faff2d0864b96e25af3cbed4513c3708cddbe37ba401f2f5c13369374dddbd0', '01f8778284c882a84ab47ed5394a19007269e28f328c178f1c870ac7bab27cf8'})

def identifiers(text):
    words = re.findall(r'[a-z0-9_.-]+', text.lower())
    for i in range(len(words)):
        for count in range(1, 5):
            word = re.sub('[^a-z0-9]', '', ''.join(words[i:i + count]))
            yield hashlib.sha256(word.encode()).hexdigest()

def check_text(text, label, denied=DENIED):
    legacy_namespace = ''.join(map(chr, (111, 112, 102)))
    if re.search(r'(?<![a-z])' + legacy_namespace + r'(?:[_-]|\b)|install' + legacy_namespace, text, re.I):
        raise AssertionError(f'Legacy namespace found in {label}; value suppressed')
    if any(value in denied for value in identifiers(text)):
        raise AssertionError(f'Private deployment identifier found in {label}; value suppressed')

def main():
    synthetic = hashlib.sha256(b'privateexample').hexdigest()
    try:
        check_text('Private Example', 'synthetic fixture', {synthetic})
    except AssertionError:
        pass
    else:
        raise AssertionError('Privacy detector did not reject split words')
    check_text('wordpress.example.com', 'public example', {synthetic})
    files = [ROOT/name for name in ['README.md','TESTSUITE.md','CHANGELOG.md','wordpress-iis.ps1']]
    for folder in ['config','docs','scripts','modules','tests','container']:
        files.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and not p.name.startswith('local'))
    for path in files:
        check_text(path.relative_to(ROOT).as_posix(), 'source filename')
        check_text(path.read_text(), str(path.relative_to(ROOT)))
    bundle = ROOT/'.artifacts/wordpriis-tools.zip'
    if bundle.exists():
        with ZipFile(bundle) as archive:
            for name in archive.namelist():
                check_text(name, 'bundle filename')
                check_text(archive.read(name).decode(), f'bundle:{name}')
    print(f'Privacy: source identifiers checked across {len(files)} files; bundle checked when present.')

if __name__ == '__main__':
    main()
