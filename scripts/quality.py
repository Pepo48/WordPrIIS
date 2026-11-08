#!/usr/bin/env python3
"""Dependency-free structural checks, complementing actual PowerShell/PHP/native regressions."""
from pathlib import Path
import json
import py_compile
import re
import subprocess
import sys
root = Path(__file__).resolve().parent.parent
errors = []
for p in root.rglob('*.json'):
    if any(part.startswith('.') for part in p.relative_to(root).parts):
        continue
    try:
        json.loads(p.read_text())
    except (ValueError, UnicodeError):
        errors.append(f'Invalid JSON: {p.relative_to(root)}')
for folder in ['scripts', 'tests']:
    for p in (root / folder).glob('*.py'):
        py_compile.compile(str(p), doraise=True)
for p in (root / 'container').glob('*.sh'):
    subprocess.run(['bash', '-n', str(p)], check=True)
for folder in ['scripts', 'modules']:
    for p in (root / folder).glob('*.ps1'):
        if re.search(r'(?i)ExecutionPolicy\s+Bypass|Set-NetFirewallProfile|DisableRealtimeMonitoring|Add-MpPreference|\biisreset\b|Start-Transcript|Invoke-Expression', p.read_text()):
            errors.append(f'Forbidden legacy production pattern: {p.relative_to(root)}')
for p in [root/'README.md', root/'TESTSUITE.md', *list((root/'docs').glob('*.md'))]:
    for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)', p.read_text()):
        if target.startswith(('https:', 'http:', '#', 'mailto:')):
            continue
        path = (p.parent / target.split('#', 1)[0]).resolve()
        if '.artifacts' in path.parts:
            continue
        if not path.exists():
            errors.append(f'Missing document target: {p.relative_to(root)} -> {target}')
if errors:
    print('\n'.join(errors)); sys.exit(1)
subprocess.run([sys.executable, str(root/'tests/privacy.py')], check=True)
print('Quality: JSON, Python/shell syntax, local documentation targets and legacy-pattern checks passed.')
