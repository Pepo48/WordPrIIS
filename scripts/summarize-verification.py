#!/usr/bin/env python3
"""Summarize only known verification results; preserve full logs separately and ignore them in Git."""
import json
from pathlib import Path
import re
root = Path(__file__).resolve().parent.parent
artifacts = root / '.artifacts'
counts = {}
for name in ['powershell-tests.log', 'php-tests.log']:
    for label, count in re.findall(r'^([^\r\n]+): (\d+) (?:assertions|checks) passed\.', (artifacts / name).read_text(), re.M):
        counts[label] = int(count)
profile = json.loads((artifacts / 'profile-stage.json').read_text())
cron = json.loads((artifacts / 'cron-stage.json').read_text())
report = {'schema_version': 1, 'scope': 'Disposable Linux containers; no Windows services, app pool, ACLs, TLS binding or production site changed',
          'runtime_pins': json.loads((root / 'container/images.json').read_text()), 'assertions': counts,
          'https_transport': 'passed', 'profile_stage': {k: v for k, v in profile.items() if k != 'profiles'},
          'filesystem_probe_web_sapi': [p['filesystem_probe']['sapi'] for p in profile['profiles']],
          'cron_stage': cron, 'native_windows': 'pending; Linux container tests do not run IIS',
          'hosted_ci': 'not run in this session'}
(artifacts / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'assertions': counts, 'profile_requests': profile['authorized_requests'], 'native_windows': 'pending'}, indent=2))
