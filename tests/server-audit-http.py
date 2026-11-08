#!/usr/bin/env python3
"""Exercise HTTP-only report generation against a trusted local HTTPS fixture."""
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading

root = Path(__file__).resolve().parent.parent
pwsh = os.environ.get('WORDPRIIS_TEST_PWSH') or shutil.which('pwsh')
if not pwsh:
    raise SystemExit('PowerShell is required; set WORDPRIIS_TEST_PWSH to the test executable.')

seen_paths = []

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        seen_paths.append(path)
        if 'missing' in path:
            status, mime, cache = 503, 'text/html', 'public, max-age=31536000'
        elif path.endswith('.css'):
            status, mime, cache = 200, 'text/css', 'public, max-age=31536000'
        elif path.endswith('.js'):
            status, mime, cache = 200, 'application/javascript', 'public, max-age=31536000'
        elif path.endswith('admin-ajax.php'):
            status, mime, cache = 400, 'text/html', 'no-store, private, public, max-age=31536000'
        else:
            status, mime, cache = 200, 'text/html', 'no-store'
        body = b'SYNTHETIC_BODY_MUST_NOT_BE_SAVED'
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Cache-Control', cache)
        self.send_header('Set-Cookie', 'private=COOKIE_MUST_NOT_BE_SAVED')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

with tempfile.TemporaryDirectory(prefix='wordpriis-audit-https-') as temp:
    folder = Path(temp)
    key, cert = folder / 'key.pem', folder / 'cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    env = dict(os.environ, CURL_CA_BUNDLE=str(cert))
    output = folder / 'report'
    command = [pwsh, '-NoLogo', '-NoProfile', '-File', str(root / 'scripts/Invoke-WordPrIISServerAudit.ps1'), '-HttpOnly', '-Url', f'https://localhost:{server.server_port}', '-OriginAddress', '127.0.0.1', '-Samples', '1', '-OutputDirectory', str(output)]
    try:
        subprocess.run(command, env=env, check=True, timeout=90)
        raw = (output / 'audit.json').read_text(encoding='utf-8-sig')
        report = json.loads(raw)
        assert len(report['http_samples']) == 10
        assert '/wp-includes/css/dashicons.min.css' in seen_paths and '/wp-includes/js/jquery/jquery.min.js' in seen_paths
        assert not any('custom-plugin' in path for path in seen_paths)
        assert all(row['status'] > 0 for row in report['http_samples'])
        ids = {row['id'] for row in report['findings']}
        assert {'http.5xx-cache', 'http.error-positive-ttl', 'http.conflicting-cache', 'http.ajax-cache'} <= ids
        assert 'COOKIE_MUST_NOT_BE_SAVED' not in raw and 'SYNTHETIC_BODY_MUST_NOT_BE_SAVED' not in raw
        assert 'wordpriis_audit=' not in raw
        assert (output / 'summary.md').is_file()
        failed = subprocess.run(command, env=env, capture_output=True, timeout=30)
        assert failed.returncode != 0, 'Existing report directory must not be overwritten'
        print('PASS: HTTPS public/origin samples, cache findings, report privacy and overwrite protection.')
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
