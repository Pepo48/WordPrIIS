#!/usr/bin/env python3
"""Real curl/stdin/TLS checks for the PowerShell profiling transport, without IIS changes."""
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
    raise SystemExit('Set WORDPRIIS_TEST_PWSH or install PowerShell.')
seen = []
token = 'a' * 64  # Synthetic test value only.

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        seen.append((self.path, self.headers.get('X-WORDPRIIS-Profile'), self.headers.get('Cookie'), self.headers.get('Authorization')))
        self.send_response(400)
        self.send_header('Set-Cookie', 'SECRET_RESPONSE_COOKIE')
        self.send_header('X-WORDPRIIS-Profile-Status', 'recording')
        self.send_header('X-WORDPRIIS-Profile-Impersonation', 'enabled')
        self.send_header('X-WORDPRIIS-Profile-OpenBasedir', 'disabled')
        self.send_header('CF-Cache-Status', 'DYNAMIC')
        self.send_header('Content-Length', '21')
        self.end_headers()
        self.wfile.write(b'SECRET_RESPONSE_BODY!')

with tempfile.TemporaryDirectory(prefix='wordpriis-profile-https-') as temp:
    folder = Path(temp)
    key, cert = folder / 'key.pem', folder / 'cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    script = folder / 'transport.ps1'
    quote = lambda s: "'" + str(s).replace("'", "''") + "'"
    script.write_text(". " + quote(root / 'scripts/Invoke-WordPrIISBootstrapProfile.ps1') + "\n"
                      "$curl=" + quote(shutil.which('curl')) + "\n"
                      "$target=[uri]'https://localhost:" + str(server.server_port) + "/wp-admin/admin-ajax.php'\n"
                      "$rows=@(Invoke-ProfileHttp $curl $target ('a'*64) '' 5; Invoke-ProfileHttp $curl $target ('a'*64) '127.0.0.1' 5)\n"
                      "$rows|ConvertTo-Json\n")
    # A hostile/default curlrc must not inject cookies, redirects, tracing or output settings.
    (folder / '.curlrc').write_text('header = "Cookie: SECRET_FROM_CURLRC"\nwrite-out = "BAD_DEFAULT_METRICS"\n')
    env = dict(os.environ, CURL_CA_BUNDLE=str(cert), CURL_HOME=str(folder))
    try:
        result = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-File', str(script)], env=env, text=True, capture_output=True, timeout=30, check=True)
        # Reproduce the config parser failure from UTF-16 redirected input.
        bad_config = ('url = "https://localhost:' + str(server.server_port) + '/wp-admin/admin-ajax.php"\n').encode('utf-16')
        malformed = subprocess.run([shutil.which('curl'), '--disable', '--config', '-'], input=bad_config, env=env, capture_output=True, timeout=10)
        assert malformed.returncode in (2, 26) and b'unknown' in malformed.stderr, 'UTF-16 config must reproduce a config parser failure'
        rows = json.loads(result.stdout)
        assert len(rows) == 2 and all(r['status'] == 400 and r['ttfb_ms'] >= 0 for r in rows)
        assert all(r['stdin_encoding'] == 'utf8-no-bom' for r in rows)
        assert all(r['profiler_status'] == 'recording' and r['cache_status'] == 'DYNAMIC' for r in rows)
        assert all(r['web_impersonation'] == 'enabled' and r['web_open_basedir'] == 'disabled' for r in rows)
        assert len(seen) == 2 and all(row == ('/wp-admin/admin-ajax.php', token, None, None) for row in seen)
        assert 'SECRET' not in result.stdout + result.stderr and token not in result.stdout + result.stderr
        # Same self-signed server without its CA must fail, never retry with insecure TLS.
        untrusted = dict(os.environ)
        untrusted.pop('CURL_CA_BUNDLE', None)
        failed = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-File', str(script)], env=untrusted, text=True, capture_output=True, timeout=30)
        assert failed.returncode != 0 and 'WORDPRIIS_PROFILE:curl-transport-or-tls' in failed.stderr
        # Catch the real exception to verify safe structured details survive PowerShell wrapping.
        inspect = folder / 'inspect.ps1'
        inspect.write_text('. ' + quote(root / 'scripts/Invoke-WordPrIISBootstrapProfile.ps1') + '\ntry { Invoke-ProfileHttp ' + quote(shutil.which('curl')) + ' ([uri]\'https://localhost:' + str(server.server_port) + '/wp-admin/admin-ajax.php\') (\'a\'*64) \'\' 5 } catch { Get-ProfileHttpFailureData $_ | ConvertTo-Json }')
        detail = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-File', str(inspect)], env=untrusted, text=True, capture_output=True, check=True, timeout=20)
        failure = json.loads(detail.stdout)
        assert failure['curl_exit'] == 60 and failure['category'] == 'certificate-verification'
        assert 'SECRET' not in detail.stdout + detail.stderr and token not in detail.stdout + detail.stderr
        assert len(seen) == 2, 'untrusted TLS must not reach the HTTP handler'
        print('PASS: profiling token over stdin, public/origin HTTPS, expected 400, body/cookie redaction UTF-16 parser-failure reproduction and TLS failure without insecure retry.')
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
