#!/usr/bin/env python3
"""Run the real task action against early-200 HTTPS fixtures; completion is mandatory."""
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse

root=Path(__file__).resolve().parent.parent
pwsh=os.environ.get('WORDPRIIS_TEST_PWSH') or shutil.which('pwsh')
if not pwsh: raise SystemExit('Set WORDPRIIS_TEST_PWSH or install PowerShell.')
token=secrets.token_hex(32); seen=[]
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*_): pass
 def do_GET(self):
  parsed=urllib.parse.urlparse(self.path); query=urllib.parse.parse_qs(parsed.query)
  run=query['wordpriis_cron_run'][0]; phase=query['wordpriis_cron_phase'][0]
  seen.append(self.headers.get('X-WORDPRIIS-Profile'))
  self.send_response(200);self.send_header('Content-Length','0');self.send_header('Set-Cookie','SECRET_COOKIE');self.end_headers()
  mode=self.server.mode
  if mode=='missing': return
  def complete():
   time.sleep(0.35)
   status={'normal':'complete','fatal':'failed','busy':'busy'}[mode]
   payload=json.dumps({'run_id':run,'phase':phase,'status':status,'reason':'SECRET_MUST_NOT_EXPORT'})
   (self.server.folder/'cron-last.json').write_text(payload)
   (self.server.folder/'run-results'/(run+'.json')).write_text(payload)
  threading.Thread(target=complete,daemon=True).start()

with tempfile.TemporaryDirectory(prefix='wordpriis-cron-http-',dir='/private/tmp' if Path('/private/tmp').is_dir() else None) as temp:
 folder=Path(temp);key=folder/'key.pem';cert=folder/'cert.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.folder=folder
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);server.socket=context.wrap_socket(server.socket,server_side=True)
 worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
 cfg={'url':f'https://localhost:{server.server_port}/wp-cron.php','curl':shutil.which('curl'),'origin_address':'','timeout_seconds':5,'job_timeout_seconds':1,'token':token}
 config=folder/'config.json';config.write_text(json.dumps(cfg));config.chmod(0o600)
 (folder/'run-results').mkdir()
 for name in ['task-last.json','cron-last.json','request.curl']: (folder/name).touch()
 env=dict(os.environ,CURL_CA_BUNDLE=str(cert));checks=[]
 try:
  for mode in ['normal','missing','fatal','busy','expired-verification']:
   server.mode='normal' if mode=='expired-verification' else mode
   state=folder/'verification.json'
   if mode=='expired-verification': state.write_text(json.dumps({'phase':'after','expires':int(time.time())-1}))
   elif state.exists(): state.unlink()
   result=subprocess.run([pwsh,'-NoLogo','-NoProfile','-File',str(root/'scripts/Invoke-WordPrIISCronTask.ps1'),'-ConfigPath',str(config)],env=env,text=True,capture_output=True,timeout=15)
   raw=(folder/'task-last.json').read_text();record=json.loads(raw)
   assert 'SECRET' not in raw+result.stdout+result.stderr and token not in raw+result.stdout+result.stderr
   assert (folder/'request.curl').read_text()==''
   if mode in ['normal','expired-verification']: assert result.returncode==0 and record['cron_complete'] and record['status']=='complete' and record['phase']=='normal'
   elif mode=='busy': assert result.returncode==0 and not record['cron_complete'] and record['status']=='busy'
   else: assert result.returncode!=0 and record['status']=='failed'
   checks.append({'case':mode,'http_200_is_not_job_proof':mode=='missing','status':record['status'],'exit_code':result.returncode,'config_cleared':True})
  assert all(t==token for t in seen)
  print(json.dumps({'scope':'local HTTPS fixture; real task action, no Windows registration','checks':checks,'token_not_exported':True},indent=2))
 finally:
  server.shutdown();worker.join(timeout=5);server.server_close()
