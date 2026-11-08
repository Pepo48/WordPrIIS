#!/usr/bin/env python3
"""Real WordPress wp-cron callback/completion proof; temporary MU files, no config edits."""
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import urllib.request

root=Path(__file__).resolve().parent.parent
podman=shutil.which('podman') or '/opt/podman/bin/podman'
container='wordpriis-verify-wp'
token=secrets.token_hex(32); digest=hashlib.sha256(token.encode()).hexdigest(); nonce=secrets.token_hex(12)
folder='/tmp/wordpriis-cron-stage-'+nonce
canary='/var/www/html/wp-content/mu-plugins/000-wordpriis-cron-test-canary.php'
gate='/var/www/html/wp-content/mu-plugins/000-wordpriis-cron-test-gate.php'
hook='wordpriis_cron_verify_'+nonce

def php(code,data=None,user='www-data'):
 return subprocess.run([podman,'exec','--user',user,'-i',container,'php','-r',code],input=data,text=True,capture_output=True,check=True).stdout

def read(name):
 raw=php("if(is_file('"+folder+'/'+name+"')){readfile('"+folder+'/'+name+"');}")
 return json.loads(raw) if raw.strip() else None

def request(phase):
 run=secrets.token_hex(16)
 url='http://127.0.0.1:8108/wp-cron.php?wordpriis_cron_run='+run+'&wordpriis_cron_phase='+phase
 with urllib.request.urlopen(urllib.request.Request(url,headers={'X-WORDPRIIS-Profile':token}),timeout=30) as response:
  assert response.status==200 and response.read()==b'', 'cron response must stay unchanged'
 until=time.monotonic()+15
 while time.monotonic()<until:
  proof=read('proof.json'); done=read('cron-last.json')
  if proof and done and proof['run_id']==run and done['run_id']==run:
   assert done['status']=='complete' and proof['doing_cron'] and proof['probe_events_cleared']
   return {'phase':phase,'canary_executed':True,'php_completed':True,'disable_wp_cron':proof['disable_wp_cron']}
  time.sleep(0.1)
 raise AssertionError('No fresh cron callback/completion proof')

php("if(file_exists('"+canary+"')||file_exists('"+gate+"')){exit(2);}")
try:
 php("mkdir('"+folder+"',0700);mkdir('"+folder+"/runs',0700);foreach(['proof.json','cron.lock','cron-last.json'] as $name){touch('"+folder+"/'.$name);}")
 sources={canary: "<?php define('WORDPRIIS_CRON_TOKEN_SHA256','"+digest+"');define('WORDPRIIS_CRON_UNTIL',"+str(int(time.time())+600)+");define('WORDPRIIS_CRON_HOOK','"+hook+"');define('WORDPRIIS_CRON_PROOF_FILE','"+folder+"/proof.json');\n"+(root/'scripts/cron-canary.php').read_text()[5:],
          gate: "<?php define('WORDPRIIS_CRON_GATE_HASH','"+digest+"');define('WORDPRIIS_CRON_GATE_LOCK','"+folder+"/cron.lock');define('WORDPRIIS_CRON_GATE_RESULT','"+folder+"/cron-last.json');define('WORDPRIIS_CRON_GATE_RUNS','"+folder+"/runs');\n"+(root/'scripts/cron-gate.php').read_text()[5:]}
 for path,source in sources.items():
  php("file_put_contents('"+path+"',stream_get_contents(STDIN));chmod('"+path+"',0644);",source,user='root')
 results=[request('before'),request('after'),request('cleanup')]
 assert all(r['disable_wp_cron'] for r in results), 'stage already disables visitor cron; external endpoint must still execute'
 assert php("define('DOING_CRON',true);require '/var/www/html/wp-load.php';echo wp_next_scheduled('"+hook+"')===false?'clear':'pending';").endswith('clear')
 print(json.dumps({'scope':'local WordPress stage only; existing DISABLE_WP_CRON=true retained','checks':results,'synthetic_events_cleared':True,'wp_config_edited':False,'real_windows_task_registered':False},indent=2))
finally:
 php("@unlink('"+canary+"');@unlink('"+gate+"');",user='root')
 php("foreach(glob('"+folder+"/runs/*') as $file){@unlink($file);}@rmdir('"+folder+"/runs');foreach(glob('"+folder+"/*') as $file){@unlink($file);}@rmdir('"+folder+"');")
