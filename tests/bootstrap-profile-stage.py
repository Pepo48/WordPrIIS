#!/usr/bin/env python3
"""Exercise the temporary MU profiler against the existing local WordPress stage; always clean up."""
import hashlib
import os
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import time
import urllib.error
import urllib.request

podman = shutil.which('podman') or '/opt/podman/bin/podman'
container = 'wordpriis-verify-wp'
wrapper = '/var/www/html/wp-content/mu-plugins/000-wordpriis-bootstrap-profile-check.php'
output = '/tmp/wordpriis-bootstrap-profile-' + secrets.token_hex(8) + '.jsonl'
token = secrets.token_hex(32)
hash_value = hashlib.sha256(token.encode()).hexdigest()
source = "<?php\ndefine('WORDPRIIS_FILESYSTEM_PROBE', true);\ndefine('WORDPRIIS_PROFILE_TOKEN_SHA256', '" + hash_value + "');\ndefine('WORDPRIIS_PROFILE_UNTIL', " + str(int(time.time()) + 900) + ");\ndefine('WORDPRIIS_PROFILE_FILE', '" + output + "');\nrequire '/var/www/html/wp-content/plugins/wordpriis/scripts/wordpriis-bootstrap-profile.php';\n"

runner_code = '--runner-code' in sys.argv
if runner_code:
    pwsh = os.environ.get('WORDPRIIS_TEST_PWSH') or shutil.which('pwsh')
    if not pwsh:
        raise SystemExit('Set WORDPRIIS_TEST_PWSH or install PowerShell for --runner-code.')
    root = Path(__file__).resolve().parent.parent
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    with tempfile.TemporaryDirectory(prefix='wordpriis-profile-code-') as temp:
        render = Path(temp) / 'render.ps1'
        render.write_text('. ' + quote(root / 'scripts/Invoke-WordPrIISBootstrapProfile.ps1') + "\n" +
                          '$source=[IO.File]::ReadAllText(' + quote(root / 'scripts/wordpriis-bootstrap-profile.php') + ")\n" +
                          '[Console]::Write((New-ProfileCode $source ' + quote(hash_value) + ' ' + str(int(time.time()) + 900) + ' ' + quote(output) + " -FileSystemProbe))\n")
        source = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-File', str(render)], capture_output=True, text=True, check=True).stdout

source += "\nrequire '/var/www/html/wp-content/plugins/wordpriis/tests/bootstrap-profile-fixture.php';\n"
# A uniquely named, nonactivated target-source fixture; never overwrite installed plugin files.
resource_dir = '/var/www/html/wp-content/plugins/wp-seopress'
resource_name = 'wordpriis-resource-' + secrets.token_hex(8)
resource_file = resource_dir + '/' + resource_name + '.php'
resource_child = resource_dir + '/' + resource_name + '-child.php'
resource_late_child = resource_dir + '/' + resource_name + '-late.php'
resource_dir_created = False
resource_source = """<?php
if (!defined('WORDPRIIS_PROFILE_TOKEN_SHA256') || wp_get_environment_type() !== 'local'
    || !wordpriis_profile_allowed($_SERVER, $_GET, $_POST, ['hash' => WORDPRIIS_PROFILE_TOKEN_SHA256, 'expires' => WORDPRIIS_PROFILE_UNTIL])) { return; }
function wordpriis_resource_stage_parent(): void { do_action('wordpriis_resource_stage_nested'); usleep(2000); }
function wordpriis_resource_stage_nested(): void { require __DIR__ . '/""" + resource_name + """-child.php'; usleep(1000); }
function wordpriis_resource_stage_factory() { return static function ($value = null) { return $value; }; }
function wordpriis_resource_stage_storm(): void {
    for ($i = 0; $i < 20000; $i++) { apply_filters('wordpriis_stage_hot_SECRET', 'SECRET_VALUE'); }
    for ($i = 0; $i < 80; $i++) { do_action('wordpriis_stage_unique_SECRET_' . $i); }
}
function wordpriis_resource_stage_late(): void { require __DIR__ . '/""" + resource_name + """-late.php'; usleep(2000); }
add_action('plugins_loaded', 'wordpriis_resource_stage_parent', 19, 0);
add_action('plugins_loaded', 'wordpriis_resource_stage_storm', 20, 0);
add_filter('wordpriis_stage_hot_SECRET', wordpriis_resource_stage_factory());
for ($i = 0; $i < 80; $i++) {
    add_action('plugins_loaded', wordpriis_resource_stage_factory(), 21, 0);
    add_action('wordpriis_stage_unique_SECRET_' . $i, wordpriis_resource_stage_factory(), 10, 0);
}
add_action('wp_loaded', 'wordpriis_resource_stage_late', 10, 0);
add_action('wordpriis_resource_stage_nested', 'wordpriis_resource_stage_nested', 10, 0);
do_action('plugin_loaded', __FILE__);
"""
source += "\nrequire '" + resource_file + "';\n"


def php(code, data=None, user='www-data'):
    return subprocess.run([podman, 'exec', '--user', user, '-i', container, 'php', '-r', code], input=data, text=True, capture_output=True, check=True).stdout

def request(headers, expected_profiler_status=None):
    req = urllib.request.Request('http://127.0.0.1:8108/wp-admin/admin-ajax.php', headers=headers)
    start = time.monotonic()
    try:
        response = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        assert response.code == 400 and body == b'0', 'no-action AJAX response must remain unchanged'
        assert response.headers.get('X-WORDPRIIS-Profile-Status') == expected_profiler_status, 'fixed profiler status only on token-authorized requests'
        if expected_profiler_status:
            assert response.headers.get('X-WORDPRIIS-Profile-Impersonation') in ('enabled', 'disabled', 'unknown')
            assert response.headers.get('X-WORDPRIIS-Profile-OpenBasedir') in ('enabled', 'disabled')
        else:
            assert response.headers.get('X-WORDPRIIS-Profile-Impersonation') is None
            assert response.headers.get('X-WORDPRIIS-Profile-OpenBasedir') is None
    return round((time.monotonic() - start) * 1000, 3)

# Preflight must not remove a file belonging to a previous/manual run.
php("if (file_exists('" + wrapper + "')) { exit(2); }")
try:
    resource_dir_created = php("echo is_dir('" + resource_dir + "') ? 'existing' : 'new';") == 'new'
    php("if (!is_dir('" + resource_dir + "')) { mkdir('" + resource_dir + "', 0755); } file_put_contents('" + resource_file + "', stream_get_contents(STDIN)); chmod('" + resource_file + "', 0644); file_put_contents('" + resource_child + "', '<?php /* synthetic successful include */'); chmod('" + resource_child + "', 0644);", resource_source, user='root')
    php("file_put_contents('" + resource_late_child + "', '<?php class WORDPRIIS_Stage_Late_Resource {}'); chmod('" + resource_late_child + "', 0644);", user='root')
    php("if (!touch('" + output + "')) { exit(3); } chmod('" + output + "', 0600);")
    php("if (!is_dir(dirname('" + wrapper + "'))) { mkdir(dirname('" + wrapper + "')); } if (file_put_contents('" + wrapper + "', stream_get_contents(STDIN)) === false) { exit(4); } chmod('" + wrapper + "', 0644);", source, user='root')
    request({})
    assert php("echo filesize('" + output + "');") == '0', 'ordinary request must not be profiled'
    times = [request({'X-WORDPRIIS-Profile': token}, 'recording') for _ in range(3)]
    request({'X-WORDPRIIS-Profile': token, 'Cookie': 'fixture=private'}, 'request-gate-rejected')
    request({'X-WORDPRIIS-Profile': 'b' * 64})
    php("chmod('" + output + "', 0000);", user='root')
    request({'X-WORDPRIIS-Profile': token}, 'output-unavailable')
    php("chmod('" + output + "', 0600);", user='root')
    records = [json.loads(line) for line in php("readfile('" + output + "');").splitlines()]
    assert len(records) == 3, 'only the three authorized anonymous probes may be written'
    for record in records:
        assert record['status'] == 400 and record['db_query_count'] > 0
        assert record['schema_version'] == 3
        assert record['filesystem_probe']['sapi'] != 'cli'
        assert record['filesystem_probe']['groups'] and record['filesystem_probe']['operations']
        assert 'SECRET' not in json.dumps(record['filesystem_probe'])
        assert 'target_resources' in record and 'target_plugin_load_intervals' in record
        resources = {row['callback']: row for row in record['target_resources']}
        assert resources['wordpriis_resource_stage_parent']['target_included_files'] == 1
        assert resources['wordpriis_resource_stage_nested']['target_included_files'] == 1
        assert resources['wordpriis_resource_stage_nested']['hook'] == 'target-nested-hook'
        assert resources['wordpriis_resource_stage_late']['target_included_files'] == 1
        assert resources['wordpriis_resource_stage_late']['declared_classes_delta'] == 1
        assert resources['wordpriis_resource_stage_late']['sampling_bucket'] == 'primary'
        assert record['resource_coverage']['sampling_policy'] == 'phase-plugin-first-invocation'
        assert record['resource_coverage']['nested_scan_cache_hits'] >= 19999
        assert record['resource_coverage']['budget_skips_by_bucket']['primary'] > 0
        assert record['resource_coverage']['resource_calls_sampled'] <= 104
        assert any(row['ending_at'].endswith(resource_name + '.php') for row in record['target_plugin_load_intervals'])
        assert record['resource_coverage']['per_file_duration_available'] is False
        callbacks = record['callback_timings']
        assert any(c['callback'] == 'wordpriis_profile_fixture_slow_callback' and c['self_ms'] >= 1 for c in callbacks)
        traced = [c for c in record['http_calls'] if c.get('callback') and c['callback']['callback'] == 'wordpriis_profile_fixture_http']
        assert len(traced) == 1 and traced[0]['phase'] == 'shutdown' and traced[0]['destination'] == 'cron-loopback'
        assert traced[0]['outcome'] == 'preempted', 'fixture HTTP is blocked before any external request'
        assert 'SECRET' not in json.dumps(record), 'fixture URL/body/auth values must not reach the report'
        names = [m['phase'] for m in record['phases']]
        assert 'plugins_loaded:leave' in names and 'wp_loaded:leave' in names
        assert 'admin_init:enter' not in names, 'no-action AJAX exits before admin initialization'
        assert 'fixture=private' not in json.dumps(record) and token not in json.dumps(record)
    print(json.dumps({'scope': 'local Podman WordPress stage only', 'authorized_requests': 3, 'runner_generated_code': runner_code,
                      'ordinary_and_cookie_requests_not_recorded': True, 'invalid_token_not_recorded': True,
                      'unwritable_output_diagnosed_without_recording': True, 'callback_and_shutdown_http_attribution': True, 'target_file_and_nested_callback_attribution': True, 'late_callback_after_sampling_storm': True, 'unchanged_ajax_response': True,
                      'elapsed_ms': times, 'profiles': records}, indent=2))
finally:
    php("@unlink('" + resource_file + "'); @unlink('" + resource_child + "'); @unlink('" + resource_late_child + "');", user='root')
    if resource_dir_created:
        php("@rmdir('" + resource_dir + "');", user='root')
    php("@unlink('" + wrapper + "'); @unlink('" + output + "');", user='root')
