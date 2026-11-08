<?php
if (PHP_SAPI !== 'cli') { exit(1); }
define('WORDPRIIS_AUDIT_LIBRARY_ONLY', true);
require __DIR__ . '/../scripts/audit-wordpress.php';
set_exception_handler(static function (Throwable $error) { fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . ' at line ' . $error->getLine() . PHP_EOL); exit(1); });
$count = 0;
$check = static function ($ok, $label) use (&$count) { if (!$ok) { throw new RuntimeException($label); } $count++; };
$source = <<<'CONFIG'
<?php
// define('DB_PASSWORD', 'wrong');
define('DB_HOST', 'localhost');
define('DB_USER', 'audit');
define('DB_PASSWORD', 's3cret\'quote\\slash');
define('DB_NAME', 'wordpress');
define('WP_DEBUG_DISPLAY', false);
define('WP_CACHE', true);
define('REMOTE_SECRET', getenv('DO_NOT_EXECUTE'));
$table_prefix = 'wp_';
file_put_contents('/tmp/wordpriis-audit-MUST-NOT-EXECUTE', 'bad');
CONFIG;
$config = wordpriis_audit_literals($source);
$check($config['DB_PASSWORD'] === "s3cret'quote\\slash", 'single-quoted config escaping');
$check($config['WP_DEBUG_DISPLAY'] === false && $config['WP_CACHE'] === true, 'boolean literals retained');
$check(!isset($config['REMOTE_SECRET']), 'environment/function expressions are not evaluated');
$check(($config['table_prefix'] ?? '') === 'wp_', 'literal table prefix parsed');
$check(!file_exists('/tmp/wordpriis-audit-MUST-NOT-EXECUTE'), 'config PHP never executed');
$remote = $config; $remote['DB_HOST'] = 'database.example.invalid';
$check(wordpriis_audit_database($remote)['status'] === 'skipped', 'remote DB cannot silently downgrade to plaintext');
// A refused local connection must expose timing without exposing credentials/errors.
$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
$endpoint = stream_socket_get_name($listener, false); fclose($listener);
$closed = $config; $closed['DB_HOST'] = $endpoint;
$failure = wordpriis_audit_database($closed);
$check($failure['status'] === 'unavailable' && is_numeric($failure['connect_ms']) && $failure['connect_ms'] >= 0, 'failed connection retains separate timing');
$check($failure['connection_target_kind'] === 'loopback_ipv4' && !str_contains(json_encode($failure), 's3cret'), 'connection metadata contains no credentials or driver error');
foreach (['database.example.invalid', '127.0.0.1', 'localhost:/private/socket'] as $ineligible) {
    $candidate = $config; $candidate['DB_HOST'] = $ineligible;
    $check(wordpriis_audit_ipv4_comparison($candidate, [])['status'] === 'skipped', 'IPv4 comparison refuses remote, existing-IP and socket settings');
}
$root = sys_get_temp_dir() . '/wordpriis-audit-test-' . bin2hex(random_bytes(8));
mkdir($root);
file_put_contents($root . '/wp-config.php', $source);
try {
    $report = wordpriis_audit_main(['root' => $root]);
    $serialized = json_encode($report);
    $check(!str_contains($serialized, 's3cret') && !str_contains($serialized, 'DB_PASSWORD'), 'report excludes database credentials');
    $check($report['database']['status'] === 'skipped', 'database is opt-in');
    $without_database = wordpriis_audit_main(['root' => $root, 'compare-loopback-ipv4' => false]);
    $check(!isset($without_database['database_ipv4_comparison']), 'comparison cannot implicitly enable database diagnostics');
    $check($report['wordpress']['literal_flags']['WP_DEBUG_DISPLAY'] === false, 'parsed config flags reach report');
    $check(!file_exists('/tmp/wordpriis-audit-MUST-NOT-EXECUTE'), 'full probe does not bootstrap config');
    foreach ([['variables_order=GP', 'register_argc_argv=1'], ['variables_order=GP', 'register_argc_argv=0']] as $settings) {
        $command = [PHP_BINARY, '-d', $settings[0], '-d', $settings[1], __DIR__ . '/../scripts/audit-wordpress.php', '--root=' . $root];
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $stdout = stream_get_contents($pipes[1]); $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]); $exit = proc_close($process);
        $check($exit === 0 && str_starts_with($stdout, 'WORDPRIIS_AUDIT_JSON:'), 'helper returns JSON without SERVER globals');
        $data = json_decode(substr($stdout, strlen('WORDPRIIS_AUDIT_JSON:')), true, 512, JSON_THROW_ON_ERROR);
        if ($settings[1] === 'register_argc_argv=1') {
            $check(($data['wordpress']['status'] ?? '') === 'inspected_without_bootstrap', 'per-process argv override permits real root inspection');
        } else {
            $valid_root = ($data['wordpress']['status'] ?? '') === 'inspected_without_bootstrap' && ($data['wordpress']['literal_flags']['WP_CACHE'] ?? null) === true;
            $safe_unavailable = ($data['status'] ?? '') === 'unavailable' && str_contains($data['reason'] ?? '', 'CLI options');
            $check($valid_root || $safe_unavailable, 'disabled argv either parses the explicit root or has a safe unavailable reason');
        }
        $check(!str_contains($stdout, 's3cret') && !file_exists('/tmp/wordpriis-audit-MUST-NOT-EXECUTE'), 'no-globals invocation neither leaks secrets nor executes config');
    }

    $process = proc_open([PHP_BINARY, __DIR__ . '/../scripts/audit-wordpress.php'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]); $exit = proc_close($process);
    $missing = json_decode(substr($out, strlen('WORDPRIIS_AUDIT_JSON:')), true, 512, JSON_THROW_ON_ERROR);
    $check($exit === 0 && $err === '' && ($missing['status'] ?? '') === 'unavailable', 'missing root never silently probes current directory');

} finally { unlink($root . '/wp-config.php'); rmdir($root); }
echo "Server audit PHP: $count checks passed.\n";
