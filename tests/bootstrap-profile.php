<?php
/** Pure diagnostic regressions: no WordPress bootstrap or external HTTP. */
$root = sys_get_temp_dir() . '/wordpriis-profile-' . bin2hex(random_bytes(8));
if (($argv[1] ?? '') === '--child') { $root = $argv[2]; }
if (!is_dir($root)) { mkdir($root); mkdir($root . '/web'); }
define('ABSPATH', $root . '/web/');
require __DIR__ . '/../scripts/wordpriis-bootstrap-profile.php';
if (($argv[1] ?? '') === '--child') {
    $hooks = [];
    function add_action($name, $fn, $priority = 10, $args = 1) { global $hooks; $hooks[$name][$priority][] = $fn; }
    function add_filter($name, $fn, $priority = 10, $args = 1) { add_action($name, $fn, $priority, $args); }
    function fire($name, ...$args) { global $hooks; $items = $hooks[$name] ?? []; ksort($items); foreach ($items as $group) { foreach ($group as $fn) { $fn(...$args); } } }
    $_SERVER['REQUEST_TIME_FLOAT'] = microtime(true) - 0.05;
    $_SERVER['HTTP_COOKIE'] = 'SECRET-cookie';
    $wpdb = (object) ['num_queries' => 17, 'last_query' => 'SECRET-SQL'];
    wordpriis_profile_start($root . '/profile.jsonl');
    fire('plugin_loaded', '/SECRET-root/plugins/example/main.php');
    fire('init');
    fire('pre_http_request', false, ['body' => 'SECRET-body'], 'https://SECRET-url.invalid/?token=SECRET-token');
    usleep(1500);
    fire('http_api_debug', ['body' => 'SECRET-response'], 'response', 'transport', [], 'https://SECRET-url.invalid/?token=SECRET-token');
    fire('http_api_debug', [], 'response', 'transport', [], 'https://unpaired.invalid');
    http_response_code(400);
    exit;
}
$count = 0;
$check = static function ($ok, $name) use (&$count) { if (!$ok) { throw new RuntimeException($name); } $count++; };
$token = str_repeat('a', 64);
$config = ['hash' => hash('sha256', $token), 'expires' => time() + 900];
$server = ['REQUEST_METHOD' => 'GET', 'SCRIPT_NAME' => '/wp-admin/admin-ajax.php', 'HTTP_X_WORDPRIIS_PROFILE' => $token];
$check(wordpriis_profile_allowed($server, [], [], $config), 'valid short-lived no-action request');
foreach (['HTTP_X_WORDPRIIS_PROFILE' => str_repeat('b', 64), 'REQUEST_METHOD' => 'POST', 'SCRIPT_NAME' => '/index.php', 'HTTP_COOKIE' => 'session=secret', 'HTTP_AUTHORIZATION' => 'Bearer secret'] as $key => $value) {
    $bad = $server; $bad[$key] = $value;
    $check(!wordpriis_profile_allowed($bad, [], [], $config), 'reject invalid token/route/method/auth');
}
$check(!wordpriis_profile_allowed($server, ['action' => 'checkout'], [], $config), 'reject all query parameters');
$check(!wordpriis_profile_allowed($server, [], ['action' => 'checkout'], $config), 'reject POST data');
$check(!wordpriis_profile_allowed($server, [], [], ['hash' => $config['hash'], 'expires' => time() - 1]), 'reject expired config');
$check(!wordpriis_profile_allowed($server, [], [], ['hash' => $config['hash'], 'expires' => time() + 3600]), 'reject excessive lifetime');
$check(!wordpriis_profile_allowed($server, [], [], ['hash' => 'invalid', 'expires' => time() + 900]), 'reject malformed hash');
$file = $root . '/profile.jsonl'; touch($file);
$check(wordpriis_profile_private_file($file, [ABSPATH]), 'existing private file accepted');
$check(wordpriis_profile_prepare($file, [ABSPATH]) === 'recording', 'writable private log ready');
$check(wordpriis_profile_prepare($root . '/missing', [ABSPATH]) === 'output-unavailable', 'missing output has fixed diagnosis');
$lock = fopen($file, 'r+b'); flock($lock, LOCK_EX);
$check(wordpriis_profile_prepare($file, [ABSPATH]) === 'output-lock-failed', 'locked output does not block request or expose error');
flock($lock, LOCK_UN); fclose($lock);
$check(!wordpriis_profile_private_file($root . '/missing', [ABSPATH]), 'file is never automatically created');
$public = ABSPATH . 'public.jsonl'; touch($public);
$check(!wordpriis_profile_private_file($public, [ABSPATH]), 'reject web-root output');
$check(wordpriis_profile_prepare($public, [ABSPATH]) === 'output-unavailable', 'public output is never opened for recording');
symlink($file, $root . '/link');
$check(!wordpriis_profile_private_file($root . '/link', [ABSPATH]), 'reject symlink output');
$check(!wordpriis_profile_private_file($file, [$root . '/missing-root']), 'fail closed on unresolved roots');
$command = [PHP_BINARY, __FILE__, '--child', $root];
$process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
$out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
$check(proc_close($process) === 0 && $out === '' && $err === '', 'profiler never changes response or prints errors');
$raw = file_get_contents($file); $record = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
$check(!str_contains($raw, 'SECRET') && !str_contains($raw, 'unpaired.invalid'), 'no paths, URLs, queries, bodies or cookies');
$check($record['db_query_count'] === 17 && $record['status'] === 400, 'query count and expected no-action status');
$check($record['pre_mu_ms'] >= 45 && $record['http_completed_count'] === 1 && $record['http_observed_ms'] >= 1, 'request and outbound elapsed time');
$check($record['http_unpaired_completions'] === 1 && $record['http_pending_keys'] === 0, 'HTTP coverage gaps explicit');
$check(array_column($record['phases'], 'phase') === ['mu_profiler_loaded', 'plugin_loaded:example/main.php', 'init:enter', 'init:leave'], 'ordered phase markers and relative plugin slug');
file_put_contents($file, str_repeat('x', 2097148));
wordpriis_profile_append($file, ['long' => 'record']);
$check(filesize($file) === 2097148, 'bounded file stops before 2 MiB');
unlink($root . '/link'); unlink($file); unlink($public); rmdir(ABSPATH); rmdir($root);
echo "Bootstrap profiler: {$count} assertions passed.\n";
