<?php
/** Real WordPress hook dispatcher only; no wp-load, plugins, database or external requests. */
if (PHP_SAPI !== 'cli') { exit(1); }
define('ABSPATH', dirname(__DIR__, 4) . '/');
define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
define('WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins');
define('WPMU_PLUGIN_DIR', WP_CONTENT_DIR . '/mu-plugins');
require ABSPATH . 'wp-includes/plugin.php';
require __DIR__ . '/../scripts/wordpriis-bootstrap-profile.php';
class WP_Error {}
$checks = 0;
$check = static function ($ok, $label) use (&$checks) { if (!$ok) { throw new RuntimeException($label); } $checks++; };
$wpdb = (object) ['num_queries' => 0];
$_SERVER['HTTP_HOST'] = 'fixture.test'; $_SERVER['SCRIPT_NAME'] = '/wp-admin/admin-ajax.php';
$begin = hrtime(true); $trace = new WORDPRIIS_Bootstrap_Trace(static fn() => round((hrtime(true) - $begin) / 1e6, 3));
$trace->install();
$order = [];
function wordpriis_trace_named($arg = '') { global $order, $wpdb; $order[] = 'named'; $wpdb->num_queries++; usleep(2000); return 'result'; }
class WORDPRIIS_Trace_Fixture {
    public static function statik() { global $order; $order[] = 'static'; }
    public function method() { global $order; $order[] = 'method'; }
    public function __invoke() { global $order; $order[] = 'invoke'; }
}
$object = new WORDPRIIS_Trace_Fixture();
add_action('plugins_loaded', 'wordpriis_trace_named', 10);
add_action('plugins_loaded', [WORDPRIIS_Trace_Fixture::class, 'statik'], 11, 0);
add_action('plugins_loaded', [$object, 'method'], 12, 0);
add_action('plugins_loaded', $object, 13, 0);
$remove = static function () { throw new RuntimeException('Removed callback must not execute'); };
add_action('plugins_loaded', $remove, 30, 0);
$mutate = static function () use (&$order, $remove) {
    $order[] = 'mutate';
    remove_action('plugins_loaded', $remove, 30);
    add_action('plugins_loaded', static function () use (&$order) { $order[] = 'dynamic'; }, 40, 0);
};
add_action('plugins_loaded', $mutate, 14, 0);
$originalKeys = array_keys($wp_filter['plugins_loaded']->callbacks[10]);
do_action('plugins_loaded');
$check($order === ['named','static','method','invoke','mutate','dynamic'], 'ordering, same keys, removal and dynamic addition behavior retained');
$check(array_keys($wp_filter['plugins_loaded']->callbacks[10]) === $originalKeys && has_action('plugins_loaded', 'wordpriis_trace_named') === 10, 'original callback identity retained');
$wrappedNamed = $wp_filter['plugins_loaded']->callbacks[10][_wp_filter_build_unique_id('plugins_loaded', 'wordpriis_trace_named', 10)]['function'];
$check($wrappedNamed('SECRET_ARGUMENT') === 'result', 'return value and supplied argument preserved without logging');
unset($wrappedNamed);
$check(remove_action('plugins_loaded', 'wordpriis_trace_named', 10), 'remove_action accepts original callable after wrapping');
$data = $trace->snapshot();
$named = array_values(array_filter($data['callback_timings'], static fn($r) => $r['callback'] === 'wordpriis_trace_named'))[0];
$check($named['calls'] === 2 && $named['total_ms'] >= 1 && $named['self_ms'] >= 1 && $named['query_count'] === 2, 'named callback time and query delta');
$check($named['source'] === 'plugins/wordpriis/tests/bootstrap-trace.php' && is_int($named['line']), 'relative callback definition location');
$names = array_column($data['callback_timings'], 'callback');
$check(in_array('WORDPRIIS_Trace_Fixture::statik', $names, true) && in_array('WORDPRIIS_Trace_Fixture::method', $names, true) && in_array('WORDPRIIS_Trace_Fixture::__invoke', $names, true), 'static, instance and invokable callbacks measured');
$check($data['callback_coverage']['dynamic_additions_may_be_unmeasured'], 'dynamic coverage limitation explicit');
$destroyed = false;
class WORDPRIIS_Trace_Lifetime { public function __invoke() {} public function __destruct() { $GLOBALS['destroyed'] = true; } }
$lifetime = new WORDPRIIS_Trace_Lifetime();
add_action('init', $lifetime, 1, 0); $trace->instrument('init');
remove_action('init', $lifetime, 1); unset($lifetime); gc_collect_cycles();
$check($destroyed, 'profiler registry does not retain removed callback objects');
$selfCalls = 0;
$selfRemoving = null;
$selfRemoving = static function () use (&$selfCalls, &$selfRemoving) { $selfCalls++; remove_action('wp_loaded', $selfRemoving, 5); };
add_action('wp_loaded', $selfRemoving, 5, 0); do_action('wp_loaded'); do_action('wp_loaded');
$check($selfCalls === 1, 'self-removal by original callable works after wrapping');
remove_all_actions('wp_loaded');
$referenceValue = 'reference';
$returnReference = static function &() use (&$referenceValue) { return $referenceValue; };
add_action('init', $returnReference, 2, 0); $trace->instrument('init');
$check($wp_filter['init']->callbacks[2][_wp_filter_build_unique_id('init', $returnReference, 2)]['function'] === $returnReference, 'reference-returning callable remains intact');
remove_action('init', $returnReference, 2);
add_action('init', 'WORDPRIIS_Trace_Fixture::statik', 3, 0); do_action('init');
$check(in_array('WORDPRIIS_Trace_Fixture::statik', array_column($trace->snapshot()['callback_timings'], 'callback'), true), 'static method string supported without deprecated reflection API');
remove_action('init', 'WORDPRIIS_Trace_Fixture::statik', 3);
$recursiveCalls = 0;
$recursive = static function () use (&$recursiveCalls) { if (++$recursiveCalls === 1) { do_action('init'); } usleep(1000); };
add_action('init', $recursive, 10, 0);
do_action('init');
$recursiveRows = array_values(array_filter($trace->snapshot()['callback_timings'], static fn($r) => $r['hook'] === 'init'));
$check($recursiveCalls === 2 && $recursiveRows[0]['calls'] === 2, 'recursive dispatch measured without duplicate wrappers');
$check($recursiveRows[0]['total_ms'] > $recursiveRows[0]['self_ms'] && $recursiveRows[0]['self_ms'] >= 1, 'self time excludes instrumented child callbacks');
$withReference = static function (&$value) { $value = 'changed'; };
add_action('init', $withReference, 20, 1);
$value = 'old'; $args = [&$value];
// Calls with reference-bearing callbacks must keep the original callable unchanged.
$trace->instrument('init');
$check($wp_filter['init']->callbacks[20][_wp_filter_build_unique_id('init', $withReference, 20)]['function'] === $withReference, 'by-reference callbacks skipped intact');
do_action_ref_array('init', $args);
$check($value === 'changed' && $trace->snapshot()['callback_coverage']['reference_callbacks_skipped'] > 0, 'reference behavior preserved and skip reported');
$exception = new RuntimeException('SECRET exception must not be recorded');
$thrower = static function () use ($exception) { throw $exception; };
add_action('wp_loaded', $thrower, 10, 0);
$caught = null; try { do_action('wp_loaded'); } catch (Throwable $error) { $caught = $error; }
$check($caught === $exception, 'same exception propagated');
$throwRows = array_values(array_filter($trace->snapshot()['callback_timings'], static fn($r) => $r['hook'] === 'wp_loaded'));
$check(array_sum(array_column($throwRows, 'exceptions')) === 1 && !$trace->snapshot()['callback_coverage']['active_callbacks'], 'exception counted and stack unwound');
// Reset only synthetic hooks; no real WordPress initialization was loaded.
remove_all_actions('wp_loaded'); remove_all_actions('init');
function wordpriis_trace_http($url, $args = [], $response = ['response' => ['code' => 200]]) {
    $pre = apply_filters('pre_http_request', false, $args + ['method' => 'POST', 'blocking' => false, 'timeout' => 0.01], $url);
    if ($pre === false) { usleep(1500); do_action('http_api_debug', $response, 'response', 'transport', $args, $url); }
    return $pre;
}
function wordpriis_trace_cron_fixture() { wordpriis_trace_http('https://fixture.test/wp-cron.php?doing_wp_cron=SECRET_TOKEN', ['body' => 'SECRET_BODY', 'headers' => ['Authorization' => 'SECRET_AUTH']]); }
add_action('shutdown', 'wordpriis_trace_cron_fixture', 10, 0);
do_action('shutdown');
$data = $trace->snapshot(); $call = $data['http_calls'][0];
$check($call['phase'] === 'shutdown' && $call['destination'] === 'cron-loopback' && $call['callback']['callback'] === 'wordpriis_trace_cron_fixture', 'shutdown cron category and originating callback');
$check($call['caller']['callback'] === 'wordpriis_trace_http', 'HTTP caller excludes transport and hook plumbing');
$check($call['elapsed_ms'] >= 1 && $call['status_code'] === 200 && $call['blocking'] === false && $call['timeout_seconds'] === 0.01, 'HTTP duration/status/nonblocking/timeout fields');
$check($data['http_completed_count'] === 1 && $data['http_observed_ms'] >= 1 && $data['http_pending_keys'] === 0, 'existing HTTP aggregate semantics retained');
wordpriis_trace_http('https://SECRET_USER:SECRET_PASSWORD@external.invalid/private/SECRET_PATH?token=SECRET_QUERY', [], new WP_Error());
$last = $trace->snapshot()['http_calls'][1];
$check($last['outcome'] === 'wp-error' && $last['status_code'] === null && $last['destination'] === 'external', 'WP_Error records no error text or URL');
$preempt = static fn() => ['body' => 'SECRET_PREEMPTED'];
add_filter('pre_http_request', $preempt, 10);
$pre = wordpriis_trace_http('https://external.invalid/preempt');
$check($pre === ['body' => 'SECRET_PREEMPTED'] && $trace->snapshot()['http_calls'][2]['outcome'] === 'preempted', 'preemptive filter result preserved without exporting response');
remove_filter('pre_http_request', $preempt, 10);
// Nested same-URL requests pair LIFO without exposing a URL hash.
$url = 'https://external.invalid/nested';
$trace->httpStart(false, [], $url); $trace->httpStart(false, [], $url);
$trace->httpEnd([], 'response', '', [], $url); $trace->httpEnd([], 'response', '', [], $url);
$check($trace->snapshot()['http_pending_keys'] === 0 && $trace->snapshot()['http_completed_count'] === 4, 'nested identical URLs paired');
$trace->httpEnd([], 'response', '', [], 'https://unpaired.invalid');
$check($trace->snapshot()['http_unpaired_completions'] === 1, 'unpaired completion coverage retained');
$closureHttp = static function () {
    $url = 'https://external.invalid/SECRET_CLOSURE_URL';
    apply_filters('pre_http_request', false, [], $url);
    do_action('http_api_debug', [], 'response', '', [], $url);
};
add_action('shutdown', $closureHttp, 20, 0); do_action('shutdown');
$closureCalls = array_values(array_filter($trace->snapshot()['http_calls'], static fn($r) => ($r['callback']['callback'] ?? '') === 'closure'));
$check(count($closureCalls) === 1 && $closureCalls[0]['caller']['callback'] === 'closure', 'PHP 8.4 closure names do not expose embedded absolute filenames');
remove_action('shutdown', $closureHttp, 20);
for ($i = 0; $i < 40; $i++) { wordpriis_trace_http('https://external.invalid/capped/' . $i); }
$data = $trace->snapshot();
$check(count($data['http_calls']) === 32 && $data['callback_coverage']['http_rows_dropped'] > 0, 'HTTP trace rows bounded with explicit drops');
$check(!str_contains(json_encode($data), 'SECRET') && !str_contains(json_encode($data), 'https://') && !str_contains(json_encode($data), '/var/www/html'), 'no arguments, URL parts, tokens, absolute paths, response or exception text');
$anonymous = new class { public function __invoke() {} };
add_action('init', $anonymous, 5, 0); do_action('init');
$check(in_array('anonymous-class::__invoke', array_column($trace->snapshot()['callback_timings'], 'callback'), true), 'anonymous class runtime name redacted');
// Verify bounded callback instrumentation with many registrations.
remove_all_actions('init');
for ($i = 0; $i < 550; $i++) { add_action('init', static function () {}, 10, 0); }
do_action('init'); $data = $trace->snapshot();
$check($data['callback_coverage']['wrapped_registrations'] === 512 && $data['callback_coverage']['callback_limit_skipped'] > 0, 'callback wrapper count bounded');
$check(count($data['callback_timings']) === 64 && $data['callback_coverage']['rows_omitted'] > 0, 'slow callback output bounded and omissions explicit');
echo "Bootstrap trace: {$checks} assertions passed.\n";
