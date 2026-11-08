<?php
/** Real dispatcher and successful PHP includes; no production plugin files or autoload changes. */
if (PHP_SAPI !== 'cli') { exit(1); }
define('ABSPATH', dirname(__DIR__, 4) . '/');
$fixture = sys_get_temp_dir() . '/wordpriis-resources-' . bin2hex(random_bytes(8));
mkdir($fixture);
define('WP_PLUGIN_DIR', $fixture);
define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
require ABSPATH . 'wp-includes/plugin.php';
require __DIR__ . '/../scripts/wordpriis-bootstrap-profile.php';
$n = 0;
$check = static function ($ok, $label) use (&$n) { if (!$ok) { throw new RuntimeException($label); } $n++; };
$wpdb = (object) ['num_queries' => 0];
$begin = hrtime(true);
$trace = new WORDPRIIS_Bootstrap_Trace(static fn() => (hrtime(true) - $begin) / 1e6);
try {
    foreach (WORDPRIIS_Profile_Resources::TARGETS as $slug) { mkdir($fixture . '/' . $slug); mkdir($fixture . '/' . $slug . '/includes'); }
    file_put_contents($fixture . '/breakdance/includes/first.php', '<?php class WORDPRIIS_First_Include {}');
    file_put_contents($fixture . '/breakdance/includes/second.php', '<?php class WORDPRIIS_Second_Include {}');
    file_put_contents($fixture . '/breakdance/main.php', <<<'PHP'
<?php
function wordpriis_resources_parent($value = '') {
    require_once __DIR__ . '/includes/first.php';
    do_action('private_SECRET_hook', $value);
    usleep(3000);
    return $value;
}
function wordpriis_resources_nested($value) {
    require_once __DIR__ . '/includes/second.php';
    $GLOBALS['resource_value'] = $value;
    usleep(1500);
}
function wordpriis_resources_repeat() { usleep(10); }
function wordpriis_resources_factory() { return static function ($value = null) { return $value; }; }
function wordpriis_resources_hot($value = null) { return $value; }
function wordpriis_resources_storm() {
    for ($i = 0; $i < 20000; $i++) { apply_filters('resource_hot_SECRET', 'SECRET_VALUE'); }
    for ($i = 0; $i < 80; $i++) { do_action('resource_unique_SECRET_' . $i); }
}
function wordpriis_resources_late_parent() { do_action('resource_late_SECRET'); }
function wordpriis_resources_mutation() { $GLOBALS['resource_mutations'] = ($GLOBALS['resource_mutations'] ?? 0) + 1; usleep(2000); }
function wordpriis_resources_effect_factory() { return static function () { $GLOBALS['resource_effects'] = ($GLOBALS['resource_effects'] ?? 0) + 1; }; }


PHP);
    file_put_contents($fixture . '/wp-rocket/main.php', <<<'PHP'
<?php
function wordpriis_resources_throw() { throw new RuntimeException('SECRET_EXCEPTION'); }
PHP);
    file_put_contents($fixture . '/wp-seopress/main.php', <<<'PHP'
<?php
function wordpriis_resources_memory() { $GLOBALS['resource_memory'] = str_repeat('SECRET', 10000); }
PHP);
    file_put_contents($fixture . '/wp-seopress-pro/main.php', <<<'PHP'
<?php
function wordpriis_resources_pro() { return 42; }
PHP);
    foreach (WORDPRIIS_Profile_Resources::TARGETS as $slug) {
        require $fixture . '/' . $slug . '/main.php';
        $trace->pluginLoaded($fixture . '/' . $slug . '/main.php');
    }
    $trace->install();
    add_action('private_SECRET_hook', 'wordpriis_resources_nested', 10, 1);
    add_filter('plugins_loaded', 'wordpriis_resources_parent', 10, 1);
    $check(apply_filters('plugins_loaded', 'SECRET_ARGUMENT') === 'SECRET_ARGUMENT', 'filter result unchanged');
    $check($GLOBALS['resource_value'] === 'SECRET_ARGUMENT', 'nested arguments unchanged');
    $data = $trace->snapshot();
    $rows = array_column($data['target_resources'], null, 'callback');
    $parent = $rows['wordpriis_resources_parent']; $nested = $rows['wordpriis_resources_nested'];
    $check($parent['elapsed_ms'] >= 4 && $nested['elapsed_ms'] >= 1, 'known slow parent/nested work timed');
    $check($parent['new_included_files'] === 2 && $nested['new_included_files'] === 1, 'inclusive include deltas with child nesting');
    $check($parent['declared_classes_delta'] === 2 && $nested['declared_classes_delta'] === 1, 'class declaration counts without names');
    $check($parent['target_file_groups']['plugins/breakdance/includes'] === 2, 'target folder attribution');
    $check($parent['target_file_examples'] === ['plugins/breakdance/includes/first.php', 'plugins/breakdance/includes/second.php'], 'relative include examples');
    $check($parent['cpu_ms'] === null || $parent['cpu_ms'] >= 0, 'CPU is optional nonnegative');
    $check($nested['hook'] === 'target-nested-hook', 'dynamic nested hook names are not exported');
    $check(has_action('private_SECRET_hook', 'wordpriis_resources_nested') === 10, 'nested callback identity retained');
    $check(remove_action('private_SECRET_hook', 'wordpriis_resources_nested'), 'nested callback removable by original function');
    apply_filters('plugins_loaded', 'again');
    $rows = $trace->snapshot()['target_resources'];
    $check(count(array_filter($rows, static fn($r) => $r['callback'] === 'wordpriis_resources_parent')) === 1 && $trace->snapshot()['resource_coverage']['repeat_calls_skipped'] >= 1, 'repeat invocation does not spend another resource sample');
    $check(count($data['target_plugin_load_intervals']) === 4, 'each target load interval retained');
    foreach ($data['target_plugin_load_intervals'] as $load) {
        $check($load['new_included_files'] === 1 && $load['target_included_files'] === 1 && $load['elapsed_ms'] >= 0, 'main file load boundary delta');
    }
    add_action('init', 'wordpriis_resources_throw');
    $threw = false;
    try { do_action('init'); } catch (RuntimeException $e) { $threw = $e->getMessage() === 'SECRET_EXCEPTION'; }
    $check($threw && $trace->snapshot()['callback_coverage']['active_callbacks'] === [], 'exception propagated and stack restored');
    remove_all_actions('init'); add_action('init', 'wordpriis_resources_memory'); do_action('init');
    add_action('wp_loaded', 'wordpriis_resources_pro'); do_action('wp_loaded');
    $rows = array_column($trace->snapshot()['target_resources'], null, 'callback');
    $check($rows['wordpriis_resources_memory']['memory_delta_bytes'] >= 60000, 'retained allocation visible');
    $check(isset($rows['wordpriis_resources_throw'], $rows['wordpriis_resources_pro']), 'Rocket and SEOPress Pro targeted');
    $check(!str_contains(json_encode($trace->snapshot()), 'SECRET') && !str_contains(json_encode($trace->snapshot()), $fixture), 'no arguments, exception text, memory contents, absolute paths or dynamic hook names');
    // Files outside target roots are counted but their paths are never exported.
    $before = ['files' => [], 'classes' => 1, 'memory' => 10, 'cpu_ms' => null];
    $files = [$fixture . '/other/SECRET.php'];
    for ($i = 0; $i < 30; $i++) { $files[] = $fixture . '/breakdance/group' . $i . '/file.php'; }
    $delta = WORDPRIIS_Profile_Resources::delta($before, ['files' => $files, 'classes' => 2, 'memory' => 0, 'cpu_ms' => null]);
    $check($delta['new_included_files'] === 31 && $delta['target_included_files'] === 30, 'non-target includes counted only');
    $check(count($delta['target_file_examples']) === 12 && $delta['file_examples_omitted'] === 18, 'file example cap explicit');
    $check(count($delta['target_file_groups']) === 16 && $delta['file_groups_omitted'] === 14, 'directory group cap explicit');
    $check($delta['memory_delta_bytes'] === -10 && $delta['cpu_ms'] === null, 'negative memory and unavailable CPU retained honestly');
    $check(!str_contains(json_encode($delta), 'SECRET') && !str_contains(json_encode($delta), $fixture), 'non-target paths redacted');
    $module = WORDPRIIS_Profile_Resources::delta($before, ['files' => [$fixture . '/wp-rocket/inc/Engine/Cache/item.php'], 'classes' => 1, 'memory' => 10, 'cpu_ms' => null]);
    $check(isset($module['target_file_groups']['plugins/wp-rocket/inc/Engine']), 'module subdirectories retained for actionable loading attribution');
    add_action('shutdown', 'wordpriis_resources_repeat');
    for ($i = 0; $i < 150; $i++) { do_action('shutdown'); }
    $data = $trace->snapshot();
    $check(count($data['target_resources']) <= 48 && $data['resource_coverage']['resource_calls_sampled'] < 20 && $data['resource_coverage']['repeat_calls_skipped'] >= 149, 'repeated cheap callbacks do not exhaust resources');
    $check(in_array('wordpriis_resources_parent', array_column($data['target_resources'], 'callback'), true), 'slow parent retained after many cheap callbacks');
    $check(!$data['resource_coverage']['per_file_duration_available'] && $data['resource_coverage']['inclusive_deltas'], 'attribution limits explicit');
    $check($data['resource_coverage']['measurement_overhead_ms'] >= 0, 'resource collector overhead exposed');
    for ($i = 0; $i < 260; $i++) { apply_filters('plugins_loaded', 'safe'); }
    $check($trace->snapshot()['resource_coverage']['nested_dispatches_without_callbacks'] >= 260 && array_sum($trace->snapshot()['resource_coverage']['nested_scan_count_by_phase']) < 10, 'empty dispatch storms do not consume scan budgets');
    for ($i = 0; $i < 20; $i++) { $trace->pluginLoaded($fixture . '/breakdance/main.php'); }
    $data = $trace->snapshot();
    $check(count($data['target_plugin_load_intervals']) === 16 && $data['resource_coverage']['plugin_load_intervals_dropped'] === 8, 'plugin boundary cap reported');
    $check(!WORDPRIIS_Profile_Resources::target('plugins/breakdance-other/file.php') && !WORDPRIIS_Profile_Resources::target('external'), 'target path boundaries are exact');
    // Reproduce production: many early callbacks plus thousands of repeated nested dispatches.
    remove_all_actions('plugins_loaded'); remove_all_actions('init'); remove_all_actions('wp_loaded'); remove_all_actions('shutdown');
    add_filter('resource_hot_SECRET', 'wordpriis_resources_hot');
    $unique = [];
    for ($i = 0; $i < 80; $i++) {
        $unique[] = wordpriis_resources_factory();
        add_action('resource_unique_SECRET_' . $i, $unique[$i], 10, 0);
        add_action('plugins_loaded', $unique[$i], 20, 0);
    }
    add_action('plugins_loaded', 'wordpriis_resources_storm', 1, 0);
    do_action('plugins_loaded');
    $storm = $trace->snapshot()['resource_coverage'];
    $check($storm['nested_scan_cache_hits'] >= 19999, '20k repeated registered dispatches scanned once');
    $check(($storm['nested_scan_count_by_phase']['plugins_loaded'] ?? 0) === 32 && $storm['nested_dispatches_skipped'] > 0, 'early distinct scans bounded per phase');
    $check($storm['budget_skips_by_bucket']['primary'] > 0 && $storm['budget_skips_by_bucket']['nested'] > 0, 'early sampling budgets demonstrably saturated');
    file_put_contents($fixture . '/breakdance/includes/late.php', '<?php class WORDPRIIS_Late_Fields {}');
    file_put_contents($fixture . '/breakdance/dynamic.php', "<?php namespace Breakdance\\DynamicData; function include_fields() { require_once __DIR__ . '/includes/late.php'; usleep(2000); }");
    require $fixture . '/breakdance/dynamic.php';
    // Saturate the ordinary wp_loaded plugin quota first; named dynamic fields have reserved capacity.
    for ($i = 0; $i < 8; $i++) { $unique[] = wordpriis_resources_factory(); add_action('wp_loaded', $unique[count($unique) - 1], 1, 0); }
    add_action('wp_loaded', 'Breakdance\\DynamicData\\include_fields', 10, 0);
    add_action('wp_loaded', 'wordpriis_resources_late_parent', 11, 0);
    add_action('resource_late_SECRET', 'wordpriis_resources_hot', 10, 0);
    do_action('wp_loaded');
    $data = $trace->snapshot();
    $late = array_values(array_filter($data['target_resources'], static fn($r) => $r['callback'] === 'Breakdance\\DynamicData\\include_fields'));
    $check(count($late) === 1 && $late[0]['sampling_bucket'] === 'priority', 'dynamic fields retained after early storms and own-phase quota saturation');
    $check($late[0]['new_included_files'] === 1 && $late[0]['declared_classes_delta'] === 1 && $late[0]['elapsed_ms'] >= 1, 'late dynamic-field include and initialization measured');
    $check(($data['resource_coverage']['nested_scan_count_by_phase']['wp_loaded'] ?? 0) >= 1, 'later phase retains distinct-hook scan capacity');
    $check(count($data['target_resources']) <= 48 && $data['resource_coverage']['resource_calls_sampled'] <= 104, 'partitioned budgets preserve original size bounds with fewer snapshots');
    $check(!str_contains(json_encode($data), 'SECRET') && !str_contains(json_encode($data), $fixture), 'sampling/cache diagnostics do not expose hook names or values');
    $check($data['resource_coverage']['sampling_policy'] === 'phase-plugin-first-invocation', 'policy is identifiable in report');
    $previousScans = $data['resource_coverage']['nested_scan_count_by_phase']['wp_loaded'];
    add_action('resource_late_SECRET', 'wordpriis_resources_mutation', 20, 0);
    do_action('wp_loaded');
    $data = $trace->snapshot();
    $check($GLOBALS['resource_mutations'] === 1 && $data['resource_coverage']['nested_scan_count_by_phase']['wp_loaded'] === $previousScans + 1, 'callback-count change invalidates the nested scan cache');
    $check(remove_action('resource_late_SECRET', 'wordpriis_resources_mutation', 20), 'new cached-hook callback retains its original removal identity');
    do_action('wp_loaded');
    $check($GLOBALS['resource_mutations'] === 1, 'removed callback stays removed after cached rescan');
    for ($i = 0; $i < 200; $i++) { $unique[] = wordpriis_resources_effect_factory(); add_action('resource_late_SECRET', $unique[count($unique) - 1], 30, 0); }
    do_action('wp_loaded');
    $data = $trace->snapshot();
    $check($GLOBALS['resource_effects'] === 200 && ($data['callback_coverage']['nested_wrapper_limit_skipped'] ?? 0) > 0, 'nested wrapper reservation never suppresses unwrapped callbacks');
    $check($data['callback_coverage']['wrapped_registrations'] <= 512 && count($data['target_resources']) <= 48, 'wrapper and output limits hold under a callback-registration storm');


} finally {
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($fixture, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $item) { if ($item->isDir()) { rmdir($item->getPathname()); } else { unlink($item->getPathname()); } }
    rmdir($fixture);
}
echo "Bootstrap resources: $n assertions passed.\n";
