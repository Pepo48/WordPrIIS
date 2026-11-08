<?php
/** Temporary MU diagnostic. Not part of the distributed plugin. See docs/bootstrap-profile.md. */
if (!defined('ABSPATH')) { return; }

function wordpriis_profile_allowed(array $server, array $get, array $post, array $config): bool {
    $now = time();
    return ($server['REQUEST_METHOD'] ?? '') === 'GET'
        && preg_match('~/wp-admin/admin-ajax\.php$~D', $server['SCRIPT_NAME'] ?? '') === 1
        && $get === [] && $post === []
        && empty($server['HTTP_COOKIE']) && empty($server['HTTP_AUTHORIZATION'])
        && is_int($config['expires'] ?? null) && $config['expires'] > $now && $config['expires'] <= $now + 1800
        && is_string($config['hash'] ?? null) && preg_match('/^[a-f0-9]{64}$/D', $config['hash']) === 1
        && is_string($server['HTTP_X_WORDPRIIS_PROFILE'] ?? null) && strlen($server['HTTP_X_WORDPRIIS_PROFILE']) === 64
        && hash_equals($config['hash'], hash('sha256', $server['HTTP_X_WORDPRIIS_PROFILE']));
}

function wordpriis_profile_private_file(string $file, array $roots): bool {
    $resolved = realpath($file);
    if ($resolved === false || !is_file($resolved) || !is_writable($resolved) || is_link($file)) { return false; }
    foreach ($roots as $root) {
        $root = realpath($root);
        if ($root === false) { return false; }
        $prefix = strtolower(rtrim(str_replace('\\', '/', $root), '/') . '/');
        if (str_starts_with(strtolower(str_replace('\\', '/', $resolved)), $prefix)) { return false; }
    }
    return true;
}

function wordpriis_profile_append(string $file, array $record): void {
    // The owner precreates the private file with its final ACL; never create a web-accessible log.
    $handle = @fopen($file, 'r+b');
    if (!$handle) { return; }
    try {
        if (!@flock($handle, LOCK_EX)) { return; }
        $line = json_encode($record, JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
        $size = @fstat($handle)['size'] ?? 2097152;
        if ($size + strlen($line) <= 2097152) { @fseek($handle, 0, SEEK_END); @fwrite($handle, $line); }
        flock($handle, LOCK_UN);
    } finally { fclose($handle); }
}

/** Bounded request-local resource deltas. No directory scans, file reads or autoloader changes. */
final class WORDPRIIS_Profile_Resources {
    public const TARGETS = ['breakdance', 'wp-rocket', 'wp-seopress', 'wp-seopress-pro'];
    public static function target(string $source): bool {
        foreach (self::TARGETS as $slug) { if (str_starts_with($source, 'plugins/' . $slug . '/')) { return true; } }
        return false;
    }
    public static function capture(): array {
        $usage = function_exists('getrusage') ? getrusage() : false;
        $cpu = null;
        if (is_array($usage) && isset($usage['ru_utime.tv_sec'], $usage['ru_utime.tv_usec'], $usage['ru_stime.tv_sec'], $usage['ru_stime.tv_usec'])) {
            $cpu = ($usage['ru_utime.tv_sec'] + $usage['ru_stime.tv_sec']) * 1000 + ($usage['ru_utime.tv_usec'] + $usage['ru_stime.tv_usec']) / 1000;
        }
        return ['files' => get_included_files(), 'classes' => count(get_declared_classes()), 'memory' => memory_get_usage(false), 'cpu_ms' => $cpu];
    }
    public static function delta(array $before, array $after): array {
        // get_included_files reports distinct successful includes, not filesystem probes or repeated require calls.
        $files = array_values(array_diff($after['files'], $before['files']));
        $groups = []; $examples = []; $targetCount = 0;
        foreach ($files as $file) {
            $source = WORDPRIIS_Bootstrap_Trace::source($file);
            if (!self::target($source)) { continue; }
            $targetCount++;
            $parts = explode('/', $source);
            // Group by plugin plus up to two directories to expose module loading, never absolute paths.
            $group = implode('/', array_slice($parts, 0, min(4, count($parts) - 1)));
            $groups[$group] = ($groups[$group] ?? 0) + 1;
            if (count($examples) < 12) { $examples[] = $source; }
        }
        arsort($groups); $omitted = max(0, count($groups) - 16);
        return ['new_included_files' => count($files), 'target_included_files' => $targetCount,
            'target_file_groups' => array_slice($groups, 0, 16, true), 'file_groups_omitted' => $omitted,
            'target_file_examples' => $examples, 'file_examples_omitted' => max(0, $targetCount - count($examples)),
            'declared_classes_delta' => max(0, $after['classes'] - $before['classes']),
            'memory_delta_bytes' => $after['memory'] - $before['memory'],
            'cpu_ms' => $before['cpu_ms'] === null || $after['cpu_ms'] === null ? null : round(max(0, $after['cpu_ms'] - $before['cpu_ms']), 3)];
    }
}

/** Request-local instrumentation; installed only after the existing token/route gate. */
final class WORDPRIIS_Bootstrap_Trace {
    private const HOOKS = ['plugins_loaded', 'init', 'wp_loaded', 'shutdown'];
    private $elapsed;
    private array $wrapped = [];
    private array $rows = [];
    private array $stack = [];
    private array $pending = [];
    private array $http = [];
    private array $coverage = ['reference_callbacks_skipped' => 0, 'reflection_skipped' => 0, 'callback_limit_skipped' => 0, 'depth_limit_skipped' => 0, 'http_rows_dropped' => 0, 'http_pending_limit_skipped' => 0];
    private int $httpCount = 0;
    private float $httpMs = 0;
    private int $unpaired = 0;
    private array $resourcePartitions = [];
    private array $resourceSeen = [];
    private array $resourceBudgets = [];
    private array $resourceBucketSamples = ['primary' => 0, 'nested' => 0, 'priority' => 0];
    private array $resourceBudgetSkips = ['primary' => 0, 'nested' => 0, 'priority' => 0];
    private int $resourceRepeats = 0;
    private WeakMap $nestedCache;
    private array $nestedScans = [];
    private int $nestedCacheHits = 0;
    private int $nestedEmpty = 0;
    private int $nestedWrappers = 0;
    private array $loadIntervals = [];
    private int $loadIntervalsDropped = 0;
    private array $lastLoad;
    private float $lastLoadMs;
    private float $resourceOverheadMs = 0;
    private int $resourceDropped = 0;
    private int $resourceSamples = 0;
    private int $nestedDispatches = 0;
    private int $nestedSkipped = 0;

    public function __construct(callable $elapsed) {
        $this->elapsed = $elapsed; $this->nestedCache = new WeakMap();
        $this->lastLoad = WORDPRIIS_Profile_Resources::capture(); $this->lastLoadMs = ($this->elapsed)();
    }
    public function pluginLoaded(string $path): void {
        $start = hrtime(true); $now = ($this->elapsed)(); $current = WORDPRIIS_Profile_Resources::capture();
        $source = self::source($path);
        if (WORDPRIIS_Profile_Resources::target($source) && count($this->loadIntervals) < 16) {
            $this->loadIntervals[] = ['ending_at' => $source, 'elapsed_ms' => round(max(0, $now - $this->lastLoadMs), 3)]
                + WORDPRIIS_Profile_Resources::delta($this->lastLoad, $current);
        }
        elseif (WORDPRIIS_Profile_Resources::target($source)) { $this->loadIntervalsDropped++; }
        $this->lastLoad = $current; $this->lastLoadMs = ($this->elapsed)();
        $this->resourceOverheadMs += (hrtime(true) - $start) / 1e6;
    }
    public function install(): void {
        // 'all' runs before the target WP_Hook starts iterating its callbacks.
        add_action('all', function ($hook): void { $this->observeHook((string) $hook); }, PHP_INT_MIN, 1);
        add_filter('pre_http_request', [$this, 'httpStart'], PHP_INT_MAX, 3);
        add_action('http_api_debug', [$this, 'httpEnd'], PHP_INT_MAX, 5);
    }
    private function primaryPhase(): string {
        foreach (array_reverse($this->stack) as $frame) {
            $hook = $this->rows[$frame['key']]['hook'];
            if (in_array($hook, self::HOOKS, true)) { return $hook; }
        }
        return 'plugins_loaded';
    }
    private function observeHook(string $hook): void {
        global $wp_filter;
        if (in_array($hook, self::HOOKS, true)) { $this->instrument($hook); return; }
        if (!$this->stack || !$this->stack[count($this->stack) - 1]['target']) { return; }
        $this->nestedDispatches++;
        if (!isset($wp_filter[$hook]) || !$wp_filter[$hook] instanceof WP_Hook) { $this->nestedEmpty++; return; }
        $object = $wp_filter[$hook];
        $count = 0;
        foreach ($object->callbacks as $callbacks) { $count += count($callbacks); }
        if (isset($this->nestedCache[$object]) && $this->nestedCache[$object] === $count) { $this->nestedCacheHits++; return; }
        $phase = $this->primaryPhase();
        if (($this->nestedScans[$phase] ?? 0) >= 32) { $this->nestedSkipped++; return; }
        $this->nestedScans[$phase] = ($this->nestedScans[$phase] ?? 0) + 1;
        $this->nestedCache[$object] = $count;
        $this->instrument($hook, true);
    }
    private function sampleResource(string $key): ?string {
        $row = $this->rows[$key];
        if (!$row['resource_target']) { return null; }
        if (isset($this->resourceSeen[$key])) { $this->resourceRepeats++; return null; }
        // A dedicated pool keeps the known later dynamic-fields callback observable after a storm.
        $priority = $row['callback'] === 'Breakdance\\DynamicData\\include_fields'
            && str_starts_with($row['source'], 'plugins/breakdance/');
        $nested = $row['hook'] === 'target-nested-hook';
        $bucket = $priority ? 'priority' : ($nested ? 'nested' : 'primary');
        $group = $priority ? 'priority' : ($nested ? 'nested:' . $this->primaryPhase() . ':' . $row['resource_plugin'] : $row['hook'] . ':' . $row['resource_plugin']);
        $limit = $priority ? 8 : ($nested ? 2 : 4);
        if (($this->resourceBudgets[$group] ?? 0) >= $limit) { $this->resourceDropped++; $this->resourceBudgetSkips[$bucket]++; return null; }
        $this->resourceSeen[$key] = true;
        $this->resourceBudgets[$group] = ($this->resourceBudgets[$group] ?? 0) + 1;
        $this->resourceBucketSamples[$bucket]++; $this->resourceSamples++;
        return $bucket;
    }
    private function retainResource(array $detail, string $bucket): void {
        // Eight primary rows per lifecycle phase + eight priority + eight nested = at most 48.
        $partition = $bucket === 'primary' ? $detail['hook'] : $bucket;
        $this->resourcePartitions[$partition][] = $detail;
        usort($this->resourcePartitions[$partition], static fn($a, $b) => $b['elapsed_ms'] <=> $a['elapsed_ms']);
        if (count($this->resourcePartitions[$partition]) > 8) { array_pop($this->resourcePartitions[$partition]); $this->resourceDropped++; }
    }
    private static function clean(string $value, int $limit = 160): string {
        return substr(preg_replace('/[^a-zA-Z0-9_\\\\:.\/-]/', '_', $value), 0, $limit);
    }
    public static function source(string $file): string {
        $file = str_replace('\\', '/', $file);
        foreach (['WPMU_PLUGIN_DIR' => 'mu-plugins', 'WP_PLUGIN_DIR' => 'plugins', 'WP_CONTENT_DIR' => 'content', 'ABSPATH' => 'wordpress'] as $constant => $prefix) {
            if (!defined($constant)) { continue; }
            $root = rtrim(str_replace('\\', '/', (string) constant($constant)), '/') . '/';
            if (str_starts_with(strtolower($file), strtolower($root))) { return $prefix . '/' . self::clean(substr($file, strlen($root))); }
        }
        return 'external';
    }
    private static function symbol(string $class, string $function): string {
        if (str_starts_with($function, '{closure')) { $function = 'closure'; }
        if (str_contains($class, '@anonymous') || str_contains($class, "\0")) { $class = 'anonymous-class'; }
        return self::clean(($class !== '' ? $class . '::' : '') . $function);
    }
    private function describe($callback): ?array {
        try {
            if (is_array($callback)) { $ref = new ReflectionMethod($callback[0], $callback[1]); }
            elseif (is_string($callback) && str_contains($callback, '::')) { [$class, $method] = explode('::', $callback, 2); $ref = new ReflectionMethod($class, $method); }
            elseif (is_object($callback) && !$callback instanceof Closure) { $ref = new ReflectionMethod($callback, '__invoke'); }
            else { $ref = new ReflectionFunction($callback); }
            if ($ref->getFileName() === __FILE__) { return null; }
            if ($ref->returnsReference()) { $this->coverage['reference_callbacks_skipped']++; return null; }
            foreach ($ref->getParameters() as $parameter) {
                if ($parameter->isPassedByReference()) { $this->coverage['reference_callbacks_skipped']++; return null; }
            }
            return ['callback' => self::symbol($ref instanceof ReflectionMethod ? $ref->getDeclaringClass()->getName() : '', $ref->isClosure() ? 'closure' : $ref->getName()),
                'source' => $ref->getFileName() ? self::source($ref->getFileName()) : 'internal', 'line' => $ref->getStartLine() ?: null];
        } catch (Throwable $error) { $this->coverage['reflection_skipped']++; return null; }
    }
    public function instrument(string $hook, bool $nested = false): void {
        global $wp_filter;
        if ((!$nested && !in_array($hook, self::HOOKS, true)) || !isset($wp_filter[$hook]) || !$wp_filter[$hook] instanceof WP_Hook) { return; }
        foreach ($wp_filter[$hook]->callbacks as $priority => $callbacks) {
            foreach ($callbacks as $id => $entry) {
                $key = $hook . ':' . $priority . ':' . $id;
                if (isset($this->wrapped[$key]) && $entry['function'] === $this->wrapped[$key]->get()) { continue; }
                if (count($this->wrapped) >= 512 && !isset($this->wrapped[$key])) { $this->coverage['callback_limit_skipped']++; continue; }
                if ($nested && $this->nestedWrappers >= 128 && !isset($this->wrapped[$key])) { $this->coverage['nested_wrapper_limit_skipped'] = ($this->coverage['nested_wrapper_limit_skipped'] ?? 0) + 1; continue; }
                $meta = $this->describe($entry['function']);
                if ($meta === null || ($nested && !WORDPRIIS_Profile_Resources::target($meta['source']))) { continue; }
                if (!isset($this->rows[$key])) {
                    $this->rows[$key] = $meta + ['id' => count($this->rows) + 1, 'hook' => $nested ? 'target-nested-hook' : $hook, 'priority' => (int) $priority,
                        'resource_target' => WORDPRIIS_Profile_Resources::target($meta['source']), 'resource_plugin' => explode('/', $meta['source'])[1] ?? '',
                        'calls' => 0, 'total_ms' => 0.0, 'self_ms' => 0.0, 'max_ms' => 0.0, 'exceptions' => 0, 'query_count' => 0];
                }
                $original = $entry['function'];
                $wrapper = function (...$args) use ($original, $key) {
                    if (count($this->stack) >= 64) { $this->coverage['depth_limit_skipped']++; return $original(...$args); }
                    global $wpdb;
                    $queries = isset($wpdb->num_queries) ? (int) $wpdb->num_queries : 0;
                    $resourceStart = hrtime(true);
                    $resourceBucket = $this->sampleResource($key);
                    $before = $resourceBucket !== null ? WORDPRIIS_Profile_Resources::capture() : null;
                    $this->resourceOverheadMs += (hrtime(true) - $resourceStart) / 1e6;
                    $this->stack[] = ['key' => $key, 'start' => hrtime(true), 'children' => 0.0, 'target' => $this->rows[$key]['resource_target']];
                    $threw = false;
                    try { return $original(...$args); }
                    catch (Throwable $error) { $threw = true; throw $error; }
                    finally {
                        $frame = array_pop($this->stack);
                        $ms = (hrtime(true) - $frame['start']) / 1e6;
                        if ($this->stack) { $this->stack[count($this->stack) - 1]['children'] += $ms; }
                        $row =& $this->rows[$key];
                        $row['calls']++; $row['total_ms'] += $ms; $row['self_ms'] += max(0, $ms - $frame['children']);
                        if ($before !== null) {
                            $resourceStart = hrtime(true);
                            $detail = ['callback_id' => $row['id'], 'callback' => $row['callback'], 'source' => $row['source'], 'hook' => $row['hook'],
                                'elapsed_ms' => round($ms, 3)] + WORDPRIIS_Profile_Resources::delta($before, WORDPRIIS_Profile_Resources::capture());
                            $detail['sampling_bucket'] = $resourceBucket;
                            $this->retainResource($detail, $resourceBucket);
                            $this->resourceOverheadMs += (hrtime(true) - $resourceStart) / 1e6;
                        }
                        $row['max_ms'] = max($row['max_ms'], $ms); $row['exceptions'] += (int) $threw;
                        $row['query_count'] += max(0, (isset($wpdb->num_queries) ? (int) $wpdb->num_queries : 0) - $queries);
                    }
                };
                // Preserve WordPress's original unique ID, priority, insertion order and accepted_args.
                $wp_filter[$hook]->callbacks[$priority][$id]['function'] = $wrapper;
                if ($nested && !isset($this->wrapped[$key])) { $this->nestedWrappers++; }
                $this->wrapped[$key] = WeakReference::create($wrapper);
            }
        }
    }
    private function context(): array {
        global $wp_current_filter;
        $phase = 'other';
        foreach (array_reverse($wp_current_filter ?? []) as $hook) { if (in_array($hook, self::HOOKS, true)) { $phase = $hook; break; } }
        $callback = null; $callbackMeta = null;
        if ($this->stack) {
            $active = $this->rows[$this->stack[count($this->stack) - 1]['key']]; $callback = $active['id'];
            $callbackMeta = array_intersect_key($active, array_flip(['callback', 'source', 'line', 'hook', 'priority']));
        }
        $caller = ['callback' => 'unknown', 'source' => 'unknown', 'line' => null, 'location' => 'unknown'];
        foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 32) as $frame) {
            $function = $frame['function'] ?? ''; $class = $frame['class'] ?? '';
            if ($class === self::class || $class === 'WP_Hook' || str_starts_with($class, 'WP_Http') || str_starts_with($class, 'WpOrg\\Requests\\')
                || in_array($function, ['do_action', 'do_action_ref_array', 'apply_filters', 'apply_filters_ref_array', '_wp_call_all_hook', 'wp_remote_request', 'wp_remote_get', 'wp_remote_post', 'wp_safe_remote_request', 'wp_safe_remote_get', 'wp_safe_remote_post'], true)) { continue; }
            if (($frame['file'] ?? '') === __FILE__) {
                // This can be the application's callable invoked by our wrapper.
                if ($callbackMeta !== null) { $caller = array_intersect_key($callbackMeta, array_flip(['callback', 'source', 'line'])) + ['location' => 'definition']; break; }
                continue;
            }
            $caller = ['callback' => self::symbol($class, $function), 'source' => isset($frame['file']) ? self::source($frame['file']) : 'internal', 'line' => $frame['line'] ?? null, 'location' => 'callsite'];
            break;
        }
        return ['phase' => $phase, 'callback_id' => $callback, 'callback' => $callbackMeta, 'caller' => $caller];
    }
    private static function destination(string $url): string {
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));
        $requestHost = strtolower((string) parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST));
        $same = $host !== '' && ($host === $requestHost || in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true));
        $base = preg_replace('~/wp-admin/admin-ajax\.php$~D', '', $_SERVER['SCRIPT_NAME'] ?? '/wp-admin/admin-ajax.php');
        if ($same && parse_url($url, PHP_URL_PATH) === $base . '/wp-cron.php') { return 'cron-loopback'; }
        if ($same) { return 'same-site-or-loopback'; }
        if ($host === 'api-m.sandbox.paypal.com') { return 'paypal-sandbox'; }
        if ($host === 'api-m.paypal.com') { return 'paypal-live'; }
        if (in_array($host, ['api.wordpress.org', 'downloads.wordpress.org'], true)) { return 'wordpress-service'; }
        return 'external';
    }
    public function httpStart($preempt, $args, $url) {
        $index = null;
        if (count($this->http) < 32) {
            $index = count($this->http);
            $method = strtoupper((string) ($args['method'] ?? 'GET'));
            $this->http[] = $this->context() + ['destination' => self::destination((string) $url), 'method' => in_array($method, ['GET','POST','HEAD','PUT','PATCH','DELETE','OPTIONS'], true) ? $method : 'other',
                'blocking' => (bool) ($args['blocking'] ?? true), 'timeout_seconds' => isset($args['timeout']) && is_numeric($args['timeout']) ? min(300, max(0, (float) $args['timeout'])) : null,
                'started_ms' => ($this->elapsed)(), 'elapsed_ms' => null, 'status_code' => null, 'outcome' => $preempt === false ? 'pending' : 'preempted'];
        } else { $this->coverage['http_rows_dropped']++; }
        if ($preempt === false) {
            if (array_sum(array_map('count', $this->pending)) < 64) {
                $key = hash('sha256', (string) $url); $this->pending[$key][] = ['start' => hrtime(true), 'index' => $index];
            } else { $this->coverage['http_pending_limit_skipped']++; }
        }
        return $preempt;
    }
    public function httpEnd($response, $context, $transport, $args, $url): void {
        if ($context !== 'response') { return; }
        $key = hash('sha256', (string) $url);
        if (empty($this->pending[$key])) { $this->unpaired++; return; }
        $pending = array_pop($this->pending[$key]); if (!$this->pending[$key]) { unset($this->pending[$key]); }
        $ms = (hrtime(true) - $pending['start']) / 1e6; $this->httpCount++; $this->httpMs += $ms;
        if ($pending['index'] !== null) {
            $row =& $this->http[$pending['index']]; $row['elapsed_ms'] = round($ms, 3);
            $row['outcome'] = $response instanceof WP_Error ? 'wp-error' : 'response';
            $status = is_array($response) ? ($response['response']['code'] ?? null) : null;
            if (is_numeric($status) && $status >= 100 && $status <= 599) { $row['status_code'] = (int) $status; }
        }
    }
    public function snapshot(): array {
        $resources = [];
        foreach ($this->resourcePartitions as $partition) { foreach ($partition as $detail) { $resources[] = $detail; } }
        usort($resources, static fn($a, $b) => $b['elapsed_ms'] <=> $a['elapsed_ms']);
        $rows = array_values(array_filter($this->rows, static fn($row) => $row['calls'] > 0));
        usort($rows, static fn($a, $b) => $b['self_ms'] <=> $a['self_ms']);
        $omitted = max(0, count($rows) - 64); $rows = array_slice($rows, 0, 64);
        foreach ($rows as &$row) { unset($row['resource_target'], $row['resource_plugin']); foreach (['total_ms', 'self_ms', 'max_ms'] as $field) { $row[$field] = round($row[$field], 3); } } unset($row);
        $active = [];
        foreach ($this->stack as $frame) { $active[] = ['callback_id' => $this->rows[$frame['key']]['id'], 'elapsed_ms' => round((hrtime(true) - $frame['start']) / 1e6, 3)]; }
        return ['target_resources' => $resources, 'target_plugin_load_intervals' => $this->loadIntervals,
            'resource_coverage' => ['callback_rows_dropped' => $this->resourceDropped, 'resource_calls_sampled' => $this->resourceSamples, 'plugin_load_intervals_dropped' => $this->loadIntervalsDropped, 'nested_dispatches_considered' => $this->nestedDispatches,
                'nested_dispatches_skipped' => $this->nestedSkipped,
                'sampling_policy' => 'phase-plugin-first-invocation', 'samples_by_bucket' => $this->resourceBucketSamples,
                'budget_skips_by_bucket' => $this->resourceBudgetSkips, 'repeat_calls_skipped' => $this->resourceRepeats,
                'nested_scan_count_by_phase' => $this->nestedScans, 'nested_scan_cache_hits' => $this->nestedCacheHits,
                'nested_dispatches_without_callbacks' => $this->nestedEmpty, 'measurement_overhead_ms' => round($this->resourceOverheadMs, 3),
                'inclusive_deltas' => true, 'per_file_duration_available' => false],
            'callback_timings' => $rows, 'callback_coverage' => $this->coverage + ['rows_omitted' => $omitted, 'wrapped_registrations' => count($this->wrapped), 'active_callbacks' => $active, 'dynamic_additions_may_be_unmeasured' => true],
            'http_calls' => $this->http, 'http_completed_count' => $this->httpCount, 'http_observed_ms' => round($this->httpMs, 3), 'http_unpaired_completions' => $this->unpaired, 'http_pending_keys' => count($this->pending)];
    }
}

/** Opt-in metadata calibration on already included local PHP files. No contents, cache flush or code execution. */
function wordpriis_filesystem_probe(?array $files = null, int $budgetMs = 200): array {
    $start = hrtime(true); $selected = []; $counts = [];
    foreach ($files ?? get_included_files() as $file) {
        if (!is_string($file) || str_starts_with($file, '\\\\') || preg_match('~^[a-z]+://~i', $file)) { continue; }
        $source = WORDPRIIS_Bootstrap_Trace::source($file);
        $group = str_starts_with($source, 'wordpress/') ? 'wordpress' : null;
        foreach (WORDPRIIS_Profile_Resources::TARGETS as $slug) { if (str_starts_with($source, 'plugins/' . $slug . '/')) { $group = $slug; break; } }
        if ($group === null || ($counts[$group] ?? 0) >= 4) { continue; }
        $counts[$group] = ($counts[$group] ?? 0) + 1; $selected[] = $file;
    }
    $rows = []; $stopped = false;
    foreach (['is_file', 'is_readable', 'realpath'] as $operation) {
        $opStart = hrtime(true); $calls = 0; $ok = 0;
        for ($round = 0; $round < 3; $round++) {
            foreach ($selected as $file) {
                if ((hrtime(true) - $start) / 1e6 >= $budgetMs) { $stopped = true; break 2; }
                // Deliberately do NOT clear stat/realpath/OPcache; this is the request's warm effective environment.
                $result = @$operation($file); $calls++; $ok += (int) ($result !== false);
            }
        }
        $rows[] = ['operation' => $operation, 'calls' => $calls, 'successful' => $ok, 'elapsed_ms' => round((hrtime(true) - $opStart) / 1e6, 3)];
        if ($stopped) { break; }
    }
    return ['schema_version' => 1, 'scope' => 'Warm metadata operations on up to four already included files per target/core group; no disk-throughput or per-include benchmark',
        'groups' => $counts, 'operations' => $rows, 'budget_ms' => $budgetMs, 'budget_exhausted' => $stopped,
        'elapsed_ms' => round((hrtime(true) - $start) / 1e6, 3), 'php_version' => PHP_VERSION,
        'thread_safe' => (bool) PHP_ZTS, 'integer_bytes' => PHP_INT_SIZE, 'sapi' => PHP_SAPI,
        'open_basedir_enabled' => (bool) ini_get('open_basedir'), 'realpath_cache_used_bytes' => function_exists('realpath_cache_size') ? realpath_cache_size() : null,
        'xdebug_loaded' => extension_loaded('xdebug')];
}

function wordpriis_profile_start(string $file): void {
    $start = hrtime(true);
    $elapsed = static fn() => round((hrtime(true) - $start) / 1e6, 3);
    $pre = isset($_SERVER['REQUEST_TIME_FLOAT']) ? max(0, (microtime(true) - (float) $_SERVER['REQUEST_TIME_FLOAT']) * 1000) : null;
    $marks = [['phase' => 'mu_profiler_loaded', 'since_profiler_ms' => 0.0]];
    $mark = static function (string $phase) use (&$marks, $elapsed): void {
        if (count($marks) < 128) { $marks[] = ['phase' => $phase, 'since_profiler_ms' => $elapsed()]; }
    };
    foreach (['muplugins_loaded', 'plugins_loaded', 'setup_theme', 'after_setup_theme', 'init', 'wp_loaded', 'admin_init'] as $hook) {
        add_action($hook, static function () use ($mark, $hook): void { $mark($hook . ':enter'); }, PHP_INT_MIN);
        add_action($hook, static function () use ($mark, $hook): void { $mark($hook . ':leave'); }, PHP_INT_MAX);
    }
    $trace = new WORDPRIIS_Bootstrap_Trace($elapsed);
    foreach (['mu_plugin_loaded', 'network_plugin_loaded', 'plugin_loaded'] as $hook) {
        add_action($hook, static function ($path) use ($mark, $hook, $trace): void {
            $trace->pluginLoaded((string) $path);
            $path = str_replace('\\', '/', (string) $path);
            $slug = basename(dirname($path)) . '/' . basename($path);
            $mark($hook . ':' . substr(preg_replace('/[^a-zA-Z0-9_.\/-]/', '_', $slug), 0, 120));
        }, PHP_INT_MAX);
    }
    $trace->install();
    register_shutdown_function(static function () use ($file, &$marks, $elapsed, $pre, $trace): void {
        global $wpdb;
        $record = ['schema_version' => 3, 'generated_utc' => gmdate('c'), 'route' => 'no_action_ajax',
            'pre_mu_ms' => $pre === null ? null : round($pre, 3), 'since_profiler_ms' => $elapsed(),
            'status' => http_response_code(), 'phases' => $marks,
            'db_query_count' => isset($wpdb->num_queries) ? (int) $wpdb->num_queries : null,
            'web_sapi' => PHP_SAPI, 'fastcgi_impersonate' => in_array(ini_get('fastcgi.impersonate'), ['0', '1'], true) ? ini_get('fastcgi.impersonate') === '1' : null,
            'peak_memory_bytes' => memory_get_peak_usage(true)] + $trace->snapshot();
        if (function_exists('opcache_get_status')) {
            $cache = @opcache_get_status(false);
            if (is_array($cache)) {
                $record['web_opcache'] = ['enabled' => $cache['opcache_enabled'] ?? null, 'cache_full' => $cache['cache_full'] ?? null,
                    'restart_pending' => $cache['restart_pending'] ?? null,
                    'used_memory' => $cache['memory_usage']['used_memory'] ?? null,
                    'free_memory' => $cache['memory_usage']['free_memory'] ?? null,
                    'hit_rate' => $cache['opcache_statistics']['opcache_hit_rate'] ?? null,
                    'open_basedir_enabled' => (bool) ini_get('open_basedir'),
                    'realpath_cache_used_bytes' => function_exists('realpath_cache_size') ? realpath_cache_size() : null,
                    'validate_timestamps' => (bool) ini_get('opcache.validate_timestamps'),
                    'revalidate_freq_seconds' => (int) ini_get('opcache.revalidate_freq')];
            }
        }
        if (defined('WORDPRIIS_FILESYSTEM_PROBE') && WORDPRIIS_FILESYSTEM_PROBE === true) { $record['filesystem_probe'] = wordpriis_filesystem_probe(); }
        wordpriis_profile_append($file, $record);
    });
}

function wordpriis_profile_prepare(string $file, array $roots): string {
    if (!wordpriis_profile_private_file($file, $roots)) { return 'output-unavailable'; }
    $handle = @fopen($file, 'r+b');
    if (!$handle) { return 'output-open-failed'; }
    try {
        if (!@flock($handle, LOCK_EX | LOCK_NB)) { return 'output-lock-failed'; }
        flock($handle, LOCK_UN);
    } finally { fclose($handle); }
    return 'recording';
}

function wordpriis_profile_maybe_start(): void {
    if (PHP_SAPI !== 'cli' && defined('DOING_AJAX') && DOING_AJAX
        && defined('WORDPRIIS_PROFILE_TOKEN_SHA256') && defined('WORDPRIIS_PROFILE_UNTIL') && defined('WORDPRIIS_PROFILE_FILE') && is_string(WORDPRIIS_PROFILE_FILE)) {
        // Diagnostic response headers are restricted to a valid token in the short
        // collection window; normal requests receive neither headers nor profiles.
        $token = $_SERVER['HTTP_X_WORDPRIIS_PROFILE'] ?? null;
        if (is_string($token) && strlen($token) === 64 && is_string(WORDPRIIS_PROFILE_TOKEN_SHA256)
            && hash_equals(WORDPRIIS_PROFILE_TOKEN_SHA256, hash('sha256', $token))
            && is_int(WORDPRIIS_PROFILE_UNTIL) && WORDPRIIS_PROFILE_UNTIL > time() && WORDPRIIS_PROFILE_UNTIL <= time() + 1800) {
            $status = wordpriis_profile_allowed($_SERVER, $_GET, $_POST, ['hash' => WORDPRIIS_PROFILE_TOKEN_SHA256, 'expires' => WORDPRIIS_PROFILE_UNTIL])
                ? wordpriis_profile_prepare(WORDPRIIS_PROFILE_FILE, [ABSPATH, WP_CONTENT_DIR]) : 'request-gate-rejected';
            if (!headers_sent()) {
                header('X-WORDPRIIS-Profile-Status: ' . $status);
                $impersonation = ini_get('fastcgi.impersonate');
                header('X-WORDPRIIS-Profile-Impersonation: ' . ($impersonation === '1' ? 'enabled' : ($impersonation === '0' ? 'disabled' : 'unknown')));
                header('X-WORDPRIIS-Profile-OpenBasedir: ' . (ini_get('open_basedir') ? 'enabled' : 'disabled'));
                header('Cache-Control: private, no-store');
            }
            if ($status === 'recording') { wordpriis_profile_start(WORDPRIIS_PROFILE_FILE); }
        }
    }
}

wordpriis_profile_maybe_start();
