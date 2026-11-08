<?php
/** CLI-only, no WordPress bootstrap; literal config parsing and optional read-only SQL. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
ini_set('display_errors', '0');
ini_set('log_errors', '0');

function wordpriis_audit_literals(string $source): array {
    $tokens = token_get_all($source);
    $tokens = array_values(array_filter($tokens, static fn($t) => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)));
    $literal = static function ($token) {
        if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING) {
            $text = $token[1]; $value = substr($text, 1, -1);
            // Accept literal values only. Never evaluate PHP or interpolate variables.
            if ($text[0] === "'") { return str_replace(["\\'", '\\\\'], ["'", '\\'], $value); }
            if (str_contains($value, '$') || preg_match('/\\\\(?![\\\\"nrtvef$])/', $value)) { return null; }
            return stripcslashes($value);
        }
        if (is_array($token) && $token[0] === T_STRING && in_array(strtolower($token[1]), ['true', 'false'], true)) { return strtolower($token[1]) === 'true'; }
        return null;
    };
    $values = [];
    for ($i = 0; $i < count($tokens); $i++) {
        if (is_array($tokens[$i]) && $tokens[$i][0] === T_STRING && strtolower($tokens[$i][1]) === 'define' && ($tokens[$i + 1] ?? null) === '(' && ($tokens[$i + 3] ?? null) === ',') {
            $key = $literal(($tokens[$i + 2] ?? null)); $value = $literal(($tokens[$i + 4] ?? null));
            if (is_string($key) && $value !== null && ($tokens[$i + 5] ?? null) === ')') { $values[$key] = $value; }
        }
        if (is_array($tokens[$i]) && $tokens[$i][0] === T_VARIABLE && $tokens[$i][1] === '$table_prefix' && ($tokens[$i + 1] ?? null) === '=' && ($tokens[$i + 3] ?? null) === ';') {
            $values['table_prefix'] = $literal(($tokens[$i + 2] ?? null));
        }
    }
    return $values;
}

function wordpriis_audit_database(array $config): array {
    foreach (['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'table_prefix'] as $key) {
        if (!isset($config[$key]) || !is_string($config[$key])) { return ['status' => 'skipped', 'reason' => 'Database settings are not simple literal defines; no config code was executed.']; }
    }
    if (!extension_loaded('mysqli') || !preg_match('/^[a-zA-Z0-9_]+$/D', $config['table_prefix'])) { return ['status' => 'skipped', 'reason' => 'mysqli unavailable or unsupported table prefix.']; }
    mysqli_report(MYSQLI_REPORT_OFF);
    $db = mysqli_init();
    $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
    if (defined('MYSQLI_OPT_READ_TIMEOUT')) { $db->options(MYSQLI_OPT_READ_TIMEOUT, 10); }
    $host = $config['DB_HOST']; $port = 3306; $socket = null;
    if (preg_match('/^\[([^]]+)\](?::(\d+))?$/D', $host, $m)) { $host = $m[1]; $port = isset($m[2]) ? (int)$m[2] : 3306; }
    elseif (substr_count($host, ':') === 1) { [$host, $suffix] = explode(':', $host, 2); if (ctype_digit($suffix)) { $port = (int)$suffix; } else { $socket = $suffix; } }
    // Remote DB TLS/SSL configuration must be supplied explicitly by the operator.
    // Do not silently make a new plaintext connection to a remote database.
    if (!in_array(strtolower($host), ['localhost', '127.0.0.1', '::1'], true)) { return ['status' => 'skipped', 'reason' => 'Remote database: use an approved TLS-aware DB diagnostic; no new connection attempted.']; }
    $target_kind = strtolower($host) === 'localhost' ? 'loopback_hostname' : ($host === '::1' ? 'loopback_ipv6' : 'loopback_ipv4');
    $connect_start = hrtime(true);
    $connected = @$db->real_connect($host, $config['DB_USER'], $config['DB_PASSWORD'], $config['DB_NAME'], $port, $socket);
    $connect_ms = round((hrtime(true) - $connect_start) / 1e6, 3);
    if (!$connected) { $db->close(); return ['status' => 'unavailable', 'connect_ms' => $connect_ms, 'connection_target_kind' => $target_kind, 'reason' => 'Database connection failed; credentials and server error omitted.']; }
    $diagnostic_start = hrtime(true);
    $prefix = $config['table_prefix'];
    $query = static function (string $sql) use ($db): array {
        $result = $db->query($sql);
        if (!$result instanceof mysqli_result) { throw new RuntimeException('Read-only query failed.'); }
        $rows = $result->fetch_all(MYSQLI_ASSOC); $result->free(); return $rows;
    };
    try {
        if (!$db->query('SET SESSION TRANSACTION READ ONLY') || !$db->query('START TRANSACTION READ ONLY')) { throw new RuntimeException('Read-only transaction unsupported.'); }
        $start = hrtime(true); $query('SELECT 1'); $ping = (hrtime(true) - $start) / 1e6;
        $autoload = $query("SELECT COUNT(*) AS option_count, COALESCE(SUM(OCTET_LENGTH(option_value)),0) AS bytes FROM `{$prefix}options` WHERE autoload IN ('yes','on','auto-on','auto')")[0];
        $top = $query("SELECT OCTET_LENGTH(option_value) AS bytes FROM `{$prefix}options` WHERE autoload IN ('yes','on','auto-on','auto') ORDER BY OCTET_LENGTH(option_value) DESC LIMIT 10");
        $sizes = $query("SELECT ENGINE AS engine, COUNT(*) AS table_count, COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) AS bytes FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() GROUP BY ENGINE");
        $variables = $query("SHOW VARIABLES WHERE Variable_name IN ('version','innodb_buffer_pool_size','max_connections','slow_query_log','long_query_time')");
        $status = $query("SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Threads_running','Slow_queries','Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests','Uptime')");
        $server_identity = [];
        foreach ($query("SHOW VARIABLES WHERE Variable_name IN ('server_uuid','server_id','hostname','port')") as $row) { $server_identity[$row['Variable_name']] = $row['Value']; }
        ksort($server_identity);
        $session_identity = $query('SELECT DATABASE() AS database_name, CURRENT_USER() AS authenticated_principal')[0];
        // Compare identities without exporting hostnames, database or account names.
        $identity_hash = hash('sha256', json_encode([$server_identity, $session_identity], JSON_THROW_ON_ERROR));
        // Option values and SQL text are never included in the result.
        return ['status' => 'ok', 'connection_identity_sha256' => $identity_hash, 'connect_ms' => $connect_ms, 'connection_target_kind' => $target_kind, 'diagnostic_queries_ms' => round((hrtime(true) - $diagnostic_start) / 1e6, 3), 'select1_ms' => round($ping, 3), 'autoload' => $autoload, 'largest_autoload_bytes' => array_column($top, 'bytes'), 'table_engines' => $sizes, 'variables' => $variables, 'counters_since_db_start' => $status];
    } catch (Throwable $error) { return ['status' => 'unavailable', 'connect_ms' => $connect_ms, 'connection_target_kind' => $target_kind, 'diagnostic_queries_ms' => round((hrtime(true) - $diagnostic_start) / 1e6, 3), 'reason' => 'Read-only diagnostics incomplete; SQL errors and credentials omitted.']; }
    finally { $db->rollback(); $db->close(); }
}

function wordpriis_audit_ipv4_comparison(array $config, array $baseline): array {
    if (!is_string($config['DB_HOST'] ?? null) || !preg_match('/^localhost(?::[0-9]+)?$/iD', $config['DB_HOST'])) {
        return ['status' => 'skipped', 'reason' => 'Comparison only applies to a localhost TCP-style setting; socket paths, remote hosts and existing IP settings are not changed.'];
    }
    $candidate = $config;
    $candidate['DB_HOST'] = preg_replace('/^localhost/i', '127.0.0.1', $config['DB_HOST']);
    $result = wordpriis_audit_database($candidate);
    $identity_ok = isset($baseline['connection_identity_sha256'], $result['connection_identity_sha256']) && hash_equals($baseline['connection_identity_sha256'], $result['connection_identity_sha256']);
    return ['status' => $result['status'], 'scope' => 'Temporary diagnostic connection only; wp-config.php was not modified.', 'same_instance_database_principal' => $identity_ok, 'ipv4' => $result];
}

function wordpriis_audit_main(array $args): array {
    $root = $args['root'] ?? '';
    $result = ['scope' => 'CLI only; no WordPress/plugin bootstrap; FastCGI effective settings and OPcache usage are unverified. The wrapper enables register_argc_argv for this child process only.', 'php' => ['version' => PHP_VERSION, 'sapi' => PHP_SAPI, 'ini_loaded' => php_ini_loaded_file() ?: null, 'xdebug' => extension_loaded('xdebug'), 'opcache_loaded' => extension_loaded('Zend OPcache')], 'database' => ['status' => 'skipped', 'reason' => 'Use --database for bounded read-only SQL.']];
    foreach (['variables_order','register_argc_argv','memory_limit','max_execution_time','realpath_cache_size','realpath_cache_ttl','display_errors','expose_php','allow_url_include','session.cookie_secure','session.cookie_httponly','session.cookie_samesite','opcache.enable','opcache.enable_cli','opcache.memory_consumption','opcache.interned_strings_buffer','opcache.max_accelerated_files','opcache.validate_timestamps','opcache.revalidate_freq','opcache.file_cache_only'] as $key) { $result['php']['settings'][$key] = ini_get($key); }
    if (!is_dir($root)) { $result['wordpress'] = ['status' => 'skipped', 'reason' => 'WordPress root unavailable.']; return $result; }
    $config_file = $root . '/wp-config.php';
    if (!is_file($config_file)) { $config_file = dirname($root) . '/wp-config.php'; }
    $config = is_file($config_file) ? wordpriis_audit_literals(file_get_contents($config_file)) : [];
    $result['wordpress'] = ['status' => 'inspected_without_bootstrap', 'config_found' => is_file($config_file), 'object_cache_dropin' => is_file($root . '/wp-content/object-cache.php'), 'page_cache_dropin' => is_file($root . '/wp-content/advanced-cache.php')];
    foreach (['WP_DEBUG','WP_DEBUG_DISPLAY','WP_DEBUG_LOG','DISALLOW_FILE_EDIT','DISALLOW_FILE_MODS','FORCE_SSL_ADMIN','WP_CACHE','DISABLE_WP_CRON'] as $key) {
        $result['wordpress']['literal_flags'][$key] = isset($config[$key]) ? (is_bool($config[$key]) ? $config[$key] : 'non-boolean literal') : 'unknown';
    }
    $version = $root . '/wp-includes/version.php';
    if (is_file($version) && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', file_get_contents($version), $match)) { $result['wordpress']['version'] = $match[1]; }
    if (isset($args['database'])) {
        $result['database'] = wordpriis_audit_database($config);
        if (isset($args['compare-loopback-ipv4'])) { $result['database_ipv4_comparison'] = wordpriis_audit_ipv4_comparison($config, $result['database']); }
    }
    return $result;
}
// CLI entry must not depend on $_SERVER, which variables_order may disable.
// Tests/library callers explicitly opt out; HTTP execution already exits above.
if (!defined('WORDPRIIS_AUDIT_LIBRARY_ONLY')) {
    try {
        $options = getopt('', ['root:', 'database', 'compare-loopback-ipv4']);
        $result = is_array($options) && is_string($options['root'] ?? null) && $options['root'] !== '' ? wordpriis_audit_main($options) : ['status' => 'unavailable', 'reason' => 'CLI options unavailable; enable register_argc_argv for this probe process only.'];
    }
    catch (Throwable $error) { $result = ['status' => 'unavailable', 'reason' => 'Audit could not complete; internal diagnostics omitted.']; }
    echo 'WORDPRIIS_AUDIT_JSON:' . json_encode($result, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR) . PHP_EOL;
}
