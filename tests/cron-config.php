<?php
/** Config planning tests: parsing bytes only; no WordPress bootstrap or side effects. */
define('WORDPRIIS_CRON_CONFIG_LIBRARY_ONLY', true);
require __DIR__ . '/../scripts/cron-config.php';
$n = 0; $check = static function ($ok, $name) use (&$n) { if (!$ok) { throw new RuntimeException($name); } $n++; };
$base = "<?php\r\n// UTF-8: čřž; define('DISABLE_WP_CRON', false);\r\ndefine('DB_PASSWORD', 'SECRET');\r\nrequire_once ABSPATH . 'wp-settings.php';\r\n";
$plan = wordpriis_cron_config_plan($base);
$check($plan['previous_literal'] === null && $plan['changed'], 'missing flag planned before WordPress');
$check(str_contains($plan['source'], "define( 'DISABLE_WP_CRON', true );\r\nrequire_once"), 'CRLF preserved and inserted before bootstrap');
$check(str_contains($plan['source'], "define('DB_PASSWORD', 'SECRET');"), 'other settings bytes preserved');
$check(hash('sha256', $base) === $plan['original_sha256'] && hash('sha256', $plan['source']) === $plan['candidate_sha256'], 'plan fingerprints');
$false = str_replace("require_once", "define('DISABLE_WP_CRON', FALSE);\r\nrequire_once", $base);
$plan = wordpriis_cron_config_plan($false);
$check($plan['previous_literal'] === false && $plan['source'] === str_replace("'DISABLE_WP_CRON', FALSE", "'DISABLE_WP_CRON', true", $false), 'only existing literal value changes');
$true = str_replace('FALSE', 'TRUE', $false); $plan = wordpriis_cron_config_plan($true);
$check(!$plan['changed'] && $plan['source'] === $true, 'already true remains byte-identical');
foreach ([
    "<?php if (true) { define('DISABLE_WP_CRON', false); } require_once ABSPATH . 'wp-settings.php';",
    "<?php if (true) define('DISABLE_WP_CRON', false); require_once ABSPATH . 'wp-settings.php';",
    "<?php define('DISABLE_WP_CRON', getenv('SECRET')); require_once ABSPATH . 'wp-settings.php';",
    "<?php define('DISABLE_WP_CRON', false); define('DISABLE_WP_CRON', true); require_once ABSPATH . 'wp-settings.php';",
    "<?php require_once ABSPATH . 'wp-settings.php'; define('DISABLE_WP_CRON', false);",
    "<?php require 'custom-bootstrap.php';",
    "<?php include 'external-settings.php'; require_once ABSPATH . 'wp-settings.php';",
    "<?php define('DISABLE_' . 'WP_CRON', false); require_once ABSPATH . 'wp-settings.php';",
    "<?php eval('\$code'); require_once ABSPATH . 'wp-settings.php';",
] as $unsupported) {
    $failed = false; try { wordpriis_cron_config_plan($unsupported); } catch (RuntimeException $error) { $failed = true; }
    $check($failed, 'ambiguous/conditional/nonliteral/custom bootstrap refused');
}
// Standard WordPress ends its ABSPATH guard immediately before the settings load.
// The installer's inserted cron define must be parseable on recovery/reinstallation.
$standard = "<?php\r\nif (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }\r\nrequire_once ABSPATH . 'wp-settings.php';\r\n";
$installed = wordpriis_cron_config_plan($standard)['source'];
$check(wordpriis_cron_config_plan($installed)['source'] === $installed, 'installer output after ABSPATH guard can be parsed again');
$enabled = wordpriis_cron_config_plan($installed, false);
$check($enabled['previous_literal'] === true && str_contains($enabled['source'], "define( 'DISABLE_WP_CRON', false );"), 'recovery accepts top-level cron flag after closed guard');
$check(wordpriis_cron_config_plan($enabled['source'])['source'] === $installed, 'recovery and reinstall round trip preserves all other config bytes');
$strict = "<?php declare(strict_types=1);\nrequire_once ABSPATH . 'wp-settings.php';";
$check(str_starts_with(wordpriis_cron_config_plan($strict)['source'], '<?php declare(strict_types=1);'), 'strict_types stays first statement');
$side = "<?php file_put_contents('/tmp/wordpriis-cron-config-MUST-NOT-RUN', 'bad');\nrequire_once ABSPATH . 'wp-settings.php';";
wordpriis_cron_config_plan($side);
$check(!file_exists('/tmp/wordpriis-cron-config-MUST-NOT-RUN'), 'config source never evaluated');
$restored = wordpriis_cron_config_plan($true, false);
$check($restored['changed'] && $restored['source'] === str_replace("'DISABLE_WP_CRON', TRUE", "'DISABLE_WP_CRON', false", $true), 'recovery changes only true literal to false');
$check(!wordpriis_cron_config_plan($false, false)['changed'], 'visitor cron already enabled stays byte-identical');
$check(wordpriis_cron_config_plan($base, false)['source'] === $base, 'missing flag needs no definition for visitor cron');
// Exercise the exact CLI switch used by PowerShell, including lintable candidate output.
$cliSource = tempnam(sys_get_temp_dir(), 'cron-source-');
$cliCandidate = $cliSource . '.candidate';
try {
    file_put_contents($cliSource, $true);
    $process = proc_open([PHP_BINARY, __DIR__ . '/../scripts/cron-config.php', '--config=' . $cliSource, '--candidate=' . $cliCandidate, '--enable-request-cron'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
    $check(proc_close($process) === 0 && $stderr === '', 'recovery CLI succeeds without diagnostics leaking config');
    $check(str_contains(file_get_contents($cliCandidate), "'DISABLE_WP_CRON', false"), 'CLI flag enables visitor cron');
    $check(!str_contains($stdout, 'SECRET') && str_starts_with($stdout, 'WORDPRIIS_CRON_PLAN:'), 'CLI returns plan metadata only');
    $process = proc_open([PHP_BINARY, __DIR__ . '/../scripts/cron-config.php', '--config=' . $cliSource, '--diagnose'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $diagnostic = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
    $check(proc_close($process) === 0 && $stderr === '' && str_contains($diagnostic, '"status":"supported"'), 'read-only diagnostic accepts supported config without candidate');
    $check(!str_contains($diagnostic, 'SECRET') && !str_contains($diagnostic, 'sha256') && !str_contains($diagnostic, $cliSource), 'diagnostic omits config contents hashes and paths');
    file_put_contents($cliSource, "<?php define('DISABLE_WP_CRON', getenv('PRIVATE_VALUE')); require_once ABSPATH . 'wp-settings.php';");
    $process = proc_open([PHP_BINARY, __DIR__ . '/../scripts/cron-config.php', '--config=' . $cliSource, '--diagnose'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $diagnostic = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
    $check(proc_close($process) === 1 && $stderr === '' && str_contains($diagnostic, 'complex-cron-define') && !str_contains($diagnostic, 'PRIVATE_VALUE'), 'unsupported diagnostic returns fixed reason without secret expression');
} finally { unlink($cliSource); if (file_exists($cliCandidate)) { unlink($cliCandidate); } }
echo "Cron config: {$n} assertions passed.\n";
