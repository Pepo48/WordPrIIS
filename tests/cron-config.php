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
$strict = "<?php declare(strict_types=1);\nrequire_once ABSPATH . 'wp-settings.php';";
$check(str_starts_with(wordpriis_cron_config_plan($strict)['source'], '<?php declare(strict_types=1);'), 'strict_types stays first statement');
$side = "<?php file_put_contents('/tmp/wordpriis-cron-config-MUST-NOT-RUN', 'bad');\nrequire_once ABSPATH . 'wp-settings.php';";
wordpriis_cron_config_plan($side);
$check(!file_exists('/tmp/wordpriis-cron-config-MUST-NOT-RUN'), 'config source never evaluated');
echo "Cron config: {$n} assertions passed.\n";
