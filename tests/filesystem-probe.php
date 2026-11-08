<?php
if (PHP_SAPI !== 'cli') { exit(1); }
$root = sys_get_temp_dir() . '/wordpriis-fs-' . bin2hex(random_bytes(8));
mkdir($root); mkdir($root . '/plugins'); mkdir($root . '/plugins/breakdance');
define('ABSPATH', $root . '/'); define('WP_PLUGIN_DIR', $root . '/plugins');
require __DIR__ . '/../scripts/wordpriis-bootstrap-profile.php';
$n = 0;
$check = static function ($ok, $label) use (&$n) { if (!$ok) { throw new RuntimeException($label); } $n++; };
try {
    $files = [];
    for ($i = 0; $i < 10; $i++) { $file = $root . '/plugins/breakdance/file' . $i . '.php'; file_put_contents($file, '<?php /* no execution */'); $files[] = $file; }
    $files[] = 'https://SECRET.invalid/credentials'; $files[] = '\\\\SECRET\\share\\password';
    $r = wordpriis_filesystem_probe($files);
    $check($r['groups']['breakdance'] === 4, 'four files per group cap');
    $check(count($r['operations']) === 3 && !$r['budget_exhausted'], 'three metadata operations');
    foreach ($r['operations'] as $op) { $check($op['calls'] === 12 && $op['successful'] === 12 && $op['elapsed_ms'] >= 0, 'bounded successful metadata measurement'); }
    $check(!str_contains(json_encode($r), 'SECRET') && !str_contains(json_encode($r), $root), 'no file paths, URL or share credentials');
    $check($r['sapi'] === 'cli' && $r['php_version'] === PHP_VERSION && is_bool($r['thread_safe']), 'effective execution context is explicit');
    $check(wordpriis_filesystem_probe($files, 0)['budget_exhausted'], 'time budget honored before metadata calls');
    $check(wordpriis_filesystem_probe([])['operations'][0]['calls'] === 0, 'empty group has no fabricated timing work');
    $check(count(glob($root . '/plugins/breakdance/*')) === 10, 'probe does not modify files');
} finally { foreach (glob($root . '/plugins/breakdance/*') as $file) { unlink($file); } rmdir($root . '/plugins/breakdance'); rmdir($root . '/plugins'); rmdir($root); }
echo "Filesystem probe: $n assertions passed.\n";
