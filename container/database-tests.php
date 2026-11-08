<?php
if (PHP_SAPI !== 'cli') { exit(2); }
$input = tempnam(sys_get_temp_dir(), 'wordpriis-db-');
chmod($input, 0600);
try {
    $data = ['host' => 'wordpriis-verify-db', 'database' => 'wordpress', 'user' => 'wordpress', 'password' => 'local-verify-only'];
    $run = static function (array $values) use ($input): array {
        file_put_contents($input, json_encode($values));
        $p = proc_open([PHP_BINARY, __DIR__ . '/../scripts/test-database.php', $input], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
        return [proc_close($p), $out, $err];
    };
    $expected = ($argv[1] ?? '') === 'empty' ? 0 : 3;
    [$code, $out, $err] = $run($data);
    if ($code !== $expected || ($code === 0 ? trim($out) !== 'WORDPRIIS_DB_OK' : $out !== '') || $err !== '') { throw new RuntimeException('Database preflight state mismatch'); }
    $data['password'] = 'SYNTHETIC_WRONG_PASSWORD'; [$code, $out, $err] = $run($data);
    if ($code !== 1 || $out !== '' || $err !== '') { throw new RuntimeException('Database failure must not disclose connection details'); }
    echo 'Database preflight ', $argv[1], ": 2 assertions passed.\n";
} finally { unlink($input); }
