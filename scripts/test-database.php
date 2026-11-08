<?php
/** Private CLI-only empty-database preflight. No SQL/error/configuration values are printed. */
if (PHP_SAPI !== 'cli' || $argc !== 2) { exit(2); }
try {
    $data = json_decode(file_get_contents($argv[1]), true, 32, JSON_THROW_ON_ERROR);
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = mysqli_init();
    $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
    $db->real_connect($data['host'], $data['user'], $data['password'], $data['database']);
    $count = (int) $db->query('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()')->fetch_row()[0];
    if ($count !== 0) { exit(3); }
    echo "WORDPRIIS_DB_OK\n";
} catch (Throwable $error) { exit(1); }
