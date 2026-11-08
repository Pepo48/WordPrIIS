<?php
/** Permanent cron-only lock/completion bridge. Setup prepends WORDPRIIS_CRON_GATE_* constants. */
if (!defined('ABSPATH') || !defined('DOING_CRON') || !DOING_CRON || !defined('WORDPRIIS_CRON_GATE_HASH')) { return; }
function wordpriis_cron_gate_write(string $run, string $phase, string $status, ?string $reason = null): void {
    $data = ['schema_version' => 1, 'run_id' => $run, 'phase' => $phase, 'status' => $status, 'reason' => $reason, 'generated_utc' => gmdate('c')];
    // Per-run receipt prevents a later busy run from hiding the previous job's completion.
    foreach ([WORDPRIIS_CRON_GATE_RUNS . '/' . $run . '.json', WORDPRIIS_CRON_GATE_RESULT] as $path) {
        $handle = @fopen($path, 'c+b'); if (!$handle) { continue; }
        try {
            if (!flock($handle, LOCK_EX)) { continue; }
            ftruncate($handle, 0); rewind($handle); fwrite($handle, json_encode($data, JSON_THROW_ON_ERROR)); fflush($handle); flock($handle, LOCK_UN);
        } finally { fclose($handle); }
    }
}
function wordpriis_cron_gate_install(): void {
    $run = $_GET['wordpriis_cron_run'] ?? ''; $phase = $_GET['wordpriis_cron_phase'] ?? ''; $token = $_SERVER['HTTP_X_WORDPRIIS_PROFILE'] ?? '';
    $auth = is_string($run) && preg_match('/^[a-f0-9]{32}$/D', $run) && in_array($phase, ['normal','before','after','cleanup','rollback'], true)
        && is_string($token) && strlen($token) === 64 && hash_equals(WORDPRIIS_CRON_GATE_HASH, hash('sha256', $token));
    $lock = @fopen(WORDPRIIS_CRON_GATE_LOCK, 'r+b');
    if (!$lock) {
        if ($auth) { wordpriis_cron_gate_write($run, $phase, 'failed', 'lock-open-failed'); exit; }
        return; // Preserve legacy availability for unverified callers if the bridge is broken.
    }
    if (!flock($lock, LOCK_EX | LOCK_NB)) {
        fclose($lock); if ($auth) { wordpriis_cron_gate_write($run, $phase, 'busy'); } exit;
    }
    register_shutdown_function(static function () use ($lock, $auth, $run, $phase): void {
        try {
            if ($auth) {
                $last = error_get_last();
                $fatal = $last && in_array($last['type'], [E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR,E_USER_ERROR,E_RECOVERABLE_ERROR], true);
                wordpriis_cron_gate_write($run, $phase, $fatal ? 'failed' : 'complete', $fatal ? 'php-fatal' : null);
            }
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    });
}
wordpriis_cron_gate_install();
