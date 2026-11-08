<?php
/** Temporary MU canary. The setup script prepends the four WORDPRIIS_CRON_* constants. */
if (!defined('ABSPATH') || !defined('WORDPRIIS_CRON_TOKEN_SHA256')) { return; }
function wordpriis_cron_canary_context(array $server, array $query): ?array {
    if (!defined('DOING_CRON') || !DOING_CRON || ($server['REQUEST_METHOD'] ?? '') !== 'GET'
        || !empty($server['HTTP_COOKIE']) || !empty($server['HTTP_AUTHORIZATION'])
        || !is_int(WORDPRIIS_CRON_UNTIL) || time() >= WORDPRIIS_CRON_UNTIL
        || !is_string($server['HTTP_X_WORDPRIIS_PROFILE'] ?? null) || strlen($server['HTTP_X_WORDPRIIS_PROFILE']) !== 64
        || !hash_equals(WORDPRIIS_CRON_TOKEN_SHA256, hash('sha256', $server['HTTP_X_WORDPRIIS_PROFILE']))) { return null; }
    $run = $query['wordpriis_cron_run'] ?? ''; $phase = $query['wordpriis_cron_phase'] ?? '';
    if (!is_string($run) || !preg_match('/^[a-f0-9]{32}$/D', $run) || !in_array($phase, ['before','after','cleanup','rollback'], true)) { return null; }
    return ['run_id' => $run, 'phase' => $phase];
}
function wordpriis_cron_canary_write(array $context, bool $cleared): void {
    $record = $context + ['schema_version' => 1, 'generated_utc' => gmdate('c'), 'doing_cron' => defined('DOING_CRON') && DOING_CRON,
        'disable_wp_cron' => defined('DISABLE_WP_CRON') && DISABLE_WP_CRON === true, 'probe_events_cleared' => $cleared];
    $handle = @fopen(WORDPRIIS_CRON_PROOF_FILE, 'r+b');
    if (!$handle) { return; }
    try {
        if (!flock($handle, LOCK_EX)) { return; }
        $json = json_encode($record, JSON_THROW_ON_ERROR); ftruncate($handle, 0); rewind($handle); fwrite($handle, $json); fflush($handle); flock($handle, LOCK_UN);
    } finally { fclose($handle); }
}
function wordpriis_cron_canary_install(): void {
    $context = wordpriis_cron_canary_context($_SERVER, $_GET);
    if ($context === null) { return; }
    add_action(WORDPRIIS_CRON_HOOK, static function ($run, $phase) use ($context): void {
        if ($run === $context['run_id'] && $phase === $context['phase']) {
            wordpriis_cron_canary_write($context, wp_next_scheduled(WORDPRIIS_CRON_HOOK, [$run, $phase]) === false);
        }
    }, 10, 2);
    add_action('wp_loaded', static function () use ($context): void {
        // Remove only this installation's random synthetic hook, never real site jobs.
        $cleared = wp_unschedule_hook(WORDPRIIS_CRON_HOOK, true);
        if (is_wp_error($cleared)) { return; }
        if ($context['phase'] === 'cleanup') { wordpriis_cron_canary_write($context, true); return; }
        wp_schedule_single_event(time() - 5, WORDPRIIS_CRON_HOOK, [$context['run_id'], $context['phase']], true);
    }, PHP_INT_MAX, 0);
}
wordpriis_cron_canary_install();
