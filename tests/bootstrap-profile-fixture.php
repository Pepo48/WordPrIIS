<?php
/** Synthetic web-profile callbacks; loaded only by the disposable staging verification. */
if (!defined('ABSPATH') || !defined('WORDPRIIS_PROFILE_TOKEN_SHA256') || wp_get_environment_type() !== 'local'
    || !wordpriis_profile_allowed($_SERVER, $_GET, $_POST, ['hash' => WORDPRIIS_PROFILE_TOKEN_SHA256, 'expires' => WORDPRIIS_PROFILE_UNTIL])) { return; }
function wordpriis_profile_fixture_slow_callback(): void { usleep(2500); }
function wordpriis_profile_fixture_http(): void {
    // The existing stage guard short-circuits this request; no external network or cron execution.
    wp_remote_post(home_url('/wp-cron.php?wordpriis_fixture=SECRET_QUERY'), [
        'timeout' => 0.01, 'blocking' => false, 'body' => 'SECRET_BODY',
        'headers' => ['Authorization' => 'SECRET_AUTH'],
    ]);
}
add_action('plugins_loaded', 'wordpriis_profile_fixture_slow_callback', 21, 0);
add_action('shutdown', 'wordpriis_profile_fixture_http', 1, 0);
