<?php
if (!defined('ABSPATH') || wp_get_environment_type() !== 'local') { return; }
add_filter('pre_wp_mail', static fn() => true);
add_filter('pre_http_request', static fn() => new WP_Error('wordpriis_offline', 'Verification container has no external application traffic.'), PHP_INT_MAX - 1);
