<?php
/** Disposable fixture setup, never a production installer. */
if (PHP_SAPI !== 'cli') { exit(2); }
$_SERVER['HTTP_HOST'] = '127.0.0.1:8108';
define('WP_INSTALLING', true);
require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
if (wp_get_environment_type() !== 'local') { exit(2); }
if (!is_blog_installed()) { wp_install('WordPrIIS disposable verification', 'verify-admin', 'verify@example.invalid', true, '', 'local-verification-only'); }
update_option('home', 'http://127.0.0.1:8108');
update_option('siteurl', 'http://127.0.0.1:8108');
if (!is_blog_installed() || !get_user_by('login', 'verify-admin') || get_option('home') !== 'http://127.0.0.1:8108') { exit(3); }
exit(0);
