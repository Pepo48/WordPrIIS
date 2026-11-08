#!/usr/bin/env bash
set -euo pipefail
root=/var/www/html/wp-content/plugins/wordpriis
for test in server-audit bootstrap-profile bootstrap-trace bootstrap-resources filesystem-probe cron-config cron-gate; do echo "PHP suite: $test"; php -d display_errors=stderr "$root/tests/$test.php"; done
find "$root/scripts" -name '*.php' -print0 | xargs -0 -n1 php -l
