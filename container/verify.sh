#!/usr/bin/env bash
set -euo pipefail
export PATH="/opt/podman/bin:$PATH"
root=$(cd "$(dirname "$0")/.." && pwd)
runner=${PODMAN:-podman}
command -v "$runner" >/dev/null
command -v python3 >/dev/null
mkdir -p "$root/.artifacts"
wp_image=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["wordpress"])' "$root/container/images.json")
db_image=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["database"])' "$root/container/images.json")
if "$runner" pod exists wordpriis-verify; then echo 'Verification pod already exists; inspect it before removing/retrying.' >&2; exit 2; fi
for network in wordpriis-verify-back wordpriis-verify-front; do
  if "$runner" network exists "$network"; then echo "Verification network already exists: $network" >&2; exit 2; fi
done
created_pod=false
created_back=false
created_front=false
cleanup() {
  if [[ "$created_pod" == true ]]; then "$runner" pod rm -f wordpriis-verify >/dev/null; fi
  if [[ "$created_back" == true ]]; then "$runner" network rm wordpriis-verify-back >/dev/null; fi
  if [[ "$created_front" == true ]]; then "$runner" network rm wordpriis-verify-front >/dev/null; fi
}
trap cleanup EXIT
"$runner" build -t localhost/wordpriis-verify:7.6.9 -f "$root/container/Containerfile" "$root/container" > "$root/.artifacts/container-build.log" 2>&1
"$runner" run --rm --network none --security-opt=no-new-privileges -v "$root:/work:ro" localhost/wordpriis-verify:7.6.9 -File /work/container/powershell-tests.ps1 | tee "$root/.artifacts/powershell-tests.log"
"$runner" run --rm --network none --security-opt=no-new-privileges -v "$root:/work:ro" --entrypoint bash localhost/wordpriis-verify:7.6.9 -c 'python3 /work/tests/server-audit-http.py && python3 /work/tests/bootstrap-profile-runner-http.py && python3 /work/tests/cron-task-http.py' | tee "$root/.artifacts/https-tests.log"
"$runner" pod create --name wordpriis-verify --infra=false --share="" >/dev/null
created_pod=true
"$runner" network create --internal wordpriis-verify-back >/dev/null
created_back=true
"$runner" network create wordpriis-verify-front >/dev/null
created_front=true
"$runner" run -d --rm --pod wordpriis-verify --name wordpriis-verify-db --network wordpriis-verify-back --memory 384m \
  -e MARIADB_ROOT_PASSWORD=local-verify-only -e MARIADB_DATABASE=wordpress -e MARIADB_USER=wordpress -e MARIADB_PASSWORD=local-verify-only \
  "$db_image" --innodb-buffer-pool-size=64M --max-connections=20 >/dev/null
ready=false
for ((i=0;i<60;i++)); do if "$runner" exec wordpriis-verify-db healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then ready=true; break; fi; sleep 1; done
if [[ "$ready" != true ]]; then echo 'Verification database not ready.' >&2; exit 1; fi
"$runner" run -d --rm --pod wordpriis-verify --name wordpriis-verify-wp --network wordpriis-verify-back,wordpriis-verify-front --memory 512m \
  -p 127.0.0.1:8108:80 -e WORDPRESS_DB_HOST=wordpriis-verify-db -e WORDPRESS_DB_USER=wordpress \
  -e WORDPRESS_DB_PASSWORD=local-verify-only -e WORDPRESS_DB_NAME=wordpress \
  -e "WORDPRESS_CONFIG_EXTRA=define('WP_ENVIRONMENT_TYPE','local'); define('DISABLE_WP_CRON',true); define('WP_HTTP_BLOCK_EXTERNAL',true);" \
  -v "$root:/var/www/html/wp-content/plugins/wordpriis:ro" \
  -v "$root/container/guard.php:/var/www/html/wp-content/mu-plugins/wordpriis-guard.php:ro" "$wp_image" >/dev/null
ready=false
for ((i=0;i<60;i++)); do if "$runner" exec wordpriis-verify-wp test -f /var/www/html/wp-config.php; then ready=true; break; fi; sleep 1; done
if [[ "$ready" != true ]]; then echo 'Verification WordPress not ready.' >&2; exit 1; fi
echo "Checking fresh database preflight"
"$runner" exec wordpriis-verify-wp php /var/www/html/wp-content/plugins/wordpriis/container/database-tests.php empty
echo "Installing disposable WordPress fixture"
"$runner" exec wordpriis-verify-wp php /var/www/html/wp-content/plugins/wordpriis/container/install.php
"$runner" exec wordpriis-verify-wp php /var/www/html/wp-content/plugins/wordpriis/container/database-tests.php populated
"$runner" exec --user www-data wordpriis-verify-wp bash /var/www/html/wp-content/plugins/wordpriis/container/php-tests.sh | tee "$root/.artifacts/php-tests.log"
export PODMAN="$runner"
export WORDPRIIS_TEST_PWSH="$root/container/pwsh-host.sh"
python3 "$root/tests/bootstrap-profile-stage.py" --runner-code > "$root/.artifacts/profile-stage.json"
python3 "$root/tests/cron-stage.py" > "$root/.artifacts/cron-stage.json"
python3 "$root/scripts/summarize-verification.py"
echo 'Container verification passed. Reports retained under .artifacts; native Windows checks remain separate.'
