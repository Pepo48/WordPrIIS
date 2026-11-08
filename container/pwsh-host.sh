#!/usr/bin/env bash
# Code renderer only: maps the temporary -File input and checkout into an offline PS container.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
runner=${PODMAN:-podman}
file=''
previous=''
for arg in "$@"; do if [[ "$previous" == '-File' ]]; then file="$arg"; break; fi; previous="$arg"; done
if [[ -z "$file" || ! -f "$file" ]]; then echo 'Expected a local -File renderer input.' >&2; exit 2; fi
exec "$runner" run --rm --network none --security-opt=no-new-privileges \
  -v "$root:$root:ro" -v "$(dirname "$file"):$(dirname "$file"):ro" \
  --entrypoint pwsh localhost/wordpriis-verify:7.6.9 "$@"
