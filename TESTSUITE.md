# WordPrIIS verification

Source and bundle privacy checks run through `scripts/quality.py` and `tests/package.py`. They fingerprint forbidden private deployment identifiers without storing those identifiers in the regression itself. Site names, accounts, domains and client-specific application paths in retained evidence are substituted examples; timing values are preserved.

## Run everything in containers

```bash
bash container/verify.sh
```

Requires Podman, Bash and Python 3. The harness builds current checksum-pinned PowerShell 7.6.9 on Ubuntu 24.04, runs portable/HTTPS tests, then starts an isolated WordPress 7.1.4/PHP 8.5 + MariaDB 12.3.3 LTS pod. PHP, database and OS images are pinned by digest in `container/images.json` / `Containerfile`; OS security packages resolve from signed Ubuntu repositories during build. The PowerShell release archive is verified against GitHub's published digest.

No production configuration, credentials or database are loaded. The application guard blocks outbound requests and mail. The database is not published. Only WordPress port 8108 is bound on host loopback. Disposable pod/networks are removed on normal success/failure; an existing namesake pod/network is refused. Forced process/machine termination can leave lab resources; inspect their names/labels before cleanup. Existing application staging is not modified.

Results: ignored `.artifacts/powershell-tests.log`, `https-tests.log`, `php-tests.log`, `profile-stage.json`, `cron-stage.json`, `verification.json`. Full profiles/logs stay local. Saved verification JSON retains assertions, outcomes and aggregate timings, not per-request callback dumps. Package checks enforce that boundary. Saved sanitized [refactor verification](docs/verification-results/wordpriis-refactor-2026-11-08.json) distinguishes actual checks from native Windows follow-up.

## Coverage

| Suite | What it actually exercises |
|---|---|
| `tests/core.ps1` | Production config validation, secret/unknown-field rejection, pure Plan/dispatcher, PHP/wp-config/XML rendering, scoped ACL plan, real SHA256/ZIP extraction and traversal/collision rejection; parses shipped PowerShell sources. |
| `tests/bootstrap.ps1` | Real bootstrap orchestrator, pinned-artifact hashing, native-stage ordering and stop-on-failure journal/privacy. Native host/certificate/IIS installation stages are mocked. |
| `tests/server-audit.ps1` | Migrated selection, inherited PHP mapping, collector diagnostics, cache classification, DB comparison and PS5.1-compatible helpers. Native collection APIs are mocked where unavailable. |
| `tests/server-audit.php` | Actual standalone PHP config/database helper behavior and privacy; no application bootstrap. |
| `tests/server-audit-http.py` | Real trusted HTTPS public/direct-origin probes, 5xx/cache findings, body/cookie exclusion and overwrite protection. |
| `tests/bootstrap-profile.php` | Authorization/expiry/route/privacy gates, private output readiness/locking and bounded logs. |
| `tests/bootstrap-trace.php` | Real WordPress WP_Hook dispatcher: timing, return/exception propagation, nesting, removal/object lifetime, HTTP pairing/redaction and caps. |
| `tests/bootstrap-resources.php` | Real includes/classes/resource deltas, module grouping, 20,000-dispatch storms, later exact Breakdance field reservation, cache invalidation/removal and nested wrapper reservation. Uses synthetic source fixtures, not commercial plugins. |
| `tests/filesystem-probe.php` | Bounded metadata operations, per-group file cap, deadline, build/SAPI context, no path/content export or mutation. No Windows filesystem claim. |
| `tests/bootstrap-profile-runner.ps1` | Real temporary-file lifecycle and cleanup with mocked native IIS/ACL/discovery/transport boundaries, including edited/unrelated-file preservation. |
| `tests/bootstrap-profile-runner-http.py` | Real curl stdin/config handling, expected 400, TLS/public/direct-origin requests and certificate rejection without insecure retry. |
| `tests/bootstrap-profile-stage.py --runner-code` | Exact runner-generated MU PHP in real web WordPress: unchanged no-action response, ordinary/cookie/token exclusions, file/HTTP/nested attribution, later resources after storms, opt-in metadata calibration and cleanup. |
| `tests/cron-config.php` | Tokenized config planning, byte preservation, dynamic/conditional/duplicate definition refusal. |
| `tests/cron-gate.php` | Native PHP child processes: flock non-overlap, fatal handling, independent completion receipts and ordinary-page exclusion. |
| `tests/cron-setup.ps1` | Real file/atomic config transaction with mocked Windows APIs: manual/automatic/post-change/normal proof ordering, rollback, concurrent edits and task retention if effective rollback is unverified. |
| `tests/cron-recovery.ps1` | Missing-runtime association, ambiguous/unrelated target refusal, password prompting, private backups, visitor-cron restoration and verify-before-unregister ordering; native boundaries mocked. |
| `tests/cron-proof.ps1` / `cron-task-definition.ps1` | Exact receipt matching, credentials checked by SID, limited password logon, matching trigger/action limits and no password/policy bypass in action arguments. |
| `tests/cron-task-http.py` | Real task action against early-200 HTTPS with delayed/missing/fatal/busy completion receipts and expired verification state. |
| `tests/cron-stage.py` | Actual WordPress due canary callbacks and completion/cleanup in local stage. The stage already has DISABLE_WP_CRON=true; it does not test switching the stage's config. |

## Individual runs

```powershell
pwsh -NoProfile -File .\tests\core.ps1
pwsh -NoProfile -File .\tests\bootstrap.ps1
pwsh -NoProfile -File .\tests\server-audit.ps1
pwsh -NoProfile -File .\tests\bootstrap-profile-runner.ps1
pwsh -NoProfile -File .\tests\cron-setup.ps1
pwsh -NoProfile -File .\tests\cron-recovery.ps1
pwsh -NoProfile -File .\tests\cron-proof.ps1
pwsh -NoProfile -File .\tests\cron-task-definition.ps1
```

The PHP dispatcher suites require WordPress files at the expected container path; use the harness instead of running them against a production site. HTTPS fixtures require local Python/OpenSSL/curl/PowerShell and use synthetic credentials only; the verification image supplies these tools. `container/pwsh-host.sh` is a renderer adapter for web integration, not a remote server runner.

```bash
python3 scripts/quality.py
python3 tests/package.py
```

The packaging test verifies actual ZIP integrity, manifest hashes and exclusion of local configs/private trace/key files. Quality checks validate JSON, Python/shell syntax, local documentation links and prevent reintroduction of known dangerous production command patterns. They complement real regression behavior; they are not a comprehensive vulnerability scanner. No legacy Pester extraction adapters or installation demonstrations are used. Native boundaries remain explicitly mocked in portable tests; test assertions execute the actual production functions.

## Native Windows acceptance still required

GitHub Actions workflows are not shipped. Run the portable Windows checks locally in **both** Windows PowerShell 5.1 and installed PowerShell 7:

```powershell
foreach ($exe in @('powershell.exe', 'pwsh.exe')) {
    foreach ($test in @('core', 'bootstrap', 'server-audit', 'bootstrap-profile-runner', 'cron-setup', 'cron-recovery', 'cron-proof', 'cron-task-definition')) {
        & $exe -NoProfile -File (Join-Path $PWD ("tests/$test.ps1"))
        if ($LASTEXITCODE -ne 0) { throw "Failed: $exe / $test" }
    }
}
```

These portable checks do **not** create a real IIS installation or Defender/cron task. They complement the native acceptance procedure below.

Before promoting the new bootstrap implementation, use an isolated disposable **Windows Server VM**:

1. Verify official x64 NTS archive hash/signature/provenance, runtime/Rewrite prerequisites and configuration validation; confirm no import/default Plan changes the host.
2. Provide a fresh empty managed database and valid installed hostname certificate. Bootstrap new paths/site/pool; inspect actual effective FastCGI settings, anonymous identity, runtime files and ACL inheritance. Verify no other site/config/firewall was changed.
3. Complete WordPress setup. Test HTTPS, permalinks, actual CSS/JS MIME types, config denial, normal uploads and refusal to execute PHP/web.config overrides from uploads. Validate effective status-gated headers on controlled 500/502/503 fixtures and earlier-pipeline errors, including direct origin and Cloudflare.
4. Test deployment-managed core/plugin updates and WordPress/builder/WP Rocket data writes. Run full application/browser/payment/editor regression tests with the actual plugin stack; the synthetic fixture stage cannot establish compatibility.
5. Run Audit/ExportConfig/Profile/Diagnose and verify private output, profiler removal and unavailable-recorder reporting. When timed Defender recording is available, correlate actual ETL and request windows; never assume scanner blame from a quiet/failed trace.
6. Verify the cron task with the real service-account password, batch logon/GPO, automatic triggers, completion receipts, failure/rollback handling and actual web-SAPI flag. Verify credential rotation. The owner's earlier production cron success supports the migrated engine, not all new bootstrap code.
7. Test backup restoration, TLS renewal, monitoring, failure recovery and restart/worker behavior before production. Failed fresh bootstrap may leave partial owned resources; inspect its journal rather than blindly rerunning or deleting other sites.

Linux Podman containers cannot run Windows IIS or reproduce Windows Defender/filter-driver path costs. Results must never label native setup/security/performance as verified solely because container assertions pass.
