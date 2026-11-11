# WordPrIIS

Bootstrap and operate WordPress on Windows/IIS with explicit configuration, standalone PowerShell commands, private diagnostics and measured performance tuning. **This repository is an operations toolkit, not a WordPress plugin.** Keep it outside every web root.

The work grew out of a real IIS investigation: a `localhost` database connection added about two seconds, request-triggered cron dispatched a roughly one-second loopback, and a blanket cache header made errors/static-asset failures harder to diagnose. Those first two issues were corrected on the owner’s host; a remaining ~1.2-second uncached PHP bootstrap needs Windows-specific investigation. Plugin timings locate work, not its underlying cause. [Experience and non-sensitive observations](docs/experience.md).

All site identities and deployment paths in examples and retained reports are anonymized. Substitute your own verified configuration.

## Start with local verification

Requirements: Podman, Python 3 and Bash. On macOS start the Podman machine first. No Windows host, production database, PayPal credentials or proprietary plugins are needed.

```bash
bash container/verify.sh
```

This builds a checksum-pinned PowerShell 7.6.9 image, runs the real configuration/archive/orchestration functions and the migrated audit/profiler/cron regressions, then checks real PHP/WordPress requests in one disposable **wordpriis-verify** Podman pod. WordPress is published only at `127.0.0.1:8108` during the run. Database access is internal; application mail/outbound HTTP is blocked by a local-only guard. The pod/networks are removed in a trap and reports remain under ignored `.artifacts/`.

**Linux containers cannot validate IIS, Windows ACLs, certificate bindings, Defender recordings or Task Scheduler logon.** Portable tests mock those boundaries; they do not prove a production Windows bootstrap. See [TESTSUITE.md](TESTSUITE.md) for exact coverage, individual commands and native acceptance checks. The latest [namespace-clean verification](docs/verification-results/namespace-cleanup-2026-11-08.json) includes 67 cron setup assertions; earlier saved counts remain historical.

## Inspect a configuration without changing anything

Windows PowerShell **5.1** remains supported on the server. PowerShell 7 can also run portable commands. Copy the example and review it:

```powershell
Copy-Item .\config\example.json .\config\local.json
.\wordpress-iis.ps1 -Action Plan -ConfigPath .\config\local.json |
    ConvertTo-Json -Depth 8
```

The default action is `Plan`. Configuration has an explicit allowlist: credentials, arbitrary environment variables and unknown fields are rejected. JSON is data, never executable PowerShell. Passwords are supplied through **PSCredential**, not arguments, environment files, transcripts or Git. Only generated private wp-config.php and Windows Task Scheduler’s protected credential store retain credentials needed for operation.

For the existing example host, start from `config/existing-site.example.json`. It contains anonymized example paths/domain/account and leaves installer/certificate pins empty. Database/schema/user/prefix entries are placeholders to verify, not values recovered from production secrets. **Do not run Bootstrap against the existing host.**

If downloaded scripts are blocked under RemoteSigned, review the extracted trusted bundle and unblock only its `.ps1` files with `Get-ChildItem -LiteralPath . -Recurse -Filter *.ps1 | Unblock-File`. No command changes or bypasses execution policy. An enforced AllSigned policy requires signing through your normal process.

## Existing-site operations: one entry point

Run elevated **64-bit PowerShell** on the IIS server. PrivatePath must be a trusted local, unserved directory permitted by web PHP open_basedir. Examples use `C:\WordPrIISPrivate`; replace it with a trusted, PHP-allowed directory on your host.

```powershell
$cfg = '.\config\local.json'
.\wordpress-iis.ps1 -Action Audit -ConfigPath $cfg
.\wordpress-iis.ps1 -Action ExportConfig -ConfigPath $cfg
.\wordpress-iis.ps1 -Action Profile -ConfigPath $cfg
.\wordpress-iis.ps1 -Action Diagnose -ConfigPath $cfg -RecordDefender
.\wordpress-iis.ps1 -Action Verify -ConfigPath $cfg
```

| Action | Behavior |
|---|---|
| `Plan` | Validate and display desired non-sensitive settings; no host changes or downloads. |
| `Artifacts` | Download the reviewed PHP/WordPress packages from official HTTPS sources and verify SHA256; no install. |
| `Bootstrap` | Fresh site/pool/paths only; explicit Windows changes. See below. |
| `Audit` | Read-only IIS/PHP/cache/security collection and sequential public HTTP probes. Optional `-IncludeDatabase -CompareDatabaseIPv4` adds bounded read-only SQL diagnostics. |
| `ExportConfig` | Save validated desired settings plus the audit’s allowlisted effective configuration. Does not copy php.ini/wp-config/IIS XML/env wholesale. |
| `Profile` | Install an expiring token-gated MU probe, collect no-action AJAX timings, remove it and retain a private report. `-BenchmarkFileSystem` adds bounded warm metadata calibration. |
| `Diagnose` | Audit + profile with metadata calibration; optional timed Defender recording. No exclusions, configuration tuning, service restart or cache flush. |
| `Cron` | Prove manual/automatic task callbacks before disabling visitor-triggered cron. |
| `Verify` | HTTPS homepage/AJAX/core CSS/JS/config-denial/missing-asset checks. Does not test the full checkout/editor or guarantee every error’s cache policy. |

Each action delegates to a standalone operation script under `scripts/` that accepts `-ConfigPath`. Lower-level engines accept explicit target/runtime parameters; use the dispatcher for the normal workflow. All tooling uses WordPrIIS filenames and protocol identifiers. Use matching helpers/runners from one bundle; previously installed cron runtimes remain independent and must not be partially replaced. No import performs installation.

### Windows performance follow-up

```powershell
.\wordpress-iis.ps1 -Action Diagnose -ConfigPath $cfg -RecordDefender
```

The private `diagnostics.json` links sibling audit/profile output and optional `defender-private.etl`. The PHP filesystem calibration uses already included files, records aggregate timings for `is_file`, `is_readable` and `realpath`, and exports no file paths/content. It runs after normal profile timing and adds at most a bounded workload, not a disk-throughput test. Defender’s timed parameter is feature-detected; unsupported/failed recording produces an explicit partial result. Raw ETLs can contain host paths/process events; inspect locally and share the JSON summaries after review. [Diagnostic procedure](docs/windows-performance.md).

### Verified system cron

```powershell
$account = "$env:COMPUTERNAME\wordpress_service"
$credential = Get-Credential -UserName $account -Message 'Existing cron service account password'
.\wordpress-iis.ps1 -Action Cron -ConfigPath $cfg -TaskCredential $credential
```

The service account must already exist and be allowed scheduled batch logon. It need not be the IIS worker identity. The installer verifies due callbacks through manual and automatic task runs, confirms DISABLE_WP_CRON in web PHP, clears its temporary canary and tests a normal run. The permanent cron-only lock/completion bridge covers wp-cron.php’s early HTTP 200 behavior. Keep the private runtime directory and bridge. New wrapper installations use a stable `Permanent-WordPressCron-<site-hash>` directory and create `KEEP-THIS-DIRECTORY.txt`; it is not disposable audit output. A missing directory can prevent the task from starting even while its schedule remains visible. See [missing-runtime recovery](docs/cron-recovery.md). Existing tasks/gates are never overwritten. [Cron lifecycle and recovery](docs/windows-cron.md).

## Fresh Windows bootstrap

Use a maintained Windows Server and an existing **empty local** MySQL/MariaDB database (127.0.0.1; remote bootstrap connections are refused without a TLS-aware implementation) plus a valid hostname certificate already installed with its private key in `LocalMachine\My`. Certificate issuance/renewal and database-server installation remain separately managed; the old root-password/MySQL-installer/automatic-firewall flows are retired.

1. Review `config/local.json`: unique SiteName/AppPool, **new** WordPressPath/PhpPath, trusted PrivatePath, database connection and certificate thumbprint. Bootstrap currently binds HTTPS port 443 only.
2. Run `Artifacts`. `config/releases.json` pins PHP **8.5.12-1 NTS x64** and WordPress **7.1.4** as reviewed on 8 November 2026; PHP **8.4.27-1** is the supported compatibility choice. To choose it, use its hash and a separate archive path from the lockfile. The Windows `-1` package revision matters even when PHP_VERSION omits it. See [release maintenance](docs/releases.md).
3. If absent, supply local SHA256-pinned Microsoft **URL Rewrite 2.1 x64** MSI and current Visual C++ x64 runtime paths/hashes. Those optional prerequisite packages must be obtained/verified through Microsoft; the script does not silently run an unpinned installer.
4. Supply the existing database account credential and run Bootstrap:

```powershell
.\wordpress-iis.ps1 -Action Artifacts -ConfigPath $cfg
$db = Get-Credential -UserName 'wordpress' -Message 'Existing empty WordPress database account'
.\wordpress-iis.ps1 -Action Bootstrap -ConfigPath $cfg -DatabaseCredential $db
```

Bootstrap verifies packages, installs IIS CGI/prerequisites, extracts isolated PHP, generates php.ini, verifies database connectivity/emptiness, extracts WordPress, generates random salts/wp-config.php, and creates the dedicated pool/site/HTTPS binding. It leaves DISABLE_WP_CRON false until the separate verified Cron action. Finish the WordPress web setup using a strong administrator credential, then Verify/Audit/Profile and test backup restoration before exposing the site.

A private bootstrap journal records completed/failing stages without secrets. **Partial bootstrap is not automatically rolled back or safe to rerun over created resources.** Inspect that journal and remove only the owned fresh resources before retrying. Existing sites, pools, PHP installations and database tables are refused, not reconfigured. No `iisreset`, default-site removal, firewall reset, RDP/SMB opening, Defender exclusion or hosts-file edit is performed.

### Defaults and operational limits

- Dedicated ApplicationPoolIdentity, no CLR, x64, one IIS worker; no idle shutdown for that pool. Each FastCGI runtime explicitly selects its own PHPRC and conf.d scan directory. PHP FastCGI request limits match at 10,000; instances use IIS automatic sizing. Capacity/recycling still needs native measurement.
- OPcache enabled, 256 MiB/20,000 keys, timestamp validation every 60 seconds, JIT disabled. These are measured-compatible starting values, not universal optima. Existing production cache memory is not changed.
- open_basedir retained with WordPress/private/temp roots. Increasing realpath cache size while it is enabled is not presented as an optimization. The worker gets code read/execute and narrowly scoped writable data directories.
- WordPress code is deployment-managed. PHP cannot blanket-write core/plugins; dashboard code updates and WP Rocket drop-in installation need a controlled deployment identity/workflow. Test builder output in uploads and WP Rocket cache/config writes. Do not grant the worker full control to make updates “work.”
- No blanket public Cache-Control header or MIME-map overrides. Successful static assets retain 30-day caching; a status-gated 5xx outbound rule sets no-store when URL Rewrite executes. Pre-pipeline IIS/proxy errors and Cloudflare rules still need direct-origin/edge verification. [Cache policy](docs/cache-policy.md).
- Configure TLS renewal, least-privilege database access, private/off-host backups with a tested restore, external availability checks and access restricted through the intended management network. This toolkit does not claim to provision every production dependency.

The [final retention/privacy review](docs/verification-results/final-retention-review-2026-11-08.json) covers tracked files, reachable history and release bundles. Verification summaries are dated records: older versions and assertion counts describe those runs, not the current checkout. Raw reports stay local; retained JSON contains reviewed outcomes, aggregate metrics and synthetic performance evidence.

## Layout and migration

- `wordpress-iis.ps1`: dispatcher; `scripts/`: standalone operations and migrated diagnostic engines.
- `modules/`: pure validation/rendering/archive functions; no setup at import time.
- `config/`: schema examples and reviewed release metadata; no credentials.
- `tests/`, `container/`: locally invoked portable, PHP/web and HTTPS checks. No GitHub Actions workflows are required or shipped. Windows-specific acceptance remains a manual host/VM check.
- `docs/`: native runbooks, concise findings/verification summaries, limitations and migration history. Raw production reports, callback dumps and ETLs remain private and untracked.

The previous installer and tests are available in Git history. Old `-NonInteractive` commands and imperative module imports are not supported. This is a deliberate interface change; the previous tests often simulated installation rather than calling real functions. [Migration notes](docs/migration.md), [changelog](CHANGELOG.md).

### Recover a deleted cron runtime

From the complete toolkit in elevated Windows PowerShell, run `.\scripts\Recover-WordPressCron.ps1`. It detects the old task/site, requests the existing service-account password, backs up configuration and the matching gate, restores visitor cron, and verifies a replacement before disabling visitor cron again. Keep the new `Permanent-WordPressCron-Recovered-*` folder. See [recovery and failure handling](docs/cron-recovery.md), including read-only config diagnostics. Standard installer output after the ABSPATH guard is supported on recovery/reinstallation.
