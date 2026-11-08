> WordPrIIS owns this migrated audit. The current generic collector probes WordPress core CSS/JS, not WORDPRIIS plugin assets; use `wordpress-iis.ps1 -Action Audit -ConfigPath <reviewed.json>`. Historical revision numbers/results below remain evidence of the original investigation.

# Windows/IIS WordPress server audit

Run this on the actual Windows host to investigate slow uncached requests and review server hardening. The collector is an assessment tool, not a penetration test or proof that the host is secure. A server can have spare CPU/RAM while PHP waits on disk, database locks, DNS, remote calls, an overloaded FastCGI queue or serial plugin work. Page caching can conceal those waits.

## Run

Copy **both** files from the repository to a private tools directory outside every web root:

- `scripts/Invoke-WordPrIISServerAudit.ps1`
- `scripts/audit-wordpress.php`

Use elevated **64-bit Windows PowerShell 5.1** on the IIS host (PowerShell 7 can also be used where the IIS administration assembly works). The collector does not bypass execution policy. Run a reviewed local copy under your organization's normal script/signing policy. `curl.exe` is needed for HTTP timing; no new software is installed by the script.

```powershell
.\Invoke-WordPrIISServerAudit.ps1 `
  -Url 'https://wordpress.example.com' `
  -PrivatePath 'D:\wordpriis-private' `
  -OutputDirectory 'C:\AuditReports\wordpriis-first-run'
```

The site is selected from a unique hostname binding; PHP is resolved from its effective PHP FastCGI handler and matching `php.exe`, rather than the first global FastCGI entry. Exact bindings take priority over wildcard bindings. An ambiguous match is reported rather than guessed. Use `-SiteName`, `-WordPressPath` or `-PhpPath` to override or disambiguate when needed. Replace the private storage/output examples with actual paths. Do not pass your Downloads folder as PrivatePath unless it really is application storage. Output must be a **new directory outside the web root**. On Windows its ACL is restricted to the invoking identity, Administrators and SYSTEM; no existing report is overwritten. Review the local report before sharing: it contains operational paths, bindings, firewall/listener details and ACL SIDs, although database passwords, cookie values, customer data and raw request logs are not collected.

To compare the public Cloudflare route with the origin while preserving hostname/SNI/certificate validation:

```powershell
.\Invoke-WordPrIISServerAudit.ps1 `
  -Url 'https://wordpress.example.com' `
  -OriginAddress '127.0.0.1' -PagePath '/configurator/' `
  -Samples 5 -IncludeDatabase
```

Use the correct bound origin IP. The origin must present a certificate trusted by that machine. There is **no insecure TLS retry**; a Cloudflare Origin CA certificate may require the appropriate approved trust configuration. A rejected direct-origin connection is reported as unavailable, not as a slow PHP result. The script never discovers or publishes an origin address through third parties.

`-IncludeDatabase` enables SELECT/SHOW diagnostics inside a read-only transaction. The PHP helper parses simple literal settings without executing `wp-config.php`, loading WordPress or running plugins. Environment-derived credentials and nonliteral configs are skipped. Remote database hosts are skipped rather than silently creating an unencrypted diagnostic connection; use an approved TLS-aware database tool separately. No database credentials are accepted as command-line arguments or written to reports.

HTTP-only inspection works without IIS and on non-Windows systems with PowerShell/curl:

```powershell
.\Invoke-WordPrIISServerAudit.ps1 -HttpOnly -Url 'https://wordpress.example.com' -Samples 3
```

`-SkipHttp` collects local host/configuration information without HTTP requests. Default sampling is three sequential GETs per target, a 20-second per-request timeout and a five-second resource sample. Limits are 1–10 HTTP samples, 5–60 seconds per request and 1–60 resource seconds. These are light diagnostics, not a concurrent load test. Even GET requests may produce normal logs or warm application caches.

## What it checks

| Area | Evidence |
|---|---|
| IIS | Effective root configuration; inherited Cache-Control custom headers; cache-header outbound rules; static cache/compression; directory browsing; authentication/SSL settings; app-pool identity, CPU limits, queue, recycling and idle policy; selected FastCGI settings and PHPRC/max-request environment values |
| Windows resources | OS/build/boot, CPU/RAM, local disk capacity, short CPU/memory/disk queue samples, aggregate PHP/IIS/database/Defender process memory and lifetime CPU |
| Host security | Firewall profile state, effective inbound management/database/any-port rules with remote scopes, interface aliases, program/service restrictions and adapter inventory (useful for ZeroTier-only management), listening endpoints, Defender protection/signature age, recent hotfix indicators, pending reboot, SMBv1, TLS cipher names/explicit Schannel settings, broad write ACLs and private-directory containment |
| PHP | CLI version and selected ini settings, OPcache availability/configuration, Xdebug, display-errors/expose-PHP and security-relevant flags |
| WordPress | Core version, literal config flags and presence of page/object-cache drop-ins; no plugin bootstrap or customer content |
| Optional database | SELECT 1 latency, autoloaded option aggregate/top sizes without option names/values, table-engine/size totals, selected buffer/connection/slow-query settings and lifetime status counters |
| HTTP | Public/direct-origin CSS/JS, page, no-action AJAX and a nonexistent CSS resource; DNS/connect/TLS/TTFB/total timing, status/MIME/compression and allowlisted cache/security headers; conflicting public/no-store and cacheable-error detection |
| IIS logs | Tails of at most two recent files/20,000 rows: coarse request-category median/p95, 5xx substatus counts and whether the schema includes query-string logging; no URLs, queries, IPs, cookies or event messages saved |

IIS queries use the application whose path is the longest prefix of `-PagePath` (the root application by default). For WordPress in a separate IIS application, set `-PagePath` to a route within that application. The report records the selected site, application, WordPress path, PHP handler executable and discovery method under `discovery`. PHP arguments in handler mappings are never executed or serialized. Bitness-incompatible handlers are excluded; an unknown pool bitness prevents guessing a conditional handler. Nonstandard handler preconditions and host mappings still require operator verification.

## Read the result

`summary.md` lists findings and next steps. Report schema 2 adds execution bitness/elevation and `discovery` details. Collector revision `2026-11-08.4` includes the `2026-11-08.3` corrections, which remove dictionary-property cmdlet assumptions in site ranking and TLS inventory for Windows PowerShell 5.1. Diagnostics now include the precise discovery phase, safe source line/allowlisted command and recognized error identifier, with independent TLS cipher/protocol coverage. Collector failures include a fixed stage, reason code, exception type, HRESULT and a safe next step. They never include raw exception text, invocation/stack traces, PHP stderr/stdout or handler arguments. Missing commands/helpers, wrong PHP versions, denied access, ambiguous sites and malformed/incomplete PHP results are distinguishable.

IIS sections, pool/bindings, handler selection, FastCGI inventory and logs are collected independently. One inaccessible section no longer discards other IIS/cache evidence. A report can therefore contain useful partial results alongside diagnostics. `audit.json` contains evidence and explicit skipped/unavailable checks. Those are **not passes**. The script does not generate a simplistic aggregate security score.

1. **Find the cache-header source.** Check `iis.cache_header_sources`. An unconditional Cache-Control custom header is a concrete origin candidate for the public/year-long directive we observed on error and AJAX responses. Also inspect `staticContent` and outbound-rule preconditions. If IIS has no matching source, inspect Cloudflare Cache/Response/Transform rules and Workers. Public MISS/DYNAMIC headers alone cannot identify the responsible layer.
2. **Compare public and direct-origin timing.** A slow origin static file points toward IIS, TLS, filesystem/antivirus, network or contention below WordPress. Fast static but slow page/AJAX points toward PHP/database/plugins/remote calls. TTFB includes network and server work; it is not measured PHP CPU time. Curl timing phases are cumulative, not additive.
3. **Prove that a request is uncached.** `wordpriis_audit` query strings and request `Cache-Control: no-cache` are only hints; Cloudflare/WP Rocket may ignore them. Record the response cache status and verify a bypass in staging. No-action AJAX returning 400 measures a bootstrap path, not the full frontend render. Authenticated pages and full checkout are not benchmarked.
4. **Follow the waiting work.** A short low-CPU sample cannot eliminate blocking I/O/locks, and `SELECT 1` does not measure real WordPress queries. Look at FastCGI queue/recycling, OPcache configuration, autoload size, object-cache presence and sampled slow IIS categories. Confirm with a staged profile/FREB trace of the actual slow route.
5. **Review security alongside speed.** Do not disable Defender, widen app-pool rights, enable indiscriminate page caching or increase every resource limit to hide slowness. Restrict management ports and filesystem rights based on actual identities and upstream access controls.

## Limits and follow-up

- PHP CLI settings do not prove effective **FastCGI** ini selection, OPcache hit rate/exhaustion or web-SAPI extensions. This tool installs no public `phpinfo()`/profiling endpoint.
- Configuration/cipher inventory does not perform an external TLS scan, certificate-expiry assessment, authenticated authorization tests or vulnerability-advisory scan. Hotfix inventory is not proof all updates are installed. Check actual supported OS/PHP/WordPress/plugin versions against vendor advisories.
- Drop-in presence does not prove a cache is connected or effective. `DISABLE_WP_CRON=true` needs a working independent scheduler; its presence alone is not a defect.
- DACL screening is not a Windows effective-access calculation; deny ACEs/group membership, virtual-directory aliases and worker identity must be verified on host. Firewall inventory does not prove Internet exposure or Cloudflare-only origin access.
- It does not audit every plugin's source, execute unsafe firmware, send mail, make payments, clear caches, benchmark writes, change IIS/PHP/DB settings or run repair/OPTIMIZE/EXPLAIN ANALYZE on customer queries.
- Logs may use a nonstandard directory/schema or rolling header; missing summaries are coverage gaps. A query-field warning does not prove that a bearer URL was actually logged, but demands checking exclusion/redaction rules.
- Use a controlled staging reproduction to profile slow PHP/database queries, outbound HTTP time, external worker waits and actual browser LCP/INP. Defender's performance analyzer can investigate scanning cost without making blanket exclusions.

## Validation status

Executed locally: 22 PHP assertions, 61 PowerShell logic assertions and an end-to-end HTTPS fixture covering public/direct-origin sampling, cacheable-503 detection, JSON/Markdown output, body/cookie redaction and overwrite protection. PowerShell 7.4.22 ran natively on macOS ARM64; PHP ran in the existing 8.4 staging container. The portable tests can be run locally under Windows PowerShell 5.1 and PowerShell 7 using TESTSUITE.md; no GitHub Actions workflow is shipped. HTTP-only tests can run in the saved Podman stage. Windows/IIS-specific collectors still require validation on the real host; Linux container tests do not establish their runtime behavior. No production server audit has been executed by adding this tool.

## PHP helper with SERVER/argv globals disabled

The owner’s revision-3 report successfully detected IIS and PHP 8.4.27 but showed `php-helper-no-json`. That exact successful-exit/empty-output behavior was reproduced locally with `variables_order=GP`: the old entry guard depended on `$_SERVER['SCRIPT_FILENAME']`. Revision `2026-11-08.4` uses a CLI entry point independent of SERVER globals and enables `register_argc_argv=1` **only for the child probe process**, so `getopt` can parse its arguments. No php.ini/IIS setting is changed. Tests that include the helper use an explicit library-only constant; HTTP invocation still exits immediately.

Extract both matching files from the updated audit ZIP. Do not change production SERVER/argv settings just to run the diagnostic. The report now exposes the probe’s variables_order and its process-only argv setting, while retaining the distinction between CLI and FastCGI configuration.

IIS log summaries now include their sampled first/last UTC timestamps and most recent sampled 5xx time, when date/time fields are available. Historical 5xx counts are not evidence the site is failing at audit time. A separate bounded IIS/WAS System-event summary collects IDs/counts/timestamps without event messages, complementing the Application-event counts. These can identify a useful time window for a private local event/FREB review; they do not establish why a worker stopped or returned 503.

## Separate connection and query latency

Revision `2026-11-08.5` adds `database.connect_ms` (connection/authentication, including driver resolution/transport negotiation), `database.select1_ms` (the existing trivial query after connection), `database.diagnostic_queries_ms` (the read-only diagnostic query batch) and `php_helper_process_ms` (whole helper-process time, excluding the separate version check). The helper timing includes startup/config parsing/connection/diagnostic work; it is not a WordPress request profile. Connection failures retain elapsed time and a loopback hostname/IPv4/IPv6 category, without credentials or driver messages.

The owner’s first DB result showed a 0.47 ms SELECT, about 80 KiB of autoloaded options, an approximately 88 MiB database and a 128 MiB InnoDB pool with few lifetime physical reads. Those observations do not explain multi-second PHP requests and do not justify a blind large-memory change. They also did not measure connection setup. `Slow_queries=0` with `long_query_time=10` does not rule out SQL shorter than ten seconds, many small queries or waits outside the measured SELECT. See [MySQL slow-log semantics](https://dev.mysql.com/doc/refman/8.0/en/slow-query-log.html).

Use `-IncludeDatabase -SkipHttp` for the next focused run. If connect/helper times are small, profile actual WordPress/plugin/drop-in initialization and outbound calls in a controlled staging reproduction. A change from a hostname to an IP can affect transport and authentication, so measure before changing DB_HOST or grants. The audit never changes database configuration.

## Compare a slow localhost connection with IPv4

The owner’s revision-5 report measured **2,055.059 ms connecting to a loopback hostname**, versus **35.07 ms for the diagnostic query batch** and **0.513 ms for SELECT 1**. The full helper process took 2,300.669 ms. Connection setup is therefore a concrete major delay in that diagnostic, not evidence that MySQL needs more RAM. Its exact cause (resolution, transport negotiation, authentication or filtering) is not yet isolated.

Revision `2026-11-08.6` adds an explicit read-only comparison:

```powershell
.\Invoke-WordPrIISServerAudit.ps1 `
  -Url 'https://wordpress.example.com' `
  -IncludeDatabase -CompareDatabaseIPv4 -SkipHttp
```

The baseline remains unchanged. A second temporary diagnostic connection replaces **only** `localhost` with `127.0.0.1` in the in-memory config copy, preserving an explicit port. Existing IP, remote and socket-path settings are skipped. Nothing is written to `wp-config.php`. The extra connection uses the same parsed credentials; they are never emitted. The whole-helper time includes both probes when this option is used.

Compare `database.connect_ms` with `database_ipv4_comparison.ipv4.connect_ms`. Check that `same_instance_database_principal` is **true**: selected server identity, database and authenticated account are hashed internally, and only digests/equality are reported. A false result means identity is different or unavailable; a successful connection alone does not approve a host-setting change.

If IPv4 is consistently fast and identity matches, a controlled fix is to back up `wp-config.php` into a protected directory **outside every web root**, change only its DB_HOST hostname to `127.0.0.1` while retaining the port, then verify login, uncached page/AJAX timing and database metrics. Allow for the existing OPcache timestamp-revalidation interval. Keep the original setting for rollback if validation fails. Do not change database grants, disable IPv6 globally or disable security software to mask the delay. No such production change is performed by this audit.

## Observed result after the owner changed DB_HOST

The follow-up report showed the IPv4 connection at **1.049 ms**, down from **2,053.259 ms**, with the same hashed server/database/account identity. The whole helper process fell to **222.43 ms**. The comparison correctly skipped a second override once DB_HOST was already an IP.

Three new public samples per route then measured median page TTFB **1,488.91 ms** and no-action AJAX **1,174.02 ms**, compared with roughly 3.6 s/3.2 s in the earlier owner reports. All new responses were Cloudflare DYNAMIC; the first page sample was 2,494.6 ms and was retained. This is strong evidence of the observed connection delay being removed, but not a controlled same-client load test or proof of full WordPress cache bypass. Around 1.2 s of AJAX time remains to profile with the [separate opt-in web-request profiler](bootstrap-profile.md). The blanket one-year IIS header is still visible, including its conflict with AJAX no-store.

[Sanitized before/after verification](verification-results/db-ipv4-remediation-2026-11-08.json) preserves timings and public headers only; the full private host report was not added to the repository. No production change was executed from this workspace.

## RDP over ZeroTier

RDP over ZeroTier is an intentional management path for this installation. Broad-listener inventory alone is not proof of Internet access. Review `management_inbound_rules`, `network_interfaces` and the upstream firewall together to verify that TCP/UDP 3389 is limited to the intended ZeroTier interface/approved peers, including IPv6. The collector reads the Windows firewall ActiveStore so effective policy is visible. A broad allow rule may still be restricted to one program/service; those constraints are now retained.

SMB is not used for owner access. Check service dependencies before disabling or blocking it; this script does not change firewall rules or services. Keep the actual private storage paths in `-PrivatePath` so their ACLs are assessed.

The owner’s schema-2 Windows run reported `PSArgumentException`/`0x80070057` in discovery and TLS while elevated/64-bit. The dictionary-property issue is a likely explanation, not a confirmed trace of the exact original failing statement (that revision did not capture its line). Microsoft documents the [PowerShell 5.1 versus 6+ behavior](https://github.com/MicrosoftDocs/PowerShell-Docs/issues/9311). The updated revision avoids those calls, preserves granular diagnostics if another failure remains, and still needs a real-host rerun.

The same run showed the built-in RDP TCP/UDP allow rules scoped to Any remote address/Any interface. Those local rules do not enforce ZeroTier-only access. Verify upstream/deny-policy restrictions and IPv6 before asserting isolation; make any future restriction through a controlled change that preserves the approved RDP path. No firewall policy was changed by this tool.

## Primary guidance

- [Microsoft FastCGI configuration](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/fastcgi/) and [PHP Failed Request Tracing](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/troubleshoot-php-with-failed-request-tracing)
- [PHP OPcache settings](https://www.php.net/manual/en/opcache.configuration.php) and [Windows configuration](https://www.php.net/manual/en/install.windows.recommended.php)
- [WordPress performance](https://developer.wordpress.org/advanced-administration/performance/optimization/) and [autoload Site Health threshold](https://developer.wordpress.org/reference/functions/update_option/)
- [Microsoft Defender performance analyzer](https://learn.microsoft.com/en-us/defender-endpoint/tune-performance-defender-antivirus)
- [Cloudflare status-aware caching](https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/)

## Automatic request-phase follow-up

For the remaining bootstrap delay, run `Invoke-WordPrIISBootstrapProfile.ps1 -Url https://wordpress.example.com` from the extracted audit bundle in elevated 64-bit Windows PowerShell. It reuses site/PHP discovery, installs an expiring MU profiler without editing wp-config.php, sets new private-file ACLs, collects three requests, cleans up and retains the report. Unlike this read-only configuration audit, it temporarily installs diagnostic code and performs real WordPress bootstrap requests. See [the automatic profiling procedure and limits](bootstrap-profile.md#automatic-profiling-session-recommended).
