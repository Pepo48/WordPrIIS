# Investigate the remaining WordPress bootstrap delay

After the DB_HOST correction, production no-action AJAX still took about 1.2 seconds. The next useful measurement is **inside a real web request**, not another CLI configuration inventory. This temporary diagnostic is separate from the read-only server audit and is included in the standalone WordPrIIS toolkit; it is not a WordPress plugin installation.

## File loading, initialization and outbound tracing — revision 2026-11-08.8

The updated bundle enables detailed tracing automatically for the same token-authorized, anonymous no-action requests. Replace the extracted scripts together; no production plugin release or wp-config.php edit is needed. Run from the extracted toolkit root. Replace the example domain/path with verified local values and use a trusted **unserved** directory permitted by web PHP:

```powershell
Unblock-File -LiteralPath '.\scripts\Invoke-WordPrIISBootstrapProfile.ps1', '.\scripts\Invoke-WordPrIISServerAudit.ps1'
$report = Join-Path 'C:\WordPrIISPrivate' ('WORDPRIIS-Bootstrap-' + [guid]::NewGuid().ToString('N'))
.\scripts\Invoke-WordPrIISBootstrapProfile.ps1 -Url 'https://wordpress.example.com' -OutputDirectory $report
```

Review the resulting private `report.json` locally; share only a redacted summary. Runner revision is `2026-11-08.8`; individual profile records now use `schema_version: 3`. Existing phase, aggregate HTTP, query-count and OPcache fields remain available.

Revision 8 adds the opt-in web-context filesystem metadata calibration in [Windows diagnostics](windows-performance.md), without changing revision-7 sampling reservations. Use the root `wordpress-iis.ps1 -Action Profile` or `-Action Diagnose` wrapper and reviewed JSON config.

### Narrow down Breakdance, WP Rocket and SEOPress initialization

Revision 6 adds `target_resources` and `target_plugin_load_intervals` for source files inside `breakdance`, `wp-rocket`, `wp-seopress` and `wp-seopress-pro`. No plugin source, Composer loader, autoloader order or PHP/IIS configuration is changed. Only the existing authorized short-lived profiling route enables instrumentation.

`target_resources` retains **at most 48 first-invocation resource samples**, partitioned by phase and priority independently of the top-64 aggregate callback list. It no longer lets early nested work consume later phases' samples. Each row links a callback ID/symbol/source/hook to:

| Field | What it measures |
|---|---|
| elapsed_ms / cpu_ms | Callback elapsed time and process user+system CPU delta. CPU is null when unavailable; coarse CPU counters and observer overhead make small differences unreliable. A gap can include scheduling, I/O and other waits, not just disk. |
| new_included_files / target_included_files | Newly included distinct files across all code / the four target plugins during this invocation. Repeated requires of an already included file and unsuccessful filesystem/autoload probes are not counted. |
| target_file_groups / target_file_examples | Up to 16 plugin/module groups (up to two directories below the plugin) with counts and 12 relative file examples. Omission counters report truncation. These are code paths, not file contents or absolute host paths. |
| declared_classes_delta / memory_delta_bytes | Newly declared class count and net PHP used-memory delta; neither class names nor memory contents are exported. Net memory may be negative and does not measure transient peak allocation. |

These deltas are **inclusive**: a parent contains nested callback work, files, classes and CPU. Never sum parents and children. Revision 7 replaces the request-wide first-128 policy with these bounded reservations:

- **Primary hooks:** four first-invocation target callback samples per plugin per lifecycle phase (`plugins_loaded`, `init`, `wp_loaded`, `shutdown`): at most 64 snapshot pairs. Output retains the eight longest sampled primary rows per phase, so early hooks cannot evict later-phase rows.
- **Nested hooks:** two first-invocation samples per plugin per phase: at most 32 pairs, independent of primary samples. Output retains the eight longest sampled nested rows.
- **Dynamic fields:** a separate eight-sample/output reservation for the exact `Breakdance\DynamicData\include_fields` symbol defined under the Breakdance plugin root. Its first invocation is retained even if ordinary quotas have filled. This does not force the callback to run or profile it if it is absent, dynamically unwrapped or skipped for reference/registration limits.

The maximum resource sampling budget is **104 pairs**, below revision 6's 128; output remains at most 48 rows. A successfully sampled callback registration is not resource-sampled again. `callback_timings` still counts/times all its wrapped invocations, so a first resource sample must not be presented as representative of every later call. Rows include `sampling_bucket` (`primary`, `nested`, `priority`). `resource_coverage` identifies the policy as `phase-plugin-first-invocation` and reports bucket sample/skip counts and `repeat_calls_skipped`. `callback_rows_dropped` combines budget skips and retention omissions, not intentionally deduplicated repeats. Other primary callbacks can still exceed their per-plugin/phase quota; this is targeted bounded coverage, not complete function profiling.

Nested discovery caches **WP_Hook object identity plus total callback count** in a weak map. Repeated dispatches of an unchanged hook reuse instrumentation; hooks without registered callbacks consume no scan quota. A changed callback count triggers a new scan, bounded to **32 scans per lifecycle phase**. Cache hits/empty dispatches are counted separately from budget skips. Same-count callback replacement, remove-and-add between observations, and callable introspection can still escape re-instrumentation; full callback fingerprints on every high-frequency filter would add overhead. Cache hits do not re-reflect or re-wrap callbacks.

Nested registration is limited to 128 of the overall 512 wrappers, preserving space for later primary hooks. The 64-frame limit and reference/dynamic-registration exclusions still apply. Nested target callbacks appear as `target-nested-hook`; arbitrary dynamic hook names are never exported. They are discovered only when a non-primary hook dispatches with an innermost active target callback. Direct PHP calls, hooks during main-file loading and callbacks added during a dispatch can remain unmeasured. `nested_dispatches_skipped` can remain nonzero during storms; inspect phase scan counts and the desired later resource row rather than treating nonzero deliberate omissions as failed profiling.

`target_plugin_load_intervals` contains up to 16 boundaries (with a dropped counter) ending at a target plugin's `plugin_loaded`/network/MU marker, with the same resource deltas since the previous plugin marker (or profiler initialization). It includes intervening core and hook work: **it is not an exclusive main-file timer**. Included-file snapshots are taken from PHP's in-memory list; no directory scan, source read, per-file stat, cache flush, forced autoload or script-by-script OPcache query is used. `resource_coverage.measurement_overhead_ms` reports resource snapshots/grouping/retention overhead, not all profiler overhead; instrumentation and child observers can inflate parent timings.

Use the report as follows:

1. Find the slow target callback in `callback_timings`, then match its ID in `target_resources`. Compare inclusive and self elapsed time with nested target callbacks.
2. Many newly included files, classes and one dominant directory group identify a **loading-heavy span** to inspect in that installed plugin version. Examples identify files present in that span, not the slowest individual files.
3. Few new files with high CPU suggests initialization/computation or repeated work; low CPU with high elapsed suggests waits/path lookup/security scanning among other possibilities. These are investigation leads, not causal proof. Examine any matching outbound trace and SQL count delta too; no SQL text or query duration is collected.
4. Compare later samples with the first. `web_opcache` adds safe effective timestamp/revalidation settings, `open_basedir_enabled` and `realpath_cache_used_bytes`. PHP documents that [open_basedir disables the realpath cache](https://www.php.net/manual/en/ini.core.php); this is context, not proof it caused this request's cost, and the profiler does not weaken it.

PHP's [included-file list](https://www.php.net/manual/en/function.get-included-files.php) provides successful inclusion membership, not durations. [getrusage](https://www.php.net/manual/en/function.getrusage.php) provides process resource counters. Exact per-file require/autoload time or direct internal function attribution requires a separate engine-level profiler in a controlled Windows stage; this MU tool does not claim those measurements. The actual commercial plugin versions are absent from the local fixture stage, so production attribution still needs the new owner-run report.

Verification passed: **48 resource assertions**, 32 existing dispatcher assertions, 27 gate/privacy assertions, 119 PowerShell runner checks, authenticated HTTPS/TLS regressions and three real WordPress HTTP samples using runner-generated code. The stage uses synthetic target-source files and does not load the commercial production plugins. Native Windows revision-6 profiling was pending at that test stage; the historical owner-run follow-up is summarized below.

Run the same command above with the rebuilt bundle and a new output directory. Confirm `runner_revision: 2026-11-08.8`, profile `schema_version: 3`, `status: complete` and all cleanup flags true. Keep `report.json` private; share only reviewed, redacted findings. [Revision-7 sampling verification](verification-results/bootstrap-profile-sampling-2026-11-08.json) records the 20,000-dispatch storm, late-field reservation, cache invalidation and platform limits. In the next production report, look for `Breakdance\DynamicData\include_fields` in `target_resources` with `hook: wp_loaded` and `sampling_bucket: priority`, together with sample/cache/phase counters. The prior [revision-6 verification](verification-results/bootstrap-profile-resources-2026-11-08.json) is retained.

### Identify slow callbacks

Each profile's `callback_timings` contains the **64 slowest measured callbacks by self_ms**, across `plugins_loaded`, `init`, `wp_loaded`, `shutdown` and the bounded target-nested dispatches:

| Field | Interpretation |
|---|---|
| callback / source / line | Symbol and definition location. Source paths are relative to WordPress/plugin/content roots; external locations are labeled `external`. Closures and anonymous classes are normalized so PHP 8.4 runtime names cannot expose absolute filenames. |
| hook / priority / calls | Action, original priority and invocation count. IDs are request-local and can link an HTTP call to its callback. |
| total_ms / max_ms | Inclusive elapsed time across calls / longest invocation. Includes nested work, HTTP and database waits; this is not CPU time. |
| self_ms | Elapsed time excluding nested **instrumented** callback invocations. Ordinary function calls, SQL and HTTP inside the callback remain included. Do not sum this with inclusive time or HTTP durations. |
| query_count / exceptions | Inclusive SQL query-count delta and propagated exception count; neither SQL nor exception text is recorded. Nested query deltas can overlap. |

Start with rows whose hook is `plugins_loaded`: this directly attributes the previously measured 477–533 ms span, including `wordpriis_initialize` rather than only The custom plugin's main-file include interval. Look at the other hooks separately. These timers add diagnostic overhead; compare repeated runs and avoid treating sub-millisecond differences as exact benchmarks.

The collector observes WordPress's `all` hook immediately before the selected action starts, and temporarily replaces existing callable entries **in place**, retaining WordPress's original unique IDs, priorities, insertion order and accepted-argument counts. Return values and exceptions propagate. Weak references avoid retaining removed callback objects. It does not alter callbacks for ordinary/invalid-token requests. It never replaces WP_Hook itself.

`callback_coverage` makes limits explicit: at most **512 registrations** are instrumented; output retains at most 64 executed rows. Reference-parameter/reference-return callbacks and reflection failures are skipped intact. The stack is bounded to 64 measured frames. Callbacks added after the dispatch snapshot, including dynamically registered callbacks, may execute unmeasured on that invocation; later invocations can wrap them. Replacements/introspection of callable objects by other code may also observe the diagnostic wrappers. Coverage is not a claim that every plugin function was profiled. A callback that exits/fatals before finally can appear in `active_callbacks` if the final snapshot runs; it has no completed duration. A shutdown callback that terminates shutdown entirely can prevent the report record.

### Attribute outbound calls

`http_calls` contains up to **32 request traces**, with excess counts reported. Each includes:

- `phase`, the active callback's request-local ID and symbol/definition metadata, plus the nearest non-transport caller. Caller `location` distinguishes a callsite from a wrapped callback definition; no full backtrace or arguments are exported.
- `started_ms`, observed `elapsed_ms`, method, blocking flag, configured timeout, safe HTTP status and outcome (`pending`, `response`, `wp-error` or `preempted`). Preempted calls have no measured transport duration. Nonblocking-call duration describes dispatch, not background completion.
- A coarse `destination`: `cron-loopback`, `same-site-or-loopback`, `paypal-sandbox`, `paypal-live`, `wordpress-service` or `external`. A cron category requires a same-site/loopback host and the installation's exact wp-cron.php path. Hostnames, URLs, credentials, query strings, bodies, headers and provider/error text are never saved. URL hashes used to pair nested same-URL calls remain in memory only.

To confirm the earlier one-second call, look for a completed trace with approximately 1,000 ms elapsed, phase `shutdown`, destination `cron-loopback`, and caller `spawn_cron` or an active `_wp_cron` callback. That combination would support cron attribution. An external category and another callback instead points to that plugin's request. No observed call does not prove cron is disabled: it may simply not have been due during the samples. The profiler does not force scheduled jobs or send test payments.

Only WordPress HTTP API calls after MU loading are observed. Earlier filters, direct sockets/cURL, HTTP calls before the profiler, and hooks replacing/preempting requests after the observer's same-priority filter can fall outside precise attribution. Pending/unpaired/drop counts expose some gaps. Nested call durations can overlap.

Logs remain private and bounded; the limit increases from 256 KiB to **2 MiB** for detailed records. No SAVEQUERIES, full stack dumps or permanent logging are enabled. Existing automatic expiry, ACL cleanup, no-body-change behavior and report retention are unchanged.

Verification: 27 PHP gate/file/privacy assertions, **32 real WordPress-dispatcher trace assertions**, 119 PowerShell runner checks, real HTTPS transport tests, and real WordPress HTTP integration passed. The staged integration verifies WORDPRIIS callback attribution, a known slow synthetic callback, and a synthetic cron-shaped request during shutdown; the existing stage HTTP guard preempts that request, so it sends no external traffic or cron job. The dispatcher tests separately exercise completed HTTP timing, WP_Error, preemption, nested same-URL pairing, callback order/removal/self-removal, return values, recursion, exceptions, object lifetime, reference skips, redaction and caps. The owner subsequently ran this revision successfully against production callbacks; see the follow-up findings at the end of this guide. [Saved verification](verification-results/bootstrap-profile-callback-trace-2026-11-08.json).

The hook behavior follows [WordPress do_action](https://developer.wordpress.org/reference/functions/do_action/), [WP_Hook dispatch](https://developer.wordpress.org/reference/classes/wp_hook/apply_filters/) and [pre_http_request](https://developer.wordpress.org/reference/hooks/pre_http_request/).

## Automatic profiling session (recommended)

Extract the [audit bundle](../.artifacts/wordpriis-tools.zip) into a local folder on the Windows IIS host. Keep `Invoke-WordPrIISBootstrapProfile.ps1`, `Invoke-WordPrIISServerAudit.ps1` and `wordpriis-bootstrap-profile.php` together. The repository files are under `scripts/`. Open **64-bit PowerShell as Administrator**, change to that folder and run:

```powershell
.\scripts\Invoke-WordPrIISBootstrapProfile.ps1 -Url 'https://wordpress.example.com'
```

If Windows reports **not digitally signed**, the downloaded files may carry an Internet-origin mark under RemoteSigned. After reviewing the bundle, unblock **both** PowerShell files (the runner imports the audit helper), then retry:

```powershell
Unblock-File -LiteralPath '.\scripts\Invoke-WordPrIISBootstrapProfile.ps1', '.\scripts\Invoke-WordPrIISServerAudit.ps1'
.\scripts\Invoke-WordPrIISBootstrapProfile.ps1 -Url 'https://wordpress.example.com'
```

This removes those files' download marks; it does not change execution policy. If still blocked, run `Get-ExecutionPolicy -List` to distinguish AllSigned/Restricted from RemoteSigned and identify MachinePolicy/UserPolicy enforcement. Unblock-File does not satisfy AllSigned; use a trusted signed copy or the administrator-approved execution procedure for that host. The runner cannot unblock itself before PowerShell loads it. [Microsoft Unblock-File guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-5.1) and [policy precedence](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).


The script automatically selects the unique IIS hostname binding, the installation's IIS application/virtual-directory mapping, its app pool, the configured worker account/SID, the enabled anonymous request identity/SID and matching PHP CLI. It supports ApplicationPoolIdentity, SpecificUser and built-in service identities; it never reads app-pool or anonymous-account passwords. Ambiguous sites are refused rather than guessed. A machine-wide per-installation mutex prevents concurrent runner sessions from publishing duplicate profiler functions.

It then creates a new protected directory under ProgramData, grants the detected runtime identities **read/write only to the empty profiling log** and read access to the new diagnostic code, generates a secret token, validates the PHP syntax, and atomically publishes one uniquely named MU file with a 15-minute expiry. The token is supplied to curl over stdin, not its command line. Three sequential HTTPS no-action AJAX requests should return **400**; one profile must appear for each. No wp-config.php edit or OPcache wait for an existing file is required. No services are restarted, and no IIS, cache, payment or firewall settings are changed. These are real WordPress requests, so normal initialization hooks/cron may still run.

Cleanup runs in `finally` on success or failure: remove the unchanged owned MU file, remove a newly created MU directory only if empty, delete the private code copy and revoke temporary runtime-identity ACL grants. Existing MU files/directories and their ACLs are preserved. If the temporary file was edited, it is retained and reported as `cleanup-incomplete` instead of deleting someone else's changes. Existing output directories are always refused. Existing privileged-account rights are not revoked.

The console prints **Report retained: ...**. Keep these files:

- `report.json`: detected site/pool, request timings, all available profiles, fixed failure codes and cleanup results. **Send this file back for analysis.** Review operational paths/SIDs before sharing; no tokens, passwords, raw HTTP bodies or raw exceptions are recorded.
- `bootstrap.jsonl`: raw profiler samples, retained even on a partial failure.
- `summary.md`: completion/sample counts and cleanup status.

A failed/partial run exits nonzero and preserves a report when its private directory could be secured. Preflight/discovery failures before that point print a fixed stage/reason instead of creating an unsafe report. Reports use a new directory each time; the default is `C:\ProgramData\WORDPRIIS-Bootstrap-<unique-id>`.

Optional overrides:

```powershell
# Explicit site when hostname bindings are ambiguous; new report directory only.
.\scripts\Invoke-WordPrIISBootstrapProfile.ps1 -Url 'https://wordpress.example.com' `
  -SiteName 'Example WordPress' -OutputDirectory 'C:\WORDPRIIS-Profile-Run1'

# Compare the direct-origin path, retaining hostname/SNI and certificate validation.
# Replace the example address with the actual origin IP; TLS failures are not bypassed.
.\scripts\Invoke-WordPrIISBootstrapProfile.ps1 -Url 'https://wordpress.example.com' `
  -OriginAddress '192.0.2.10'
```

`-Samples` accepts 1–10 (default 3); `-TimeoutSeconds` accepts 5–60 (default 30). `-Url` is the WordPress installation URL, including a subdirectory if used. For custom layouts, supply `-WordPressPath`, `-ContentPath`, `-MuPluginPath` or `-PhpPath`. Explicit WP_CONTENT_DIR/WPMU_PLUGIN_DIR definitions require the respective path override; configuration PHP is never evaluated. Reparse-point/UNC paths are refused, and output must be outside **all detected IIS roots/virtual directories**, WordPress and the content directory. The output parent must already exist. The script does not know about a separate web server's aliases; choose a genuinely unserved location.

IIS FastCGI may impersonate the configured anonymous request identity instead of the app-pool process account. Revision `2026-11-08.3` reads the effective wp-admin anonymous-authentication configuration and grants access to both exact SIDs when different, only on the newly created diagnostic code/directory/log. It grants no access to IIS_IUSRS or other broad groups, changes no existing site ACLs, and revokes all temporary report-file grants during cleanup. If anonymous identity discovery is unavailable, the report says so and retains the pool-only scope; it does not guess IUSR. This follows Microsoft's distinction between [IIS process and request-handler identities](https://learn.microsoft.com/en-us/iis/get-started/planning-for-security/secure-content-in-iis-through-file-system-acls). Other early exits, custom-content loaders or header filtering can still prevent recording. The exact cause of the owner's revision-2 failure remains unconfirmed until a new report is collected.

Normal PowerShell cancellation runs finally, but forcibly killing the process, power loss or reboot cannot guarantee cleanup. `report.json` includes the exact temporary MU path, SHA-256 and expiry once installed. After such an interruption, verify that hash and remove only that file; its gate expires after 15 minutes. If interruption happened before recovery metadata was written, inspect the unique `000-wordpriis-bootstrap-profile-<id>.php` file locally before removing it. Retained worker grants can be removed from the new report directory/file Security properties. Do not remove existing MU plugins or alter the site's general ACLs.

Validation: **119 portable runner checks** passed, including normal/error cleanup, preservation of edited/unrelated files and existing output, syntax rejection, ACL-cleanup failure reporting and secret redaction. Real curl HTTPS tests passed for stdin-token transport, public/direct-origin requests, expected 400 handling, response-body/cookie exclusion and rejection of untrusted TLS. The runner-generated embedded MU code also passed the real local WordPress staging check with three authorized samples and cleanup. The owner subsequently completed a revision-4 run on the actual Windows/IIS host with three profiles and all cleanup flags true. Three conditional Windows ACL checks remain in the test suite for local Windows execution; they were not run in the Linux container. [Runner verification evidence](verification-results/bootstrap-profile-runner-2026-11-08.json).

## Diagnose a transport failure

Runner revision `2026-11-08.2` retains `http_failure.curl_exit`, a fixed category, `metrics_valid` and (when recognized) a fixed Schannel TLS detail. Raw curl stderr is still discarded. Typical categories distinguish DNS (6), connection (7), timeout (28), TLS handshake (35), certificate verification (60) and CA-store access (77). Exit 0 with invalid timing output uses `curl-metrics-invalid`, rather than claiming a TLS failure. See [curl's official exit-code reference](https://curl.se/docs/manpage.html#EXIT).

The owner’s first run (`2026-11-08.1`) successfully discovered the intended IIS site/pool and installed the profiler; all three cleanup flags were true. It failed before recording a sample. That old combined `curl-transport-or-tls` code does not establish the actual cause, because it also covered invalid metrics. No performance conclusion can be drawn from that run.

Revision 2 starts curl with `--disable` as its first option. User/default curl configuration therefore cannot inject cookies, tracing, redirects or alternative output settings into token-bearing probes. Tests deliberately supply a conflicting curlrc and verify it is ignored. Certificate and revocation checks remain enabled; there is no insecure retry.

For a quick transport-only check without installing the profiler or sending its token:

```powershell
curl.exe --disable --silent --show-error --noproxy '*' `
  --connect-timeout 5 --max-time 30 --output NUL `
  --write-out 'HTTP=%{http_code} TTFB=%{time_starttransfer}' `
  'https://wordpress.example.com/wp-admin/admin-ajax.php'
"`ncurl exit code: $LASTEXITCODE"
```

HTTP 400/exit 0 is expected for this route. Share the curl exit/error and timing line, not verbose header traces. Do not work around a TLS failure with `-k`, disabling revocation or changing the trust store blindly. A Schannel revocation-unavailable category can indicate unreachable certificate revocation services; it needs host-side diagnosis rather than assuming an invalid server certificate.

### Windows PowerShell stdin compatibility

Revision `2026-11-08.4` explicitly selects UTF-8 without a BOM for curl's redirected configuration. Modern .NET uses StandardInputEncoding. Windows PowerShell 5.1's .NET Framework instead constructs the redirected writer from Console.InputEncoding: the runner temporarily supplies UTF-8/no-BOM before starting curl and restores the prior encoding immediately, including on failure. No persistent console, user or machine policy is changed. The token stays on stdin, never in process arguments or a config file. [Microsoft Framework source](https://github.com/microsoft/referencesource/blob/main/System/services/monitoring/system/diagnosticts/Process.cs).

Tests inspect bytes received by a real child process while the caller uses UTF-16 and BOM-bearing UTF-8, check restoration, and reproduce curl configuration rejection with UTF-16 input. Modern curl in the test environment returns 26 for that parser error; other versions may return 2. The owner's exit-2 failure after choosing an allowed output root is consistent with a config/init failure, but its exact stderr/host encoding was not captured, so this encoding cause remains unconfirmed on that host. Fixed `http_failure.option_detail` categories now distinguish unrecognized options, missing arguments and config-read/syntax failures without saving the offending option/token or raw stderr.

For the reported IIS installation, keep using an allowed unserved path rather than the ProgramData default:

```powershell
$report = Join-Path 'C:\WordPrIISPrivate' ('WORDPRIIS-Bootstrap-' + [guid]::NewGuid().ToString('N'))
.\scripts\Invoke-WordPrIISBootstrapProfile.ps1 -Url 'https://wordpress.example.com' -OutputDirectory $report
```

The runner still verifies that this new directory is outside all detected IIS roots. No PHP restriction or certificate checks are weakened. [Revision-4 verification](verification-results/bootstrap-profile-stdin-encoding-2026-11-08.json).

## Diagnose missing profiles

Revision `2026-11-08.3` collects only fixed, token-authorized diagnostic header values into each sample:

| `profiler_status` | Meaning |
|---|---|
| `absent` | No authenticated profiler status received: MU code may not have loaded/been readable, the request may have reached another site, or a request/response header may have been removed. This does not identify which cause. |
| `request-gate-rejected` | Token was valid, but method/path, cookie/auth, parameters or configuration did not satisfy the profiling gate. |
| `output-unavailable` | Private-file existence/writability/containment checks failed. ACLs and PHP open_basedir can both matter. |
| `output-open-failed` / `output-lock-failed` | The authorized request reached the profiler but could not open/lock the protected log. |
| `recording` | Startup checks passed and shutdown recording was registered. A missing record now points toward later write/termination problems. |

`web_impersonation` and `web_open_basedir` are fixed enabled/disabled/unknown indicators from the real PHP request; no configured paths or account credentials are returned in headers. An enabled open_basedir with unavailable output may require a new `-OutputDirectory` under an already permitted **unserved** parent. Do not disable the restriction or place logs in the web root. `cache_status` retains only recognized Cloudflare cache states; a HIT needs bypass investigation.

The profiler emits these headers only for a valid token within its collection window. Ordinary/invalid-token requests receive none, response bodies remain unchanged, and no raw headers/cookies are saved. The real WordPress test now reproduces an unreadable log and verifies `output-unavailable` without creating a profile; it also checks normal/cookie/invalid-token exclusions. [Revision-3 evidence](verification-results/bootstrap-profile-runtime-identity-2026-11-08.json).

### Observed open_basedir restriction on the IIS host

The owner's revision-3 report reached the profiler and returned `profiler_status=output-unavailable`, `web_open_basedir=enabled`, `web_impersonation=disabled` and HTTP 400/Cloudflare DYNAMIC at 5,524.915 ms TTFB. The discovered anonymous and pool SIDs matched. All cleanup flags were true. This rules out a missing/stripped request token or unreadable MU file for that request; it does not prove which filesystem check failed. The default ProgramData output being outside PHP's allowed trees is the leading explanation, pending inspection of the actual permitted paths.

Use a new `-OutputDirectory` below an already allowed private/unserved parent once identified. The same script can be reused; do not disable open_basedir, grant additional broad ACLs or move reports into WordPress. To inspect only relevant setting lines locally:

```powershell
$files = @(
    'C:\Program Files\PHP\v8.4\php.ini'
    'C:\inetpub\wwwroot\wordpress\.user.ini'
    'C:\inetpub\wwwroot\wordpress\wp-admin\.user.ini'
)
foreach ($file in $files) {
    if (Test-Path -LiteralPath $file) {
        Select-String -LiteralPath $file -Pattern '^\s*open_basedir\s*=' |
            Select-Object Path, LineNumber, Line
    }
}
```

This is configuration evidence, not a guaranteed full effective web-SAPI listing: another scanned ini, IIS/registry per-directory setting or runtime tightening may also apply. Share only the matched setting lines, never full PHP/IIS/wp-config files. If no unserved allowed tree exists, review a narrowly scoped configuration change rather than bypassing the guard.

[PHP documents](https://www.php.net/manual/en/ini.core.php#ini.open-basedir) that open_basedir also disables the realpath cache. That makes it relevant to the remaining performance investigation even if a CLI audit showed a configured 4 MiB realpath-cache size. It is a possible contributor, not a measured attribution of the observed 5.5 seconds; profile the actual request before changing the restriction.

## Manual installation fallback on the IIS host

Test this procedure in staging first. The file records only anonymous GET requests to `wp-admin/admin-ajax.php` with **no query parameters or POST data** and a matching secret header. Normal requests, cookies, Authorization headers, expired configurations and missing private files do not activate recording. No action handler, payment, customer session or page render is exercised. WordPress initialization itself can run normal plugin hooks/cron; this is an actual request, unlike the no-bootstrap audit helper.

1. Identify the site's actual app-pool identity and every web root/virtual directory. Create an empty `C:\WORDPRIISDiagnostics\bootstrap.jsonl` **outside all served directories**. Remove inherited broad access; grant Administrators/SYSTEM access and only the actual PHP runtime identity/identities (pool plus configured anonymous account if impersonation is used) the read/write access needed for this file. Do not grant IIS_IUSRS broad access to the diagnostic directory. The profiler checks containment against ABSPATH and WP_CONTENT_DIR; only the owner can verify other IIS aliases/sites. It does not create the file or change ACLs.
2. Generate a fresh token in PowerShell 5.1+ and keep that shell open. Do not paste the token into chat or save it in Git:

   ```powershell
   $bytes = New-Object byte[] 32
   $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
   $rng.GetBytes($bytes); $rng.Dispose()
   $token = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
   $sha = [Security.Cryptography.SHA256]::Create()
   $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($token))).Replace('-', '').ToLowerInvariant()
   $sha.Dispose()
   $until = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 900
   "define('WORDPRIIS_PROFILE_TOKEN_SHA256', '$hash');"
   "define('WORDPRIIS_PROFILE_UNTIL', $until);"
   "define('WORDPRIIS_PROFILE_FILE', 'C:/WORDPRIISDiagnostics/bootstrap.jsonl');"
   ```

3. Back up wp-config.php privately outside the web roots. Add the three **printed defines** before WordPress is loaded. The raw token is not stored in wp-config.php. Expiry must be an integer Unix timestamp within the next 30 minutes; the example uses 15 minutes. Wait for the configured OPcache revalidation interval when changing existing PHP files.
4. Copy [scripts/wordpriis-bootstrap-profile.php](../scripts/wordpriis-bootstrap-profile.php) to the site's `wp-content/mu-plugins/000-wordpriis-bootstrap-profile.php`. Create mu-plugins if absent with the site's normal code-file ACLs. The early filename maximizes MU-plugin coverage; other MU plugins that sort earlier remain in the pre-MU interval. There is no activation screen.
5. Run three sequential probes from the same PowerShell session. The header is passed on stdin rather than exposed in curl's command line. No browser cookies are sent. Do not add a query string or `-k`:

   ```powershell
   1..3 | ForEach-Object {
       @(
           'url = "https://wordpress.example.com/wp-admin/admin-ajax.php"'
           "header = `"X-WORDPRIIS-Profile: $token`""
           'header = "Cache-Control: no-cache"'
           'output = "NUL"'
           'silent'
           'show-error'
           'max-time = 30'
           'write-out = "status=%{http_code} ttfb=%{time_starttransfer}\n"'
       ) | curl.exe --config -
   }
   ```

   Status **400 with body `0`** is expected for no-action AJAX. Do not use curl `--fail`, which would treat that expected status as a transport failure. If the private JSONL file remains empty, check clock/expiry, token shell, selected IIS application, actual worker ACLs, MU-file installation/OPcache revalidation, header forwarding and cookie/query exclusion. No diagnostic body is printed; token-authorized requests receive fixed profiler-status/context headers. Check local PHP errors privately if required; do not enable public display_errors. Do not configure request-header logging for the token.
6. Read the private JSONL file. Each line is one sample; it stops accepting new records at **2 MiB**. Remove the temporary MU file and all three config defines after collecting the samples, clear `$token` from the shell and retain/delete the protected log according to local practice. Expiry disables collection but does not remove installed code. Keep these diagnostics out of the release ZIP and do not commit production profiles without reviewing them.

If Cloudflare strips the header or blocks the request, use curl's `resolve` config entry with the correct origin IP and the existing hostname, preserving TLS/SNI/certificate validation. Do not expose a new public PHP probe. Compare public and origin timings separately; do not assume a request cache hint guarantees bypass.

## Read the phases

| Evidence | Meaning and next step |
|---|---|
| `pre_mu_ms` dominates | Time since PHP request start before this MU file: core/database connection, early cache drop-ins and earlier MU files. It does not separate those components or measure IIS queue/network time. Check actual object-cache health/connection latency and early loading, then use a bounded private FREB trace if necessary. |
| Gap before `plugin_loaded:directory/file.php` | Approximate interval ending after that plugin loads. It also includes intervening core work and callbacks; it is not exclusive plugin execution time. Reproduce/isolate the candidate in staging rather than disabling production plugins indiscriminately. |
| Hook `enter` to `leave` | Approximate aggregate callbacks for that hook. Large `init` or `plugins_loaded` spans identify a stage for deeper profiling. Callbacks using the same extreme priorities can fall outside a marker. |
| `http_observed_ms` is large | Inclusive time of matched, synchronous WordPress HTTP API calls observed after MU loading; can include transport and filter work. Nested calls can overlap. No destinations, arguments or responses are saved. Direct cURL/socket calls and preempted requests are not covered; pending/unpaired counts expose some coverage gaps. |
| PHP profile is fast but client TTFB remains slow | Investigate IIS/FastCGI queue, startup/recycling, TLS/proxy/network or work before PHP request timing. Use [Microsoft's bounded Failed Request Tracing procedure](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/troubleshoot-php-with-failed-request-tracing); protect traces, restrict the route/time window and disable tracing afterward. Traces can contain sensitive headers. |
| `web_opcache` | Actual web-SAPI aggregate availability/fullness/memory/hit rate, unlike CLI configuration. The hit rate is worker/cache lifetime data, not a per-request performance result; unavailable/restricted status is omitted. |

Markers use monotonic elapsed milliseconds since profiler loading. `pre_mu_ms` uses PHP's wall-clock request-start timestamp and is approximate. Records include status, query **count**, peak memory, phase markers and aggregate HTTP counters; they never enable SAVEQUERIES or record SQL, values, request URLs, IPs, cookies, tokens, full paths or error text. Plugin directory/file slugs are recorded. At most 128 markers are retained. Normal requests still execute the small gate check while the temporary file is installed.

No-action AJAX loads WordPress through `wp_loaded` and then exits **before `admin_init`** in the tested core. An absent admin_init marker is expected. This profile cannot establish performance of checkout, logged-in administration or a full page.

## Reproduce verification locally

Run the isolated verification harness from this repository:

```sh
bash container/verify.sh
```

It runs the authorization/privacy, callback tracing, resource sampling and filesystem regressions, then starts the disposable `wordpriis-verify` pod on loopback port 8108. The runner-generated MU wrapper is exercised with three authorized requests plus ordinary/cookie/token exclusion probes. Cleanup removes the owned pod and networks. Historical fixture evidence below predates this harness and is not a new performance measurement.

The real WordPress fixture-stage run preserved status 400/body `0`, recorded only the three authorized probes and reached wp_loaded in each. Client elapsed times were 9.221–10.130 ms; web-SAPI OPcache was enabled and not full. This is a small local stage with different plugins/OS/HTTP path; it does **not** explain or clear production's remaining delay. [Saved local evidence](verification-results/bootstrap-profile-stage-2026-11-08.json).

Hook semantics: [plugin_loaded](https://developer.wordpress.org/reference/hooks/plugin_loaded/), [muplugins_loaded](https://developer.wordpress.org/reference/hooks/muplugins_loaded/), [http_api_debug](https://developer.wordpress.org/reference/hooks/http_api_debug/) and [WordPress hook sequence](https://developer.wordpress.org/apis/hooks/action-reference/).

## First successful production run

The owner completed revision `2026-11-08.4` with three profiles and all cleanup flags true, using an output directory under the already permitted private automation tree. Public TTFB was 5.454 s, 1.236 s and 1.187 s. The largest later hook span was plugins_loaded (477–533 ms); individual callback attribution remains outstanding. See [the measured findings and limits](production-bootstrap-findings-2026-11-08.md). Native Windows/IIS profiling has now succeeded on this host; this does not mean the hosted CI jobs have run.

## Successful production callback attribution

The owner completed revision `2026-11-08.5` with 300 instrumented registrations, no cap/reference/reflection drops and complete cleanup. It confirmed the one-second shutdown HTTP call as spawn_cron and identified Breakdance/WP Rocket/Imagify/SEOPress among the largest recurring callbacks. The top-64 limit omitted exact WORDPRIIS callback durations. See [the follow-up findings](production-bootstrap-findings-2026-11-08.md#callback-attribution-confirmed-revision-5). No runtime or scheduler change was made from this workspace.


## Production revision-6 follow-up

The owner successfully ran revision 6 on IIS with complete cleanup. It attributed Breakdance's element initialization to 185 included element files/175 classes, WP Rocket startup to a 614-file span dominated by Engine code, and SEOPress Pro's earlier main-load interval to service loading. The warm AJAX baseline remains about 1.2 seconds. Resource and nested-dispatch caps were reached, so later dynamic-field resource attribution remains incomplete. See [the findings summary and coverage limits](production-bootstrap-findings-2026-11-08.md#confirmed-findings). This owner-run production result supersedes the earlier pending-production statement for revision 6; no hosted CI result is claimed.


## Production revision-7 follow-up

The owner completed revision 7 with successful cleanup. Breakdance dynamic-field resource details were retained in all three priority samples: 128 included files, 122 classes and 113–118 ms. Only 41 resource samples and 32 nested scans were needed; no nested scan-budget skips occurred. Deliberate per-bucket and nested-wrapper omissions remain visible. The production run supersedes the earlier pending owner-run status, while native bootstrap acceptance remains a separate check. See [the summarized results and limits](production-bootstrap-findings-2026-11-08.md).
