# Verified Windows Task Scheduler cron

This replaces visitor-triggered WP-Cron only after the existing service account has executed real canary callbacks through Task Scheduler. It uses the IIS/PHP discovery from the audit tools and keeps operational status lightweight. No WordPress core files are patched.

## Run on the IIS server

Extract the diagnostic bundle into a private tools folder such as `C:\AuditReports\wordpriis-server-audit`. Keep all supplied files together. Open **64-bit Windows PowerShell 5.1 as Administrator** and run:

```powershell
cd 'C:\AuditReports\wordpriis-server-audit'
Unblock-File -LiteralPath '.\scripts\Install-VerifiedWordPressCron.ps1', '.\scripts\Invoke-WordPrIISCronTask.ps1', '.\scripts\Invoke-WordPrIISBootstrapProfile.ps1', '.\scripts\Invoke-WordPrIISServerAudit.ps1'

$account = "$env:COMPUTERNAME\wordpress_service"
$credential = Get-Credential -UserName $account -Message 'Existing WordPress service account'
$runtime = Join-Path 'C:\WordPrIISPrivate' ('WORDPRIIS-Cron-' + [guid]::NewGuid().ToString('N'))

.\scripts\Install-VerifiedWordPressCron.ps1 `
    -Url 'https://wordpress.example.com' `
    -TaskAccount $account `
    -TaskCredential $credential `
    -RuntimeDirectory $runtime
```

Enter the password locally in the credential prompt. Do not paste it in chat, use plaintext `-Password` arguments or save it in scripts. The installer resolves the requested account and credential username to the same SID. It passes the password to Windows Task Scheduler's registration API only; it is not written to the report, action arguments or runtime configuration. Windows manages the registered task's protected credential. The script does not create accounts, reset passwords, add group memberships, explicitly grant logon rights or bypass execution policy. Existing privileged-account rights are not removed. Account password expiry/rotation still needs updating in Task Scheduler.

The checked-out WordPrIIS source did not contain this account's provisioning, so host resolution and actual scheduled logon are authoritative. A batch-logon denial, invalid password, execution-policy restriction, inaccessible PHP output or TLS/WAF error prevents the config switch. Diagnose the actual policy instead of giving the account administrator privileges.

`C:\WordPrIISPrivate` is used because this host's PHP open_basedir permits it; the ProgramData default used by earlier profiling did not. RuntimeDirectory must be **new**, have an existing trusted parent, be local/non-reparse and outside all detected IIS/WordPress roots and virtual-directory aliases. It must share the wp-config.php volume for atomic publication. Existing directories, tasks and cron gate modules are never overwritten. Other web servers/aliases still require owner verification. Specify `-SiteName`, `-WordPressPath`, `-ContentPath`, `-MuPluginPath`, `-PhpPath` or a custom `-TaskName` where needed.

The default task name is `WORDPRIIS WordPress Cron - Example WordPress`. Frequency is every minute (`-IntervalMinutes 1`, range 1–15). HTTP timeout defaults to 120 seconds (`-RequestTimeoutSeconds`); PHP completion timeout is 300 seconds (`-JobTimeoutSeconds`). The task execution limit covers both plus a margin. Verification timeout is 240 seconds per checkpoint (`-VerificationTimeoutSeconds`); the automatic-trigger checkpoint additionally allows one recurrence interval. Setup normally takes several minutes and can wait for PHP's existing OPcache revalidation. It prints progress; leave the window open.

`-OriginAddress <actual-IP>` optionally targets the origin with the configured hostname/SNI and valid certificate verification. No `-k`/insecure retry, proxy credential or public diagnostic endpoint is added. DNS, TLS, firewall, WAF and certificate trust must also work under the service account, not just the administrator's session.

## What must pass before request cron is disabled

1. Discover the unique IIS site/application, matching PHP, config and runtime identities. Plan the byte-preserving config edit and validate candidate PHP syntax without executing wp-config.php. Keep an exact administrator-only backup outside the web roots.
2. Install a cron-only lock/completion MU bridge and a temporary token-gated canary. Create the recurring task under `wordpress_service` with Password logon and **Limited** run level, independent of the interactive login. No elevation or machine-wide policy bypass is embedded in the action.
3. Manually start that **registered task** and require matching task result, PHP completion receipt and an executed due canary callback. HTTP 200 alone is explicitly insufficient: wp-cron.php may flush the response before loading WordPress.
4. Wait for a **distinct automatic trigger** to execute the same proof, with wp-config.php still unchanged.
5. Atomically enable the literal DISABLE_WP_CRON setting, preserving the config's other bytes, newline style and ACL. Verify another scheduled callback sees **DISABLE_WP_CRON=true** in the real web SAPI. A literal true already present is left unchanged; an already true runtime setting is also preserved when no literal exists.
6. Clear only the setup's random synthetic hook, remove its canary/token verification state, and verify a normal task run completes through the permanent bridge. Retain the task, runtime files and report.

The task runs real due WordPress jobs, not just the canary; normal site notifications, updates and other scheduled work can execute. Successful canary/completion checks demonstrate the dispatch and callback path, not that every plugin job is logically healthy.

## Non-overlap and private status

Task Scheduler uses `MultipleInstances=IgnoreNew`. In addition, `cron-gate.php` holds an OS file lock until PHP shutdown finishes, covering early response flushing. The task action waits for its **own run-ID completion receipt** rather than accepting an unrelated run's marker. Busy calls are skipped without running a second wp-cron instance; they do not satisfy installation proof. PHP fatal failures and completion timeouts fail the task. The bridge serializes this host's wp-cron.php executions; separate WP-CLI workers, other nodes and unrelated asynchronous plugin workers are outside this lock.

The permanent MU gate is named `000-wordpriis-cron-gate-<id>.php` and does nothing for ordinary page requests. It checks a private random header token before writing completion receipts; it does not make the otherwise public cron endpoint a new authentication boundary. An unauthenticated existing caller remains usable under the lock. If the bridge cannot open its lock, authenticated task requests fail; legacy callers retain WordPress's original availability behavior. The token grants no payment, admin, upload or download entitlement.

Runtime code/config files are administrator/SYSTEM-owned with read access for the chosen task account. PHP gets only the directory traversal/read and data-file/run-receipt permissions required by the bridge. The isolated `run-results` directory allows data creation/deletion, not edits to task code or config. The backup/candidate wp-config files remain administrator-only. If the installer/task/PHP identities share an SID or existing administrator privileges, ACLs cannot separate those pre-existing privileges; no rights are silently revoked.

The task stores its random bridge token in the protected `config.json`; this is **not** the Windows account password or a PayPal credential. A precreated protected `request.curl` carries the header during curl execution and is emptied afterward, avoiding passwords/tokens in process arguments and avoiding console/stdin encoding dependencies in noninteractive Windows PowerShell. Hard termination can leave that protected file populated; it must remain private. No raw HTTP body, cookies, headers, error messages, SQL or customer values are saved.

Retained files:

| File | Use |
|---|---|
| `install-report.json` | Setup checkpoints, task/site/SID, hashes, recovery paths and rollback/cleanup status. **Share this report, not the entire folder.** |
| `task-last.json` | Latest task attempt: time, run ID, phase, HTTP timing, PHP complete/busy/failure state and redacted failure category. |
| `cron-last.json` | Latest authenticated PHP bridge status; correlate its run ID with task-last.json. |
| `run-results/*.json` | Per-run PHP receipts. The task consumes its own; stale receipts are pruned after 24 hours with bounded scanning. |
| `config.json` / scripts | Durable task action and private header token. Keep restricted; do not upload or commit them. |
| `wp-config.before.php` | **Contains production configuration secrets.** Exact private rollback backup; never send it with the report. |

A normal success has phase `normal`, `cron_complete=true` and Task Scheduler LastTaskResult 0. A busy run has `cron_complete=false` and must not be mistaken for executed work. Repeated failure/busy states, a stale task-last timestamp or nonzero Task Scheduler result need investigation. Keep the runtime folder: the registered action and permanent MU gate depend on it. No monitoring agent, global debug logging or automatic external alert service is installed.

## Failure and recovery

Before the switch, any verification failure leaves wp-config.php unchanged and removes only the task/modules created by this attempt. After the switch, failure attempts to restore the exact original bytes/ACL and verifies that a web canary sees visitor cron enabled again before removing the preverified task. OPcache revalidation may delay that proof. If config changed concurrently or effective rollback cannot be verified, the installer **retains the preverified task and permanent gate**, reports `rollback-incomplete`, and does not overwrite an owner's changes. Inspect the report before removing anything.

The temporary canary is hash-checked before removal. Edited files are retained and reported instead of deleted. Cleanup tries to clear its random synthetic hook and revoke canary-proof permissions; a cleanup failure is explicit. No unrelated jobs, plugins, scheduled tasks or options are removed. The script refuses reruns over an existing task/runtime/gate; use the report to inspect or recover the existing installation first.

Do not close/kill setup during its transaction. Normal errors run cleanup; forced termination/reboot cannot guarantee it. The task remains capable of normal runs after its temporary verification state expires, so an interrupted post-switch setup does not disable the scheduler after the canary window ends. The report records the exact task, gate/canary paths and hashes and private backup location. Before an uninstall, restore/verify the prior visitor-cron setting or establish another scheduler, then remove the specific task and gate. Do not delete the runtime directory while its task or gate remains active. Do not blindly restore an old full wp-config backup over later edits.

Config editing is deliberately conservative: literal DISABLE_WP_CRON values and the standard top-level `require_once ABSPATH . 'wp-settings.php';` layout are supported. Conditional/dynamic flag definitions, eval, delegated config includes, duplicate definitions and custom bootstrap layouts require manual review and are refused before task activation. The installer does not evaluate config code to guess its intent.

## Upstream issue and scope

[WordPress #63858](https://core.trac.wordpress.org/ticket/63858?cnum_hist=6&cversion=0) was fixed by moving cron dispatch to shutdown; the [6.9 performance guide](https://make.wordpress.org/core/2025/11/18/wordpress-6-9-frontend-performance-field-guide/#spawn-wp-cron-at-shutdown-instead-of-init) describes that mitigation. The production profile already showed shutdown dispatch. [Requests #826](https://github.com/WordPress/Requests/issues/826) documents blocking=false behavior, and the [bundled cURL transport](https://github.com/WordPress/WordPress/blob/master/wp-includes/Requests/src/Transport/Curl.php) rounds short timeouts upward. The scheduler removes visitor-triggered dispatch; it does not reapply that core patch or fix the separate ~1.2-second plugin initialization baseline. Measure after deployment rather than claiming a guaranteed one-second TTFB improvement.

Primary setup guidance: [WordPress external scheduler](https://developer.wordpress.org/plugins/cron/hooking-wp-cron-into-the-system-task-scheduler/), [Microsoft task triggers](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger) and [task principals](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal).

## Verification and future home

Regression coverage uses real temporary config files and atomic replacement with mocked Windows task/IIS APIs; native PHP child processes for locking, fatal reporting and independent receipts; early-200 HTTPS fixtures for the real task action; and a real WordPress canary/completion run in the disposable Podman stage. The stage already has DISABLE_WP_CRON=true and retains it; false-to-true/rollback transaction tests use temp files separately. No production task has been registered from this workspace. Native Windows scheduled logon, trigger execution, account/GPO behavior and ACL deployment remain to be verified by running the guarded installer on the actual host. Run the portable checks locally under Windows PowerShell 5.1 and PowerShell 7 as documented in TESTSUITE.md; no hosted CI workflow is shipped.

Build the standalone bundle with `python3 scripts/package.py`. Test commands are recorded in TESTSUITE.md and the local container harness. The standalone toolkit includes these tools/fixtures; it is separate from any application plugin ZIP. See [saved verification results](verification-results/windows-cron-setup-2026-11-08.json): 65 historical setup transaction, 11 proof, 7 task definition, 17 config and 10 PHP gate assertions passed, together with HTTPS task fixtures, real WordPress callbacks and the existing profiler regressions. The later namespace-clean run passed 67 setup assertions, including cross-namespace existing-gate refusal; see [the latest namespace verification](verification-results/namespace-cleanup-2026-11-08.json).

The shared audit, profiling and cron tooling now lives in WordPrIIS. The refactored dispatcher and standalone commands replace the old installer; see the root README and TESTSUITE for current setup, testing and native Windows acceptance requirements. Historical owner-run results above remain unchanged.
