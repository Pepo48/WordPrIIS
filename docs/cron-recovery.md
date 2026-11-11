# Recover a missing permanent cron runtime

A Task Scheduler entry is not the complete cron service. Its private runtime contains the runner, config, lock and completion files; the MU gate references those paths. Do not delete it with temporary profiling reports. New installations have a stable `Permanent-WordPressCron-<site-hash>` name, a `KEEP-THIS-DIRECTORY.txt` marker and an explicit retained-runtime warning. Existing installations are not renamed automatically.

`LastTaskResult = 2147942667` is `0x8007010B` (Win32 `ERROR_DIRECTORY`, 267): the directory name is invalid. Check the task's WorkingDirectory, its existence, syntax and the service account's access. A displayed LastRunTime records an attempted launch, not successful PHP cron completion. [Microsoft error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).

Password logon supports noninteractive execution while the user is logged out. InteractiveToken does not. Password expiry, batch-logon policy and filesystem permissions still matter. [Microsoft logon types](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type).

## Immediate availability

If the runtime is missing, temporarily change the **existing** wp-config.php definition to `define( 'DISABLE_WP_CRON', false );`; do not add a duplicate. This restores visitor-triggered scheduling until a replacement task has proved completion. The loopback performance cost can return temporarily. A completely cached page may not bootstrap WordPress, so validate due jobs through an uncached request too. This does not by itself prove every plugin job succeeds.

A complete secure backup can be restored to the original path with its ACLs and matching gate/task. Do not recreate an empty directory or mix newly renamed scripts with an old config/protocol. If no complete backup exists, use the coordinated replacement below.

## Single-command recovery

Extract the **complete current toolkit** outside all web roots. Open elevated 64-bit Windows PowerShell 5.1 in its root and run:

```powershell
.\scripts\Recover-WordPressCron.ps1
```

No local configuration file is required. The script prompts for the existing task account password; the password is not passed in command arguments or written to reports. Do not run Bootstrap. This entry point uses bundled helpers, so copying only this one file is insufficient.

The script detects WordPress IIS application roots and HTTPS bindings, then matches a single missing-runtime cron task to the MU gate containing its exact lock path. IIS discovery resolves the PHP handler and worker identity. Custom content/MU paths or ambiguous matches require local inspection; the script stops instead of guessing. With an explicit HTTPS `-Url`, a matching named HTTP origin binding is supported for reverse-proxy deployments; an unnamed binding also requires an explicit `-SiteName`. The public request remains HTTPS with normal certificate validation. To disambiguate an HTTPS binding or task:

```powershell
.\scripts\Recover-WordPressCron.ps1 -Url 'https://your-site.example/' `
    -TaskName 'Existing WordPress Cron task name' -SiteName 'Existing IIS site name'
```

`-TaskPath` selects a non-root scheduler folder. `-TaskAccount` optionally restricts discovery to an existing account. By default, the account is detected from the selected task. The supplied credential must match the selected task account by SID.

Before replacing anything, it retains private copies of wp-config.php, the old task XML and the exact old gate. It tokenizes configuration without executing it, restores visitor-triggered cron using an atomic, hash-checked edit, and preserves the config ACL. It then disables the broken task and removes only the hash-matched gate. The verified installer creates a new permanent runtime under the original parent, applies permissions and verifies manual and automatic canaries before disabling request-triggered cron. It also verifies cron after the config change and a normal run. Only a complete installer result permits unregistering the old task.

The folder is named `Permanent-WordPressCron-Recovered-<id>` and contains `KEEP-THIS-DIRECTORY.txt`. **Keep this folder permanently.** It holds private operational credentials and configuration backups; keep it outside web roots and preserve its permissions. The existing parent must remain trusted, PHP-allowed and on the wp-config volume.

## Failure and follow-up

A failure prints only a fixed stage/code and, once available, a private recovery-report path. Keep that report and the install-report.json in the replacement runtime. Never share config backups, task XML, runtime config or tokens in chat. Do not remove a retained replacement task/gate blindly. Installer rollback restores the visitor-cron state it received; an incomplete rollback requires local inspection. A successful replacement is retained even if unregistering the old disabled task fails.

After success, check LastTaskResult and `task-last.json` (`phase: normal`, `cron_complete: true`), then verify automatic execution while logged out. Inspect plugin due jobs and purge stale page caches. Canary completion proves the bridge and test callback, not every plugin job.

Portable recovery tests exercise real temporary files and the transaction while mocking IIS, ACLs, credentials and Task Scheduler. The installer has separate config, proof and stage regressions. An operator-reported native Windows recovery completed on 11 November 2026, including manual/automatic canaries and post-config verification. Automatic execution after logging out and success of individual plugin jobs remain acceptance checks. A Linux container does not validate Windows logon rights or ACLs.

## Diagnose a missing or ambiguous match

```powershell
.\scripts\Recover-WordPressCron.ps1 -Diagnose -Url 'https://your-site.example/' -SiteName 'Existing IIS site name'
```

This makes no changes and does not request a password. It prints only counts: named task/account/action matches, missing runtimes, site routes, MU directories, unique gates, exact lock-path matches and final candidate pairs. Zero site routes means no usable binding/application match; provide the public HTTPS URL and exact IIS site for an unnamed/proxied binding. Multiple pairs require explicit task/site/URL selection. A missing gate or lock-path mismatch requires local inspection; do not remove unrelated MU files or weaken the match. Discovery failures print these counts automatically.

## Configuration planner diagnostics

A fixed `config-*` reason identifies why a configuration cannot be planned. Do not share wp-config.php, configuration backups or candidate files. Use the following read-only helper with your detected PHP executable and actual config path:

```powershell
& 'C:\PHP\php.exe' -d register_argc_argv=1 -d display_errors=0 -d log_errors=0 `
    '.\scripts\cron-config.php' '--config=C:\Sites\WordPress\wp-config.php' --diagnose
```

It prints only supported/previous boolean state or a fixed failure code; it creates no candidate and executes no WordPress configuration. Conditional/duplicate/nonliteral cron definitions and custom bootstrap includes remain unsupported. Standard installer-generated definitions after the closing ABSPATH guard are supported, including recovery/reinstall round trips. A `visitor-cron` planning failure occurs before the old task is disabled or its gate removed; private backups may already exist. Preserve them until recovery succeeds.
