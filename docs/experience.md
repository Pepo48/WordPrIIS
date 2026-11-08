# Experience behind the defaults

Site names, domains, accounts and paths in this repository are anonymized examples. Replace them with locally verified values; timing and version observations retain their original meaning.

This record separates owner-observed production facts from proposed defaults. It contains no database passwords, API tokens, salts, private keys, WordPress configuration dumps or raw trace files. Domain/account/path names are operational metadata and still warrant review before sharing.

## What was actually observed

As of 8 November 2026: Windows Server 2022, IIS site **Example WordPress**, pool **WordPress**, WordPress root `C:\inetpub\wwwroot\wordpress`, PHP under `C:\Program Files\PHP\v8.4`, and existing local service account **wordpress_service**. RDP management uses ZeroTier; SMB is not used. This toolkit does not broaden that access.

The observed PHP web restriction permits the WordPress root, Windows TEMP and `C:\WordPrIISPrivate`. ProgramData profiling output failed because PHP could not write there; the allowed, private automation location worked. Do not copy those paths onto an unrelated host without inspection.

- Database connect/auth time dropped from approximately 2053 ms to about 1 ms after the owner changed local DB transport from localhost to 127.0.0.1. This does not mean all localhost use is slow on every machine; the audit has a bounded identity-checked comparison.
- A one-second outbound request was attributed to spawn_cron at shutdown. A real Windows scheduled task was verified manually and automatically under the existing service-account credential before DISABLE_WP_CRON was changed. The owner confirmed post-change web settings, normal task completion and cleanup.
- Warm anonymous no-action AJAX still takes around 1.2 seconds. File-heavy Breakdance element/dynamic-field loading, WP Rocket initialization and SEOPress service/Action loading account for substantial elapsed time. Those spans do not prove defective plugins: the owner reports the same stack is fast on Linux/Plesk, but no comparable Linux trace is available.
- Revision-7 sampling captured Breakdance dynamic fields in all three requests: 128 included files, 122 classes, 113–118 ms. Bounded phase quotas and cached nested-hook scans reduced sampled calls from 128 to 41 and eliminated scan-budget skips. Deliberate callback omissions remain documented.
- OPcache is enabled, not full and has ample free memory. open_basedir is enabled and realpath-cache usage is zero. Increasing cache capacity is not an evidence-based fix for the remaining baseline.
- IIS had an unconditional one-year Cache-Control custom header in addition to a separate 30-day static policy. The unconditional header appeared on dynamic/error responses. Removing/narrowing it and testing origin/edge error behavior are separate from measuring PHP speed; the saved profile does not prove that cache remediation was deployed.

Database name/user/prefix, exact certificate, artifact provenance and current effective host configuration must be rechecked locally; they are not inferred from secret configuration. `config/existing-site.example.json` is an operations starting point with placeholders for those fields, not a complete server export.

## What changed in WordPrIIS

The old imperative modules, root-password command arguments, web-root rollback scripts, firewall resets, policy-bypass tasks, hard-coded old installer versions and mock-only installation demonstrations are removed from the active toolkit. History remains in Git. New profiles retain timestamp validation and filesystem isolation, use matching FastCGI limits, scoped data writes, private reports, a proved cron switch and status-aware cache policy.

No plugin hooks are bypassed. No production settings were changed by this repository refactor. Containers validate logic, rendering, archive handling, privacy and actual Linux PHP/web behavior, not the remaining Windows bottleneck. Windows-native acceptance is required before treating a fresh bootstrap as production verified.

Concise anonymized findings and verification results remain under [production findings](production-bootstrap-findings-2026-11-08.md) and `docs/verification-results/`.

The machine-readable [observed non-sensitive settings](observed-settings-2026-11-08.json) are historical facts, distinct from the desired fresh-install JSON and effective reports generated on a host.
