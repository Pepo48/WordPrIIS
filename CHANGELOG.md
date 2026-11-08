# Changelog

## Unreleased — 2026-11-08

- Complete the final retention/privacy/reference review: keep raw diagnostics ignored, clarify dated verification summaries, remove obsolete publication flags and align runbooks with the final tool layout.

- Rename all legacy application-specific tooling, symbols, headers, environment variables and report markers to WordPrIIS. Parse marker lengths dynamically, detect pre-existing cron gates across namespaces and prevent reintroducing the old namespace in source/bundles.

- Remove GitHub Actions automation and its checkout dependency. Keep the complete locally invoked suite, with explicit Windows PowerShell 5.1/7 commands and separate native IIS acceptance steps.

- Remove detailed production profiles and embedded fixture callback dumps from Git and the toolkit bundle. Keep a concise anonymized findings summary and verification outcomes; enforce the distribution boundary with package regressions.

- Anonymize site identities, domains, service accounts and client-specific paths/source labels in examples, runbooks and retained reports. Add privacy regression checks for source and the distribution bundle.

- Rebuild WordPrIIS around one `wordpress-iis.ps1` dispatcher and standalone artifact, fresh-bootstrap, audit, profile, Windows-diagnostics, configuration-export, verification and proved-cron commands. Imports and default Plan no longer install or configure the host.
- Separate allowlisted non-sensitive JSON configuration from PSCredential inputs. Keep generated credentials/configuration and runtime reports private; remove transcripts, plaintext root-password arguments, web-root rollback scripts, policy-bypass tasks and automatic firewall/remote-access changes.
- Replace active imperative legacy modules and demonstration-style Pester adapters with production-function regressions, real archive/hash/ZIP traversal checks, failure journals and explicit native Windows acceptance requirements. Preserve legacy history in Git rather than shipping dormant executable setup code.
- Bind each fresh FastCGI application to its own PHPRC/conf.d instead of inheriting a stale global PHP configuration. Reject remote plaintext database bootstrap and audit generic WordPress core assets without requiring a custom plugin.
- Fresh bootstrap uses new isolated paths/site/pool, official pinned packages, an existing empty managed database and valid installed TLS certificate. Preserve filesystem isolation, scoped code/data ACLs, matching FastCGI limits, timestamp validation and visitor cron until its separate proved replacement works. Failed partial bootstrap is journaled, not falsely described as fully rolled back/idempotent.
- Move the shared audit, callback/resource profiler, private PHP helpers, verified cron engine, regression suites, concise anonymized findings, verification results and runbooks into WordPrIIS. Use neutral WordPrIIS filenames, symbols and protocol markers; existing installations remain self-contained.
- Add an opt-in bounded warm filesystem-metadata calibration inside web PHP (runner revision 2026-11-08.8), effective version/build/SAPI context and optional timed Defender correlation with explicit unavailable/partial coverage. No plugin bypass, scanner exclusion, cache flush or security weakening is applied.
- Pin current reviewed releases: PHP Windows 8.5.12-1 NTS x64 (8.4.27-1 compatibility option), WordPress 7.1.4, verification PowerShell 7.6.9 and MariaDB 12.3.3 LTS. Update container references and remove old MySQL/win-acme installation pins. Preserve historical observed versions in evidence.
- Verify the migrated PHP helper on PHP 8.5 as well as its prior 8.4 baseline: getopt may parse options with register_argc_argv disabled, so require an explicit root and accept valid parsing instead of asserting it must fail.
- Rewrite README and TESTSUITE around local verification, configuration and operations first. Add release/provenance, experience, cache-policy, migration and Windows follow-up documentation; retain production-vs-container verification limits.

## Before the refactor

The original Git history contains the installer’s incremental IIS/PHP/MySQL/WordPress, certificate, firewall, backup and rollback work. There was no existing changelog to truncate. Those implementations are historical; their old production-readiness/idempotence claims are not carried forward as verified behavior.
