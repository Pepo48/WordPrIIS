# Migration from the original WordPrIIS / legacy tooling

## Ownership

WordPrIIS now owns shared Windows/IIS audit, bootstrap profiling, filesystem calibration, system-cron setup and their tests. The application repository retains application/payment/storage/browser tests and plugin-specific deployment policy. Operational development must not diverge across duplicate engines.

The migration ports the shared Windows working-tree tools and sanitized evidence, including PowerShell 5.1 compatibility, IIS/PHP selection, safe collector diagnostics, PHP output/open_basedir handling, callback/HTTP/resource attribution, late-phase sampling reservations and proved cron rollback behavior. Filenames, PHP symbols, request headers and report markers now use the WordPrIIS namespace. Use all files from the same toolkit version; mixing older helpers and runners is unsupported. No production plugin or server behavior changes just because files move repositories.

## Old WordPrIIS commands

The old `-NonInteractive`/interactive-config flow is retired. The old module files often executed setup while imported, then the entry point called functions that were not defined there. The prior Pester adapter/tests simulated setup operations instead of invoking those real modules. They are removed from active source; use Git history to inspect them.

The replacement is:

```powershell
.\wordpress-iis.ps1 -Action Plan -ConfigPath .\config\local.json
```

Choose a specific operation after reviewing that plan. Existing hosts use Audit/Profile/Diagnose/ExportConfig/Verify/Cron. Bootstrap refuses existing paths/site/pool and requires pinned artifacts, an empty local managed database and installed TLS certificate. It does not silently upgrade an existing server. Database-server installation, account provisioning, certificates/renewal, firewall/management-network policy and backup scheduling now belong to explicit managed host workflows instead of the old unsafe shortcuts.

No root database password is accepted in JSON or process arguments. Use database-scoped PSCredential. No execution-policy bypass, default-site removal, shared firewall reset or web-root secrets/rollback script is retained. Fresh worker code writes are restricted, so dashboard plugin/core deployment must use a separate controlled identity/workflow.

## Existing operational installations

Do not remove an already registered cron task, its runtime folder or its permanent MU gate just to switch tool ownership. The runtime task copies its required scripts and uses fixed private paths; an installed task is independent of the repository checkout. Preserve its account credential rotation and status checks. The new Cron command refuses an existing gate/task; it is not an upgrade/uninstall tool.

Copy/extract the new standalone toolkit outside the website, create/review an existing-site config, and run Audit or Profile there. Old extracted bundles continue to exist independently until the operator replaces them. New filesystem calibration is opt-in and has not been owner-verified on Windows merely because the migrated base profiler previously succeeded there.

Dates, measurements and limitations remain in the evidence; site identity, account names and application-specific source labels are anonymized examples. No raw production wp-config/php.ini, API secret, private key, ETL or credential file is part of the repository.

The refactor does not remove files left on a server by the old installer. Inventory any legacy credential/backup/rollback files locally and keep secrets outside web roots; repository cleanup is not remote server cleanup.

Previously installed cron runtimes remain self-contained and are not upgraded by this rename. Keep their existing task, MU gate and private runtime together. The installer detects pre-existing gate signatures across namespaces and refuses a second installation; do not rename or replace live files independently.
