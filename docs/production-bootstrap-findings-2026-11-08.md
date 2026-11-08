# WordPress on IIS: findings summary

These historical observations come from one anonymized Windows/IIS deployment on 8 November 2026. They guide diagnostics; they are not universal benchmarks. Detailed production profiles and per-request callback dumps are intentionally excluded from Git and the toolkit bundle.

## Confirmed findings

| Observation | Result and implication |
|---|---|
| Database loopback resolution | Changing the owner’s connection from localhost to 127.0.0.1 removed about two seconds of connection delay. Verify database/account identity before making this change elsewhere. |
| Visitor-triggered cron | A shutdown cron dispatch took about one second despite a nominal nonblocking 0.01-second timeout. A Windows task was verified with manual/automatic canaries before disabling visitor spawning. Later profiles observed no outbound cron dispatch. This does not prove all scheduled jobs succeed. |
| Remaining uncached bootstrap | Later no-action AJAX samples remained roughly 1.18–1.26 seconds. Removing cron dispatch did not establish a steady-state cure. Slow first requests were retained separately. |
| Breakdance element loading | A later initialization span was about 269–283 ms, including approximately 185 included element files and 175 classes. |
| Breakdance dynamic fields | Later-priority sampling retained roughly 113–118 ms, 128 included files and 122 classes. |
| WP Rocket initialization | Later rocket_init spans were roughly 96–97 ms with an inclusive 614-file/500-class loading span. |
| SEOPress initialization | Pro main-load boundary intervals were roughly 141–143 ms; the two Kernel callbacks together were about 66–67 ms. Boundary intervals include intervening work. |
| Cache configuration | A blanket inherited one-year Cache-Control header affected error responses as well as static assets. Successful static caching and error no-store policy require separate direct-origin/edge verification. |

These spans overlap and must not be added together. Included-file counts describe work occurring during a span, not individual file execution times or proof of slow storage. The custom application plugin was not shown to dominate the retained slow-callback results; bounded omissions prevent clearing every unmeasured callback.

## Remaining investigation

The owner reported a comparable Linux deployment was fast, but no matched Linux measurements were available. Windows-specific causes remain hypotheses. Web OPcache was enabled, not full and had ample free memory; increasing memory is unsupported by these observations. open_basedir was enabled and realpath-cache usage was zero, consistent with PHP’s documented restriction. Its actual latency contribution, Defender costs and cold filesystem effects were not isolated.

Use [the Windows diagnostic procedure](windows-performance.md) to compare effective PHP/FastCGI settings, bounded warm filesystem metadata operations and optional private Defender recordings. Correlate slow first requests with worker startup/recycling. Change one setting at a time in an equivalent Windows stage; do not disable security restrictions, add blanket exclusions or skip plugin hooks based on these timings alone.

The revised sampler reserved later-phase coverage with 41 resource samples and 32 nested scans, with no nested scan-budget skips in the observed run. Top-row, registration and per-bucket limits still omit work. Observed resource-counter overhead was about 12 ms; this excludes other instrumentation overhead.

## Verification and retention

Owner-run profiles reported successful temporary cleanup. The system-cron canaries demonstrated callback completion before and after DISABLE_WP_CRON changed. These are historical owner-run observations, distinct from this toolkit’s [container verification](verification-results/wordpriis-refactor-2026-11-08.json) and [cron regression results](verification-results/windows-cron-setup-2026-11-08.json). Native acceptance of the new Windows bootstrap remains pending.

No-action AJAX returns HTTP 400 by design and ends before admin_init; it does not measure page rendering, checkout, Core Web Vitals or every scheduled job. Keep fresh raw audit reports, per-request profiles, callback dumps and ETLs private and untracked. Commit only reviewed aggregate findings and concise verification results. See [the profiler runbook](bootstrap-profile.md).
