# Cache-policy investigation — 8 November 2026

## Observations

The plugin repository has no rule emitting `public, max-age=31536000`. Fresh public GET requests with unique query strings produced the following responses (raw public headers are [saved here](verification-results/cache-headers-before-2026-11-08.json)):

| Resource | Status | Cache-Control | Cloudflare |
|---|---:|---|---|
| Plugin logger JS / CSS bundle | 200 | `public, max-age=31536000` | MISS |
| WordPress jQuery JS | 200 | `public, max-age=31536000` | MISS |
| Unique nonexistent plugin CSS | 404 | `public, max-age=31536000` | MISS |
| `/wp-json/` | 200 | `public, max-age=31536000` | DYNAMIC |
| `/wp-admin/admin-ajax.php` without action | 400 | WordPress no-store/private **plus** appended `public, max-age=31536000` | DYNAMIC |

An earlier response already demonstrated the same one-year header on a cached 500. No production 5xx was deliberately generated in this investigation.

The scope and appended conflicting header suggest a blanket IIS/custom-header, proxy or Cloudflare response-header rule. This is an inference, not proof of the exact source. Cloudflare MISS/DYNAMIC responses still traverse response-header rules, so those observations cannot distinguish origin configuration from edge modification. WP Rocket settings were not inspected. A public header alone does not identify which component set it.

## Follow-up from the corrected-site server report

The owner’s second report (`audit (1).json`, reviewed locally, not copied into Git) **confirmed** the effective IIS `httpProtocol/customHeaders` collection contains `Cache-Control: public, max-age=31536000`. It also showed a separate static-content `UseMaxAge` policy of 30 days. The blanket IIS custom header is therefore a confirmed origin source of the one-year directive, rather than only an origin/edge hypothesis. Its defining file may still be inherited; inspect IIS effective configuration/source locally before editing.

Remove/narrow that specific blanket custom header while preserving the static-content policy and application-generated no-store/private headers. The prepared status-aware 5xx edge safeguard remains a proposal. The owner’s report still showed slow PHP/bootstrap paths and a failed PHP collector; auto-detection and safe diagnostics were added to support the next run. No production setting has been changed from this workspace.

## Required effective-policy review

Inspect the live IIS site-root/parent configuration for `httpProtocol/customHeaders`, `staticContent/clientCache`, and outbound rules containing `Cache-Control`, `31536000` or `365.00:00:00`. IIS Configuration Editor or `appcmd list config` can reveal inherited settings absent from the site file. Do not replace the site's complete web.config with a sample or remove its unrelated headers/rewrite rules.

In Cloudflare inspect Cache Rules, Cache Response Rules, Response Header Transform Rules, older Page Rules and Workers routes. Locate the unconditional public/max-age append and restrict it to eligible successful static responses. Preserve the application's no-store/private directives on checkout, AJAX, authenticated and download-capability responses. Observe rule ordering and any custom cache key/query normalization.

## Targeted origin correction

The latest IPv4 follow-up still showed the year-long directive on page and AJAX responses. There are **two separate effective IIS settings**: an unconditional custom response header (365 days) and staticContent/clientCache (30 days). Cloudflare's four-hour Browser Cache TTL does not explain the confirmed IIS entry or cap a longer origin max-age.

On the host, select **Example WordPress** in IIS Manager → HTTP Response Headers. Inspect only the Cache-Control entry and its local/inherited source. Configuration Editor's `system.webServer/httpProtocol` view and configuration-source selection can help locate the defining server/location/web.config entry. Back up the affected configuration privately outside served directories before changing it; an IIS applicationHost backup does not substitute for a separate physical web.config backup.

- If the unconditional `<add name="Cache-Control" value="public, max-age=31536000" />` is defined locally at the WordPress root, remove **that entry only**.
- If inherited from a parent used by other sites, suppress it at this WordPress application's scope with the following fragment, merged into its existing configuration. Remove any local Cache-Control `add` too, or it will reintroduce the header.

```xml
<!-- Merge at the WordPress application root, NOT the custom-plugin plugin root. -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="Cache-Control" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

Do not add a second system.webServer/httpProtocol/customHeaders block if one already exists, use `<clear />`, replace the complete file or unlock a locked section indiscriminately. A locked inherited section needs an administrator's site-scoped change at the allowed level. Preserve all unrelated headers, rewrite rules and the separate **30-day staticContent/clientCache** setting. No URL Rewrite dependency is added. Microsoft documents [targeted inherited-header removal](https://learn.microsoft.com/en-us/previous-versions/iis/settings-schema/ms690687%28v%3Dvs.90%29) separately from [static client caching](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/staticcontent/clientcache/).

This corrects the blanket custom header; it does **not** itself guarantee no-store for every IIS/proxy-generated error. Validate direct-origin successful static files, missing static files, AJAX and controlled staging 5xx afterward. The pending edge safeguard below is still needed if errors remain cacheable. A successful asset retaining 30-day max-age is long caching; there is no need to append a year-long directive to every response to obtain it. Only extend successful, versioned assets to a year through a separately verified status-aware policy.

No production IIS/Cloudflare change has been performed. Apply and verify one layer at a time so its effect is attributable.

## Prepared 5xx safeguard

[The proposed rule](rules/no-store-5xx.proposal.json) is a **single Cache Response Rule**, for the `http_response_cache_settings` phase, matching origin status 500–599 on the two site hostnames. It sets no-store/no-cache/max-age=0 for both edge and browsers and removes conflicting long-lived/public directives. It does not match successful assets, so their existing long caching remains unchanged.

This file is a proposal, **not deployed infrastructure**. Add it through the dashboard or append it to the existing phase ruleset after reviewing current rules. Do not PUT this single object as a replacement for an entire ruleset. Cloudflare documents that later matching Cache Response Rules win; ensure subsequent rules/response transforms do not reintroduce conflicting client headers. Check origin Host rewrites before using the hostname expression.

Correcting the origin's blanket header is still required for direct-origin behavior. If the host has a blanket IIS custom header, remove only that Cache-Control entry and retain a success/status-aware static cache policy. Do not add a new rewrite-module dependency to the plugin-root config without verifying that module and host-level delegation.

## Verification after deployment

1. Successful versioned CSS/JS: 200 with the existing long TTL; repeat should remain cacheable. Retain validators and query-string versioning.
2. Controlled **non-production** 500/502/503 fixtures: no-store, no appended public/positive max-age, repeated requests not served as HIT with an increasing Age. Test 5xx generated before PHP too. Avoid an intentional outage or public failure endpoint on the live store.
3. AJAX/payment/download/REST responses: preserve their application cache policy; do not append the static one-year header.
4. Purge already-cached failures only after the policy change, then recheck the original affected URLs. New rules do not prove that previously stored errors have been removed.

The corrected-site report now identifies the effective IIS custom header. Its defining inherited configuration and any edge overrides still need inspection before deployment; no live cache policy or server configuration has been changed.

Primary references: [Cloudflare Cache Response Rules](https://developers.cloudflare.com/cache/how-to/cache-response-rules/), [supported directives](https://developers.cloudflare.com/cache/how-to/cache-response-rules/settings/), [status-code TTLs](https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/), [IIS client cache](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/staticcontent/clientcache/).
