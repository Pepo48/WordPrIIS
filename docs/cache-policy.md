# IIS and Cloudflare cache policy

The WORDPRIIS incident had two separate causes: plugin-root inherited collection collisions produced HTTP 500 HTML responses where CSS/JS was expected, and a parent IIS custom Cache-Control header appended a year-long public TTL to dynamic/error responses. Fix the actual IIS configuration error; accepting HTML as a stylesheet or script is not a fix.

Fresh WordPrIIS root configuration:

- Removes only inherited custom Cache-Control and selected duplicate security-header keys before adding local values. No collection-wide clear or MIME-map overrides are emitted.
- Leaves normal WordPress dynamic cache directives intact and configures 30-day static caching.
- Uses a URL Rewrite outbound rule matching 500–599 to replace Cache-Control with no-store when the module handles that response.
- Does not claim coverage of errors generated before configuration/module execution. Verify direct origin as well as the edge; a valid template/XML test does not execute the native IIS pipeline.

Do not replace an existing live root web.config with this fresh-install template. Inspect the effective site/parent custom headers and remove only the specific bad inherited entry, preserving unrelated protections and rewrite rules. Locked sections need a permitted administrator-level change, not indiscriminate unlocking. Keep versioned successful assets cacheable; never attach a positive static TTL to every response.

For Cloudflare, review request Cache Rules, Cache Response Rules, transformations, Workers and rule ordering. Browser Cache TTL is not proof that a longer origin directive has been capped. The [WORDPRIIS-specific proposed no-store rule](rules/no-store-5xx.proposal.json) is retained as historical evidence; it is not deployed infrastructure or a generic account/ruleset replacement. No Cloudflare credentials/API writes are part of this toolkit.

Native acceptance must include successful CSS/JS MIME/status/cache headers, missing assets, no-action AJAX, authenticated responses, payment/download responses, and controlled non-production 500/502/503 errors generated both inside PHP and earlier in IIS/proxy processing. Repeated 5xx must not become edge HITs. Verify that application no-store/private directives survive origin and edge behavior. Do not create an intentional outage on the live store to test this.

[Original header evidence and targeted correction](cache-policy-investigation-2026-11-08.md). [Microsoft static cache settings](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/staticcontent/clientcache/). [Microsoft URL Rewrite response-header examples](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/modifying-http-response-headers).
