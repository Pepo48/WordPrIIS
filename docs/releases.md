# Release and dependency maintenance

Reviewed against official metadata on **8 November 2026**:

| Component | Active reference |
|---|---|
| PHP Windows default | 8.5.12-1, NTS x64 VS17, vendor SHA256 in `config/releases.json` |
| PHP compatibility branch | 8.4.27-1, NTS x64 VS17, separately pinned SHA256 |
| WordPress | 7.1.4, exact official HTTPS release URL; SHA256 computed from that download (not a vendor-published signature) |
| Verification PowerShell | 7.6.9, official release tarballs with GitHub-published SHA256 for arm64/x64 |
| Verification OS | Ubuntu 24.04 image pinned by digest; current signed-repository package security updates at build |
| Verification web/database | WordPress 7.1.4/PHP 8.5 and MariaDB 12.3.3 LTS, immutable image digests |
| Host PowerShell | Windows PowerShell 5.1 compatibility retained; OS-maintained, not an old third-party dependency to replace blindly |
| Database server / TLS issuance | Externally managed; old MySQL 8.4.4 and win-acme 2.2.9 installer pins/commands retired |
| IIS prerequisites | OS-maintained IIS + current Microsoft URL Rewrite 2.1 x64 / Visual C++ x64 runtime if absent; local hashes required for execution |

PHP's Windows package revision `-1` may not appear in PHP_VERSION. A matching language version alone does not establish that a Windows package/security rebuild is present. Existing host upgrades require their own native staged deployment, preserving php.ini, certificates and data; this repository refactor does not update the production server.

`Artifacts` downloads only hashes admitted by the reviewed lockfile, over official HTTPS without redirects. It refuses an existing mismatching file, verifies a temporary download, then renames it. Bootstrap rehashes archives and extracts from the same open read-only stream. No floating “latest.zip” is executed during bootstrap. Prerequisite EXE/MSI hashes and Microsoft signing/provenance must be reviewed before supplying them.

For future updates, consult the official release metadata, review compatibility/security notes, update URLs/checksums/container digests, run the complete suite and native acceptance checks, and commit the new lock and verification evidence together. Do not rewrite historical production evidence to pretend old measurements used current versions. A lock does not prove patch currency forever.

Sources: [PHP Windows releases](https://downloads.php.net/~windows/releases/releases.json), [PHP stable releases](https://www.php.net/releases/index.php?json&version=8.5), [WordPress update API](https://api.wordpress.org/core/version-check/1.7/), [PowerShell releases](https://github.com/PowerShell/PowerShell/releases), [Microsoft URL Rewrite](https://www.iis.net/downloads/microsoft/url-rewrite), [Visual C++ runtime](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
