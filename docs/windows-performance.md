# Investigating the remaining Windows cost

Run from the private extracted WordPrIIS toolkit in elevated 64-bit PowerShell:

```powershell
.\wordpress-iis.ps1 -Action Diagnose -ConfigPath .\config\local.json -RecordDefender
```

This creates a new private Diagnostics directory. The read-only audit selects the configured IIS site/PHP handler and records allowlisted configuration and collector diagnostics. The temporary MU profiler retains revision-7 phase/plugin reservations and adds the opt-in filesystem probe (runner revision **2026-11-08.8**, profile schema 3). Normal Profile runs omit calibration unless `-BenchmarkFileSystem` is supplied.

## What the filesystem probe means

At final profiling shutdown, sample up to four already included local PHP files per target plugin/core group. Run three warm rounds each of is_file, is_readable and realpath, checking a 200 ms work budget before each metadata operation. No directory tree scan, content read, cache reset, additional include, plugin bypass or runtime configuration change occurs. PHP version/build/thread-safety/SAPI, open_basedir state, realpath-cache usage and aggregate operation counts/times are saved; file paths and contents are not.

The workload occurs **after** the normal since_profiler_ms measurement. Client TTFB/total can include its extra cost; do not compare calibrated TTFB directly with old uncalibrated samples. Operations may share PHP/OS cache state. A single OS call can exceed the nominal budget; this is not a hard native I/O timeout. This is a warm metadata calibration, not disk throughput, cold loading or proof that those operations caused a plugin span. CLI-only PHP configuration still does not establish web-SAPI behavior.

## Defender correlation

Timed `New-MpPerformanceRecording -Seconds` support is feature-detected. When available, a background recording overlaps the profiler; startup is approximate, without a native readiness acknowledgement. Recordings that fail, time out or lack support produce explicit failed/unavailable coverage and a partial diagnostic result. No scanner is disabled, no exclusion is added, and no unrelated WPR session is cancelled.

Keep raw ETLs private: they can contain process events and absolute paths. Inspect locally:

```powershell
Get-MpPerformanceReport -Path 'C:\private\Diagnostics-...\defender-private.etl' -TopProcesses 10 -TopFiles 10
```

If timed recording is unavailable, start `New-MpPerformanceRecording -RecordTo <private-path>` interactively in a separate elevated window, run Profile in another window, then press ENTER in the recorder to save it. Do not close/kill the recorder. A forcibly stopped background recording may leave an ETW session requiring local inspection; the toolkit deliberately does not cancel pre-existing/global tracing blindly.

## What to test next on Windows

1. Verify effective x64 **NTS** FastCGI build, extension set, worker lifetime and actual OPcache usage/settings. The official Windows package now has a `-1` release revision; PHP_VERSION alone does not prove that build revision is deployed.
2. Correlate metadata cost and Defender events during the same workload. High plugin CPU does not distinguish PHP computation, path canonicalization and system/filter-driver work. A quiet recording does not prove all filesystem costs are absent.
3. Use bounded IIS Failed Request Tracing when HTTP time materially exceeds PHP/request time. Keep trace rules short-lived and private; raw headers/bodies can contain secrets.
4. Only after attribution, test one setting at a time in an isolated Windows stage and rerun functional checks. Preserve permissions, open_basedir and timestamp validation by default. Increasing worker counts improves concurrency, not necessarily serial single-request latency.

The owner cannot currently supply Linux/Plesk diagnostic access. No claim of a measured Windows/Linux ratio is made for this site. Do not rewrite Breakdance/WP Rocket/SEOPress initialization based solely on Windows callback timing.

## Sources checked 8 November 2026

- [PHP Windows NTS/build guidance](https://www.php.net/manual/en/install.windows.manual.php)
- [OPcache settings and Windows limitations](https://www.php.net/manual/en/opcache.configuration.php)
- [open_basedir disables realpath cache](https://www.php.net/manual/en/ini.core.php)
- [Microsoft FastCGI configuration](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/fastcgi/)
- [Defender timed recording](https://learn.microsoft.com/en-us/powershell/module/defenderperformance/new-mpperformancerecording)
- [Defender analyzer workflow](https://learn.microsoft.com/en-us/defender-endpoint/tune-performance-defender-antivirus)
- [IIS PHP Failed Request Tracing](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/troubleshoot-php-with-failed-request-tracing)
- [PHP filesystem slowdown report #80695](https://bugs.php.net/bug.php?id=80695): PHP 7.4-era report, classified “Not a bug”; precedent, not proof of an unfixed PHP 8.4 issue.
- [Independent PHP-on-Windows measurements](https://ephpm.dev/analysis/php-on-windows/): project-specific workloads, not this WordPress installation or a vendor guarantee.
