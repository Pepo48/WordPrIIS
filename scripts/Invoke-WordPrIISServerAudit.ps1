#requires -Version 5.1
<#
.SYNOPSIS
Read-only Windows/IIS/WordPress security and performance assessment.
.DESCRIPTION
Writes a private JSON/Markdown report only. No tuning, service restarts, cache purges,
WordPress bootstrap, public probe installation, load test or credential collection.
GET requests can still cause normal application logging/cache warmup. See docs/server-audit.md.
#>
[CmdletBinding()]
param(
    [string]$SiteName,
    [uri]$Url,
    [string]$WordPressPath,
    [string]$PhpPath,
    [string]$OriginAddress,
    [string]$PagePath = '/',
    [string[]]$PrivatePath = @(),
    [ValidateRange(1,10)][int]$Samples = 3,
    [ValidateRange(5,60)][int]$TimeoutSeconds = 20,
    [ValidateRange(1,60)][int]$CounterSeconds = 5,
    [string]$OutputDirectory,
    [switch]$IncludeDatabase,
    [switch]$CompareDatabaseIPv4,
    [switch]$SkipHttp,
    [switch]$HttpOnly
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-AuditFinding {
    param([string]$Id, [string]$Severity, [string]$Evidence, [string]$NextStep)
    [pscustomobject]@{ id=$Id; severity=$Severity; evidence=$Evidence; next_step=$NextStep }
}
function Test-AuditBelowPath {
    param([string]$Candidate,[string]$Parent)
    $a = [IO.Path]::GetFullPath($Candidate).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $b = [IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $a.Equals($b,[StringComparison]::OrdinalIgnoreCase) -or $a.StartsWith($b+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
}
function Get-AuditCacheFindings {
    param([int]$Status,[hashtable]$Headers,[string]$Kind)
    $cc = [string]$Headers['cache-control']
    $positive = $cc -match '(?i)(?:^|[,\s])(?:s-maxage|max-age)\s*=\s*[1-9][0-9]*'
    $noStore = $cc -match '(?i)(?:^|[,\s])no-store(?:[,\s]|$)'
    $shared = $cc -match '(?i)(?:^|[,\s])public(?:[,\s]|$)'
    if ($Status -ge 500 -and $Status -le 599 -and (!$noStore -or $positive -or $shared)) {
        New-AuditFinding 'http.5xx-cache' 'high' '5xx lacks an unambiguous no-store policy.' 'Correct origin/edge status-aware caching; do not give errors the static TTL.'
    }
    if ($noStore -and ($positive -or $shared)) {
        New-AuditFinding 'http.conflicting-cache' 'high' 'no-store is combined with public or a positive TTL.' 'Find an appended IIS custom header, outbound rule or Cloudflare response transform.'
    }
    if ($Status -ge 400 -and $positive) {
        New-AuditFinding 'http.error-positive-ttl' 'warning' 'An error response has a positive cache lifetime.' 'Review negative/error caching separately from successful assets.'
    }
    if ($Kind -eq 'ajax' -and (!$noStore -or $positive)) {
        New-AuditFinding 'http.ajax-cache' 'high' 'AJAX response does not have a clean no-store policy.' 'Preserve WordPress no-store/private directives at origin and edge.'
    }
    if ($Kind -eq 'static' -and $Status -eq 200 -and !$positive) {
        New-AuditFinding 'http.static-short-cache' 'info' 'Successful static response has no positive max-age.' 'Consider long caching for versioned static assets after excluding errors and sensitive responses.'
    }
}
function Get-AuditPercentile {
    param([double[]]$Values,[double]$Percentile=0.5)
    if (!$Values -or !$Values.Count) { return $null }
    $ordered = @($Values | Sort-Object)
    $index = [Math]::Max(0,[Math]::Ceiling($Percentile*$ordered.Count)-1)
    return [Math]::Round($ordered[$index],2)
}
function Invoke-AuditCurl {
    param([string]$Executable,[uri]$Target,[string]$DirectAddress,[int]$Timeout,[string]$Kind,[int]$Sample,[string]$Route)
    $nullDevice = if ([Environment]::OSVersion.Platform -eq 'Win32NT') { 'NUL' } else { '/dev/null' }
    $argsList = @('--silent','--show-error','--noproxy','*','--max-time',"$Timeout",'--connect-timeout','5','--compressed',
        '--max-redirs','0','--output',$nullDevice,'--dump-header','-',
        '--write-out',"`nWORDPRIIS_METRICS|%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{size_download}",
        '--header','Cache-Control: no-cache','--user-agent','WORDPRIIS-Server-Audit/1.0')
    if ($DirectAddress) {
        $address = if ($DirectAddress.Contains(':')) { '['+$DirectAddress+']' } else { $DirectAddress }
        $argsList += @('--resolve',('{0}:{1}:{2}' -f $Target.DnsSafeHost,$Target.Port,$address))
    }
    $argsList += @('--url',$Target.AbsoluteUri)
    # No raw body, cookies, query string, remote IP or curl error text is retained.
    $raw = @(& $Executable @argsList 2>$null)
    $exitCode = $LASTEXITCODE
    $metric = @($raw | Where-Object { $_ -like 'WORDPRIIS_METRICS|*' })
    if ($exitCode -ne 0 -or !$metric.Count) {
        return [pscustomobject]@{ route=$Route; kind=$Kind; sample=$Sample; status=0; curl_exit=$exitCode; note='Request failed (TLS, connection, timeout or curl capability); no insecure retry.' }
    }
    $parts = ([string]$metric[-1]).Split('|')
    $headers = @{}
    $allowed = @('cache-control','cdn-cache-control','cloudflare-cdn-cache-control','age','cf-cache-status','content-type','content-encoding','server','x-powered-by','x-rocket-cache','x-cache','strict-transport-security','x-content-type-options','referrer-policy')
    foreach ($line in $raw) {
        if ([string]$line -match '^HTTP/') { $headers=@{} }
        if ([string]$line -match '^([^:]+):\s*(.*)$') {
            $name=$matches[1].ToLowerInvariant(); $value=$matches[2].Trim()
            if ($allowed -contains $name) {
                $headers[$name] = if ($headers.ContainsKey($name)) { $headers[$name]+', '+$value } else { $value }
                if ($headers[$name].Length -gt 1024) { $headers[$name]=$headers[$name].Substring(0,1024) }
            }
        }
    }
    $numbers = @($parts[2..7] | ForEach-Object { [double]::Parse($_,[Globalization.CultureInfo]::InvariantCulture) })
    [pscustomobject]@{
        route=$Route; kind=$Kind; sample=$Sample; status=[int]$parts[1]; curl_exit=$exitCode; headers=$headers
        dns_ms=[Math]::Round(1000*$numbers[0],2); connect_ms=[Math]::Round(1000*$numbers[1],2)
        tls_ready_ms=[Math]::Round(1000*$numbers[2],2); ttfb_ms=[Math]::Round(1000*$numbers[3],2)
        total_ms=[Math]::Round(1000*$numbers[4],2); transfer_bytes=$numbers[5]
        cache_observation= if ($headers['cf-cache-status']) { $headers['cf-cache-status'] } else { 'unknown; no proof of WordPress/page-cache bypass' }
    }
}
function Get-AuditFailure {
    param($Record,[string]$Stage)
    $exception=$Record.Exception
    for($depth=0;$depth -lt 8 -and $exception.InnerException;$depth++){ $exception=$exception.InnerException }
    $code='collector-error';$hint='Review this collector locally; raw messages, command lines and configuration contents are deliberately omitted.'
    $hex='0x'+$exception.HResult.ToString('X8')
    if($exception -is [UnauthorizedAccessException] -or $hex -eq '0x80070005'){$code='access-denied';$hint='Run elevated 64-bit PowerShell and verify delegated configuration/registry permissions.'}
    elseif($exception -is [IO.FileNotFoundException] -or $hex -eq '0x80070002'){$code='file-or-component-missing';$hint='Verify the IIS administration component or explicitly selected helper/executable exists.'}
    elseif($exception -is [Management.Automation.CommandNotFoundException]){$code='command-unavailable';$hint='The collector command/module is not installed or available in this PowerShell edition.'}
    elseif($hex -eq '0x800700B7'){$code='duplicate-config-entry';$hint='Inspect inherited IIS collection keys for duplicates.'}
    elseif($hex -eq '0x80070021'){$code='locked-config-section';$hint='Inspect IIS section delegation at the server/site level; do not unlock unrelated protections.'}
    elseif($exception -is [Management.Automation.PropertyNotFoundException] -or $Record.CategoryInfo.Category -eq 'InvalidOperation'){$code='unsupported-property-or-operation';$hint='Verify installed IIS/PowerShell versions; other collector results are retained.'}
    if($code -eq 'collector-error' -and $hex -eq '0x80070057'){$code='invalid-collector-argument';$hint='A collector command/API rejected an argument or property. Use source_line and the allowlisted command/error identifier to locate it; do not change server permissions based on this alone.'}
    $category=[string]$Record.CategoryInfo.Category
    $result=@{stage=$Stage;code=$code;exception_type=$exception.GetType().FullName;hresult=$hex;category=$category;next_step=$hint}
    if($Record.InvocationInfo){
        $result['source_line']=[int]$Record.InvocationInfo.ScriptLineNumber
        if($Record.InvocationInfo.MyCommand -and $Record.InvocationInfo.MyCommand.Name -in @('Add-Type','New-Object','Measure-Object','Select-Object','ForEach-Object','Get-TlsCipherSuite','Get-ItemProperty','Select-AuditSite','Get-AuditConfig','Resolve-AuditPhp')){$result['command']=$Record.InvocationInfo.MyCommand.Name}
    }
    $identifier=([string]$Record.FullyQualifiedErrorId).Split(',')[0]
    if($identifier -in @('GenericMeasurePropertyNotFound','ExpandPropertyNotFound','NamedParameterNotFound','ParameterBindingFailed','CannotConvertArgumentNoMessage','TYPE_ALREADY_EXISTS','ASSEMBLY_ALREADY_EXISTS')){$result['error_identifier']=$identifier}
    return $result
}
function ConvertTo-AuditCipherInventory {
    param([object[]]$CipherObjects)
    $names=@();$unrecognized=0
    foreach($cipher in $CipherObjects){
        $name=$null
        if($cipher -is [Collections.IDictionary]){if($cipher.Contains('Name')){$name=[string]$cipher['Name']}}
        elseif($null -ne $cipher -and $cipher.PSObject.Properties['Name']){$name=[string]$cipher.Name}
        if($name -and $name -match '^TLS_[A-Za-z0-9_]{1,120}$'){$names+=$name}else{$unrecognized++}
    }
    return @{names=$names;unrecognized=$unrecognized}
}
function New-AuditFailureCoverage {
    param([string]$Check,$Record,[string]$Stage,[string]$Status='unavailable')
    return @{check=$Check;status=$Status;diagnostic=Get-AuditFailure $Record $Stage;note='Raw error messages, invocation text and stack traces are not collected.'}
}
function Select-AuditSite {
    param([object[]]$Sites,[uri]$Target,[string]$RequestedName,[string]$RequestedRoot)
    if($RequestedName){
        $named=@($Sites|Where-Object{$_.name -ieq $RequestedName})
        if($named.Count -eq 1){return @{status='selected';name=$named[0].name;selected_by='explicit-site-name'}}
        return @{status='unavailable';code='requested-site-not-found';candidate_names=@($Sites|ForEach-Object{$_.name});next_step='Use an exact candidate site name or omit SiteName for hostname detection.'}
    }
    $ranked=@()
    foreach($candidate in $Sites){
        $score=0
        foreach($binding in $candidate.bindings){
            $name=([string]$binding.hostname).TrimEnd('.')
            $targetName=$Target.DnsSafeHost.TrimEnd('.')
            $exact=$name -ieq $targetName
            $wildcard=$name.StartsWith('*.') -and $targetName.EndsWith($name.Substring(1),[StringComparison]::OrdinalIgnoreCase)
            if($exact -or $wildcard){
                $rank=if($exact){100}else{50}
                if($binding.protocol -ieq $Target.Scheme){$rank+=20}
                if([int]$binding.port -eq $Target.Port){$rank+=10}
                $score=[Math]::Max($score,$rank)
            }
        }
        $rootMatch=$false
        if($RequestedRoot){foreach($physicalRoot in $candidate.roots){if($physicalRoot -and (Test-AuditBelowPath $RequestedRoot $physicalRoot)){$rootMatch=$true}}}
        if($score -gt 0 -or $rootMatch){$ranked+=@{name=$candidate.name;score=$score;root_match=$rootMatch}}
    }
    if(!$ranked.Count){return @{status='unavailable';code='no-hostname-or-root-match';candidate_names=@($Sites|ForEach-Object{$_.name});next_step='Supply SiteName for an IP-only/default binding, or supply the actual WordPressPath. No default site was guessed.'}}
    # Windows PowerShell 5.1 property cmdlets do not reliably adapt dictionary keys.
    $topScore=0
    foreach($rankedSite in $ranked){$topScore=[Math]::Max($topScore,[int]$rankedSite['score'])}
    $best=@($ranked|Where-Object{$_.score -eq $topScore})
    if($best.Count -gt 1 -and $RequestedRoot){$matching=@($best|Where-Object{$_.root_match});if($matching.Count -eq 1){$best=$matching}}
    if($best.Count -ne 1){return @{status='unavailable';code='ambiguous-site-match';candidate_names=@($best|ForEach-Object{$_.name});next_step='More than one IIS site matches; specify SiteName or a disambiguating WordPressPath.'}}
    return @{status='selected';name=$best[0].name;selected_by=if($topScore -gt 0){'binding-hostname'}else{'explicit-wordpress-root'}}
}
function Resolve-AuditPhp {
    param([object[]]$Handlers,[string]$RequestedPath,[Nullable[bool]]$Pool32Bit=$null)
    if($RequestedPath){
        if(Test-Path -LiteralPath $RequestedPath -PathType Leaf){return @{status='selected';path=[IO.Path]::GetFullPath($RequestedPath);selected_by='explicit-php-path'}}
        return @{status='unavailable';code='explicit-php-not-found';next_step='Provide the matching php.exe; the supplied file does not exist.'}
    }
    foreach($handler in $Handlers){
        if([string]$handler.modules -notmatch '(?i)(?:^|,)\s*FastCgiModule\s*(?:,|$)'){continue}
        if([string]$handler.path -notin @('*.php','*')){continue}
        $verbs=([string]$handler.verb).Split(',')|ForEach-Object{$_.Trim()}
        if('*' -notin $verbs -and 'GET' -notin $verbs){continue}
        $condition=[string]$handler.precondition
        if($null -eq $Pool32Bit -and $condition -match '(?i)bitness(32|64)'){return @{status='unavailable';code='pool-bitness-unverified';next_step='Application-pool bitness could not be read; supply PhpPath or resolve that collector before selecting a conditional handler.'}}
        if(($Pool32Bit -and $condition -match '(?i)bitness64') -or (!$Pool32Bit -and $condition -match '(?i)bitness32')){continue}
        # scriptProcessor is executable|arguments. Never execute its arguments.
        $processor=[Environment]::ExpandEnvironmentVariables((([string]$handler.processor).Split('|')[0]).Trim().Trim('"'))
        if([IO.Path]::GetFileName($processor) -notmatch '(?i)^php(?:-cgi)?\.exe$'){continue}
        $path=Join-Path (Split-Path $processor) 'php.exe'
        if(Test-Path -LiteralPath $path -PathType Leaf){return @{status='selected';path=$path;handler_executable=$processor;selected_by='effective-site-php-handler';handler_path=$handler.path;handler_precondition=$condition}}
        return @{status='unavailable';code='handler-cli-sibling-missing';handler_executable=$processor;next_step='The site PHP handler was found, but matching php.exe is absent. Supply PhpPath from that PHP distribution.'}
    }
    return @{status='unavailable';code='no-effective-php-handler';next_step='No applicable PHP FastCGI handler was found at the selected application. Verify its application path or provide the matching PhpPath; no global PHP version was guessed.'}
}
function Invoke-AuditPhpProbe {
    param([string]$Executable,[string]$Probe,[string]$Root,[switch]$Database,[switch]$CompareIPv4)
    if(!(Test-Path -LiteralPath $Probe -PathType Leaf)){return @{status='unavailable';code='php-helper-missing';next_step='Keep audit-wordpress.php beside Invoke-WordPrIISServerAudit.ps1.'}}
    $savedPreference=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$versionRaw=@(& $Executable '-v' 2>&1);$versionExit=$LASTEXITCODE}finally{$ErrorActionPreference=$savedPreference}
    $version=$null
    foreach($line in $versionRaw){if([string]$line -match '^PHP\s+(\d+\.\d+\.\d+)'){$version=$matches[1];break}}
    if($versionExit -ne 0 -or !$version){return @{status='unavailable';code='php-version-probe-failed';exit_code=$versionExit;next_step='Run the selected php.exe locally to diagnose missing DLLs, architecture or startup configuration; raw output is omitted.'}}
    if([version]$version -lt [version]'8.0.0'){return @{status='unavailable';code='php-version-unsupported';version=$version;next_step='The diagnostic helper needs PHP 8.0+. WORDPRIIS runtime requires 8.4+; verify the site handler before changing runtime versions.'}}
    $phpArgs=@('-d','register_argc_argv=1','-d','display_errors=0','-d','display_startup_errors=0','-d','log_errors=0',$Probe,('--root='+$Root));if($Database){$phpArgs+='--database'};if($Database -and $CompareIPv4){$phpArgs+='--compare-loopback-ipv4'}
    $savedPreference=$ErrorActionPreference
    $probeClock=[Diagnostics.Stopwatch]::StartNew()
    try{$ErrorActionPreference='Continue';$raw=@(& $Executable @phpArgs 2>&1);$exitCode=$LASTEXITCODE}finally{$ErrorActionPreference=$savedPreference}
    $probeClock.Stop()
    $json=@($raw|Where-Object{$_ -like 'WORDPRIIS_AUDIT_JSON:*'})
    if($exitCode -ne 0){return @{status='unavailable';code='php-helper-nonzero-exit';exit_code=$exitCode;version=$version;next_step='Check the helper/runtime compatibility locally; raw stdout/stderr may contain secrets and is omitted.'}}
    if(!$json.Count){return @{status='unavailable';code='php-helper-no-json';version=$version;next_step='Verify the matching helper file and CLI startup; no raw output is included.'}}
    try{$data=([string]$json[-1]).Substring('WORDPRIIS_AUDIT_JSON:'.Length)|ConvertFrom-Json}catch{return @{status='unavailable';code='php-helper-invalid-json';version=$version;next_step='Use matching audit files and check PHP encoding/runtime locally.'}}
    if(!$data.PSObject.Properties['php'] -or !$data.php.PSObject.Properties['settings']){return @{status='unavailable';code='php-helper-incomplete-result';version=$version;next_step='The helper could not collect expected PHP fields; use matching audit files and inspect the host locally.'}}
    return @{status='collected';version=$version;helper_process_ms=[Math]::Round($probeClock.Elapsed.TotalMilliseconds,3);data=$data}
}

function Get-AuditConfig {
    param($Manager,[string]$Location,[string]$ApplicationPath='/')
    $cfg = $Manager.GetWebConfiguration($Location,$ApplicationPath)
    $result = [ordered]@{}
    # Select attributes, never serialize whole sections containing credentials.
    $spec = @{
        'system.webServer/directoryBrowse'=@('enabled')
        'system.webServer/security/authentication/anonymousAuthentication'=@('enabled')
        'system.webServer/security/authentication/basicAuthentication'=@('enabled')
        'system.webServer/security/access'=@('sslFlags')
        'system.webServer/urlCompression'=@('doStaticCompression','doDynamicCompression')
        'system.webServer/staticContent'=@()
        'system.webServer/caching'=@('enabled','enableKernelCache')
    }
    foreach ($name in $spec.Keys) {
        try {
            $section=$cfg.GetSection($name); $entry=[ordered]@{}
            foreach ($key in $spec[$name]) { $entry[$key]=[string]$section.GetAttributeValue($key) }
            if ($name -eq 'system.webServer/staticContent') {
                $child=$section.GetChildElement('clientCache')
                foreach ($key in @('cacheControlMode','cacheControlMaxAge','cacheControlCustom')) { $entry[$key]=[string]$child.GetAttributeValue($key) }
            }
            $result[$name]=$entry
        } catch { $result[$name]=@{status='unavailable';diagnostic=Get-AuditFailure $_ ('iis.section.'+$name)} }
    }
    $sources = New-Object System.Collections.Generic.List[object]
    try {
        $custom=$cfg.GetSection('system.webServer/httpProtocol').GetCollection('customHeaders')
        foreach ($item in $custom) {
            if ([string]$item['name'] -ieq 'Cache-Control') { $sources.Add(@{source='effective IIS httpProtocol/customHeaders'; value=[string]$item['value']}) }
        }
    } catch { $result['custom_header_diagnostic']=Get-AuditFailure $_ 'iis.custom-headers' }
    try {
        $outbound=$cfg.GetSection('system.webServer/rewrite').GetCollection('outboundRules')
        foreach ($rule in $outbound) {
            $match=$rule.GetChildElement('match')
            if ([string]$match['serverVariable'] -match '(?i)^RESPONSE_(CACHE_CONTROL|CDN_CACHE_CONTROL|CLOUDFLARE_CDN_CACHE_CONTROL)$') {
                $sources.Add(@{source='effective IIS outbound header rule'; rule=[string]$rule['name']; action=[string]$rule.GetChildElement('action')['value']; precondition=[string]$rule['preCondition']})
            }
        }
    } catch { $result['outbound_rule_diagnostic']=Get-AuditFailure $_ 'iis.outbound-rules' }
    $result['cache_header_sources']=@($sources.ToArray())
    return $result
}
function Get-AuditLogSummary {
    param([string]$Directory)
    if (!(Test-Path -LiteralPath $Directory -PathType Container)) { return @{status='unavailable';code='log-directory-missing';next_step='Verify the IIS logging directory and whether central/custom logging is configured.'} }
    $files=@(Get-ChildItem -LiteralPath $Directory -Filter '*.log' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 2)
    $stats=@{}; $queryLogged=$false; $seen=0; $substatus=@{}; $first=$null; $last=$null; $last5xx=$null
    foreach ($file in $files) {
        $fieldLine=@(Get-Content -LiteralPath $file.FullName -TotalCount 40 | Where-Object { $_ -like '#Fields:*' } | Select-Object -Last 1)
        if (!$fieldLine.Count) { continue }
        $fields=($fieldLine[-1] -replace '^#Fields:\s*','') -split '\s+'
        if ($fields -contains 'cs-uri-query') { $queryLogged=$true }
        $indices=@{}; for($i=0;$i -lt $fields.Count;$i++){ $indices[$fields[$i]]=$i }
        if (!$indices.ContainsKey('sc-status') -or !$indices.ContainsKey('time-taken') -or !$indices.ContainsKey('cs-uri-stem')) { continue }
        foreach($line in (Get-Content -LiteralPath $file.FullName -Tail 10000)) {
            if ($line.StartsWith('#')) { continue }
            $values=$line -split '\s+'
            if ($values.Count -ne $fields.Count) { continue }
            $duration=0.0; $status=0
            if (![double]::TryParse($values[$indices['time-taken']],[ref]$duration) -or ![int]::TryParse($values[$indices['sc-status']],[ref]$status)) { continue }
            $timestamp=$null
            if($indices.ContainsKey('date') -and $indices.ContainsKey('time')){
                $parsed=[DateTime]::MinValue
                if([DateTime]::TryParseExact(($values[$indices['date']]+' '+$values[$indices['time']]),'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal,[ref]$parsed)){
                    $timestamp=$parsed.ToUniversalTime()
                    if($null -eq $first -or $timestamp -lt $first){$first=$timestamp}
                    if($null -eq $last -or $timestamp -gt $last){$last=$timestamp}
                    if($status -ge 500 -and ($null -eq $last5xx -or $timestamp -gt $last5xx)){$last5xx=$timestamp}
                }
            }
            $stem=$values[$indices['cs-uri-stem']]
            $category=if($stem -match '(?i)admin-ajax\.php$'){'ajax'}elseif($stem -match '(?i)wordpriis-download'){'download'}elseif($stem -match '(?i)\.(css|js|png|jpg|webp|woff2?)$'){'static'}elseif($stem -match '(?i)\.php$'){'php'}else{'page-or-other'}
            if (!$stats.ContainsKey($category)) { $stats[$category]=New-Object System.Collections.Generic.List[double] }
            $stats[$category].Add($duration); $seen++
            if ($status -ge 500) {
                $sub=if($indices.ContainsKey('sc-substatus')){$values[$indices['sc-substatus']]}else{'unknown'}
                $key="$status.$sub"; if(!$substatus.ContainsKey($key)){$substatus[$key]=0};$substatus[$key]++
            }
        }
    }
    $groups=@(foreach($name in $stats.Keys){[pscustomobject]@{category=$name;count=$stats[$name].Count;median_ms=Get-AuditPercentile $stats[$name].ToArray();p95_ms=Get-AuditPercentile $stats[$name].ToArray() 0.95}})
    return @{status='sampled'; sample_first_utc=if($first){$first.ToString('o')}else{$null};sample_last_utc=if($last){$last.ToString('o')}else{$null};last_5xx_utc=if($last5xx){$last5xx.ToString('o')}else{$null};rows=$seen; max_rows=20000; groups=$groups; errors_5xx_by_substatus=$substatus; query_field_enabled=$queryLogged; note='Recent file tails, not a fixed time window. No URLs, queries, IPs, cookies or usernames saved.'}
}
function Get-AuditAcl {
    param([string]$Path)
    $entries=@()
    foreach($ace in (Get-Acl -LiteralPath $Path).Access) {
        try { $sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid='unresolved' }
        $broad=$sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-32-568')
        $writable=([int]$ace.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::Write) -ne 0 -or ([int]$ace.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::ChangePermissions) -ne 0
        $entries+=@{sid=$sid; rights=[string]$ace.FileSystemRights; type=[string]$ace.AccessControlType; inherited=$ace.IsInherited; broad_allow_write=($broad -and $writable -and $ace.AccessControlType -eq 'Allow')}
    }
    return @{path=$Path;entries=$entries;note='DACL screen only; deny/group membership/effective access must be checked under actual app-pool/worker identities.'}
}
function Invoke-WordPrIISServerAudit {
    if($CompareDatabaseIPv4 -and !$IncludeDatabase){throw 'CompareDatabaseIPv4 requires IncludeDatabase; the comparison is opt-in and read-only.'}
    if (!$Url -or !$Url.IsAbsoluteUri -or $Url.Scheme -ne 'https' -or $Url.UserInfo -or $Url.Query -or $Url.Fragment -or $Url.AbsolutePath -ne '/') { throw 'Supply -Url as an HTTPS origin only, for example https://wordpress.example.com.' }
    if (!$PagePath.StartsWith('/') -or $PagePath.StartsWith('//') -or $PagePath -match '[?#\r\n]') { throw 'PagePath must be a same-origin path without query strings or credentials.' }
    if ($OriginAddress) { $parsed=$null; if(![Net.IPAddress]::TryParse($OriginAddress,[ref]$parsed)){throw 'OriginAddress must be an IP address, not another hostname.'} }
    $windows=[Environment]::OSVersion.Platform -eq 'Win32NT'
    if (!$windows -and !$HttpOnly) { throw 'Server inspection requires Windows. Use -HttpOnly for portable HTTP diagnostics.' }
    $findings=New-Object System.Collections.Generic.List[object]
    $coverage=New-Object System.Collections.Generic.List[object]
    $report=[ordered]@{schema_version=2;collector_revision='2026-11-08.7';generated_utc=[DateTime]::UtcNow.ToString('o'); scope='Bounded read-only assessment; not a penetration test, load test or security certification.';host=$Url.DnsSafeHost;findings=$null;coverage=$null}
    $manager=$null; $site=$null; $iis=$null; $physical=$null; $application=$null; $applicationPath='/'
    $report['execution']=@{powershell_version=$PSVersionTable.PSVersion.ToString();process_64bit=[Environment]::Is64BitProcess;windows=$windows}
    if($windows){$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity);$report['execution']['elevated']=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
    $report['discovery']=@{site=@{status='not-run'};php=@{status='unavailable';code='site-discovery-unavailable';next_step='Resolve IIS site discovery or supply the matching PhpPath.'}}
    if (!$HttpOnly) {
        $discoveryStage='iis.assembly-load'
        try {
            $assembly=Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
            if(!('Microsoft.Web.Administration.ServerManager' -as [type])){Add-Type -Path $assembly}
            $discoveryStage='iis.manager-open'
            $manager=New-Object Microsoft.Web.Administration.ServerManager
            $discoveryStage='iis.site-inventory'
            $inventory=@(foreach($candidate in $manager.Sites){
                $roots=@($candidate.Applications|ForEach-Object{[Environment]::ExpandEnvironmentVariables($_.VirtualDirectories['/'].PhysicalPath)})
                $bindings=@(foreach($binding in $candidate.Bindings){if($binding.BindingInformation -match '^.*:([0-9]+):(.*)$'){@{protocol=$binding.Protocol;port=[int]$matches[1];hostname=$matches[2]}}})
                @{name=$candidate.Name;roots=$roots;bindings=$bindings}
            })
            $report['discovery']['site_inventory']=@($inventory|ForEach-Object{@{name=$_.name;bindings=$_.bindings}})
            $discoveryStage='iis.site-selection'
            $selection=Select-AuditSite $inventory $Url $SiteName $WordPressPath
            $report['discovery']['site']=$selection
            if($selection.status -eq 'selected'){
                $discoveryStage='iis.application-selection'
                $SiteName=$selection.name;$site=$manager.Sites[$SiteName]
                $physical=[Environment]::ExpandEnvironmentVariables($site.Applications['/'].VirtualDirectories['/'].PhysicalPath)
                $applications=@($site.Applications|Where-Object{$_.Path -eq '/' -or $PagePath -eq $_.Path -or $PagePath.StartsWith($_.Path.TrimEnd('/')+'/',[StringComparison]::OrdinalIgnoreCase)}|Sort-Object @{Expression={$_.Path.Length};Descending=$true})
                $application=$applications[0];$applicationPath=$application.Path
                if(!$WordPressPath){$WordPressPath=[Environment]::ExpandEnvironmentVariables($application.VirtualDirectories['/'].PhysicalPath)}
                $report['discovery']['site']['application_path']=$applicationPath
                $report['discovery']['site']['wordpress_path']=$WordPressPath
                $coverage.Add(@{check='IIS site discovery';status='collected';note='Selected by explicit name or unique hostname/root; application selected by PagePath.'})
            }else{$coverage.Add(@{check='IIS site discovery';status='unavailable';diagnostic=$selection})}
        }catch{
            $coverage.Add((New-AuditFailureCoverage 'IIS site discovery' $_ $discoveryStage))
        }
        if($site){
            $iis=[ordered]@{site_name=$SiteName;site_id=$site.Id}
            $report['iis']=$iis
            try{
                $settings=Get-AuditConfig $manager $SiteName $applicationPath
                foreach($key in $settings.Keys){$iis[$key]=$settings[$key]}
                $iis['site_state']=[string]$site.State
                $coverage.Add(@{check='IIS effective configuration';status='collected';note='Per-section failures are included alongside successful section data.'})
            }catch{$coverage.Add((New-AuditFailureCoverage 'IIS effective configuration' $_ 'iis.effective-config'))}
            $pool32Bit=$null
            try{
                $pool=$manager.ApplicationPools[$application.ApplicationPoolName];$pool32Bit=[bool]$pool.Enable32BitAppOnWin64
                $iis['pool']=@{state=[string]$pool.State;identity_type=[string]$pool.ProcessModel.IdentityType;start_mode=[string]$pool.StartMode;idle_timeout=[string]$pool.ProcessModel.IdleTimeout;max_processes=$pool.ProcessModel.MaxProcesses;queue_length=$pool.QueueLength;cpu_limit_raw=$pool.Cpu.Limit;cpu_action=[string]$pool.Cpu.Action;recycle_private_memory_kb=$pool.Recycling.PeriodicRestart.PrivateMemory;recycle_interval=[string]$pool.Recycling.PeriodicRestart.Time;enable_32bit=$pool32Bit}
            }catch{$coverage.Add((New-AuditFailureCoverage 'IIS application pool' $_ 'iis.pool'))}
            try{$iis['bindings']=@($site.Bindings|ForEach-Object{@{protocol=$_.Protocol;binding=$_.BindingInformation;ssl_flags=[string]$_.SslFlags}})}catch{$coverage.Add((New-AuditFailureCoverage 'IIS bindings' $_ 'iis.bindings'))}
            $handlers=@()
            try{
                $cfg=$manager.GetWebConfiguration($SiteName,$applicationPath)
                $handlers=@($cfg.GetSection('system.webServer/handlers').GetCollection()|ForEach-Object{@{path=[string]$_['path'];verb=[string]$_['verb'];modules=[string]$_['modules'];processor=[string]$_['scriptProcessor'];precondition=[string]$_['preCondition']}})
                # Do not serialize processor arguments: they may contain sensitive -d values.
                $report['discovery']['php']=Resolve-AuditPhp $handlers $PhpPath $pool32Bit
            }catch{$coverage.Add((New-AuditFailureCoverage 'IIS PHP handler' $_ 'iis.php-handler'));$report['discovery']['php']=@{status='unavailable';code='effective-handler-read-failed'}}
            try{
                $fast=@(foreach($app in $manager.GetApplicationHostConfiguration().GetSection('system.webServer/fastCgi').GetCollection()){
                    $item=@{};foreach($key in @('fullPath','maxInstances','instanceMaxRequests','idleTimeout','activityTimeout','requestTimeout','queueLength','monitorChangesTo')){$item[$key]=[string]$app[$key]}
                    $envValues=@{};foreach($variable in $app.GetCollection('environmentVariables')){if([string]$variable['name'] -in @('PHPRC','PHP_FCGI_MAX_REQUESTS')){$envValues[[string]$variable['name']]=[string]$variable['value']}}
                    $item['selected_environment']=$envValues;$item
                })
                $iis['fastcgi']=$fast
            }catch{$coverage.Add((New-AuditFailureCoverage 'IIS FastCGI settings' $_ 'iis.fastcgi'))}
        }
        if($PhpPath){$report['discovery']['php']=Resolve-AuditPhp @() $PhpPath}
        if($report['discovery']['php']['status'] -eq 'selected'){$PhpPath=$report['discovery']['php']['path']}
        else{$coverage.Add(@{check='PHP path discovery';status='unavailable';diagnostic=$report['discovery']['php']})}
    }
    if(!$OutputDirectory){$OutputDirectory=Join-Path ([IO.Path]::GetTempPath()) ('wordpriis-server-audit-'+[guid]::NewGuid().ToString('N'))}
    $OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
    if(Test-Path -LiteralPath $OutputDirectory){throw 'OutputDirectory must be a new directory; existing reports are never overwritten.'}
    if($WordPressPath -and (Test-AuditBelowPath $OutputDirectory $WordPressPath)){throw 'Write the report outside the WordPress/web root.'}
    if($site -and $physical -and (Test-AuditBelowPath $OutputDirectory $physical)){throw 'Write the report outside the IIS document root.'}
    [void][IO.Directory]::CreateDirectory($OutputDirectory)
    if($windows){
        $acl=New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')){
            $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow');$acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $OutputDirectory -AclObject $acl
    }else{& chmod 700 -- $OutputDirectory}
    if(!$HttpOnly){
        try {
            $os=Get-CimInstance Win32_OperatingSystem
            $cpu=Get-CimInstance Win32_Processor
            $report['system']=@{os=$os.Caption;version=$os.Version;build=$os.BuildNumber;boot_utc=$os.LastBootUpTime.ToUniversalTime().ToString('o');logical_cpus=($cpu|Measure-Object NumberOfLogicalProcessors -Sum).Sum;ram_total_bytes=[double]$os.TotalVisibleMemorySize*1024;ram_free_bytes=[double]$os.FreePhysicalMemory*1024}
            $report['disks']=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {@{drive=$_.DeviceID;size_bytes=$_.Size;free_bytes=$_.FreeSpace}})
            $samplesList=@()
            for($i=0;$i -lt $CounterSeconds;$i++){
                $counter=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
                $memory=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
                $disks=Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
                $samplesList+=@{cpu_percent=$counter.PercentProcessorTime;available_mb=$memory.AvailableMBytes;pages_per_sec=$memory.PagesPersec;disk_queue=$disks.CurrentDiskQueueLength;disk_read_seconds=$disks.AvgDisksecPerRead;disk_write_seconds=$disks.AvgDisksecPerWrite}
                if($i -lt $CounterSeconds-1){Start-Sleep -Seconds 1}
            }
            $report['resource_samples']=$samplesList
            $report['process_groups']=@(Get-Process | Where-Object {$_.ProcessName -in @('w3wp','php-cgi','mysqld','mariadbd','MsMpEng')} | Group-Object ProcessName | ForEach-Object {@{name=$_.Name;count=$_.Count;working_set_bytes=($_.Group|Measure-Object WorkingSet64 -Sum).Sum;cpu_seconds_lifetime=($_.Group|Measure-Object CPU -Sum).Sum}})
            $coverage.Add(@{check='System/resource sample';status='collected';note='Short sample; low CPU does not exclude serial waits or intermittent contention.'})
        }catch{$coverage.Add((New-AuditFailureCoverage 'System/resource sample' $_ 'os.resources' 'partial-or-unavailable'))}
        try{
            $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {@{name=[string]$_.Name;enabled=$_.Enabled;default_inbound=[string]$_.DefaultInboundAction;default_outbound=[string]$_.DefaultOutboundAction}})
            $report['firewall_profiles']=$profiles
            foreach($p in $profiles){if(!$p.enabled){$findings.Add((New-AuditFinding 'os.firewall-disabled' 'high' ('Firewall profile disabled: '+$p.name) 'Enable and validate the appropriate host firewall policy after reviewing access requirements.'))}}
            $broad=@();$management=@()
            foreach($rule in (Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow)){
                $address=@($rule|Get-NetFirewallAddressFilter);$port=@($rule|Get-NetFirewallPortFilter)
                foreach($pf in $port){if([string]$pf.LocalPort -match '^(Any|22|135|139|445|3306|3389|5985|5986|8172)$'){
                    $entry=@{rule_name=$rule.Name;profile=[string]$rule.Profile;protocol=[string]$pf.Protocol;port=[string]$pf.LocalPort;remote_addresses=@($address|ForEach-Object{$_.RemoteAddress});note='Effective allow-rule inventory, not proof of public reachability; deny rules and upstream controls still apply.'}
                    try{
                        $entry['interface_aliases']=@($rule|Get-NetFirewallInterfaceFilter|ForEach-Object{$_.InterfaceAlias})
                        $entry['programs']=@($rule|Get-NetFirewallApplicationFilter|ForEach-Object{$_.Program})
                        $entry['services']=@($rule|Get-NetFirewallServiceFilter|ForEach-Object{$_.Service})
                    }catch{$entry['constraint_diagnostic']=Get-AuditFailure $_ 'os.firewall.rule-constraints'}
                    $management+=$entry
                    if($entry.remote_addresses -contains 'Any'){$broad+=$entry}
                }}
            }
            $report['management_inbound_rules']=$management
            try{$report['network_interfaces']=@(Get-NetAdapter|ForEach-Object{@{name=$_.Name;description=$_.InterfaceDescription;status=[string]$_.Status;index=$_.ifIndex}})}catch{$coverage.Add((New-AuditFailureCoverage 'Network interfaces' $_ 'os.interfaces'))}
            foreach($p in $profiles){if($p.default_inbound -eq 'Allow'){$findings.Add((New-AuditFinding 'os.default-inbound-allow' 'high' ('Firewall default inbound policy allows traffic: '+$p.name) 'Review the effective policy and restrict inbound access to required services and approved sources.'))}}
            $report['broad_inbound_rules']=$broad
            if($broad.Count){$findings.Add((New-AuditFinding 'os.broad-management-rules' 'warning' 'Broad inbound rules cover management/database/any ports.' 'Review program/service constraints and restrict management access to approved VPN/admin sources; verify upstream firewall too.'))}
            $report['listening_ports']=@(Get-NetTCPConnection -State Listen | Group-Object LocalAddress,LocalPort | ForEach-Object {@{address=$_.Group[0].LocalAddress;port=$_.Group[0].LocalPort}})
            $coverage.Add(@{check='Firewall/listeners';status='collected';note='Local inventory does not prove Internet reachability or Cloudflare-only origin access.'})
        }catch{$coverage.Add((New-AuditFailureCoverage 'Firewall/listeners' $_ 'os.firewall'))}
        try{$mp=Get-MpComputerStatus;$report['defender']=@{antivirus_enabled=$mp.AntivirusEnabled;realtime_enabled=$mp.RealTimeProtectionEnabled;signature_age_days=$mp.AntivirusSignatureAge};if(!$mp.RealTimeProtectionEnabled){$findings.Add((New-AuditFinding 'os.defender-not-realtime' 'warning' 'Microsoft Defender realtime protection is not enabled.' 'Verify another supported antivirus product protects the host. Do not disable scanning or add blanket website/PHP exclusions to tune performance.'))}}catch{$coverage.Add((New-AuditFailureCoverage 'Defender' $_ 'os.defender'))}
        try{$report['recent_hotfixes']=@(Get-HotFix|Sort-Object InstalledOn -Descending|Select-Object -First 5|ForEach-Object {@{id=$_.HotFixID;installed=[string]$_.InstalledOn}});$report['pending_reboot']=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')}catch{$coverage.Add((New-AuditFailureCoverage 'Patch/reboot indicators' $_ 'os.patches'))}
        try{$report['smb']=Get-SmbServerConfiguration|Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature;if($report['smb'].EnableSMB1Protocol){$findings.Add((New-AuditFinding 'os.smb1-enabled' 'high' 'SMBv1 server protocol enabled.' 'Remove SMBv1 after confirming legacy dependencies; restrict SMB exposure.'))}}catch{$coverage.Add((New-AuditFailureCoverage 'SMB' $_ 'os.smb'))}
        try{
            $cipherInventory=ConvertTo-AuditCipherInventory @(Get-TlsCipherSuite)
            $report['tls_cipher_names']=$cipherInventory.names
            $coverage.Add(@{check='TLS cipher inventory';status=if($cipherInventory.unrecognized){'partial'}else{'collected'};unrecognized_objects=$cipherInventory.unrecognized;note='Dictionary/object names read directly for Windows PowerShell compatibility; no raw cipher objects collected.'})
        }catch{$coverage.Add((New-AuditFailureCoverage 'TLS cipher inventory' $_ 'os.tls.ciphers'))}
        try{
            $protocols=@()
            foreach($protocol in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3')){
                $key='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$protocol+'\Server'
                if(Test-Path $key){$p=Get-ItemProperty $key;$protocols+=@{protocol=$protocol;enabled=if($p.PSObject.Properties['Enabled']){$p.Enabled}else{'OS default'};disabled_by_default=if($p.PSObject.Properties['DisabledByDefault']){$p.DisabledByDefault}else{'OS default'}}}
            }
            $report['schannel_explicit_protocols']=$protocols
            $coverage.Add(@{check='TLS protocol configuration';status='partial';note='Absent registry entries use OS defaults; this is not a TLS handshake scan or certificate-expiry check.'})
        }catch{$coverage.Add((New-AuditFailureCoverage 'TLS protocol configuration' $_ 'os.tls.protocols'))}
        try{$events=Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 200;$report['application_error_counts']=@($events|Group-Object ProviderName,Id|ForEach-Object {@{provider=$_.Group[0].ProviderName;event_id=$_.Group[0].Id;count=$_.Count}})}catch{$coverage.Add((New-AuditFailureCoverage 'Application error counts' $_ 'os.events' 'none-or-unavailable'))}
        try{
            $systemEvents=@(Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2,3;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 500)
            $report['iis_was_event_summary']=@($systemEvents|Where-Object{$_.ProviderName -match '(?i)(?:WAS|W3SVC|IIS)'}|Group-Object ProviderName,Id|ForEach-Object{
                $times=@($_.Group|ForEach-Object{$_.TimeCreated.ToUniversalTime()}|Sort-Object)
                @{provider=$_.Group[0].ProviderName;event_id=$_.Group[0].Id;count=$_.Count;first_utc=$times[0].ToString('o');last_utc=$times[-1].ToString('o')}
            })
            $coverage.Add(@{check='IIS/WAS System events';status='sampled';note='Up to 500 System warning/error/critical events in 24h, then provider filtering. Empty results do not prove no IIS events. No event messages or process command lines saved.'})
        }catch{$coverage.Add((New-AuditFailureCoverage 'IIS/WAS System events' $_ 'iis.was-events' 'none-or-unavailable'))}
        $paths=@($WordPressPath);if($WordPressPath){$paths+=Join-Path $WordPressPath 'wp-config.php';$paths+=Join-Path $WordPressPath 'wp-content'};$paths+=$PrivatePath
        $aclRows=@();foreach($path in $paths){if($path -and (Test-Path -LiteralPath $path)){try{$row=Get-AuditAcl $path;$aclRows+=$row;if(@($row.entries|Where-Object {$_.broad_allow_write}).Count){$findings.Add((New-AuditFinding 'fs.broad-write-ace' 'warning' ('Broad allow-write ACE on '+$path) 'Check effective permissions and give only app-pool/worker identities the required rights.'))}}catch{$coverage.Add((New-AuditFailureCoverage 'Filesystem ACL' $_ 'fs.acl'))}}};$report['acl']=$aclRows
        if($WordPressPath){foreach($path in $PrivatePath){if(Test-AuditBelowPath $path $WordPressPath){$findings.Add((New-AuditFinding 'fs.private-inside-webroot' 'high' 'A supplied private directory is inside WordPress.' 'Move private customer input/output/logs outside every document root and alias.'))}}}
        if($site){try{$logRoot=[Environment]::ExpandEnvironmentVariables($site.LogFile.Directory);$report['iis_logs']=Get-AuditLogSummary (Join-Path $logRoot ('W3SVC'+$site.Id));if($report['iis_logs'].ContainsKey('query_field_enabled') -and $report['iis_logs']['query_field_enabled']){$findings.Add((New-AuditFinding 'logs.query-field' 'warning' 'IIS W3C schema includes query strings.' 'Verify capability-bearing downloads are excluded or redacted, including proxy/CDN logs; do not share raw logs.'))}}catch{$coverage.Add((New-AuditFailureCoverage 'IIS log sample' $_ 'iis.logs'))}}
        if($iis){
            if($iis.Contains('pool') -and $iis['pool']['identity_type'] -eq 'LocalSystem'){$findings.Add((New-AuditFinding 'iis.system-identity' 'high' 'App pool runs as LocalSystem.' 'Use a dedicated least-privilege app-pool identity and review filesystem access.'))}
            if($iis.Contains('system.webServer/directoryBrowse') -and $iis['system.webServer/directoryBrowse'].Contains('enabled') -and $iis['system.webServer/directoryBrowse']['enabled'] -eq 'True'){$findings.Add((New-AuditFinding 'iis.directory-browsing' 'high' 'Directory browsing is enabled.' 'Disable directory listings where not explicitly required.'))}
            foreach($source in @($iis['cache_header_sources'])){if($source.source -eq 'effective IIS httpProtocol/customHeaders'){$findings.Add((New-AuditFinding 'iis.global-cache-header' 'high' 'Effective IIS customHeaders defines Cache-Control for all responses in scope.' 'Remove or narrow the blanket header; keep long caching only for successful public static assets, no-store on 5xx and sensitive dynamic responses.'))}}
            if($iis.Contains('pool') -and $iis['pool']['cpu_limit_raw'] -gt 0 -and $iis['pool']['cpu_action'] -match 'Throttle|Kill'){$findings.Add((New-AuditFinding 'iis.cpu-policy' 'warning' 'App pool CPU policy can throttle or terminate requests.' 'Correlate policy with resource samples and slow-request timing before changing limits.'))}
        }
        if($PhpPath -and (Test-Path -LiteralPath $PhpPath -PathType Leaf)){
            try{
                $probe=Join-Path $PSScriptRoot 'audit-wordpress.php'
                $probeResult=Invoke-AuditPhpProbe $PhpPath $probe $WordPressPath -Database:$IncludeDatabase -CompareIPv4:$CompareDatabaseIPv4
                if($probeResult.status -ne 'collected'){
                    $coverage.Add(@{check='PHP/WordPress';status='unavailable';diagnostic=$probeResult})
                }else{
                $php=$probeResult.data
                $report['php_wordpress']=$php
                $report['php_helper_process_ms']=$probeResult.helper_process_ms
                if(!$php.php.opcache_loaded -or $php.php.settings.'opcache.enable' -ne '1'){$findings.Add((New-AuditFinding 'php.opcache-cli-disabled' 'warning' 'The inspected CLI configuration lacks enabled OPcache.' 'Verify the actual FastCGI php.ini/PHPRC and OPcache enablement; CLI enable_cli=0 is normal and not itself a web-performance defect.'))}
                if($php.php.xdebug){$findings.Add((New-AuditFinding 'php.xdebug-loaded' 'warning' 'Xdebug is loaded in the inspected PHP configuration.' 'Verify whether FastCGI also loads Xdebug; measure its impact and restrict development tooling on production.'))}
                if($php.database.status -eq 'ok' -and [double]$php.database.autoload.bytes -gt 800000){$findings.Add((New-AuditFinding 'wp.large-autoload' 'warning' 'Autoloaded options exceed 800 kB.' 'Identify responsible options/plugins in a separate protected review; do not delete options automatically.'))}
                if($php.PSObject.Properties['wordpress'] -and $php.wordpress.PSObject.Properties['literal_flags'] -and $php.wordpress.literal_flags.WP_DEBUG_DISPLAY -eq $true){$findings.Add((New-AuditFinding 'wp.debug-display' 'high' 'A literal WP_DEBUG_DISPLAY=true was found.' 'Disable public error display in the effective production configuration and keep private diagnostics.'))}
                if($php.php.settings.display_errors -eq '1'){$findings.Add((New-AuditFinding 'php.display-errors-cli' 'warning' 'display_errors is enabled in the inspected CLI configuration.' 'Verify the web-SAPI effective setting; public PHP error display can disclose internal paths/configuration.'))}
                if($php.php.settings.allow_url_include -eq '1'){$findings.Add((New-AuditFinding 'php.remote-includes-cli' 'high' 'allow_url_include is enabled in the inspected PHP configuration.' 'Disable remote PHP includes in the production web-SAPI after reviewing application requirements.'))}
                $coverage.Add(@{check='PHP/WordPress';status='CLI/literal-inspection';note='WordPress was not executed. CLI does not prove FastCGI effective runtime; no OPcache hit-rate or plugin timing claim.'})
                }
            }catch{$coverage.Add((New-AuditFailureCoverage 'PHP/WordPress' $_ 'php.probe'))}
        }else{$coverage.Add(@{check='PHP/WordPress';status='skipped';note='Matching php.exe unavailable; pass -PhpPath. No configuration/bootstrap code executed.'})}
    }
    if(!$SkipHttp){
        $curl=Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
        if(!$curl){$curl=Get-Command curl -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1}
        if($curl){
            $rows=@();$token=[guid]::NewGuid().ToString('N')
            $targets=@(@{path=$PagePath;kind='page'},@{path='/wp-includes/css/dashicons.min.css';kind='static'},@{path='/wp-includes/js/jquery/jquery.min.js';kind='static'},@{path='/wp-admin/admin-ajax.php';kind='ajax'},@{path=('/wp-includes/wordpriis-audit-missing-'+$token+'.css');kind='missing-static'})
            $routes=@(@{name='public';address=''});if($OriginAddress){$routes+=@{name='direct-origin';address=$OriginAddress}}
            foreach($route in $routes){foreach($target in $targets){for($n=1;$n -le $Samples;$n++){
                $builder=New-Object UriBuilder($Url);$builder.Path=$target.path;$builder.Query='wordpriis_audit='+$token
                $row=Invoke-AuditCurl $curl.Source $builder.Uri $route.address $TimeoutSeconds $target.kind $n $route.name
                $rows+=$row
                if($row.status -gt 0){foreach($finding in @(Get-AuditCacheFindings $row.status $row.headers $row.kind)){$findings.Add($finding)}}
            }}}
            $report['http_samples']=$rows
            $report['http_summary']=@($rows|Where-Object{$_.status -gt 0}|Group-Object route,kind|ForEach-Object{[pscustomobject]@{route=$_.Group[0].route;kind=$_.Group[0].kind;count=$_.Count;median_ttfb_ms=Get-AuditPercentile @($_.Group|ForEach-Object{$_.ttfb_ms});p95_ttfb_ms=Get-AuditPercentile @($_.Group|ForEach-Object{$_.ttfb_ms}) 0.95;statuses=@($_.Group|ForEach-Object{$_.status}|Sort-Object -Unique)}})
            $failedRequests=@($rows|Where-Object{$_.status -eq 0}).Count
            if($failedRequests){$findings.Add((New-AuditFinding 'http.unavailable' 'info' ($failedRequests.ToString()+' HTTP samples failed before a usable response.') 'Inspect curl_exit and origin trust/connectivity; do not interpret missing timings as successful or fast requests.'))}
            $coverage.Add(@{check='HTTP timings';status=if($failedRequests){'partial-or-unavailable'}else{'sampled'};note='Sequential GETs only. Unique query/no-cache request is not proof of page-cache bypass. DNS/TCP/TLS times are cumulative; TTFB includes network and server work, not just PHP. No browser LCP/INP or authenticated request measured.'})
        }else{$coverage.Add(@{check='HTTP timings';status='unavailable';note='curl.exe required; no insecure TLS fallback.'})}
    }
    if($manager){$manager.Dispose()}
    $coverage.Add(@{check='Updates/dependency advisories';status='manual-follow-up';note='Version inventory does not prove patch currency; compare supported PHP/WordPress/plugins/OS releases and vendor advisories.'})
    $coverage.Add(@{check='Uncached PHP/plugin/query profiling';status='manual-follow-up';note='Use a verified cache-bypass route in staging plus FastCGI/FREB/WordPress profiling. No server settings, caches or query logging changed.'})
    $report['findings']=@($findings.ToArray()|Sort-Object id,evidence -Unique)
    $report['coverage']=$coverage.ToArray()
    $jsonPath=Join-Path $OutputDirectory 'audit.json';$report|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $md=New-Object System.Collections.Generic.List[string]
    $md.Add('# WORDPRIIS server audit');$md.Add('');$md.Add('UTC: '+$report.generated_utc);$md.Add('');$md.Add('Read audit.json for selected configuration, measurements and coverage gaps. Reports contain operational paths/bindings/SIDs; review before sharing. No automatic fixes were made.');$md.Add('');$md.Add('## Findings')
    foreach($f in $report.findings){$md.Add('');$md.Add('### '+$f.severity.ToUpperInvariant()+': '+$f.id);$md.Add($f.evidence);$md.Add('Next: '+$f.next_step)}
    $md.Add('');$md.Add('## Coverage and limits');foreach($c in $report.coverage){$md.Add('- '+$c.check+': '+$c.status);if($c.ContainsKey('note')){$md.Add('  '+$c.note)};if($c.ContainsKey('diagnostic')){$md.Add('  Diagnostic: '+($c.diagnostic|ConvertTo-Json -Compress -Depth 4))}}
    $md.Add('');$md.Add('## Interpret slowness');$md.Add('Compare public vs direct-origin TTFB and cache status. Slow origin static responses point below WordPress; fast static plus slow dynamic responses point toward PHP/database/plugins/external waits. Confirm with IIS log samples and real FastCGI profiling. A cache HIT can conceal the bottleneck; an unverified cache-busting query is not an uncached baseline. Low CPU may mean blocking I/O, locks or serialized work. Do not disable antivirus or enable indiscriminate caching to mask errors.')
    $md|Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.md') -Encoding UTF8
    Write-Output ('Audit saved: '+$OutputDirectory)
    Write-Output ('Findings: '+$report.findings.Count+'. Inspect coverage: skipped checks are not passes.')
}
if ($MyInvocation.InvocationName -ne '.') { Invoke-WordPrIISServerAudit }
