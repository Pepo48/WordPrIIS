# Portable behavioral checks; no IIS or Windows host changes.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Invoke-WordPrIISServerAudit.ps1')
$checks=0
function Assert-Audit($Condition,[string]$Message){if(!$Condition){throw $Message};$script:checks++}
$rows=@(Get-AuditCacheFindings 503 @{'cache-control'='public, max-age=31536000'} 'static')
Assert-Audit (@($rows|Where-Object{$_.id -eq 'http.5xx-cache'}).Count -eq 1) 'cacheable 503 detected'
$rows=@(Get-AuditCacheFindings 200 @{'cache-control'='public, max-age=31536000'} 'static')
Assert-Audit ($rows.Count -eq 0) 'long caching remains valid for successful static assets'
$rows=@(Get-AuditCacheFindings 503 @{'cache-control'='no-store, max-age=0'} 'static')
Assert-Audit ($rows.Count -eq 0) 'clean no-store errors accepted'
$rows=@(Get-AuditCacheFindings 400 @{'cache-control'='no-store, private, public, max-age=31536000'} 'ajax')
Assert-Audit (@($rows|Where-Object{$_.id -eq 'http.conflicting-cache'}).Count -eq 1) 'appended conflicting header detected'
Assert-Audit (@($rows|Where-Object{$_.id -eq 'http.ajax-cache'}).Count -eq 1) 'AJAX public TTL detected'
$rows=@(Get-AuditCacheFindings 404 @{'cache-control'='public, max-age=31536000'} 'missing-static')
Assert-Audit (@($rows|Where-Object{$_.id -eq 'http.error-positive-ttl'}).Count -eq 1) 'missing CSS with static TTL detected'
Assert-Audit ((Get-AuditPercentile @(9,1,5) 0.5) -eq 5) 'median calculation'
Assert-Audit ((Get-AuditPercentile @(9,1,5) 0.95) -eq 9) 'p95 calculation'
$base=[IO.Path]::GetTempPath()
Assert-Audit (Test-AuditBelowPath (Join-Path $base 'wp/child') (Join-Path $base 'wp')) 'child-path containment'
Assert-Audit (!(Test-AuditBelowPath (Join-Path $base 'wp-other') (Join-Path $base 'wp'))) 'sibling paths not conflated'
$logs=Join-Path $base ('wordpriis-audit-logtest-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($logs)
try {
    @('#Fields: date time cs-uri-stem cs-uri-query sc-status sc-substatus time-taken',
      '2026-11-07 23:00:00 /wp-admin/admin-ajax.php token=SHOULD_NOT_APPEAR 200 0 1200',
      '2026-11-08 00:00:00 /index.php private=SHOULD_NOT_APPEAR 500 19 300',
      '2026-11-08 00:01:00 /file.css - 200 0 10') | Set-Content (Join-Path $logs 'test.log')
    $summary=Get-AuditLogSummary $logs
    Assert-Audit ($summary.rows -eq 3) 'bounded log sample parsed'
    Assert-Audit ($summary.errors_5xx_by_substatus['500.19'] -eq 1) 'IIS 500.19 counted'
    Assert-Audit ($summary.sample_first_utc.StartsWith('2026-11-07T23:00:00') -and $summary.sample_last_utc.StartsWith('2026-11-08T00:01:00')) 'IIS sample UTC time window retained'
    Assert-Audit ($summary.last_5xx_utc.StartsWith('2026-11-08T00:00:00')) 'historical 5xx time separated from audit time'
    Assert-Audit ($summary.query_field_enabled) 'query logging schema flagged'
    Assert-Audit (!(($summary|ConvertTo-Json -Depth 8) -match 'SHOULD_NOT_APPEAR|admin-ajax.php|index.php')) 'report excludes raw request paths/queries'
} finally {Remove-Item -LiteralPath $logs -Recurse -Force}
# IIS discovery uses synthetic inventories; never guess across ambiguous sites.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('wordpriis-audit-discovery-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
try {
    $sites=@(
        @{name='Other';roots=@(Join-Path $fixture 'other');bindings=@(@{protocol='https';hostname='other.example';port=443})},
        @{name='Actual WORDPRIIS';roots=@(Join-Path $fixture 'wordpress');bindings=@(@{protocol='https';hostname='wordpress.example.com';port=443})}
    )
    $chosen=Select-AuditSite $sites ([uri]'https://wordpress.example.com') '' ''
    Assert-Audit ($chosen.name -eq 'Actual WORDPRIIS' -and $chosen.selected_by -eq 'binding-hostname') 'site selected by hostname instead of first site'
    $duplicate=@($sites[1],@{name='Duplicate';roots=@(Join-Path $fixture 'duplicate');bindings=$sites[1].bindings})
    Assert-Audit ((Select-AuditSite $duplicate ([uri]'https://wordpress.example.com') '' '').code -eq 'ambiguous-site-match') 'ambiguous hostname is not guessed'
    Assert-Audit ((Select-AuditSite $duplicate ([uri]'https://wordpress.example.com') '' (Join-Path $fixture 'wordpress')).name -eq 'Actual WORDPRIIS') 'explicit WordPress root breaks duplicate-host tie'
    Assert-Audit ((Select-AuditSite $sites ([uri]'https://wordpress.example.com') 'Other' '').name -eq 'Other') 'explicit site override retained'
    Assert-Audit ((Select-AuditSite $sites ([uri]'https://wordpress.example.com') 'Missing' '').code -eq 'requested-site-not-found') 'invalid site name diagnosed'
    Assert-Audit ((Select-AuditSite $sites ([uri]'https://unknown.example') '' '').code -eq 'no-hostname-or-root-match') 'unknown hostname does not select default site'
    $wild=@(@{name='Wildcard';roots=@();bindings=@(@{protocol='https';hostname='*.example.com';port=443})},@{name='Exact';roots=@();bindings=@(@{protocol='https';hostname='shop.example.com';port=443})})
    Assert-Audit ((Select-AuditSite $wild ([uri]'https://shop.example.com') '' '').name -eq 'Exact') 'exact binding preferred over wildcard'
    Assert-Audit ((Select-AuditSite $wild ([uri]'https://other.example.com') '' '').name -eq 'Wildcard') 'wildcard binding resolves bounded hostname suffix'
    $phpFolder=Join-Path $fixture 'PHP 8.4';[void][IO.Directory]::CreateDirectory($phpFolder)
    $cli=Join-Path $phpFolder 'php.exe';[IO.File]::WriteAllText($cli,'synthetic; never executed')
    $handler=@{path='*.php';verb='GET,POST';modules='FastCgiModule';precondition='bitness64';processor=('"'+(Join-Path $phpFolder 'php-cgi.exe')+'"|-dsecret=DO_NOT_LEAK')}
    $resolved=Resolve-AuditPhp @($handler) '' $false
    Assert-Audit ($resolved.path -eq $cli -and $resolved.selected_by -eq 'effective-site-php-handler') 'PHP resolved from selected handler with spaced quoted path'
    Assert-Audit (!(($resolved|ConvertTo-Json) -match 'DO_NOT_LEAK|secret=')) 'handler arguments never serialized'
    Assert-Audit ((Resolve-AuditPhp @($handler) '').code -eq 'pool-bitness-unverified') 'unknown app-pool bitness is not guessed'
    Assert-Audit ((Resolve-AuditPhp @($handler) '' $true).code -eq 'no-effective-php-handler') 'wrong-bitness handler excluded'
    Assert-Audit ((Resolve-AuditPhp @() $cli).path -eq $cli) 'explicit PHP path override retained'
    Assert-Audit ((Resolve-AuditPhp @() (Join-Path $fixture 'missing.exe')).code -eq 'explicit-php-not-found') 'missing explicit PHP file diagnosed'
    $missing=@{};foreach($key in $handler.Keys){$missing[$key]=$handler[$key]};$missing.processor=Join-Path $fixture 'missing/php-cgi.exe'
    Assert-Audit ((Resolve-AuditPhp @($missing) '' $false).code -eq 'handler-cli-sibling-missing') 'missing CLI sibling diagnosed rather than choosing global PHP'
    try{throw (New-Object UnauthorizedAccessException('secret=DO_NOT_LEAK; token=PRIVATE'))}catch{$diagnostic=Get-AuditFailure $_ 'test.denied'}
    Assert-Audit ($diagnostic.code -eq 'access-denied') 'access-denied classified'
    Assert-Audit (!(($diagnostic|ConvertTo-Json) -match 'DO_NOT_LEAK|PRIVATE|secret=|token=')) 'exception message and stack excluded'
    try{& 'wordpriis-command-that-does-not-exist'}catch{$diagnostic=Get-AuditFailure $_ 'test.command'}
    Assert-Audit ($diagnostic.code -eq 'command-unavailable') 'missing command classified'
    $helper=Join-Path $fixture 'audit-wordpress.php';[IO.File]::WriteAllText($helper,'synthetic; never executed')
    Assert-Audit ((Invoke-AuditPhpProbe 'not-executed' (Join-Path $fixture 'missing.php') '').code -eq 'php-helper-missing') 'missing PHP helper diagnosed before invocation'
    function Fake-AuditPhp {
        $global:LASTEXITCODE=0
        if($args -contains '-v'){Write-Output ('PHP '+$script:fakeVersion+' (cli)');return}
        $script:probeArgvEnabled=$args -contains 'register_argc_argv=1'
        $script:probeCompareEnabled=$args -contains '--compare-loopback-ipv4'
        $script:probeDatabaseEnabled=$args -contains '--database'
        if($script:fakeMode -eq 'nonzero'){$global:LASTEXITCODE=7;Write-Output 'secret=DO_NOT_LEAK';return}
        if($script:fakeMode -eq 'missing-json'){Write-Output 'secret=DO_NOT_LEAK';return}
        if($script:fakeMode -eq 'invalid-json'){Write-Output 'WORDPRIIS_AUDIT_JSON:secret=DO_NOT_LEAK';return}
        if($script:fakeMode -eq 'incomplete'){Write-Output 'WORDPRIIS_AUDIT_JSON:{"status":"unavailable"}';return}
        Write-Output 'WORDPRIIS_AUDIT_JSON:{"php":{"version":"8.4.0","settings":{}},"database":{"status":"skipped"}}'
    }
    $script:fakeVersion='7.4.33';$script:fakeMode='ok'
    Assert-Audit ((Invoke-AuditPhpProbe 'Fake-AuditPhp' $helper '').code -eq 'php-version-unsupported') 'old PHP diagnosed without executing helper'
    $script:fakeVersion='8.4.0'
    foreach($case in @(@('nonzero','php-helper-nonzero-exit'),@('missing-json','php-helper-no-json'),@('invalid-json','php-helper-invalid-json'),@('incomplete','php-helper-incomplete-result'))){
        $script:fakeMode=$case[0];$probe=Invoke-AuditPhpProbe 'Fake-AuditPhp' $helper ''
        Assert-Audit ($probe.code -eq $case[1]) ('PHP failure classified: '+$case[0])
        Assert-Audit (!(($probe|ConvertTo-Json) -match 'DO_NOT_LEAK|secret=')) 'PHP raw stdout/stderr excluded'
    }
    $script:fakeMode='ok'
    Assert-Audit ((Invoke-AuditPhpProbe 'Fake-AuditPhp' $helper '').status -eq 'collected') 'valid PHP helper result retained'
    $timed=Invoke-AuditPhpProbe 'Fake-AuditPhp' $helper ''
    Assert-Audit ($timed.helper_process_ms -ge 0) 'helper process duration retained separately from database query time'
    Assert-Audit $script:probeArgvEnabled 'argument parsing enabled for child PHP process only'
    [void](Invoke-AuditPhpProbe 'Fake-AuditPhp' $helper '' -Database -CompareIPv4)
    Assert-Audit ($script:probeCompareEnabled -and $script:probeDatabaseEnabled) 'opt-in comparison flag reaches PHP with database diagnostics'
    [void](Invoke-AuditPhpProbe 'Fake-AuditPhp' $helper '' -CompareIPv4)
    Assert-Audit (!$script:probeCompareEnabled -and !$script:probeDatabaseEnabled) 'comparison flag cannot implicitly enable database access'
} finally {Remove-Item -LiteralPath $fixture -Recurse -Force}

# A failed IIS section must not erase successful settings or cache-header evidence.
$script:mockSection=New-Object PSObject
$script:mockSection|Add-Member ScriptMethod GetAttributeValue {param($name) return 'True'}
$script:mockSection|Add-Member ScriptMethod GetChildElement {param($name) return $this}
$script:mockSection|Add-Member ScriptMethod GetCollection {param($name) if($name -eq 'customHeaders'){return @(@{name='Cache-Control';value='public, max-age=31536000'})};return @()}
$script:mockConfig=New-Object PSObject
$script:mockConfig|Add-Member ScriptMethod GetSection {param($name) if($name -eq 'system.webServer/directoryBrowse'){throw (New-Object UnauthorizedAccessException('secret=DO_NOT_LEAK'))};return $script:mockSection}
$mockManager=New-Object PSObject
$mockManager|Add-Member ScriptMethod GetWebConfiguration {param($name,$path) $script:requestedApplication=$path;return $script:mockConfig}
$partial=Get-AuditConfig $mockManager 'Fixture' '/wordpress'
Assert-Audit ($partial['system.webServer/caching']['enabled'] -eq 'True') 'successful IIS sections survive adjacent failure'
Assert-Audit ($partial['system.webServer/directoryBrowse']['diagnostic']['code'] -eq 'access-denied') 'IIS section failure retains safe reason'
Assert-Audit ($partial['cache_header_sources'].Count -eq 1) 'cache-header evidence retained with partial IIS configuration'
Assert-Audit ($script:requestedApplication -eq '/wordpress') 'effective configuration uses selected application path'
Assert-Audit (!(($partial|ConvertTo-Json -Depth 10) -match 'DO_NOT_LEAK|secret=')) 'IIS failure does not expose config or exception text'
# Discovery must not depend on property cmdlets adapting hashtable keys (PS 5.1).
function Measure-Object {throw 'DO_NOT_LEAK: synthetic Windows property adapter failure'}
try{
    $dictionarySite=@(@{name='Only';roots=@();bindings=@(@{protocol='https';hostname='wordpress.example.com';port=443})})
    Assert-Audit ((Select-AuditSite $dictionarySite ([uri]'https://wordpress.example.com') '' '').name -eq 'Only') 'site ranking avoids dictionary property cmdlets'
}finally{Remove-Item Function:Measure-Object}
$inventory=ConvertTo-AuditCipherInventory @(@{Name='TLS_AES_256_GCM_SHA384'},[pscustomobject]@{Name='TLS_AES_128_GCM_SHA256'},@{Other='DO_NOT_LEAK'},@{Name='secret=DO_NOT_LEAK'})
Assert-Audit ($inventory.names.Count -eq 2 -and $inventory.unrecognized -eq 2) 'TLS names support dictionary/native objects and skip unknown shapes'
Assert-Audit (!(($inventory|ConvertTo-Json) -match 'DO_NOT_LEAK|secret=')) 'unexpected cipher objects never serialized'
try{[pscustomobject]@{Other='secret=DO_NOT_LEAK'}|Select-Object -ExpandProperty Name -ErrorAction Stop}catch{$invalid=Get-AuditFailure $_ 'test.invalid-property'}
Assert-Audit ($invalid.code -eq 'invalid-collector-argument' -and $invalid.command -eq 'Select-Object') 'argument failure identifies allowlisted command'
Assert-Audit ($invalid.source_line -gt 0 -and $invalid.error_identifier -eq 'ExpandPropertyNotFound') 'failure includes source line and known error identifier'
Assert-Audit (!(($invalid|ConvertTo-Json) -match 'DO_NOT_LEAK|secret=')) 'new diagnostic metadata does not include raw error input'
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../scripts/Invoke-WordPrIISServerAudit.ps1'),[ref]$tokens,[ref]$errors)
Assert-Audit ($errors.Count -eq 0) 'PowerShell parser passes'
Write-Output "Server audit PowerShell: $checks checks passed."
