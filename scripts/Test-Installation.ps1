#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Test-WordPrIISInstallation {
    param([hashtable]$Config)
    $folder=New-WordPrIISReportDirectory $Config 'Verification'
    . (Join-Path $PSScriptRoot 'Invoke-WordPrIISServerAudit.ps1')
    $curl=(Get-Command curl.exe -CommandType Application -ErrorAction Stop).Source
    $routes=@(
        @{path='/';expected=200;mime='text/html'},
        @{path='/wp-admin/admin-ajax.php';expected=400;mime=''},
        @{path='/wp-includes/css/dashicons.min.css';expected=200;mime='text/css'},
        @{path='/wp-includes/js/jquery/jquery.min.js';expected=200;mime='javascript'},
        @{path='/wp-config.php';expected=@(403,404);mime=''},
        @{path='/wp-includes/wordpriis-missing.css';expected=404;mime=''}
    )
    $rows=@(foreach($route in $routes){
        $target=[uri]::new([uri]$Config.Url,$route.path)
        $sample=Invoke-AuditCurl $curl $target '' 30 'verification' 1 $route.path
        $mime=if($sample.PSObject.Properties['headers']){[string]$sample.headers['content-type']}else{''}
        $ok=@($route.expected) -contains $sample.status -and (!$route.mime -or $mime -match [regex]::Escape($route.mime))
        @{route=$route.path;status=$sample.status;passed=$ok;timing_ms=if($sample.PSObject.Properties['ttfb_ms']){$sample.ttfb_ms}else{$null}}
    })
    $report=@{schema_version=1;status=if(@($rows|Where-Object{!$_.passed}).Count){'failed'}else{'complete'};checks=$rows;limits=@('No login, checkout, upload execution, cache-generated 5xx or certificate-renewal test','Verify native IIS and edge error caching separately; successful asset checks do not prove all errors are no-store')}
    Write-WordPrIISJson (Join-Path $folder 'verification.json') $report
    if($report.status -ne 'complete'){throw 'WORDPRIIS:http-verification-failed'}
    Write-Output ('Verification report: '+$folder)
}
if($MyInvocation.InvocationName -ne '.') { Test-WordPrIISInstallation (Read-WordPrIISConfig $ConfigPath) }
