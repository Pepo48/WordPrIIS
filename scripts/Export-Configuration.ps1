#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Get-WordPrIISBinaryInventory {
    param([hashtable]$Config)
    @(foreach($file in @('php.exe','php-cgi.exe','ext/php_opcache.dll')){
        $path=Join-Path $Config.PhpPath $file
        if(!(Test-Path -LiteralPath $path -PathType Leaf)){@{file=$file;status='missing'};continue}
        try{@{file=$file;status='collected';sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}}catch{@{file=$file;status='unavailable';code='binary-hash-failed'}}
    })
}
function Export-WordPrIISConfiguration {
    param([hashtable]$Config)
    $folder=New-WordPrIISReportDirectory $Config 'Configuration'
    # Config validation admits only this public schema. Never dump phpinfo, env, IIS XML or wp-config.
    Write-WordPrIISJson (Join-Path $folder 'desired-config.json') $Config
    Write-WordPrIISJson (Join-Path $folder 'php-binary-hashes.json') @(Get-WordPrIISBinaryInventory $Config)
    & (Join-Path $PSScriptRoot 'Invoke-WordPrIISServerAudit.ps1') -Url $Config.Url -SiteName $Config.SiteName -WordPressPath $Config.WordPressPath -PhpPath (Join-Path $Config.PhpPath 'php.exe') -OutputDirectory (Join-Path $folder 'effective') -SkipHttp
    Write-Output ('Private configuration report: '+$folder)
}
if($MyInvocation.InvocationName -ne '.') { Export-WordPrIISConfiguration (Read-WordPrIISConfig $ConfigPath) }
