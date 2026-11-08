#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath,[switch]$IncludeDatabase,[switch]$CompareDatabaseIPv4,[switch]$SkipHttp)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Invoke-WordPrIISAudit {
    param([hashtable]$c,[switch]$Db,[switch]$Compare,[switch]$NoHttp)
& (Join-Path $PSScriptRoot 'Invoke-WordPrIISServerAudit.ps1') -Url $c.Url -SiteName $c.SiteName -WordPressPath $c.WordPressPath -PhpPath (Join-Path $c.PhpPath 'php.exe') -OutputDirectory (Join-Path $c.PrivatePath ('Audit-'+[guid]::NewGuid().ToString('N'))) -IncludeDatabase:$Db -CompareDatabaseIPv4:$Compare -SkipHttp:$NoHttp

}
if($MyInvocation.InvocationName -ne '.') { Invoke-WordPrIISAudit (Read-WordPrIISConfig $ConfigPath) -Db:$IncludeDatabase -Compare:$CompareDatabaseIPv4 -NoHttp:$SkipHttp }
