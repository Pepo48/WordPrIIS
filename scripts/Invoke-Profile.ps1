#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath,[switch]$BenchmarkFileSystem)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Invoke-WordPrIISProfile {
    param([hashtable]$c,[switch]$FileSystemProbe)
& (Join-Path $PSScriptRoot 'Invoke-WordPrIISBootstrapProfile.ps1') -Url $c.Url -SiteName $c.SiteName -WordPressPath $c.WordPressPath -PhpPath (Join-Path $c.PhpPath 'php.exe') -OutputDirectory (Join-Path $c.PrivatePath ('Profile-'+[guid]::NewGuid().ToString('N'))) -BenchmarkFileSystem:$FileSystemProbe

}
if($MyInvocation.InvocationName -ne '.') { Invoke-WordPrIISProfile (Read-WordPrIISConfig $ConfigPath) -FileSystemProbe:$BenchmarkFileSystem }
