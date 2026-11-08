#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
. (Join-Path $PSScriptRoot '../modules/Artifacts.ps1')
function Get-WordPrIISArtifact {
    param([uri]$Uri,[string]$Expected,[string]$Destination)
    if($Uri.Scheme -ne 'https' -or $Uri.UserInfo -or $Uri.Query -or $Uri.Fragment -or $Uri.DnsSafeHost -notin @('downloads.php.net','downloads.wordpress.org')){throw 'WORDPRIIS:official-artifact-url-required'}
    Assert-WordPrIISPlainPath $Destination
    if(Test-Path -LiteralPath $Destination){Test-WordPrIISArtifact $Destination $Expected;return}
    $parent=Split-Path $Destination -Parent;if(!(Test-Path -LiteralPath $parent)){$null=[IO.Directory]::CreateDirectory($parent)}
    $temp=Join-Path $parent ([guid]::NewGuid().ToString('N')+'.download')
    try{
        Invoke-WebRequest -Uri $Uri -OutFile $temp -UseBasicParsing -MaximumRedirection 0
        Test-WordPrIISArtifact $temp $Expected
        [IO.File]::Move($temp,$Destination)
    }finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
}
function Get-WordPrIISArtifacts {
    param([hashtable]$Config)
    $lock=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '../config/releases.json'))|ConvertFrom-Json
    $php=@($lock.php.recommended,$lock.php.compatibility_branch)|Where-Object{$_.sha256 -ieq $Config.PhpArchiveSha256}
    if(@($php).Count -ne 1 -or $lock.wordpress.sha256 -ine $Config.WordPressArchiveSha256){throw 'WORDPRIIS:reviewed-release-hash-required'}
    Get-WordPrIISArtifact $php.url $php.sha256 $Config.PhpArchivePath
    Get-WordPrIISArtifact $lock.wordpress.url $lock.wordpress.sha256 $Config.WordPressArchivePath
    Write-Output 'Verified release artifacts ready. No service or site configuration changed.'
}
if($MyInvocation.InvocationName -ne '.') { Get-WordPrIISArtifacts (Read-WordPrIISConfig $ConfigPath) }
