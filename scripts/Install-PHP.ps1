#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
. (Join-Path $PSScriptRoot '../modules/Artifacts.ps1')
. (Join-Path $PSScriptRoot '../modules/Templates.ps1')
function Install-WordPrIISPhp {
    param([hashtable]$Config)
    Assert-WordPrIISWindows
    Test-WordPrIISArtifact $Config.PhpArchivePath $Config.PhpArchiveSha256
    Expand-WordPrIISArtifact $Config.PhpArchivePath $Config.PhpArchiveSha256 $Config.PhpPath
    if(!(Test-Path -LiteralPath (Join-Path $Config.PhpPath 'php-cgi.exe'))){throw 'WORDPRIIS:php-cgi-missing'}
    foreach($dir in @('php-data','php-data\tmp','php-data\sessions','php-data\opcache')){$null=[IO.Directory]::CreateDirectory((Join-Path $Config.PrivatePath $dir))}
    Set-WordPrIISPrivateAcl (Join-Path $Config.PrivatePath 'php-data') -Directory
    [IO.File]::WriteAllText((Join-Path $Config.PhpPath 'php.ini'),(Get-WordPrIISPhpIni $Config),(New-Object Text.UTF8Encoding($false)))
    $null=[IO.Directory]::CreateDirectory((Join-Path $Config.PhpPath 'conf.d'))
    $exe=Join-Path $Config.PhpPath 'php.exe'
    $saved=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$out=@(& $exe '-c' (Join-Path $Config.PhpPath 'php.ini') '-d' 'display_errors=0' '-d' 'log_errors=0' '-r' 'echo PHP_ZTS ? "ts" : (PHP_INT_SIZE === 8 ? "nts-x64" : "nts-x86");' 2>$null);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$saved}
    if($code -ne 0 -or ($out -join '') -ne 'nts-x64'){throw 'WORDPRIIS:php-nts-x64-runtime-check-failed'}
}
if($MyInvocation.InvocationName -ne '.') { Install-WordPrIISPhp (Read-WordPrIISConfig $ConfigPath) }
