#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath,[Management.Automation.PSCredential]$DatabaseCredential)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
. (Join-Path $PSScriptRoot '../modules/Artifacts.ps1')
. (Join-Path $PSScriptRoot '../modules/Templates.ps1')
function Initialize-WordPrIISWordPress {
    param([hashtable]$Config,[Management.Automation.PSCredential]$Credential)
    Assert-WordPrIISWindows
    Assert-WordPrIISLocalDatabase $Config
    if(!$Credential -or $Credential.UserName -cne $Config.DatabaseUser){throw 'WORDPRIIS:database-credential-mismatch'}
    $folder=New-WordPrIISReportDirectory $Config 'database-preflight';$inputPath=Join-Path $folder 'input.json';$probe=Join-Path $folder 'test.php'
    try {
        Write-WordPrIISJson $inputPath @{host=$Config.DatabaseHost;database=$Config.DatabaseName;user=$Credential.UserName;password=$Credential.GetNetworkCredential().Password}
        Set-WordPrIISPrivateAcl $inputPath
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'test-database.php') -Destination $probe
        $saved=$ErrorActionPreference
        try{$ErrorActionPreference='Continue';$out=@(& (Join-Path $Config.PhpPath 'php.exe') '-c' (Join-Path $Config.PhpPath 'php.ini') '-d' 'display_errors=0' '-d' 'log_errors=0' $probe $inputPath 2>$null);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$saved}
        if($code -ne 0 -or ($out -join '').Trim() -ne 'WORDPRIIS_DB_OK'){throw 'WORDPRIIS:empty-database-preflight-failed'}
    }finally{foreach($p in @($inputPath,$probe)){if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -Force}}}
    Expand-WordPrIISArtifact $Config.WordPressArchivePath $Config.WordPressArchiveSha256 $Config.WordPressPath 'wordpress/'
    if(!(Test-Path -LiteralPath (Join-Path $Config.WordPressPath 'wp-settings.php')) -or !(Test-Path -LiteralPath (Join-Path $Config.WordPressPath 'wp-includes\version.php'))){throw 'WORDPRIIS:wordpress-package-invalid'}
    $wpConfig=Join-Path $Config.WordPressPath 'wp-config.php'
    if(Test-Path -LiteralPath $wpConfig){throw 'WORDPRIIS:package-must-not-contain-wp-config'}
    Set-WordPrIISPrivateAcl $Config.WordPressPath -Directory
    [IO.File]::WriteAllText($wpConfig,(Get-WordPrIISWpConfig $Config $Credential),(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $Config.WordPressPath 'web.config'),(Get-WordPrIISWebConfig),(New-Object Text.UTF8Encoding($false)))
}
if($MyInvocation.InvocationName -ne '.') { Initialize-WordPrIISWordPress (Read-WordPrIISConfig $ConfigPath) $DatabaseCredential }
