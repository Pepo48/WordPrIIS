#requires -Version 5.1
<# One entry point; every operation also has a standalone script. Default action is a pure plan. #>
[CmdletBinding()]
param(
    [ValidateSet('Plan','Artifacts','Bootstrap','Audit','Profile','Cron','Diagnose','ExportConfig','Verify')][string]$Action='Plan',
    [string]$ConfigPath=(Join-Path $PSScriptRoot 'config/example.json'),
    [Management.Automation.PSCredential]$DatabaseCredential,
    [Management.Automation.PSCredential]$TaskCredential,
    [switch]$IncludeDatabase,[switch]$CompareDatabaseIPv4,[switch]$RecordDefender,
    [switch]$BenchmarkFileSystem
)
. (Join-Path $PSScriptRoot 'modules/Common.ps1')
function Get-WordPrIISCommand {
    param([string]$Name)
    $commands=@{Artifacts='Get-Artifacts.ps1';Bootstrap='Invoke-Bootstrap.ps1';Audit='Invoke-Audit.ps1';Profile='Invoke-Profile.ps1';Cron='Install-Cron.ps1';Diagnose='Invoke-WindowsDiagnostics.ps1';ExportConfig='Export-Configuration.ps1';Verify='Test-Installation.ps1'}
    if(!$commands.ContainsKey($Name)){throw 'WORDPRIIS:unsupported-action'}
    return Join-Path (Join-Path $PSScriptRoot 'scripts') $commands[$Name]
}
function Invoke-WordPrIIS {
    $c=Read-WordPrIISConfig $ConfigPath
    if($Action -eq 'Plan'){return Get-WordPrIISPlan $c}
    $arguments=@{ConfigPath=$ConfigPath}
    switch($Action){
        'Bootstrap' {if(!$DatabaseCredential){$DatabaseCredential=Get-Credential -UserName $c.DatabaseUser -Message 'Existing empty WordPress database account'};$arguments.DatabaseCredential=$DatabaseCredential}
        'Cron' {$arguments.TaskCredential=$TaskCredential}
        'Audit' {$arguments.IncludeDatabase=$IncludeDatabase;$arguments.CompareDatabaseIPv4=$CompareDatabaseIPv4}
        'Profile' {$arguments.BenchmarkFileSystem=$BenchmarkFileSystem}
        'Diagnose' {$arguments.RecordDefender=$RecordDefender}
    }
    & (Get-WordPrIISCommand $Action) @arguments
}
if($MyInvocation.InvocationName -ne '.'){
    try{Invoke-WordPrIIS}catch{
        $code=if($_.Exception.Message -match '^(WORDPRIIS|WORDPRIIS_PROFILE|WORDPRIIS_CRON):[a-zA-Z0-9-]+$'){$_.Exception.Message}else{'WORDPRIIS:operation-failed'}
        Write-Error ($code+'; inspect the private stage/report. No raw configuration or credential values are printed.');exit 1
    }
}
