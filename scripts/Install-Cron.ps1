#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath,[Management.Automation.PSCredential]$TaskCredential)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Install-WordPrIISCron {
    param([hashtable]$c,[Management.Automation.PSCredential]$Credential)
$account=$env:COMPUTERNAME+'\'+$c.ServiceAccountName
if(!$Credential){$Credential=Get-Credential -UserName $account -Message 'Existing WordPress cron service account password'}
& (Join-Path $PSScriptRoot 'Install-VerifiedWordPressCron.ps1') -Url $c.Url -SiteName $c.SiteName -WordPressPath $c.WordPressPath -PhpPath (Join-Path $c.PhpPath 'php.exe') -TaskAccount $account -TaskCredential $Credential -RuntimeDirectory (Join-Path $c.PrivatePath ('Cron-'+[guid]::NewGuid().ToString('N')))

}
if($MyInvocation.InvocationName -ne '.') { Install-WordPrIISCron (Read-WordPrIISConfig $ConfigPath) $TaskCredential }
