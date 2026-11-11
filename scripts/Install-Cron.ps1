#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath,[Management.Automation.PSCredential]$TaskCredential)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Get-WordPrIISCronRuntime {
    param([hashtable]$Config)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$key=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(([uri]$Config.Url).AbsoluteUri))).Replace('-','').Substring(0,16).ToLowerInvariant()}finally{$sha.Dispose()}
    return Join-Path $Config.PrivatePath ('Permanent-WordPressCron-'+$key)
}
function Install-WordPrIISCron {
    param([hashtable]$c,[Management.Automation.PSCredential]$Credential)
$account=$env:COMPUTERNAME+'\'+$c.ServiceAccountName
if(!$Credential){$Credential=Get-Credential -UserName $account -Message 'Existing WordPress cron service account password'}
& (Join-Path $PSScriptRoot 'Install-VerifiedWordPressCron.ps1') -Url $c.Url -SiteName $c.SiteName -WordPressPath $c.WordPressPath -PhpPath (Join-Path $c.PhpPath 'php.exe') -TaskAccount $account -TaskCredential $Credential -RuntimeDirectory (Get-WordPrIISCronRuntime $c)

}
if($MyInvocation.InvocationName -ne '.') { Install-WordPrIISCron (Read-WordPrIISConfig $ConfigPath) $TaskCredential }
