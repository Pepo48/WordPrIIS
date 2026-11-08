#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath,[Management.Automation.PSCredential]$DatabaseCredential)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
. (Join-Path $PSScriptRoot 'Install-Prerequisites.ps1') -ConfigPath $ConfigPath
. (Join-Path $PSScriptRoot 'Install-PHP.ps1') -ConfigPath $ConfigPath
. (Join-Path $PSScriptRoot 'Initialize-WordPress.ps1') -ConfigPath $ConfigPath -DatabaseCredential $DatabaseCredential
. (Join-Path $PSScriptRoot 'Configure-IIS.ps1') -ConfigPath $ConfigPath
function Invoke-WordPrIISBootstrap {
    param([hashtable]$Config,[Management.Automation.PSCredential]$Credential)
    Assert-WordPrIISWindows
    Assert-WordPrIISLocalDatabase $Config
    if(!$Credential -or $Credential.UserName -cne $Config.DatabaseUser){throw 'WORDPRIIS:database-credential-mismatch'}
    # All artifact/identity/collision checks precede mutation of the machine.
    Test-WordPrIISArtifact $Config.PhpArchivePath $Config.PhpArchiveSha256
    Test-WordPrIISArtifact $Config.WordPressArchivePath $Config.WordPressArchiveSha256
    foreach($key in @('WordPressPath','PhpPath')){Assert-WordPrIISPlainPath $Config[$key];if(Test-Path -LiteralPath $Config[$key]){throw 'WORDPRIIS:new-installation-paths-required'}}
    Assert-WordPrIISPlainPath $Config.PrivatePath
    if(([uri]$Config.Url).Port -ne 443){throw 'WORDPRIIS:bootstrap-requires-https-port-443'}
    if($Config.CertificateThumbprint -notmatch '^[a-fA-F0-9]{40}$'){throw 'WORDPRIIS:existing-tls-certificate-required'}
    $cert=Get-Item ('Cert:\LocalMachine\My\'+$Config.CertificateThumbprint)
    if(!$cert.HasPrivateKey -or $cert.NotAfter -lt (Get-Date)){throw 'WORDPRIIS:tls-certificate-not-usable'}
    if(Get-Service W3SVC -ErrorAction SilentlyContinue){
        Import-Module WebAdministration
        if((Get-Website|Where-Object{$_.Name -eq $Config.SiteName}) -or (Test-Path ('IIS:\AppPools\'+$Config.AppPool))){throw 'WORDPRIIS:new-site-and-pool-required'}
    }
    if($Config.VcRuntimePath){Test-WordPrIISArtifact $Config.VcRuntimePath $Config.VcRuntimeSha256}
    if($Config.UrlRewriteMsiPath){Test-WordPrIISArtifact $Config.UrlRewriteMsiPath $Config.UrlRewriteMsiSha256}
    # Journal is private even when prerequisites/DB preflight fail. This is not an automatic rollback.
    $folder=New-WordPrIISReportDirectory $Config 'Bootstrap'
    $report=[ordered]@{schema_version=1;status='incomplete';stage='preflight';completed=@();site=$Config.SiteName;generated_utc=[DateTime]::UtcNow.ToString('o');scope='Fresh paths/site/pool only; existing database and TLS certificate required. No remote-access or firewall changes.'}
    try {
        foreach($step in @('Prerequisites','PHP','WordPress','IIS')){
            $report.stage=$step;Write-WordPrIISJson (Join-Path $folder 'bootstrap.json') $report
            switch($step){
                'Prerequisites' {Install-WordPrIISPrerequisites $Config}
                'PHP' {Install-WordPrIISPhp $Config}
                'WordPress' {Initialize-WordPrIISWordPress $Config $Credential}
                'IIS' {Configure-WordPrIISIis $Config}
            }
            $report.completed+=@($step)
        }
        $report.status='complete';$report['next']='Complete the WordPress web setup, verify HTTPS/assets/uploads/updates/backup restore, then run Audit/Profile and the separate verified Cron installer.'
    }catch{$report.status='failed';$report['error_code']=if($_.Exception.Message -match '^WORDPRIIS:[a-zA-Z0-9-]+$'){$_.Exception.Message}else{'WORDPRIIS:bootstrap-stage-failed'};throw}
    finally{Write-WordPrIISJson (Join-Path $folder 'bootstrap.json') $report;Write-Host ('Bootstrap journal: '+(Join-Path $folder 'bootstrap.json'))}
}
if($MyInvocation.InvocationName -ne '.') { Invoke-WordPrIISBootstrap (Read-WordPrIISConfig $ConfigPath) $DatabaseCredential }
