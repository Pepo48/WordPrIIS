#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
. (Join-Path $PSScriptRoot '../modules/Artifacts.ps1')
function Install-WordPrIISPrerequisites {
    param([hashtable]$Config)
    Assert-WordPrIISWindows
    Import-Module ServerManager
    $features=@('Web-Server','Web-Static-Content','Web-Default-Doc','Web-Http-Errors','Web-Http-Logging','Web-Request-Monitor','Web-Filtering','Web-CGI','Web-Mgmt-Console')
    $missing=@(Get-WindowsFeature -Name $features|Where-Object{!$_.Installed}|ForEach-Object{$_.Name})
    if($missing.Count){$result=Install-WindowsFeature -Name $missing -IncludeManagementTools;if(!$result.Success){throw 'WORDPRIIS:iis-features-failed'};if([string]$result.RestartNeeded -eq 'Yes'){throw 'WORDPRIIS:reboot-required'}}
    Import-Module WebAdministration
    if($Config.VcRuntimePath){Test-WordPrIISArtifact $Config.VcRuntimePath $Config.VcRuntimeSha256;$p=Start-Process -FilePath $Config.VcRuntimePath -ArgumentList '/install /quiet /norestart' -Wait -PassThru;if($p.ExitCode -notin @(0,1638,3010)){throw 'WORDPRIIS:vc-runtime-failed'}}
    if(!(Get-WebGlobalModule|Where-Object{$_.Name -eq 'RewriteModule'})){
        Test-WordPrIISArtifact $Config.UrlRewriteMsiPath $Config.UrlRewriteMsiSha256
        $p=Start-Process -FilePath (Join-Path $env:windir 'System32\msiexec.exe') -ArgumentList ('/i "'+$Config.UrlRewriteMsiPath+'" /qn /norestart') -Wait -PassThru
        if($p.ExitCode -notin @(0,3010)){throw 'WORDPRIIS:url-rewrite-install-failed'}
        if(!(Get-WebGlobalModule|Where-Object{$_.Name -eq 'RewriteModule'})){throw 'WORDPRIIS:url-rewrite-unavailable'}
    }
}
if($MyInvocation.InvocationName -ne '.') { Install-WordPrIISPrerequisites (Read-WordPrIISConfig $ConfigPath) }
