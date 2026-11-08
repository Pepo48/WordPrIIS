#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Get-WordPrIISAclPlan {
    param([hashtable]$Config)
    @(
        @{path=$Config.WordPressPath;rights='ReadAndExecute';inherit=$true},
        @{path=$Config.PhpPath;rights='ReadAndExecute';inherit=$true},
        @{path=$Config.PrivatePath;rights='ReadAndExecute';inherit=$false},
        @{path=(Join-Path $Config.PrivatePath 'php-data');rights='Modify';inherit=$true},
        @{path=(Join-Path $Config.WordPressPath 'wp-content\uploads');rights='Modify';inherit=$true},
        @{path=(Join-Path $Config.WordPressPath 'wp-content\cache');rights='Modify';inherit=$true},
        @{path=(Join-Path $Config.WordPressPath 'wp-content\wp-rocket-config');rights='Modify';inherit=$true}
    )
}
function Get-WordPrIISFastCgiEnvironment {
    param([hashtable]$Config)
    @(@{name='PHP_FCGI_MAX_REQUESTS';value='10000'},@{name='PHPRC';value=$Config.PhpPath},@{name='PHP_INI_SCAN_DIR';value=(Join-Path $Config.PhpPath 'conf.d')})
}
function Configure-WordPrIISIis {
    param([hashtable]$Config)
    Assert-WordPrIISWindows;Import-Module WebAdministration
    if((Get-Website|Where-Object{$_.Name -eq $Config.SiteName}) -or (Test-Path ('IIS:\AppPools\'+$Config.AppPool))){throw 'WORDPRIIS:new-site-and-pool-required'}
    $thumb=$Config.CertificateThumbprint
    if($thumb -notmatch '^[a-fA-F0-9]{40}$'){throw 'WORDPRIIS:existing-tls-certificate-required'}
    $cert=Get-Item ('Cert:\LocalMachine\My\'+$thumb)
    if(!$cert.HasPrivateKey -or $cert.NotAfter -lt (Get-Date) -or $cert.NotBefore -gt (Get-Date)){throw 'WORDPRIIS:tls-certificate-not-usable'}
    $hostName=([uri]$Config.Url).DnsSafeHost
    $matched=$false
    foreach($name in $cert.DnsNameList){$dns=[string]$name.Unicode;if($dns -ieq $hostName -or ($dns.StartsWith('*.') -and $hostName.IndexOf('.') -gt 0 -and $hostName.Substring($hostName.IndexOf('.')+1) -ieq $dns.Substring(2))){$matched=$true}}
    if(!$matched){throw 'WORDPRIIS:tls-hostname-mismatch'}
    if(Get-WebBinding|Where-Object{$_.protocol -eq 'https' -and $_.bindingInformation -match (':443:'+ [regex]::Escape($hostName)+'$')}){throw 'WORDPRIIS:https-binding-already-exists'}
    $null=New-WebAppPool -Name $Config.AppPool
    $poolPath='IIS:\AppPools\'+$Config.AppPool
    Set-ItemProperty $poolPath -Name managedRuntimeVersion -Value ''
    Set-ItemProperty $poolPath -Name enable32BitAppOnWin64 -Value $false
    Set-ItemProperty $poolPath -Name processModel.identityType -Value 4
    Set-ItemProperty $poolPath -Name processModel.maxProcesses -Value 1
    Set-ItemProperty $poolPath -Name processModel.idleTimeout -Value ([TimeSpan]::Zero)
    Set-ItemProperty $poolPath -Name startMode -Value 'AlwaysRunning'
    $php=Join-Path $Config.PhpPath 'php-cgi.exe'
    $filter="system.webServer/fastCgi/application[@fullPath='$php']"
    if(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $filter){throw 'WORDPRIIS:new-fastcgi-runtime-required'}
    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/fastCgi' -Name '.' -Value @{fullPath=$php;maxInstances=0;instanceMaxRequests=10000;idleTimeout=300;activityTimeout=130;requestTimeout=140}
    foreach($entry in @(Get-WordPrIISFastCgiEnvironment $Config)){Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter ($filter+'/environmentVariables') -Name '.' -Value $entry}
    $null=New-Website -Name $Config.SiteName -PhysicalPath $Config.WordPressPath -ApplicationPool $Config.AppPool -Port 443 -HostHeader $hostName -Ssl -SslFlags 1
    (Get-WebBinding -Name $Config.SiteName -Protocol https).AddSslCertificate($thumb,'My')
    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $Config.SiteName -Filter 'system.webServer/handlers' -Name '.' -Value @{name='WordPrIIS PHP';path='*.php';verb='GET,HEAD,POST';modules='FastCgiModule';scriptProcessor=$php;resourceType='File';requireAccess='Script'}
    # appcmd supports environment/runtime details without exposing any account password.
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $Config.SiteName -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name userName -Value ''
    $account=New-Object Security.Principal.NTAccount('IIS AppPool\'+$Config.AppPool)
    $sid=$account.Translate([Security.Principal.SecurityIdentifier])
    foreach($rule in @(Get-WordPrIISAclPlan $Config)){
        Assert-WordPrIISPlainPath $rule.path
        if(!(Test-Path -LiteralPath $rule.path)){$null=[IO.Directory]::CreateDirectory($rule.path)}
        $acl=Get-Acl -LiteralPath $rule.path
        $inherit=if($rule.inherit){'ContainerInherit,ObjectInherit'}else{'None'}
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,$rule.rights,$inherit,'None','Allow')))
        Set-Acl -LiteralPath $rule.path -AclObject $acl
    }
}
if($MyInvocation.InvocationName -ne '.') { Configure-WordPrIISIis (Read-WordPrIISConfig $ConfigPath) }
