#requires -Version 5.1
<#
.SYNOPSIS
Temporarily profile anonymous no-action WordPress AJAX on the detected IIS site.
.DESCRIPTION
Run elevated, 64-bit, on the IIS host. Installs a unique expiring MU profiler without
editing wp-config.php, collects bounded samples, and cleans up in finally. Keeps a
private report. No service restart, cache purge, payment or IIS configuration change.
#>
[CmdletBinding()]
param(
    [uri]$Url,
    [string]$SiteName,
    [string]$WordPressPath,
    [string]$ContentPath,
    [string]$MuPluginPath,
    [string]$PhpPath,
    [string]$OriginAddress,
    [string]$OutputDirectory,
    [ValidateRange(1,10)][int]$Samples = 3,
    [ValidateRange(5,60)][int]$TimeoutSeconds = 30,
    [switch]$BenchmarkFileSystem
)
# Reuse the tested read-only site/PHP selection and redacted failure helpers.
. (Join-Path $PSScriptRoot 'Invoke-WordPrIISServerAudit.ps1') -Url $Url -SiteName $SiteName -WordPressPath $WordPressPath -PhpPath $PhpPath -OriginAddress $OriginAddress -OutputDirectory $OutputDirectory -Samples $Samples -TimeoutSeconds $TimeoutSeconds

function Assert-ProfileHost {
    if([Environment]::OSVersion.Platform -ne 'Win32NT' -or ![Environment]::Is64BitProcess){throw 'WORDPRIIS_PROFILE:windows-64bit-required'}
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'WORDPRIIS_PROFILE:administrator-required'}
}
function Get-ProfileAccount {
    param([string]$IdentityType,[string]$PoolName,[string]$UserName)
    switch($IdentityType){
        'ApplicationPoolIdentity' {return 'IIS AppPool\'+$PoolName}
        'SpecificUser' {if(!$UserName){throw 'WORDPRIIS_PROFILE:worker-account-missing'};return $UserName}
        'LocalSystem' {return 'S-1-5-18'}
        'LocalService' {return 'S-1-5-19'}
        'NetworkService' {return 'S-1-5-20'}
        default {throw 'WORDPRIIS_PROFILE:worker-identity-unsupported'}
    }
}
function Assert-ProfilePlainPath {
    param([string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    if($full.StartsWith('\\')){throw 'WORDPRIIS_PROFILE:unc-path-unsupported'}
    $item=$full
    while($item){
        if(Test-Path -LiteralPath $item){if((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'WORDPRIIS_PROFILE:reparse-path-unsupported'}}
        $parent=[IO.Directory]::GetParent($item)
        $item=if($parent){$parent.FullName}else{$null}
    }
}
function Get-ProfileDiscovery {
    param([uri]$Target,[string]$RequestedSite,[string]$RequestedRoot,[string]$RequestedContent,[string]$RequestedPhp,[string]$RequestedMu)
    if(!('Microsoft.Web.Administration.ServerManager' -as [type])){Add-Type -Path (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll')}
    $manager=New-Object Microsoft.Web.Administration.ServerManager
    try{
        $roots=@(foreach($s in $manager.Sites){foreach($a in $s.Applications){foreach($v in $a.VirtualDirectories){[Environment]::ExpandEnvironmentVariables($v.PhysicalPath)}}})
        $inventory=@(foreach($s in $manager.Sites){@{name=$s.Name;roots=@($s.Applications|ForEach-Object{[Environment]::ExpandEnvironmentVariables($_.VirtualDirectories['/'].PhysicalPath)});bindings=@(foreach($b in $s.Bindings){if($b.BindingInformation -match '^.*:([0-9]+):(.*)$'){@{protocol=$b.Protocol;port=[int]$matches[1];hostname=$matches[2]}}})}})
        $selection=Select-AuditSite $inventory $Target $RequestedSite $RequestedRoot
        if($selection.status -ne 'selected'){throw ('WORDPRIIS_PROFILE:'+ $selection.code)}
        $site=$manager.Sites[$selection.name]
        $path=$Target.AbsolutePath.TrimEnd('/');if(!$path){$path='/'}
        $apps=@($site.Applications|Where-Object{$_.Path -eq '/' -or $path -eq $_.Path -or $path.StartsWith($_.Path.TrimEnd('/')+'/',[StringComparison]::OrdinalIgnoreCase)}|Sort-Object @{Expression={$_.Path.Length};Descending=$true})
        $app=$apps[0];$pool=$manager.ApplicationPools[$app.ApplicationPoolName]
        $mapped=@(foreach($v in $app.VirtualDirectories){$virtual=($app.Path.TrimEnd('/')+$v.Path).TrimEnd('/');if(!$virtual){$virtual='/'};if($virtual -eq '/' -or $path -eq $virtual -or $path.StartsWith($virtual+'/',[StringComparison]::OrdinalIgnoreCase)){@{url=$virtual;physical=[Environment]::ExpandEnvironmentVariables($v.PhysicalPath)}}})
        $mapping=@($mapped|Sort-Object @{Expression={$_.url.Length};Descending=$true})[0]
        $root=$RequestedRoot
        if(!$root){$relative=$path.Substring($mapping.url.TrimEnd('/').Length).TrimStart('/');$root=Join-Path $mapping.physical ($relative.Replace('/',[IO.Path]::DirectorySeparatorChar))}
        $root=[IO.Path]::GetFullPath($root)
        if(!(Test-Path -LiteralPath (Join-Path $root 'wp-settings.php') -PathType Leaf)){throw 'WORDPRIIS_PROFILE:wordpress-root-not-found'}
        $config=Join-Path $root 'wp-config.php';if(!(Test-Path -LiteralPath $config)){ $config=Join-Path (Split-Path $root -Parent) 'wp-config.php' }
        $text=[IO.File]::ReadAllText($config)
        if($text -match 'WORDPRIIS_PROFILE_(TOKEN_SHA256|UNTIL|FILE)'){throw 'WORDPRIIS_PROFILE:existing-profiler-config'}
        if(!$RequestedContent -and $text -match 'WP_CONTENT_DIR'){throw 'WORDPRIIS_PROFILE:custom-content-override-required'}
        $content=if($RequestedContent){[IO.Path]::GetFullPath($RequestedContent)}else{Join-Path $root 'wp-content'}
        if(!(Test-Path -LiteralPath $content -PathType Container)){throw 'WORDPRIIS_PROFILE:content-directory-missing'}
        if(!$RequestedMu -and $text -match 'WPMU_PLUGIN_DIR'){throw 'WORDPRIIS_PROFILE:custom-mu-override-required'}
        $mu=if($RequestedMu){[IO.Path]::GetFullPath($RequestedMu)}else{Join-Path $content 'mu-plugins'}
        $cfg=$manager.GetWebConfiguration($site.Name,$app.Path)
        $handlers=@($cfg.GetSection('system.webServer/handlers').GetCollection()|ForEach-Object{@{path=[string]$_['path'];verb=[string]$_['verb'];modules=[string]$_['modules'];processor=[string]$_['scriptProcessor'];precondition=[string]$_['preCondition']}})
        $php=Resolve-AuditPhp $handlers $RequestedPhp ([bool]$pool.Enable32BitAppOnWin64)
        if($php.status -ne 'selected'){throw ('WORDPRIIS_PROFILE:'+ $php.code)}
        $account=Get-ProfileAccount ([string]$pool.ProcessModel.IdentityType) $pool.Name ([string]$pool.ProcessModel.UserName)
        $sid=if($account -match '^S-1-'){New-Object Security.Principal.SecurityIdentifier($account)}else{(New-Object Security.Principal.NTAccount($account)).Translate([Security.Principal.SecurityIdentifier])}
        # FastCGI can impersonate the configured anonymous request identity rather
        # than the worker process. Read its name/SID only, never its password.
        $anonymous=@{status='unavailable';enabled=$null;sid=$null}
        $runtimeSids=@($sid.Value)
        try{
            $authCfg=$manager.GetWebConfiguration($site.Name,($path.TrimEnd('/')+'/wp-admin'))
            $section=$authCfg.GetSection('system.webServer/security/authentication/anonymousAuthentication')
            $enabled=[bool]$section['enabled'];$anonymous=@{status='collected';enabled=$enabled;sid=$null}
            if($enabled){
                $name=[string]$section['userName']
                $requestSid=if(!$name){$sid}else{(New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier])}
                $anonymous.sid=$requestSid.Value
                $runtimeSids=@($runtimeSids+@($requestSid.Value)|Select-Object -Unique)
            }
        }catch{$anonymous=@{status='unavailable';enabled=$null;sid=$null}}
        return @{site_name=$site.Name;application_path=$app.Path;pool_name=$pool.Name;identity_type=[string]$pool.ProcessModel.IdentityType;worker_sid=$sid.Value;runtime_sids=$runtimeSids;anonymous_identity=$anonymous;root=$root;content=$content;mu=$mu;web_roots=@($roots)+@($root,$content);php=$php.path}
    }finally{$manager.Dispose()}
}
function Assert-ProfileNoExistingMu {
    param([string]$MuPath)
    if(Test-Path -LiteralPath $MuPath){foreach($file in @(Get-ChildItem -LiteralPath $MuPath -Filter '*.php' -File)){
        if($file.Length -gt 1048576){throw 'WORDPRIIS_PROFILE:large-mu-file-review-required'}
        if([IO.File]::ReadAllText($file.FullName) -match 'wordpriis_profile_start|WORDPRIIS_PROFILE_TOKEN_SHA256'){throw 'WORDPRIIS_PROFILE:existing-mu-profiler'}
    }}
}
function Enter-ProfileLock {
    param([string]$Root)
    $canonical=[IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar).ToLowerInvariant()
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$key=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))).Replace('-','')}finally{$sha.Dispose()}
    $name='WORDPRIIS-Bootstrap-'+$key
    if([Environment]::OSVersion.Platform -eq 'Win32NT'){$name='Global\'+$name}
    $mutex=New-Object Threading.Mutex($false,$name)
    try{
        $acquired=$false
        try{$acquired=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$acquired=$true}
        if(!$acquired){throw 'WORDPRIIS_PROFILE:profiling-session-already-running'}
        return $mutex
    }catch{$mutex.Dispose();throw}
}
function Set-ProfileAcl {
    param([string]$Path,[string[]]$WorkerSid,[ValidateSet('None','Read','Write')][string]$WorkerAccess='None',[switch]$Directory)
    $acl=if($Directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
    $acl.SetAccessRuleProtection($true,$false)
    $inherit=if($Directory){'ContainerInherit,ObjectInherit'}else{'None'}
    foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl',$inherit,'None','Allow')))
    }
    if($WorkerAccess -ne 'None'){
        $rights=if($WorkerAccess -eq 'Write'){'Read, Write'}else{'ReadAndExecute'}
        # Worker access does not inherit onto future reports or diagnostic code.
        foreach($sid in @($WorkerSid|Select-Object -Unique)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),$rights,'None','None','Allow')))}
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function New-ProfileCode {
    param([string]$Source,[string]$Hash,[long]$Expires,[string]$Log,[switch]$FileSystemProbe)
    $literal=$Log.Replace('\','/').Replace("'","\'")
    if(!$Source.StartsWith('<?php')){throw 'WORDPRIIS_PROFILE:invalid-profiler-source'}
    $probe=if($FileSystemProbe){"define('WORDPRIIS_FILESYSTEM_PROBE', true);`n"}else{''}
    return "<?php`nif (!defined('ABSPATH')) { return; }`ndefine('WORDPRIIS_PROFILE_TOKEN_SHA256', '$Hash');`ndefine('WORDPRIIS_PROFILE_UNTIL', $Expires);`ndefine('WORDPRIIS_PROFILE_FILE', '$literal');`n"+$probe+$Source.Substring(5)
}
function Get-ProfileCurlFailure {
    param([int]$ExitCode,[string]$Stderr,[bool]$MetricsValid)
    $categories=@{1='unsupported-protocol';2='curl-initialization-or-option';3='invalid-url';5='proxy-dns';6='host-dns';7='connection';23='local-output-write';26='local-input-read';27='out-of-memory';28='timeout';35='tls-handshake';52='empty-server-reply';55='send';56='receive';58='client-certificate';60='certificate-verification';77='ca-store-read';80='tls-shutdown';97='proxy-handshake'}
    $category=if($ExitCode -eq 0){'invalid-metrics'}elseif($categories.ContainsKey($ExitCode)){$categories[$ExitCode]}else{'curl-other'}
    $result=@{curl_exit=$ExitCode;category=$category;metrics_valid=$MetricsValid}
    # Fixed categories only: never return stderr, certificate subjects, URLs or headers.
    if($ExitCode -in @(35,60,77)){
        if($Stderr -match 'CRYPT_E_REVOCATION_OFFLINE|CERT_TRUST_REVOCATION_STATUS_UNKNOWN|0x80092013'){$result['tls_detail']='revocation-status-unavailable'}
        elseif($Stderr -match 'SEC_E_UNTRUSTED_ROOT|CERT_E_UNTRUSTEDROOT|0x80090325|0x800B0109'){$result['tls_detail']='untrusted-root'}
        elseif($Stderr -match 'SEC_E_CERT_EXPIRED|CERT_E_EXPIRED|0x80090328|0x800B0101'){$result['tls_detail']='certificate-expired'}
        elseif($Stderr -match 'SEC_E_WRONG_PRINCIPAL|CERT_E_CN_NO_MATCH|0x80090322|0x800B010F'){$result['tls_detail']='certificate-name-mismatch'}
    }
    if($ExitCode -in @(2,26)){
        if($Stderr -match '(?i)unknown option|unrecognized option|option.*is unknown|not supported'){$result['option_detail']='unrecognized-or-unsupported-option'}
        elseif($Stderr -match '(?i)requires.*parameter|requires.*argument|no.*parameter'){$result['option_detail']='missing-option-argument'}
        elseif($Stderr -match '(?i)error.*read|cannot.*read|failed.*open'){$result['option_detail']='config-read-failed'}
        elseif($Stderr -match '(?i)config|option.*badly|parse'){$result['option_detail']='config-or-option-syntax'}
        else{$result['option_detail']='initialization-unspecified'}
    }
    return $result
}
function Get-ProfileHttpFailureData {
    param($Record)
    $exception=$Record.Exception
    for($i=0;$i -lt 8 -and $exception;$i++){
        if($exception.Data.Contains('wordpriis_http_failure')){return $exception.Data['wordpriis_http_failure']}
        $exception=$exception.InnerException
    }
    return $null
}
function Start-ProfileCurlProcess {
    param($Process)
    $utf8=New-Object Text.UTF8Encoding($false)
    if($Process.StartInfo.PSObject.Properties['StandardInputEncoding']){
        $Process.StartInfo.StandardInputEncoding=$utf8
        [void]$Process.Start()
    }else{
        # .NET Framework (Windows PowerShell 5.1) uses Console.InputEncoding
        # when constructing the redirected writer and can flush its BOM at Start.
        # Set it before Start, then restore immediately; never change machine policy.
        $savedEncoding=[Console]::InputEncoding
        try{[Console]::InputEncoding=$utf8;[void]$Process.Start()}finally{[Console]::InputEncoding=$savedEncoding}
    }
}
function Invoke-ProfileHttp {
    param([string]$Curl,[uri]$Target,[string]$Token,[string]$DirectAddress,[int]$Timeout,[string]$ConfigFile)
    $nullDevice=if([Environment]::OSVersion.Platform -eq 'Win32NT'){'NUL'}else{'/dev/null'}
    $config=@(('url = "'+$Target.AbsoluteUri+'"'),('header = "X-WORDPRIIS-Profile: '+$Token+'"'),'header = "Cache-Control: no-cache"','noproxy = "*"',('output = "'+$nullDevice+'"'),'dump-header = "-"','silent','show-error','connect-timeout = 5',('max-time = '+$Timeout),'max-redirs = 0','write-out = "WORDPRIIS|%{http_code}|%{time_starttransfer}|%{time_total}"')
    if($DirectAddress){$ip=if($DirectAddress.Contains(':')){'['+$DirectAddress+']'}else{$DirectAddress};$config+='resolve = "'+$Target.DnsSafeHost+':'+$Target.Port+':'+$ip+'"'}
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Curl;$info.Arguments='--disable --config -';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    if($ConfigFile){
        Assert-ProfilePlainPath $ConfigFile
        if(!(Test-Path -LiteralPath $ConfigFile -PathType Leaf) -or $ConfigFile -match '["\r\n]'){throw 'WORDPRIIS_PROFILE:invalid-precreated-curl-config'}
        [IO.File]::WriteAllText($ConfigFile,($config -join "`n")+"`n",(New-Object Text.UTF8Encoding($false)))
        $info.Arguments='--disable --config "'+$ConfigFile+'"'
    }
    $info.RedirectStandardInput=!$ConfigFile;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process;$process.StartInfo=$info;$started=$false
    try{
        if($ConfigFile){[void]$process.Start()}else{Start-ProfileCurlProcess $process};$started=$true;$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
        if(!$ConfigFile){$process.StandardInput.WriteLine(($config -join "`n"));$process.StandardInput.Close()}
        if(!$process.WaitForExit(($Timeout+5)*1000)){$process.Kill();throw 'WORDPRIIS_PROFILE:curl-process-timeout'}
        $raw=$out.GetAwaiter().GetResult();$stderr=$err.GetAwaiter().GetResult()
        $metric=[regex]::Match($raw,'(?m)^WORDPRIIS\|([0-9]{3})\|([0-9.]+)\|([0-9.]+)\r?$')
        $valid=$metric.Success
        if($process.ExitCode -ne 0 -or !$valid){
            $failure=Get-ProfileCurlFailure $process.ExitCode $stderr $valid
            $code=if($process.ExitCode -eq 0){'curl-metrics-invalid'}else{'curl-transport-or-tls'}
            $exception=New-Object InvalidOperationException('WORDPRIIS_PROFILE:'+$code)
            $exception.Data['wordpriis_http_failure']=$failure
            throw $exception
        }
        $profilerStatus='absent';$cacheStatus='unknown';$impersonation='unknown';$openBasedir='unknown'
        foreach($line in $raw.Split("`n")){
            if($line -match '(?i)^X-WORDPRIIS-Profile-Status:\s*(recording|request-gate-rejected|output-unavailable|output-open-failed|output-lock-failed)\s*$'){$profilerStatus=$matches[1].ToLowerInvariant()}
            if($line -match '(?i)^X-WORDPRIIS-Profile-Impersonation:\s*(enabled|disabled|unknown)\s*$'){$impersonation=$matches[1].ToLowerInvariant()}
            if($line -match '(?i)^X-WORDPRIIS-Profile-OpenBasedir:\s*(enabled|disabled)\s*$'){$openBasedir=$matches[1].ToLowerInvariant()}
            if($line -match '(?i)^CF-Cache-Status:\s*(HIT|MISS|DYNAMIC|BYPASS|EXPIRED|STALE|REVALIDATED|UPDATING)\s*$'){$cacheStatus=$matches[1].ToUpperInvariant()}
        }
        return @{status=[int]$metric.Groups[1].Value;ttfb_ms=[Math]::Round(1000*[double]::Parse($metric.Groups[2].Value,[Globalization.CultureInfo]::InvariantCulture),3);total_ms=[Math]::Round(1000*[double]::Parse($metric.Groups[3].Value,[Globalization.CultureInfo]::InvariantCulture),3);stdin_encoding=$(if(!$ConfigFile){'utf8-no-bom'}else{$null});config_transport=$(if($ConfigFile){'private-file'}else{'stdin'});profiler_status=$profilerStatus;cache_status=$cacheStatus;web_impersonation=$impersonation;web_open_basedir=$openBasedir}
    }finally{
        if($started -and !$process.HasExited){$process.Kill()};$process.Dispose()
        if($ConfigFile){[IO.File]::WriteAllText($ConfigFile,'')}
    }
}
function Remove-ProfileOwnedFile {
    param([string]$Path,[string]$ExpectedHash)
    if(!(Test-Path -LiteralPath $Path)){return $true}
    Assert-ProfilePlainPath $Path
    if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $ExpectedHash){return $false}
    Remove-Item -LiteralPath $Path -Force
    return $true
}
function Invoke-WordPrIISBootstrapProfile {
    $stage='preflight';$discovery=$null;$reportDir=$null;$installed=$null;$pending=$null;$codeHash=$null;$createdMu=$false;$log=$null;$ownedReport=$false;$secureReport=$false;$pendingOwned=$false;$published=$false;$sessionLock=$null
    $report=[ordered]@{schema_version=1;runner_revision='2026-11-08.8';request_mode=$(if($OriginAddress){'direct-origin'}else{'public'});generated_utc=[DateTime]::UtcNow.ToString('o');status='incomplete';samples=@();profiles=@();cleanup=@{mu_removed=$true;temporary_worker_access_removed=$true;temporary_code_removed=$true};scope='Anonymous no-action web requests only. Normal WordPress initialization can run hooks/cron. No wp-config/IIS configuration changes.'}
    try{
    try{
        Assert-ProfileHost
        if($Url.Scheme -ne 'https' -or $Url.UserInfo -or $Url.Query -or $Url.Fragment -or $Url.AbsoluteUri -match '["\r\n]'){throw 'WORDPRIIS_PROFILE:invalid-target-url'}
        if($OriginAddress){$ip=$null;if(![Net.IPAddress]::TryParse($OriginAddress,[ref]$ip)){throw 'WORDPRIIS_PROFILE:origin-address-not-ip'}}
        $stage='discovery';$discovery=Get-ProfileDiscovery $Url $SiteName $WordPressPath $ContentPath $PhpPath $MuPluginPath
        $stage='session-lock';$sessionLock=Enter-ProfileLock $discovery.root
        Assert-ProfilePlainPath $discovery.mu
        Assert-ProfileNoExistingMu $discovery.mu
        $report['discovery']=@{site_name=$discovery.site_name;application_path=$discovery.application_path;pool_name=$discovery.pool_name;identity_type=$discovery.identity_type;worker_sid=$discovery.worker_sid;runtime_sids=$discovery.runtime_sids;anonymous_identity=$discovery.anonymous_identity;wordpress_path=$discovery.root;content_path=$discovery.content}
        $curl=(Get-Command curl.exe -CommandType Application -ErrorAction Stop).Source
        $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'wordpriis-bootstrap-profile.php'))
        $stage='output-validation'
        $reportDir=if($OutputDirectory){[IO.Path]::GetFullPath($OutputDirectory)}else{Join-Path $env:ProgramData ('WORDPRIIS-Bootstrap-'+[guid]::NewGuid().ToString('N'))}
        Assert-ProfilePlainPath $reportDir
        if(Test-Path -LiteralPath $reportDir){throw 'WORDPRIIS_PROFILE:report-already-exists'}
        if(!(Test-Path -LiteralPath (Split-Path $reportDir -Parent) -PathType Container)){throw 'WORDPRIIS_PROFILE:report-parent-missing'}
        foreach($root in $discovery.web_roots){Assert-ProfilePlainPath $root;if(Test-AuditBelowPath $reportDir $root){throw 'WORDPRIIS_PROFILE:report-inside-web-root'}}
        Assert-ProfilePlainPath $discovery.mu
        $stage='private-report-setup';$null=New-Item -ItemType Directory -Path $reportDir -ErrorAction Stop;$ownedReport=$true
        Set-ProfileAcl $reportDir $discovery.runtime_sids 'Read' -Directory;$secureReport=$true
        $log=Join-Path $reportDir 'bootstrap.jsonl';[IO.File]::WriteAllText($log,'');Set-ProfileAcl $log $discovery.runtime_sids 'Write'
        $bytes=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
        $token=[BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()
        $sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($token))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
        $expires=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+900
        $code=New-ProfileCode $source $hash $expires $log -FileSystemProbe:$BenchmarkFileSystem
        $privateCode=Join-Path $reportDir 'profiler-code.php';[IO.File]::WriteAllText($privateCode,$code,(New-Object Text.UTF8Encoding($false)))
        $stage='php-syntax';$saved=$ErrorActionPreference
        try{$ErrorActionPreference='Continue';$null=@(& $discovery.php '-d' 'display_errors=0' '-d' 'display_startup_errors=0' '-d' 'log_errors=0' '-l' $privateCode 2>&1);$syntaxExit=$LASTEXITCODE}finally{$ErrorActionPreference=$saved}
        if($syntaxExit -ne 0){throw 'WORDPRIIS_PROFILE:php-syntax-check-failed'}
        $stage='mu-install'
        if(!(Test-Path -LiteralPath $discovery.mu)){$null=New-Item -ItemType Directory -Path $discovery.mu -ErrorAction Stop;$createdMu=$true;Set-ProfileAcl $discovery.mu $discovery.runtime_sids 'Read' -Directory}
        $id=[guid]::NewGuid().ToString('N');$pending=Join-Path $discovery.mu ('.wordpriis-profile-'+$id+'.tmp');$installed=Join-Path $discovery.mu ('000-wordpriis-bootstrap-profile-'+$id+'.php')
        # Unique paths, complete write before atomic publication; never replace an existing MU file.
        $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$pendingOwned=$true
        try{$buffer=[Text.Encoding]::UTF8.GetBytes($code);$stream.Write($buffer,0,$buffer.Length)}finally{$stream.Dispose()}
        $codeHash=(Get-FileHash -LiteralPath $pending -Algorithm SHA256).Hash
        Set-ProfileAcl $pending $discovery.runtime_sids 'Read'
        [IO.File]::Move($pending,$installed);$published=$true
        $report.cleanup.mu_removed=$false
        $report['recovery']=@{temporary_mu_file=$installed;sha256=$codeHash;expires_utc=[DateTimeOffset]::FromUnixTimeSeconds($expires).UtcDateTime.ToString('o');note='If the process is forcibly killed or the server reboots, remove this exact MU file after checking its hash. No wp-config edits were made.'}
        $report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $reportDir 'report.json') -Encoding UTF8
        $target=[uri]($Url.GetLeftPart([UriPartial]::Authority)+$Url.AbsolutePath.TrimEnd('/')+'/wp-admin/admin-ajax.php')
        $stage='measurements'
        for($i=1;$i -le $Samples;$i++){
            $sample=Invoke-ProfileHttp $curl $target $token $OriginAddress $TimeoutSeconds
            $sample['sample']=$i;$report.samples+=@($sample)
            if($sample.status -ne 400){throw 'WORDPRIIS_PROFILE:unexpected-http-status'}
            # PHP shutdown may finish shortly after curl has received the response.
            $until=[DateTime]::UtcNow.AddSeconds(5)
            do{$lines=@([IO.File]::ReadAllLines($log)|Where-Object{$_});if($lines.Count -ge $i){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $until)
            if($lines.Count -lt $i){throw 'WORDPRIIS_PROFILE:profile-record-missing'}
        }
        $report.profiles=@($lines|ForEach-Object{$_|ConvertFrom-Json})
        $report.status='complete'
    }catch{
        $report.status='failed';$report['diagnostic']=Get-AuditFailure $_ $stage
        $httpFailure=Get-ProfileHttpFailureData $_
        if($httpFailure){$report['http_failure']=$httpFailure}
        if($_.Exception.Message -match '^WORDPRIIS_PROFILE:([a-z0-9-]+)$'){$report.diagnostic.code=$matches[1]}
        # Preserve useful fixed hints without returning raw exceptions or invocation text.
        $hints=@{'output-validation'='Use a new local directory outside every IIS root/alias, with an existing trusted parent and no reparse points.';discovery='Verify the unique hostname/application mapping, custom ContentPath, previous profiler presence and selected PHP. No app-pool password is read.';'private-report-setup'='Check local output containment and administrator/worker ACL access.';'php-syntax'='The selected PHP could not validate the profiler; inspect that PHP runtime privately.';measurements='Expected HTTP 400 plus one JSONL record per probe. Check http_failure for curl exit/category and optional fixed TLS detail. For received responses, check redirects/WAF/header forwarding/worker ACLs. Do not bypass certificate validation.'}
        if($hints.ContainsKey($stage)){$report.diagnostic.next_step=$hints[$stage]}
        if($report.diagnostic.code -eq 'profile-record-missing'){
            $report.diagnostic.next_step='Inspect samples[].profiler_status and discovery.anonymous_identity/runtime_sids: absent means no authenticated profiler response (MU not loaded/readable, wrong route/site or stripped request/response header); request-gate-rejected means request context mismatch; output-* means private output access/lock failure (web_open_basedir=enabled can also restrict the output location); recording with no record means shutdown/write/early-termination failure. Cache HIT also needs bypass investigation. No TLS failure is implied.'
        }
    }finally{
        $token=$null;$bytes=$null
        if($published -and $codeHash){try{$report.cleanup.mu_removed=Remove-ProfileOwnedFile $installed $codeHash}catch{$report.cleanup.mu_removed=$false}}
        if($pendingOwned -and (Test-Path -LiteralPath $pending)){try{if(!$codeHash -or !(Remove-ProfileOwnedFile $pending $codeHash)){$report.cleanup.mu_removed=$false;$report['retained_pending_file']=$pending}}catch{$report.cleanup.mu_removed=$false}}
        if($createdMu){try{if(@(Get-ChildItem -LiteralPath $discovery.mu -Force).Count -eq 0){[IO.Directory]::Delete($discovery.mu)}}catch{}}
        if($secureReport){
            if($log -and (Test-Path -LiteralPath $log)){try{$report.profiles=@([IO.File]::ReadAllLines($log)|Where-Object{$_}|ForEach-Object{$_|ConvertFrom-Json})}catch{}}
            foreach($aclPath in @($log,$reportDir)){
                if($aclPath -and (Test-Path -LiteralPath $aclPath)){
                    try{Set-ProfileAcl $aclPath $discovery.runtime_sids 'None' -Directory:($aclPath -eq $reportDir)}catch{$report.cleanup.temporary_worker_access_removed=$false}
                }
            }
            $privateCode=Join-Path $reportDir 'profiler-code.php'
            if(Test-Path -LiteralPath $privateCode){try{Remove-Item -LiteralPath $privateCode -Force}catch{$report.cleanup.temporary_code_removed=$false}}
            if(!$report.cleanup.mu_removed -or !$report.cleanup.temporary_worker_access_removed -or !$report.cleanup.temporary_code_removed){$report.status='cleanup-incomplete'}
            $report|ConvertTo-Json -Depth 16|Set-Content -LiteralPath (Join-Path $reportDir 'report.json') -Encoding UTF8
            @('# WORDPRIIS bootstrap profile',('Status: '+$report.status),('Samples: '+$report.samples.Count),('Profiles: '+$report.profiles.Count),('Temporary MU removed: '+$report.cleanup.mu_removed),('Temporary worker access removed: '+$report.cleanup.temporary_worker_access_removed),'Read report.json for phases and safe diagnostics. No wp-config.php or IIS configuration was edited.')|Set-Content -LiteralPath (Join-Path $reportDir 'summary.md') -Encoding UTF8
            Write-Host ('Report retained: '+$reportDir)
        }else{
            if($ownedReport){try{if(@(Get-ChildItem -LiteralPath $reportDir -Force).Count -eq 0){[IO.Directory]::Delete($reportDir)}}catch{}}
            $reason=if($report.Contains('diagnostic')){$report.diagnostic.code}else{'interrupted'}
            Write-Warning ('Profiling stopped before a private report was created. Stage: '+$stage+'. Reason: '+$reason+'. Raw errors omitted.')
        }
    }
    }finally{if($sessionLock){$sessionLock.ReleaseMutex();$sessionLock.Dispose()}}
    return [pscustomobject]$report
}
if($MyInvocation.InvocationName -ne '.'){
    $result=Invoke-WordPrIISBootstrapProfile
    if($result.status -ne 'complete'){Write-Error ('Profiling status: '+$result.status+'. Review the retained report or preflight stage.');exit 1}
}
