# Portable runner lifecycle checks; synthetic IIS discovery, no real server changes.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Invoke-WordPrIISBootstrapProfile.ps1')
$checks=0
function Assert-Runner($Condition,[string]$Message){if(!$Condition){throw $Message};$script:checks++}
Assert-Runner ((Get-ProfileAccount 'ApplicationPoolIdentity' 'A Pool' '') -eq 'IIS AppPool\A Pool') 'per-pool account'
Assert-Runner ((Get-ProfileAccount 'SpecificUser' 'A Pool' 'HOST\worker') -eq 'HOST\worker') 'SpecificUser account without password'
Assert-Runner ((Get-ProfileAccount 'LocalSystem' '' '') -eq 'S-1-5-18') 'SYSTEM identity'
Assert-Runner ((Get-ProfileAccount 'LocalService' '' '') -eq 'S-1-5-19') 'local-service identity'
Assert-Runner ((Get-ProfileAccount 'NetworkService' '' '') -eq 'S-1-5-20') 'network-service identity'
$refused=$false;try{Get-ProfileAccount 'Unknown' '' ''}catch{$refused=$true}
Assert-Runner $refused 'unknown identity refused'
$refused=$false;try{Get-ProfileAccount 'SpecificUser' '' ''}catch{$refused=$true}
Assert-Runner $refused 'missing custom account refused'
foreach($entry in @(@(6,'host-dns'),@(7,'connection'),@(28,'timeout'),@(35,'tls-handshake'),@(60,'certificate-verification'),@(77,'ca-store-read'),@(0,'invalid-metrics'))){
    $detail=Get-ProfileCurlFailure $entry[0] 'SECRET raw stderr / private token' $false
    Assert-Runner ($detail.category -eq $entry[1] -and ($detail|ConvertTo-Json) -notmatch 'SECRET|private token') 'safe curl exit classification'
}
$detail=Get-ProfileCurlFailure 35 'SECRET URL CRYPT_E_REVOCATION_OFFLINE 0x80092013' $false
Assert-Runner ($detail.tls_detail -eq 'revocation-status-unavailable' -and ($detail|ConvertTo-Json) -notmatch 'SECRET') 'Schannel fixed revocation category'
$detail=Get-ProfileCurlFailure 60 'SEC_E_UNTRUSTED_ROOT private subject' $true
Assert-Runner ($detail.tls_detail -eq 'untrusted-root' -and ($detail|ConvertTo-Json) -notmatch 'private subject') 'Schannel fixed untrusted-root category'
$option=Get-ProfileCurlFailure 2 'curl: option SECRET_TOKEN: is unknown' $false
Assert-Runner ($option.option_detail -eq 'unrecognized-or-unsupported-option' -and ($option|ConvertTo-Json) -notmatch 'SECRET_TOKEN') 'option error classification omits offending token'
# Simulate Framework's missing StandardInputEncoding property on every platform.
$originalEncoding=[Console]::InputEncoding
try{
    [Console]::InputEncoding=New-Object Text.UnicodeEncoding($false,$true)
    $fake=[pscustomobject]@{StartInfo=[pscustomobject]@{};seen_codepage=0;seen_preamble=-1;fail=$false}
    $fake|Add-Member ScriptMethod Start {
        $this.seen_codepage=[Console]::InputEncoding.CodePage
        $this.seen_preamble=[Console]::InputEncoding.GetPreamble().Length
        if($this.fail){throw 'Synthetic start failure'}
        return $true
    }
    Start-ProfileCurlProcess $fake
    Assert-Runner ($fake.seen_codepage -eq 65001 -and $fake.seen_preamble -eq 0) 'legacy writer starts with UTF8 and no BOM'
    Assert-Runner ([Console]::InputEncoding.CodePage -eq 1200) 'console encoding restored after successful start'
    $fake.fail=$true;$failed=$false
    try{Start-ProfileCurlProcess $fake}catch{$failed=$true}
    Assert-Runner ($failed -and [Console]::InputEncoding.CodePage -eq 1200) 'console encoding restored after failed start'
    $modern=[pscustomobject]@{StartInfo=[pscustomobject]@{StandardInputEncoding=$null};seen_codepage=0;seen_preamble=-1}
    $modern|Add-Member ScriptMethod Start {
        $this.seen_codepage=$this.StartInfo.StandardInputEncoding.CodePage
        $this.seen_preamble=$this.StartInfo.StandardInputEncoding.GetPreamble().Length
        return $true
    }
    Start-ProfileCurlProcess $modern
    Assert-Runner ($modern.seen_codepage -eq 65001 -and $modern.seen_preamble -eq 0 -and [Console]::InputEncoding.CodePage -eq 1200) 'modern encoding explicit with no console mutation'
}finally{[Console]::InputEncoding=$originalEncoding}
$testBase=if(Test-Path -LiteralPath '/private/tmp'){'/private/tmp'}else{[IO.Path]::GetTempPath()}
$fixture=Join-Path $testBase ('wordpriis-runner-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$web=Join-Path $fixture 'web';[void][IO.Directory]::CreateDirectory($web)
$mu=Join-Path $web 'mu-plugins'
$existing=Join-Path $web 'wp-config.php';[IO.File]::WriteAllText($existing,'ORIGINAL_CONFIG_SECRET')
try{
    Assert-ProfilePlainPath $fixture
    $code=New-ProfileCode '<?php /* fixture */' ('a'*64) 12345 "C:\private folder\owner's\profile.jsonl"
    Assert-Runner ($code.Contains("C:/private folder/owner\'s/profile.jsonl")) 'PHP path literal escaping'
    Assert-Runner ($code.Contains("define('WORDPRIIS_PROFILE_UNTIL', 12345)")) 'expiry embedded as integer'
    $owned=Join-Path $fixture 'owned.php';[IO.File]::WriteAllText($owned,'owned')
    $hash=(Get-FileHash -LiteralPath $owned -Algorithm SHA256).Hash
    [IO.File]::WriteAllText($owned,'owner edited')
    Assert-Runner (!(Remove-ProfileOwnedFile $owned $hash)) 'edited file never removed'
    Assert-Runner (Test-Path -LiteralPath $owned) 'edited file retained'
    $hash=(Get-FileHash -LiteralPath $owned -Algorithm SHA256).Hash
    Assert-Runner (Remove-ProfileOwnedFile $owned $hash) 'unchanged owned file removed'
    Assert-Runner (!(Test-Path -LiteralPath $owned)) 'owned file gone'
    if([Environment]::OSVersion.Platform -eq 'Win32NT'){
        $aclFolder=Join-Path $fixture 'acl';[void][IO.Directory]::CreateDirectory($aclFolder)
        Set-ProfileAcl $aclFolder 'S-1-5-19' 'Read' -Directory
        $aclFile=Join-Path $aclFolder 'log';[IO.File]::WriteAllText($aclFile,'')
        Set-ProfileAcl $aclFile @('S-1-5-19','S-1-5-20') 'Write'
        $acl=Get-Acl -LiteralPath $aclFile
        Assert-Runner $acl.AreAccessRulesProtected 'Windows file inheritance disabled'
        $workerRules=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IdentityReference.Value -in @('S-1-5-19','S-1-5-20')})
        Assert-Runner ($workerRules.Count -eq 2 -and @($workerRules|Where-Object{$_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Delete}).Count -eq 0) 'worker can write without delete/full-control'
        Set-ProfileAcl $aclFile 'S-1-5-19' 'None'
        $acl=Get-Acl -LiteralPath $aclFile
        Assert-Runner (@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IdentityReference.Value -in @('S-1-5-19','S-1-5-20')}).Count -eq 0) 'Windows worker ACE removed'
    }
    $mutex=Enter-ProfileLock $web
    try{
        $child=Join-Path $fixture 'lock-check.ps1'
        $scriptPath=(Join-Path $PSScriptRoot '../scripts/Invoke-WordPrIISBootstrapProfile.ps1').Replace("'","''")
        $rootLiteral=$web.Replace("'","''")
        $childCode=". '$scriptPath'`n"+'try { $m=Enter-ProfileLock '+"'$rootLiteral'"+'; $m.ReleaseMutex(); $m.Dispose(); exit 5 } catch { if ($_.Exception.Message -eq "WORDPRIIS_PROFILE:profiling-session-already-running") { Write-Output "LOCKED"; exit 0 }; exit 6 }'
        [IO.File]::WriteAllText($child,$childCode)
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $info.Arguments='-NoLogo -NoProfile -File "'+$child+'"';$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=New-Object Diagnostics.Process;$process.StartInfo=$info
        try{
            [void]$process.Start()
            if(!$process.WaitForExit(10000)){$process.Kill();throw 'Lock test timeout'}
            Assert-Runner ($process.ExitCode -eq 0 -and $process.StandardOutput.ReadToEnd().Trim() -eq 'LOCKED') 'concurrent process cannot acquire installation mutex'
        }finally{$process.Dispose()}
    }finally{$mutex.ReleaseMutex();$mutex.Dispose()}
    # Inspect actual redirected bytes in a native child, not merely an encoding label.
    $originalInputEncoding=[Console]::InputEncoding
    try{
        foreach($encoding in @((New-Object Text.UnicodeEncoding($false,$true)),(New-Object Text.UTF8Encoding($true)))){
            [Console]::InputEncoding=$encoding
            $childCommand='$memory=New-Object IO.MemoryStream; [Console]::OpenStandardInput().CopyTo($memory); $bytes=$memory.ToArray(); @{length=$bytes.Length;first=[int]$bytes[0];nul_count=@($bytes|Where-Object{$_ -eq 0}).Count}|ConvertTo-Json -Compress'
            $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCommand))
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            $info.Arguments='-NoLogo -NoProfile -EncodedCommand '+$encoded
            $info.UseShellExecute=$false;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $process=New-Object Diagnostics.Process;$process.StartInfo=$info
            try{
                Start-ProfileCurlProcess $process
                $payload='url = "https://example.test/"'
                $process.StandardInput.WriteLine($payload);$process.StandardInput.Close()
                if(!$process.WaitForExit(10000)){$process.Kill();throw 'Stdin byte test timeout'}
                $bytes=$process.StandardOutput.ReadToEnd()|ConvertFrom-Json
                Assert-Runner ($process.ExitCode -eq 0 -and $bytes.first -eq 117 -and $bytes.nul_count -eq 0 -and $bytes.length -eq [Text.Encoding]::UTF8.GetByteCount($payload+[Environment]::NewLine)) 'actual stdin contains exact UTF8 bytes with no BOM or NULs'
                Assert-Runner ([Console]::InputEncoding.CodePage -eq $encoding.CodePage -and [Console]::InputEncoding.GetPreamble().Length -eq $encoding.GetPreamble().Length) 'actual child start preserves caller encoding'
            }finally{$process.Dispose()}
        }
    }finally{[Console]::InputEncoding=$originalInputEncoding}
    # Mock platform-bound APIs only. Main installation, expiry, file lifecycle and report code run.
    function Assert-ProfileHost {}
    function Get-ProfileDiscovery {return @{site_name='Fixture';application_path='/';pool_name='FixturePool';identity_type='SpecificUser';worker_sid='fixture-sid';runtime_sids=@('fixture-sid','anonymous-fixture-sid');anonymous_identity=@{status='collected';enabled=$true;sid='anonymous-fixture-sid'};root=$web;content=$web;mu=$mu;web_roots=@($web);php='fixture-php'}}
    $script:aclCalls=New-Object Collections.Generic.List[object]
    function Set-ProfileAcl {param($Path,$WorkerSid,$WorkerAccess,[switch]$Directory);$script:aclCalls.Add(@{path=$Path;access=$WorkerAccess;sids=@($WorkerSid)});if($script:scenario -eq 'acl-failure' -and $WorkerAccess -eq 'None' -and $Path.EndsWith('bootstrap.jsonl')){throw 'SECRET ACL error'}}
    function Get-Command {param($Name,$CommandType,$ErrorAction);return @{Source='fixture-curl'}}
    # Native CLI validation stand-in; captures code before publication, never executes WordPress.
    function fixture-php {param([Parameter(ValueFromRemainingArguments=$true)]$Arguments);$global:LASTEXITCODE=if($script:scenario -eq 'syntax-failure'){1}else{0}}
    $script:scenario='success';$script:requestCount=0
    function Invoke-ProfileHttp {
        param($Curl,$Target,$Token,$DirectAddress,$Timeout)
        $script:requestCount++
        Assert-Runner ($Target.AbsoluteUri -eq 'https://example.test/wp-admin/admin-ajax.php') 'fixed no-action route'
        Assert-Runner ($Token.Length -eq 64) 'fresh 256-bit hex token'
        $files=@(Get-ChildItem -LiteralPath $mu -Filter '000-wordpriis-bootstrap-profile-*.php')
        Assert-Runner ($files.Count -eq 1) 'one complete temporary MU published'
        $installed=[IO.File]::ReadAllText($files[0].FullName)
        Assert-Runner (!$installed.Contains($Token)) 'raw token absent from installed code'
        if($script:scenario -eq 'failure'){$error=New-Object InvalidOperationException('SECRET raw exception with credentials');$error.Data['wordpriis_http_failure']=Get-ProfileCurlFailure 28 'SECRET stderr' $false;throw $error}
        if($script:scenario -eq 'edited'){[IO.File]::WriteAllText($files[0].FullName,$installed+'/* owner edit */')}
        if($script:scenario -eq 'missing-profile'){return @{status=400;ttfb_ms=7;total_ms=8;profiler_status='output-unavailable'}}
        $line='{"schema_version":1,"status":400,"pre_mu_ms":2,"since_profiler_ms":3,"phases":[]}'
        [IO.File]::AppendAllText((Join-Path $OutputDirectory 'bootstrap.jsonl'),$line+"`n")
        return @{status=400;ttfb_ms=7;total_ms=8}
    }
    $Url=[uri]'https://example.test';$Samples=2
    foreach($scenario in @('success','failure','edited','syntax-failure','acl-failure','existing-mu','missing-profile')){
        $script:scenario=$scenario;$script:requestCount=0;$muAclBefore=@($script:aclCalls|Where-Object{$_.path -eq $mu}).Count;$OutputDirectory=Join-Path $fixture $scenario
        if($scenario -eq 'existing-mu'){[void][IO.Directory]::CreateDirectory($mu);[IO.File]::WriteAllText((Join-Path $mu 'unrelated.php'),'KEEP_MU')}
        $result=Invoke-WordPrIISBootstrapProfile
        $raw=[IO.File]::ReadAllText((Join-Path $OutputDirectory 'report.json'))
        Assert-Runner (!$raw.Contains('SECRET') -and !$raw.Contains('ORIGINAL_CONFIG_SECRET')) 'errors/config secret omitted'
        Assert-Runner ([IO.File]::ReadAllText($existing) -eq 'ORIGINAL_CONFIG_SECRET') 'wp-config never edited'
        Assert-Runner (!(Test-Path -LiteralPath (Join-Path $OutputDirectory 'profiler-code.php'))) 'private code removed'
        Assert-Runner (@($script:aclCalls|Where-Object{$_.path -eq $OutputDirectory -and $_.access -eq 'None'}).Count -eq 1) 'temporary directory worker grant removed'
        if($scenario -eq 'success'){
            Assert-Runner ($result.status -eq 'complete' -and $result.profiles.Count -eq 2 -and $result.samples.Count -eq 2) 'all samples and profiles retained'
            $grants=@($script:aclCalls|Where-Object{$_.path -eq (Join-Path $OutputDirectory 'bootstrap.jsonl') -and $_.access -eq 'Write'})
            Assert-Runner ($grants.Count -eq 1 -and $grants[0].sids.Count -eq 2 -and 'anonymous-fixture-sid' -in $grants[0].sids) 'pool and exact anonymous request identity granted on private log only'
            Assert-Runner ($result.discovery.anonymous_identity.enabled -and $result.discovery.runtime_sids.Count -eq 2) 'both runtime identities retained for diagnostics'
            Assert-Runner ($result.cleanup.mu_removed -and !(Test-Path -LiteralPath $mu)) 'MU file and newly empty directory cleaned'
        }elseif($scenario -eq 'failure'){
            Assert-Runner ($result.status -eq 'failed' -and $result.cleanup.mu_removed) 'request failure still cleans MU'
            Assert-Runner ($result.http_failure.curl_exit -eq 28 -and $result.http_failure.category -eq 'timeout') 'safe transport diagnostic survives main report'
            Assert-Runner (!(Test-Path -LiteralPath $mu)) 'request failure removes newly empty directory'
        }elseif($scenario -eq 'missing-profile'){
            Assert-Runner ($result.status -eq 'failed' -and $result.diagnostic.code -eq 'profile-record-missing') 'missing profile classified independently of curl'
            Assert-Runner ($result.samples[0].profiler_status -eq 'output-unavailable' -and $result.diagnostic.next_step.Contains('profiler_status') -and $result.cleanup.mu_removed) 'missing output retains gate evidence and cleans up'
        }elseif($scenario -eq 'syntax-failure'){
            Assert-Runner ($result.status -eq 'failed' -and $result.diagnostic.code -eq 'php-syntax-check-failed' -and $script:requestCount -eq 0) 'syntax failure prevents publication/requests'
        }elseif($scenario -eq 'acl-failure'){
            Assert-Runner ($result.status -eq 'cleanup-incomplete' -and !$result.cleanup.temporary_worker_access_removed -and $result.cleanup.mu_removed) 'ACL cleanup failure explicit; MU still removed'
        }elseif($scenario -eq 'existing-mu'){
            Assert-Runner ($result.status -eq 'complete' -and [IO.File]::ReadAllText((Join-Path $mu 'unrelated.php')) -eq 'KEEP_MU') 'unrelated preexisting MU preserved'
            Assert-Runner (@($script:aclCalls|Where-Object{$_.path -eq $mu}).Count -eq $muAclBefore) 'preexisting MU directory ACL untouched'
            Remove-Item -LiteralPath $mu -Recurse -Force
        }else{
            Assert-Runner ($result.status -eq 'cleanup-incomplete' -and !$result.cleanup.mu_removed) 'edited file reported as cleanup incomplete'
            Assert-Runner (Test-Path -LiteralPath $result.recovery.temporary_mu_file) 'edited file preserved for review'
            Remove-Item -LiteralPath $mu -Recurse -Force
        }
    }
    # Existing report directory: absolutely no ACL/content changes on rejection.
    $OutputDirectory=Join-Path $fixture 'existing';[void][IO.Directory]::CreateDirectory($OutputDirectory)
    $sentinel=Join-Path $OutputDirectory 'profiler-code.php';[IO.File]::WriteAllText($sentinel,'KEEP')
    $before=$script:aclCalls.Count;$result=Invoke-WordPrIISBootstrapProfile
    Assert-Runner ($result.diagnostic.code -eq 'report-already-exists') 'existing output explicitly diagnosed'
    Assert-Runner ($script:aclCalls.Count -eq $before -and [IO.File]::ReadAllText($sentinel) -eq 'KEEP') 'existing output never mutated by finally'
    $OutputDirectory=Join-Path $web 'unsafe';$result=Invoke-WordPrIISBootstrapProfile
    Assert-Runner ($result.diagnostic.code -eq 'report-inside-web-root' -and !(Test-Path -LiteralPath $OutputDirectory)) 'web-root reports refused before writing'
    $Url=[uri]'http://example.test';$OutputDirectory=Join-Path $fixture 'insecure';$result=Invoke-WordPrIISBootstrapProfile
    Assert-Runner ($result.diagnostic.code -eq 'invalid-target-url') 'HTTP targets refused'
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
Write-Host "Bootstrap runner: $checks checks passed."
