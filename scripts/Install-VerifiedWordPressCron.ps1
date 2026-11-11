#requires -Version 5.1
<#
.SYNOPSIS
Install and verify Windows-triggered WordPress cron, then disable visitor spawning.
.DESCRIPTION
Elevated 64-bit Windows only. Uses the existing WordPress service account for HTTPS requests; accepts PSCredential.
Requires a NEW, private, PHP-allowed RuntimeDirectory on the wp-config volume. Verifies
manual + automatic task canaries before editing config, then verifies the web setting.
Retains an administrator-only wp-config backup and a redacted installation report.
#>
[CmdletBinding()]
param(
    [uri]$Url,
    [string]$RuntimeDirectory,
    [string]$SiteName,
    [string]$WordPressPath,
    [string]$ContentPath,
    [string]$MuPluginPath,
    [string]$PhpPath,
    [string]$OriginAddress,
    [string]$TaskName,
    [string]$TaskAccount='wordpress_service',
    [Management.Automation.PSCredential]$TaskCredential,
    [ValidateRange(1,15)][int]$IntervalMinutes=1,
    [ValidateRange(30,300)][int]$RequestTimeoutSeconds=120,
    [ValidateRange(60,600)][int]$VerificationTimeoutSeconds=240,
    [ValidateRange(60,3600)][int]$JobTimeoutSeconds=300
)
. (Join-Path $PSScriptRoot 'Invoke-WordPrIISBootstrapProfile.ps1') -Url $Url -SiteName $SiteName -WordPressPath $WordPressPath -ContentPath $ContentPath -MuPluginPath $MuPluginPath -PhpPath $PhpPath -OriginAddress $OriginAddress

function Write-CronJson {
    param([string]$Path,$Value)
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 16),(New-Object Text.UTF8Encoding($false)))
}
function Set-CronCompletionAcl {
    param([string]$Path,[string[]]$WorkerSids,[string]$TaskSid)
    Set-ProfileAcl $Path $WorkerSids 'Write'
    $acl=Get-Acl -LiteralPath $Path
    $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($TaskSid)),'Read','None','None','Allow')
    $acl.AddAccessRule($rule);Set-Acl -LiteralPath $Path -AclObject $acl
}
function Set-CronRunsAcl {
    param([string]$Path,[string[]]$WorkerSids,[string]$TaskSid)
    Set-ProfileAcl $Path @() 'None' -Directory
    $acl=Get-Acl -LiteralPath $Path
    foreach($sid in @(@($WorkerSids)+@($TaskSid)|Select-Object -Unique)){
        $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'Modify','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-CronConfigPlan {
    param([string]$Php,[string]$Config,[string]$Candidate,[switch]$EnableRequestCron)
    $options=@();if($EnableRequestCron){$options+=@('--enable-request-cron')}
    $saved=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$raw=@(& $Php '-d' 'register_argc_argv=1' '-d' 'display_errors=0' '-d' 'log_errors=0' (Join-Path $PSScriptRoot 'cron-config.php') ('--config='+$Config) ('--candidate='+$Candidate) @options 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$saved}
    $line=@($raw|Where-Object{[string]$_ -like 'WORDPRIIS_CRON_PLAN:*'})
    if(!$line.Count){throw 'WORDPRIIS_CRON:config-plan-no-result'}
    $plan=([string]$line[-1]).Substring('WORDPRIIS_CRON_PLAN:'.Length)|ConvertFrom-Json
    if($code -ne 0 -or $plan.PSObject.Properties['error']){
        $allowed=@('dynamic-config-not-supported','ambiguous-settings-load','complex-cron-define','ambiguous-or-unsupported-config','cron-define-after-settings','invalid-plan-paths','candidate-write-failed','config-plan-failed')
        if($plan.PSObject.Properties['error'] -and [string]$plan.error -in $allowed){throw ('WORDPRIIS_CRON:config-'+[string]$plan.error)}
        throw 'WORDPRIIS_CRON:config-layout-not-supported'
    }
    $saved=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$null=@(& $Php '-d' 'display_errors=0' '-d' 'log_errors=0' '-l' $Candidate 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$saved}
    if($code -ne 0){throw 'WORDPRIIS_CRON:candidate-syntax-failed'}
    return $plan
}
function Resolve-CronAccountSid {
    param([string]$Account)
    return (New-Object Security.Principal.NTAccount($Account)).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Get-CronTaskIdentity {
    param([string]$Account,[Management.Automation.PSCredential]$Credential)
    if(!$Credential){throw 'WORDPRIIS_CRON:task-credential-required'}
    try{$expected=Resolve-CronAccountSid $Account;$actual=Resolve-CronAccountSid $Credential.UserName}catch{throw 'WORDPRIIS_CRON:task-account-unresolved'}
    if($expected -ne $actual){throw 'WORDPRIIS_CRON:credential-account-mismatch'}
    return @{sid=$actual;username=$Credential.UserName}
}
function Register-CronScheduledTask {
    param([string]$Name,[string]$Folder,[int]$Minutes,[int]$Timeout,[int]$JobTimeout,[Management.Automation.PSCredential]$Credential)
    if(Get-ScheduledTask -TaskPath '\' -TaskName $Name -ErrorAction SilentlyContinue){throw 'WORDPRIIS_CRON:task-already-exists'}
    $powershell=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args='-NoProfile -NonInteractive -File "'+(Join-Path $Folder 'Invoke-WordPrIISCronTask.ps1')+'" -ConfigPath "'+(Join-Path $Folder 'config.json')+'"'
    $action=New-ScheduledTaskAction -Execute $powershell -Argument $args -WorkingDirectory $Folder
    $principal=New-ScheduledTaskPrincipal -UserId $Credential.UserName -LogonType Password -RunLevel Limited
    $trigger=New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes(1)) -RepetitionInterval ([TimeSpan]::FromMinutes($Minutes))
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::FromSeconds($Timeout+$JobTimeout+60)) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task=New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Description 'WORDPRIIS verified HTTPS WordPress cron; private status in the runtime directory.'
    $password=$Credential.GetNetworkCredential().Password
    try{$null=Register-ScheduledTask -TaskPath '\' -TaskName $Name -InputObject $task -User $Credential.UserName -Password $password}finally{$password=$null}
}
function Wait-CronTaskProof {
    param([string]$Name,[string]$Folder,[string]$Phase,[Nullable[bool]]$Disabled,[int]$Timeout,[string]$PreviousRun,[switch]$Automatic,[switch]$WithoutCanary)
    if(!$Automatic){Start-ScheduledTask -TaskPath '\' -TaskName $Name}
    $until=[DateTime]::UtcNow.AddSeconds($Timeout)
    do{
        try{
            $last=[IO.File]::ReadAllText((Join-Path $Folder 'task-last.json'))|ConvertFrom-Json
            $task=Get-ScheduledTask -TaskPath '\' -TaskName $Name
            $info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $Name
            if($last -and $last.phase -eq $Phase -and $last.run_id -ne $PreviousRun -and $task.State -eq 'Ready'){
                if($last.exit_code -ne 0 -or $info.LastTaskResult -ne 0){throw 'WORDPRIIS_CRON:scheduled-request-failed'}
                if($WithoutCanary -and $last.cron_complete -eq $true){return @{run_id=$last.run_id;phase=$Phase;http_status=$last.http_status;task_result=[long]$info.LastTaskResult;automatic=[bool]$Automatic}}
                $proof=[IO.File]::ReadAllText((Join-Path $Folder 'proof.json'))|ConvertFrom-Json
                if($last.cron_complete -eq $true -and $proof -and $proof.run_id -eq $last.run_id -and $proof.phase -eq $Phase -and $proof.doing_cron -eq $true -and $proof.probe_events_cleared -eq $true -and ($null -eq $Disabled -or $proof.disable_wp_cron -eq $Disabled)){
                    return @{run_id=$last.run_id;phase=$Phase;http_status=$last.http_status;task_result=[long]$info.LastTaskResult;automatic=[bool]$Automatic;canary_executed=$true;disable_wp_cron=[bool]$proof.disable_wp_cron;probe_events_cleared=$true}
                }
            }
        }catch{if($_.Exception.Message -like 'WORDPRIIS_CRON:*'){throw}}
        Write-Progress -Activity 'Verifying scheduled WordPress cron' -Status ($Phase+': waiting for '+$(if($Automatic){'an automatic trigger'}else{'a fresh task run and callback proof'}))
        Start-Sleep -Milliseconds 500
    }while([DateTime]::UtcNow -lt $until)
    throw 'WORDPRIIS_CRON:canary-verification-timeout'
}
function Publish-CronConfig {
    param([string]$Candidate,[string]$Config,[string]$ExpectedHash)
    if((Get-FileHash -LiteralPath $Config -Algorithm SHA256).Hash -ine $ExpectedHash){throw 'WORDPRIIS_CRON:config-changed-concurrently'}
    # Source/destination are required to be on one volume; no temporary config in web roots.
    [IO.File]::Replace($Candidate,$Config,[NullString]::Value)
}
function Invoke-InstallWordPrIISWordPressCron {
    $stage='preflight';$folder=$null;$ownedFolder=$false;$secure=$false;$discovery=$null;$taskOwned=$false;$taskVerified=$false;$changed=$false;$config=$null;$plan=$null;$lock=$null;$mu=$null;$gate=$null;$gateHash=$null;$muHash=$null;$createdMu=$false;$token=$null;$success=$false;$retainTask=$false;$configAcl=$null
    $report=[ordered]@{schema_version=1;installer_revision='2026-11-08.1';status='failed';checks=@();rollback=@{config_restored=$false;task_removed=$false};cleanup=@{canary_removed=$true;verification_token_removed=$true;canary_proof_access_removed=$true;probe_events_removed=$true};scope='Runs real due cron jobs. Verifies a temporary canary; does not prove every site job succeeds.'}
    try{
      try{
        Assert-ProfileHost
        if(!$RuntimeDirectory -or $Url.Scheme -ne 'https' -or $Url.UserInfo -or $Url.Query -or $Url.Fragment){throw 'WORDPRIIS_CRON:private-runtime-and-https-url-required'}
        $stage='task-account'
        if(!$TaskCredential){$TaskCredential=Get-Credential -UserName $TaskAccount -Message 'Enter the existing WordPress service account credential for Task Scheduler.'}
        $taskIdentity=Get-CronTaskIdentity $TaskAccount $TaskCredential;$taskSid=$taskIdentity.sid
        $stage='iis-discovery'
        $discovery=Get-ProfileDiscovery $Url $SiteName $WordPressPath $ContentPath $PhpPath $MuPluginPath
        $lock=Enter-ProfileLock $discovery.root;Assert-ProfileNoExistingMu $discovery.mu
        if(Test-Path -LiteralPath $discovery.mu){foreach($file in @(Get-ChildItem -LiteralPath $discovery.mu -Filter '*.php')){if([IO.File]::ReadAllText($file.FullName) -match '(?i)\b[A-Z][A-Z0-9_]*_CRON_GATE_HASH\b|function\s+[a-z][a-z0-9_]*_cron_gate_install\b'){throw 'WORDPRIIS_CRON:existing-cron-gate'}}}
        $config=Join-Path $discovery.root 'wp-config.php';if(!(Test-Path -LiteralPath $config)){ $config=Join-Path (Split-Path $discovery.root -Parent) 'wp-config.php' }
        Assert-ProfilePlainPath $config;Assert-ProfilePlainPath $discovery.mu
        $stage='private-runtime-validation'
        $folder=[IO.Path]::GetFullPath($RuntimeDirectory);Assert-ProfilePlainPath $folder
        if($folder -match '["\r\n]' -or (Test-Path -LiteralPath $folder) -or !(Test-Path -LiteralPath (Split-Path $folder -Parent) -PathType Container)){throw 'WORDPRIIS_CRON:new-private-runtime-required'}
        foreach($root in $discovery.web_roots){Assert-ProfilePlainPath $root;if(Test-AuditBelowPath $folder $root){throw 'WORDPRIIS_CRON:runtime-inside-web-root'}}
        if([IO.Path]::GetPathRoot($folder) -ine [IO.Path]::GetPathRoot($config)){throw 'WORDPRIIS_CRON:runtime-must-share-config-volume'}
        if(!$TaskName){$TaskName='WORDPRIIS WordPress Cron - '+$discovery.site_name}
        if($TaskName -notmatch '^[a-zA-Z0-9 _.-]{1,100}$'){throw 'WORDPRIIS_CRON:invalid-task-name'}
        if(Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue){throw 'WORDPRIIS_CRON:task-already-exists'}
        $curl=(Get-Command curl.exe -CommandType Application).Source
        if($OriginAddress){$ip=$null;if(![Net.IPAddress]::TryParse($OriginAddress,[ref]$ip)){throw 'WORDPRIIS_CRON:origin-must-be-ip'}}
        $stage='protected-runtime';$null=New-Item -ItemType Directory -Path $folder;$ownedFolder=$true
        Set-ProfileAcl $folder (@($taskSid)+@($discovery.runtime_sids)) 'Read' -Directory;$secure=$true
        $report['runtime_directory']=$folder;$report['task_name']=$TaskName;$report['task_account_sid']=$taskSid;$report['site_name']=$discovery.site_name
        $keep=Join-Path $folder 'KEEP-THIS-DIRECTORY.txt';[IO.File]::WriteAllText($keep,"PERMANENT WORDPRESS CRON RUNTIME - DO NOT DELETE.`r`nThe scheduled task and cron MU gate require this directory, including config, scripts, locks and receipts.`r`nIt contains private operational credentials/recovery material. Keep it outside web roots, preserve ACLs and back it up securely.`r`n");Set-ProfileAcl $keep $taskSid 'Read'
        foreach($name in @('Invoke-WordPrIISCronTask.ps1','Invoke-WordPrIISBootstrapProfile.ps1','Invoke-WordPrIISServerAudit.ps1')){
            $path=Join-Path $folder $name;[IO.File]::WriteAllBytes($path,[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)));Set-ProfileAcl $path $taskSid 'Read'
        }
        $cronUrl=$Url.GetLeftPart([UriPartial]::Authority)+$Url.AbsolutePath.TrimEnd('/')+'/wp-cron.php'
        foreach($name in @('task-last.json','request.curl')){ $path=Join-Path $folder $name;[IO.File]::WriteAllText($path,'');Set-ProfileAcl $path $taskSid 'Write' }
        [IO.File]::WriteAllText((Join-Path $folder 'proof.json'),'');Set-ProfileAcl (Join-Path $folder 'proof.json') $discovery.runtime_sids 'Write'
        $stage='config-plan';$candidate=Join-Path $folder 'wp-config.candidate.php'
        $plan=Get-CronConfigPlan $discovery.php $config $candidate
        $report['config_plan']=$plan;$configAcl=Get-Acl -LiteralPath $config
        [IO.File]::WriteAllBytes((Join-Path $folder 'wp-config.before.php'),[IO.File]::ReadAllBytes($config))
        if((Get-FileHash -LiteralPath (Join-Path $folder 'wp-config.before.php') -Algorithm SHA256).Hash -ine $plan.original_sha256){throw 'WORDPRIIS_CRON:config-changed-before-backup'}
        $bytes=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
        $token=[BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant();$sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($token))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
        Write-CronJson (Join-Path $folder 'config.json') @{url=$cronUrl;curl=$curl;origin_address=$OriginAddress;timeout_seconds=$RequestTimeoutSeconds;job_timeout_seconds=$JobTimeoutSeconds;token=$token};Set-ProfileAcl (Join-Path $folder 'config.json') $taskSid 'Read'
        $expires=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+7200
        Write-CronJson (Join-Path $folder 'verification.json') @{phase='before';expires=$expires};Set-ProfileAcl (Join-Path $folder 'verification.json') $taskSid 'Read'
        $nonce=[guid]::NewGuid().ToString('N');$hook='wordpriis_cron_verify_'+$nonce
        $proofPath=(Join-Path $folder 'proof.json').Replace('\','/').Replace("'","\'")
        $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'cron-canary.php'))
        $code="<?php`nif (!defined('ABSPATH')) { return; }`ndefine('WORDPRIIS_CRON_TOKEN_SHA256', '$hash');`ndefine('WORDPRIIS_CRON_UNTIL', $expires);`ndefine('WORDPRIIS_CRON_HOOK', '$hook');`ndefine('WORDPRIIS_CRON_PROOF_FILE', '$proofPath');`n"+$source.Substring(5)
        if(!(Test-Path -LiteralPath $discovery.mu)){$null=New-Item -ItemType Directory -Path $discovery.mu;$createdMu=$true;Set-ProfileAcl $discovery.mu $discovery.runtime_sids 'Read' -Directory}
        # A cron-only bridge holds an OS file lock through PHP shutdown, beyond early HTTP 200.
        [IO.File]::WriteAllText((Join-Path $folder 'cron.lock'),'');Set-ProfileAcl (Join-Path $folder 'cron.lock') $discovery.runtime_sids 'Write'
        [IO.File]::WriteAllText((Join-Path $folder 'cron-last.json'),'');Set-CronCompletionAcl (Join-Path $folder 'cron-last.json') $discovery.runtime_sids $taskSid
        $lockPath=(Join-Path $folder 'cron.lock').Replace('\','/').Replace("'","\'")
        $resultPath=(Join-Path $folder 'cron-last.json').Replace('\','/').Replace("'","\'")
        $runs=Join-Path $folder 'run-results';$null=New-Item -ItemType Directory -Path $runs;Set-CronRunsAcl $runs $discovery.runtime_sids $taskSid
        $runsPath=$runs.Replace('\','/').Replace("'","\'")
        $gateSource=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'cron-gate.php'))
        $gateCode="<?php`nif (!defined('ABSPATH')) { return; }`ndefine('WORDPRIIS_CRON_GATE_HASH', '$hash');`ndefine('WORDPRIIS_CRON_GATE_LOCK', '$lockPath');`ndefine('WORDPRIIS_CRON_GATE_RESULT', '$resultPath');`ndefine('WORDPRIIS_CRON_GATE_RUNS', '$runsPath');`n"+$gateSource.Substring(5)
        $gate=Join-Path $discovery.mu ('000-wordpriis-cron-gate-'+$nonce+'.php')
        $gatePending=Join-Path $discovery.mu ('.wordpriis-cron-gate-'+$nonce+'.tmp');[IO.File]::WriteAllText($gatePending,$gateCode,(New-Object Text.UTF8Encoding($false)))
        $gateHash=(Get-FileHash -LiteralPath $gatePending -Algorithm SHA256).Hash;Set-ProfileAcl $gatePending $discovery.runtime_sids 'Read';[IO.File]::Move($gatePending,$gate)
        $mu=Join-Path $discovery.mu ('000-wordpriis-cron-canary-'+$nonce+'.php')
        # Canary is harmless for requests without its short-lived header token. No secrets in its source.
        $pending=Join-Path $discovery.mu ('.wordpriis-cron-canary-'+$nonce+'.tmp')
        [IO.File]::WriteAllText($pending,$code,(New-Object Text.UTF8Encoding($false)))
        $muHash=(Get-FileHash -LiteralPath $pending -Algorithm SHA256).Hash;Set-ProfileAcl $pending $discovery.runtime_sids 'Read'
        [IO.File]::Move($pending,$mu);$report.cleanup.canary_removed=$false
        $report['recovery']=@{task_path='\';canary_file=$mu;canary_sha256=$muHash;synthetic_hook=$hook;config_backup=(Join-Path $folder 'wp-config.before.php');cron_gate_file=$gate;cron_gate_sha256=$gateHash}
        Write-CronJson (Join-Path $folder 'install-report.json') $report
        $stage='register-task';Register-CronScheduledTask $TaskName $folder $IntervalMinutes $RequestTimeoutSeconds $JobTimeoutSeconds $TaskCredential;$taskOwned=$true;$report.cleanup.probe_events_removed=$false
        $stage='manual-canary';Write-Host 'Verifying a real scheduled-task canary before editing wp-config.php...'
        $first=Wait-CronTaskProof $TaskName $folder 'before' $null $VerificationTimeoutSeconds ''
        $report.checks+=@($first);$taskVerified=$true
        $stage='automatic-canary';Write-Host 'Waiting for one automatic trigger before editing wp-config.php...'
        $automatic=Wait-CronTaskProof $TaskName $folder 'before' $null ($VerificationTimeoutSeconds+$IntervalMinutes*60) $first.run_id -Automatic
        $report.checks+=@($automatic)
        $stage='disable-request-cron'
        if($automatic.disable_wp_cron -eq $true -and $null -eq $plan.previous_literal){$report['config_action']='already-disabled-at-runtime'}
        elseif($plan.changed){Publish-CronConfig $candidate $config $plan.original_sha256;$changed=$true;Set-Acl -LiteralPath $config -AclObject $configAcl}
        Write-CronJson (Join-Path $folder 'verification.json') @{phase='after';expires=$expires}
        $stage='post-change-canary';Write-Host 'Verifying the scheduled callback sees DISABLE_WP_CRON=true...'
        $after=Wait-CronTaskProof $TaskName $folder 'after' $true $VerificationTimeoutSeconds $automatic.run_id
        $report.checks+=@($after)
        Write-CronJson (Join-Path $folder 'verification.json') @{phase='cleanup';expires=$expires}
        $stage='clear-canary-events';$cleared=Wait-CronTaskProof $TaskName $folder 'cleanup' $true $VerificationTimeoutSeconds $after.run_id;$report.checks+=@($cleared);$report.cleanup.probe_events_removed=$true
        Remove-Item -LiteralPath (Join-Path $folder 'verification.json') -Force
        $stage='normal-task-run';$normal=Wait-CronTaskProof $TaskName $folder 'normal' $null $VerificationTimeoutSeconds $cleared.run_id -WithoutCanary;$report.checks+=@($normal)
        if(!(Remove-ProfileOwnedFile $mu $muHash)){throw 'WORDPRIIS_CRON:canary-edited-during-setup'};$report.cleanup.canary_removed=$true
        $success=$true;$report.status='complete';$report['request_cron_disabled']=$true
      }catch{
        $report['diagnostic']=Get-AuditFailure $_ $stage
        if($_.Exception.Message -match '^WORDPRIIS_CRON:([a-z0-9-]+)$'){$report.diagnostic.code=$matches[1]}
        $hints=@{'task-account'='Use Get-Credential for the existing local/domain service account; no passwords, groups or rights are changed.';'register-task'='Verify service-account credentials and batch-logon policy. The installer never grants account rights or bypasses policy.';'manual-canary'='Inspect task-last.json, cron-last.json, proof.json and Task Scheduler result. HTTP 200 alone is insufficient.';'automatic-canary'='A distinct automatic trigger must execute; inspect task enabled state, trigger and account logon.';'post-change-canary'='A fresh callback must see DISABLE_WP_CRON=true. OPcache revalidation can delay it; config is rolled back on timeout.'}
        if($hints.ContainsKey($stage)){$report.diagnostic.next_step=$hints[$stage]}
      }finally{
        if($taskOwned -and !$report.cleanup.probe_events_removed){
            try{
                Write-CronJson (Join-Path $folder 'verification.json') @{phase='cleanup';expires=$expires}
                $cleanupProof=Wait-CronTaskProof $TaskName $folder 'cleanup' $null 60 ''
                $report.cleanup.probe_events_removed=$true
            }catch{}
        }
        if(!$success -and $changed){
            try{
                $rollback=Join-Path $folder 'wp-config.rollback.php';[IO.File]::WriteAllBytes($rollback,[IO.File]::ReadAllBytes((Join-Path $folder 'wp-config.before.php')))
                Publish-CronConfig $rollback $config $plan.candidate_sha256;Set-Acl -LiteralPath $config -AclObject $configAcl;$report.rollback.config_restored=$true
                $report.cleanup.probe_events_removed=$false
                Write-CronJson (Join-Path $folder 'verification.json') @{phase='rollback';expires=$expires}
                $rollbackProof=Wait-CronTaskProof $TaskName $folder 'rollback' $false $VerificationTimeoutSeconds ''
                $report.rollback['web_setting_verified']=$true;$report.cleanup.probe_events_removed=$true
            }catch{$retainTask=$true;$report.status='rollback-incomplete';$report['rollback_hint']='wp-config changed or could not be restored. The preverified task is retained; inspect privately before removing it.'}
        }
        if($taskOwned -and !$success -and !$retainTask){
            try{Stop-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskPath '\' -TaskName $TaskName -Confirm:$false;$report.rollback.task_removed=$true}catch{$report.status='rollback-incomplete'}
        }
        if($gate -and $gateHash -and !$success -and !$retainTask){try{if(!(Remove-ProfileOwnedFile $gate $gateHash)){$report.status='cleanup-incomplete'}}catch{$report.status='cleanup-incomplete'}}
        if($mu -and $muHash){try{$report.cleanup.canary_removed=Remove-ProfileOwnedFile $mu $muHash}catch{$report.cleanup.canary_removed=$false}}
        if($secure){
            foreach($name in @('verification.json','request.curl','wp-config.candidate.php','wp-config.rollback.php')){
                $path=Join-Path $folder $name
                try{if(Test-Path -LiteralPath $path){if($name -eq 'request.curl'){[IO.File]::WriteAllText($path,'')}else{Remove-Item -LiteralPath $path -Force}}}catch{if($name -eq 'verification.json'){$report.cleanup.verification_token_removed=$false}}
            }
            try{Set-ProfileAcl (Join-Path $folder 'proof.json') @() 'None';Set-ProfileAcl $folder (@($taskSid)+$(if($success -or $retainTask){@($discovery.runtime_sids)}else{@()})) 'Read' -Directory}catch{$report.cleanup.canary_proof_access_removed=$false}
            if($createdMu){try{if(@(Get-ChildItem -LiteralPath $discovery.mu -Force).Count -eq 0){[IO.Directory]::Delete($discovery.mu)}}catch{}}
            if((!$report.cleanup.canary_removed -or !$report.cleanup.verification_token_removed -or !$report.cleanup.canary_proof_access_removed -or !$report.cleanup.probe_events_removed) -and $report.status -ne 'rollback-incomplete'){$report.status='cleanup-incomplete'}
            Write-CronJson (Join-Path $folder 'install-report.json') $report
            Write-Host ('Report retained: '+(Join-Path $folder 'install-report.json'))
            if($success -or $retainTask){Write-Warning ('PERMANENT CRON RUNTIME - KEEP THIS DIRECTORY: '+$folder+'. The scheduled task and MU gate depend on it.')}
        }elseif($ownedFolder){try{if(@(Get-ChildItem -LiteralPath $folder -Force).Count -eq 0){[IO.Directory]::Delete($folder)}}catch{}}
        if(!$secure){Write-Warning ('Cron setup stopped before a private report was created. Stage: '+$stage+'; code: '+$report.diagnostic.code)}
        $token=$null
      }
    }finally{if($lock){$lock.ReleaseMutex();$lock.Dispose()}}
    return [pscustomobject]$report
}
if($MyInvocation.InvocationName -ne '.'){
    $result=Invoke-InstallWordPrIISWordPressCron
    if($result.status -ne 'complete'){Write-Error ('Cron setup failed at a safe checkpoint. Review install-report.json; do not remove a retained task before inspecting rollback status.');exit 1}
}
