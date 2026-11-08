# Portable transaction regressions: real temp files/atomic replacement, mocked IIS/task APIs only.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Install-VerifiedWordPressCron.ps1')
$n=0
function Assert-Cron($ok,[string]$label){if(!$ok){throw $label};$script:n++}
$base=if(Test-Path '/private/tmp'){'/private/tmp'}else{[IO.Path]::GetTempPath()}
$fixture=Join-Path $base ('wordpriis-cron-tests-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $fixture
$web=Join-Path $fixture 'web';$null=New-Item -ItemType Directory -Path $web
$config=Join-Path $web 'wp-config.php';$mu=Join-Path $web 'mu-plugins'
$original="<?php define('SECRET', 'DO_NOT_EXPORT'); define('DISABLE_WP_CRON', false);"
function Assert-ProfileHost {}
function Get-CronTaskIdentity {param($Account,$Credential);return @{sid='task-sid';username='fixture-account'}}
function Get-ProfileDiscovery {return @{site_name='Fixture';root=$web;content=$web;mu=$script:mu;runtime_sids=@('pool-sid');web_roots=@($web);php='fixture-php'}}
function Get-ScheduledTask {param($TaskPath,$TaskName,$ErrorAction);return $script:task}
function Get-Command {param($Name,$CommandType);return @{Source='fixture-curl'}}
$aclCalls=New-Object Collections.Generic.List[object]
function Set-ProfileAcl {param($Path,$WorkerSid,$WorkerAccess,[switch]$Directory);$aclCalls.Add(@{path=$Path;sids=@($WorkerSid);access=$WorkerAccess})}
function Get-Acl {param($LiteralPath);return 'fixture-acl'}
function Set-CronRunsAcl {param($Path,$WorkerSids,$TaskSid)}
function Set-CronCompletionAcl {param($Path,$WorkerSids,$TaskSid)}
function Set-Acl {param($LiteralPath,$AclObject)}
function Get-CronConfigPlan {
    param($Php,$Config,$Candidate)
    $raw=[IO.File]::ReadAllText($Config);$next=$raw.Replace("'DISABLE_WP_CRON', false", "'DISABLE_WP_CRON', true")
    [IO.File]::WriteAllText($Candidate,$next)
    return [pscustomobject]@{changed=$true;previous_literal=$false;original_sha256=(Get-FileHash $Config).Hash;candidate_sha256=(Get-FileHash $Candidate).Hash}
}
function Register-CronScheduledTask {param($Name,$Folder,$Minutes,$Timeout);$script:task=@{name=$Name};$script:events.Add('registered')}
function Start-ScheduledTask {param($TaskPath,$TaskName)}
function Stop-ScheduledTask {param($TaskPath,$TaskName,$ErrorAction)}
function Unregister-ScheduledTask {param($TaskPath,$TaskName,[switch]$Confirm);$script:events.Add('unregistered');$script:task=$null}
function Wait-CronTaskProof {
    param($Name,$Folder,$Phase,$Disabled,$Timeout,$PreviousRun,[switch]$Automatic,[switch]$WithoutCanary)
    $label=if($Automatic){'automatic'}else{$Phase};$script:events.Add($label)
    if($Phase -eq 'before'){Assert-Cron ([IO.File]::ReadAllText($config) -eq $original) 'configuration stays untouched until manual and automatic proofs'}
    if(($script:scenario -eq 'rollback-unverified' -and $Phase -in @('after','rollback')) -or $script:scenario -eq $label){throw 'WORDPRIIS_CRON:synthetic-verification-failure'}
    if($script:scenario -eq 'concurrent-edit' -and $Phase -eq 'after'){[IO.File]::AppendAllText($config,'/* owner changed file */');throw 'WORDPRIIS_CRON:synthetic-verification-failure'}
    if($Phase -eq 'rollback'){Assert-Cron ([IO.File]::ReadAllText($config) -eq $original) 'rollback proof follows exact config restoration'}
    if($Phase -eq 'after'){Assert-Cron ([IO.File]::ReadAllText($config).Contains("'DISABLE_WP_CRON', true")) 'post-change proof follows actual replacement'}
    return @{run_id=[guid]::NewGuid().ToString('N');phase=$Phase;disable_wp_cron=($Phase -notin @('before','rollback'));canary_executed=(!$WithoutCanary);probe_events_cleared=$true;automatic=[bool]$Automatic;http_status=200;task_result=0}
}
$Url=[uri]'https://fixture.test';$TaskName='WORDPRIIS Fixture Cron';$TaskCredential=New-Object Management.Automation.PSCredential('fixture-account',(ConvertTo-SecureString 'FIXTURE_ONLY' -AsPlainText -Force))
try{
 foreach($case in @('success','before','automatic','after','normal','concurrent-edit','rollback-unverified')){
    $script:scenario=$case;$script:task=$null;$script:events=New-Object Collections.Generic.List[string]
    [IO.File]::WriteAllText($config,$original)
    $RuntimeDirectory=Join-Path $fixture $case
    $result=Invoke-InstallWordPrIISWordPressCron
    $raw=[IO.File]::ReadAllText((Join-Path $RuntimeDirectory 'install-report.json'))
    Assert-Cron (!$raw.Contains('DO_NOT_EXPORT') -and !$raw.Contains('"token"')) 'installation report contains no config values or header token'
    Assert-Cron (!(Test-Path (Join-Path $RuntimeDirectory 'verification.json')) -and $result.cleanup.verification_token_removed) 'verification state removed'
    Assert-Cron ($result.cleanup.canary_removed -and @(Get-ChildItem -LiteralPath $mu -Filter '*canary*.php' -ErrorAction SilentlyContinue).Count -eq 0) 'temporary canary and empty new MU directory removed'
    Assert-Cron ([IO.File]::ReadAllText((Join-Path $RuntimeDirectory 'wp-config.before.php')) -eq $original) 'exact private backup retained'
    if($case -eq 'success'){
      Assert-Cron ($result.status -eq 'complete' -and $script:task -and $result.checks.Count -eq 5) 'task retained after all five verification checkpoints'
      Assert-Cron (($script:events -join ',') -eq 'registered,before,automatic,after,cleanup,normal') 'proofs precede config switch and normal run follows cleanup'
      Assert-Cron ([IO.File]::ReadAllText($config).Contains("'DISABLE_WP_CRON', true")) 'request-triggered cron disabled only on success'
    }elseif($case -eq 'rollback-unverified'){
      Assert-Cron ($result.status -eq 'rollback-incomplete' -and $script:task -and $result.rollback.config_restored -and !$result.rollback.task_removed) 'unverified effective rollback retains the preverified task'
      Assert-Cron ([IO.File]::ReadAllText($config) -eq $original) 'rollback bytes restored even when web proof fails'
    }elseif($case -eq 'concurrent-edit'){
      Assert-Cron ($result.status -eq 'rollback-incomplete' -and $script:task -and !$result.rollback.config_restored) 'concurrent config edit is not overwritten; preverified task retained'
      Assert-Cron ([IO.File]::ReadAllText($config).Contains('owner changed file')) 'owner edit preserved'
    }else{
      Assert-Cron ($result.status -eq 'failed' -and !$script:task -and $result.rollback.task_removed) 'verification failure unregisters only owned task'
      Assert-Cron ([IO.File]::ReadAllText($config) -eq $original) 'failed setup leaves or restores original config'
      if($case -in @('after','normal')){Assert-Cron $result.rollback.config_restored 'post-switch failure rolls back flag'}
    }
    if(Test-Path $mu){Remove-Item -LiteralPath $mu -Recurse -Force}
 }
 # Pre-existing gates from any previous namespace must block a second installation.
 foreach($prefix in @('PREVIOUS', 'WORDPRIIS')) {
  $script:task=$null;$RuntimeDirectory=Join-Path $fixture ('must-not-create-'+$prefix)
  $null=New-Item -ItemType Directory -Path $mu -Force
  [IO.File]::WriteAllText((Join-Path $mu 'existing-gate.php'), ('<?php define("'+$prefix+'_CRON_GATE_HASH", "fixture");'))
  $result=Invoke-InstallWordPrIISWordPressCron
  Assert-Cron ($result.diagnostic.code -eq 'existing-cron-gate' -and !(Test-Path $RuntimeDirectory) -and !$script:task) 'previous namespace refuses before mutation'
  Remove-Item -LiteralPath $mu -Recurse -Force
 }
 # Existing task/output refuse without mutating either.
 $script:scenario='existing';$script:task=@{name='existing'};$RuntimeDirectory=Join-Path $fixture 'do-not-create'
 $result=Invoke-InstallWordPrIISWordPressCron
 Assert-Cron ($script:task.name -eq 'existing' -and !(Test-Path $RuntimeDirectory)) 'existing task never overwritten or removed'
 $script:task=$null;$RuntimeDirectory=Join-Path $fixture 'success'
 $saved=[IO.File]::ReadAllText((Join-Path $RuntimeDirectory 'install-report.json'))
 $result=Invoke-InstallWordPrIISWordPressCron
 Assert-Cron ([IO.File]::ReadAllText((Join-Path $RuntimeDirectory 'install-report.json')) -eq $saved) 'existing report directory untouched on refusal'
 # Atomic config publication refuses a stale expected hash.
 $candidate=Join-Path $fixture 'candidate';[IO.File]::WriteAllText($candidate,'NEW')
 $failed=$false;try{Publish-CronConfig $candidate $config ('0'*64)}catch{$failed=$true}
 Assert-Cron ($failed -and (Test-Path $candidate)) 'concurrent config mismatch refuses publication'
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
Write-Host "Cron setup: $n assertions passed."
