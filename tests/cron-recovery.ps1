# Actual recovery transaction/files, with IIS, ACL, credentials and scheduler boundaries mocked.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Recover-WordPressCron.ps1')
$n=0
function Check($ok,$message){if(!$ok){throw $message};$script:n++}
$base=Join-Path ([IO.Path]::GetTempPath()) ('cron-recovery-'+[guid]::NewGuid().ToString('N'))
$web=Join-Path $base 'web';$mu=Join-Path $web 'wp-content/mu-plugins';$null=New-Item -ItemType Directory -Path $mu -Force
$missing=Join-Path $base 'deleted-runtime';$config=Join-Path $web 'wp-config.php';$gate=Join-Path $mu '000-fixture-gate.php'
$site=@{site='Fixture';root=$web;mu=$mu;url='https://fixture.test/'}
$old=@{TaskName='Fixture WordPress Cron';TaskPath='\';State='Ready';Actions=@(@{WorkingDirectory=$missing});Principal=@{UserId='HOST\fixture_service'}}
$TaskName='';$TaskPath='\';$TaskAccount='fixture_service';$Url=$null;$TaskCredential=$null
$script:tasks=@($old);$script:sites=@($site)
function Assert-ProfileHost {}
function Assert-WordPrIISPlainPath {param($Path)}
function Assert-ProfilePlainPath {param($Path)}
function Get-ScheduledTask {param($TaskName,$TaskPath);if($TaskName){return $old};return $script:tasks}
function Get-RecoveryIisInventory {return $script:sites}
function Get-ProfileDiscovery {return @{root=$web;mu=$mu;php='fixture';site_name='Fixture'}}
function Enter-ProfileLock {param($Path);$o=New-Object PSObject;$o|Add-Member ScriptMethod ReleaseMutex {};$o|Add-Member ScriptMethod Dispose {};return $o}
function Get-Credential {param($UserName,$Message);$script:prompted++;return New-Object Management.Automation.PSCredential($UserName,(ConvertTo-SecureString 'FIXTURE_ONLY' -AsPlainText -Force))}
function Get-CronTaskIdentity {param($Account,$Credential);if($script:badCredential){throw 'WORDPRIIS_CRON:credential-account-mismatch'};return @{sid='fixture'}}
function New-WordPrIISReportDirectory {param($Config,$Purpose);$p=Join-Path $Config.PrivatePath ($Purpose+'-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $p;return $p}
function Export-ScheduledTask {param($TaskName,$TaskPath);return '<Task>fixture</Task>'}
function Get-CronConfigPlan {param($Php,$Config,$Candidate,[switch]$EnableRequestCron)
 Check $EnableRequestCron 'recovery explicitly requests enabled visitor cron'
 $source=[IO.File]::ReadAllText($Config);$next=$source.Replace('true','false');[IO.File]::WriteAllText($Candidate,$next)
 return @{changed=($next -ne $source);original_sha256=(Get-FileHash $Config).Hash}
}
function Get-Acl {param($LiteralPath);return 'fixture'}
function Set-Acl {param($LiteralPath,$AclObject)}
function Disable-ScheduledTask {param($TaskName,$TaskPath);$script:events.Add('disable-old');$old.State='Disabled'}
function Unregister-ScheduledTask {param($TaskName,$TaskPath,[switch]$Confirm);$script:events.Add('remove-old')}
function Invoke-RecoveryVerifiedInstaller {param($Discovery,$Target,$Credential,$Runtime,$Name)
 Check ([IO.File]::ReadAllText($config).Contains('false')) 'visitor cron is enabled before replacement verification'
 Check (!(Test-Path $gate)) 'only associated old gate removed before replacement'
 Check ($old.State -eq 'Disabled') 'old task disabled before replacement'
 Check ($Runtime -like '*Permanent-WordPressCron-Recovered-*') 'replacement path explicitly permanent'
 $script:events.Add('verify')
 if($script:failInstall){return @{status='failed';request_cron_disabled=$false}}
 [IO.File]::WriteAllText($config,"<?php define('DISABLE_WP_CRON', true);")
 return @{status='complete';request_cron_disabled=$true}
}
function Reset-Fixture {
 [IO.File]::WriteAllText($config,"<?php define('DISABLE_WP_CRON', true); // PRIVATE_FIXTURE")
 [IO.File]::WriteAllText($gate,"<?php define('FIXTURE_CRON_GATE_HASH','fixture'); define('FIXTURE_CRON_GATE_LOCK','"+$missing.Replace('\','/')+"/cron.lock');")
 $old.State='Ready';$script:tasks=@($old);$script:sites=@($site);$script:events=New-Object Collections.Generic.List[string]
 $script:prompted=0;$script:badCredential=$false;$script:failInstall=$false
}
try {
 Check ((Get-RecoveryBindingUrl 'https' '*:443:fixture.test' '/' $null $false) -eq 'https://fixture.test/') 'named HTTPS binding inferred'
 Check (!(Get-RecoveryBindingUrl 'http' '*:80:fixture.test' '/' $null $false)) 'public HTTPS not invented from HTTP binding'
 Check ((Get-RecoveryBindingUrl 'http' '*:80:fixture.test' '/' ([uri]'https://fixture.test/') $false) -eq 'https://fixture.test/') 'explicit public HTTPS can match HTTP origin hostname'
 Check (!(Get-RecoveryBindingUrl 'https' '*:443:' '/' ([uri]'https://fixture.test/') $false)) 'unnamed binding requires explicit site'
 Check ((Get-RecoveryBindingUrl 'https' '*:443:' '/' ([uri]'https://fixture.test/') $true) -eq 'https://fixture.test/') 'explicit site and URL resolve unnamed binding'
 Check (!(Get-RecoveryBindingUrl 'https' '*:443:other.test' '/' ([uri]'https://fixture.test/') $true)) 'mismatching named hostname refused'
 Check (!(Get-RecoveryBindingUrl 'https' '*:443:fixture.test' '/subsite' ([uri]'https://fixture.test/') $true)) 'wrong application route refused'
 $refused=$false;try{$null=Get-RecoveryBindingUrl 'http' '*:80:fixture.test' '/' ([uri]'http://fixture.test/') $true}catch{$refused=$true};Check $refused 'non-HTTPS public target refused'
 Reset-Fixture
 $counts=Select-CronRecoveryTarget @($old) @($site) '' '\' $TaskAccount $null -Diagnostics
 Check ($counts.missing_runtimes -eq 1 -and $counts.candidate_pairs -eq 1) 'diagnostic explains unique match counts'
 Check (!(($counts|ConvertTo-Json -Compress).Contains($base))) 'diagnostic omits private filesystem paths'
 $Diagnose=$true;$result=Invoke-CronRecovery;$Diagnose=$false
 Check ($result.status -eq 'diagnostic-only' -and $script:prompted -eq 0 -and (Test-Path $gate) -and $old.State -eq 'Ready') 'diagnose mode never prompts, disables tasks or removes gates'
 Reset-Fixture
 $selected=Select-CronRecoveryTarget @($old) @($site) '' '\' 'fixture_service' $null
 Check ($selected.gate -eq $gate) 'missing runtime associated with exact gate and IIS root'
 foreach($case in @('duplicate-task','duplicate-site','wrong-owner','unrelated-gate','existing-runtime','running-task','wrong-url')) {
  Reset-Fixture;$targetUrl=$null
  switch($case){
   'duplicate-task' {$script:tasks=@($old,$old)}
   'duplicate-site' {$script:sites=@($site,$site)}
   'wrong-owner' {$TaskAccount='other'}
   'unrelated-gate' {[IO.File]::WriteAllText($gate,"<?php define('FIXTURE_CRON_GATE_HASH','unrelated');")}
   'existing-runtime' {$null=New-Item -ItemType Directory -Path $missing}
   'running-task' {$old.State='Running'}
   'wrong-url' {$targetUrl=[uri]'https://other.test/'}
  }
  $refused=$false
  try {$null=Select-CronRecoveryTarget $script:tasks $script:sites '' '\' $TaskAccount $targetUrl}catch{$refused=$true}
  Check $refused ('unsafe discovery refused: '+$case)
  Check ([IO.File]::ReadAllText($config).Contains('true')) 'discovery refusal never changes wp-config'
  $TaskAccount='fixture_service';if(Test-Path $missing){Remove-Item -LiteralPath $missing}
 }
 Reset-Fixture;$script:badCredential=$true;$result=Invoke-CronRecovery
 Check ($result.status -eq 'failed' -and $result.stage -eq 'credential') 'incorrect credentials stop before mutation'
 Check ((Test-Path $gate) -and $old.State -eq 'Ready') 'credential failure preserves old bridge'
 foreach($fail in @($false,$true)) {
  Reset-Fixture;$script:failInstall=$fail;$result=Invoke-CronRecovery
  Check ($script:prompted -eq 1) 'existing task account password requested once'
  if(!$fail){
   Check ($result.status -eq 'complete' -and $result.replacement_verified -and $result.old_task_removed) 'successful replacement fully reported'
   Check (($script:events -join ',') -eq 'disable-old,verify,remove-old') 'old task removed only after verified replacement'
  }else{
   Check ($result.status -eq 'failed' -and !$result.old_task_removed) 'failed replacement retains disabled old task and recovery evidence'
   Check ([IO.File]::ReadAllText($config).Contains('false')) 'failed verification leaves visitor cron available'
   Check (($script:events -join ',') -eq 'disable-old,verify') 'failed verification never unregisters old task'
  }
 }
 $reports=@(Get-ChildItem -LiteralPath $base -Directory -Filter 'CronRecovery-*')
 Check ($reports.Count -eq 2) 'one protected evidence directory per attempted transaction'
 foreach($dir in $reports){
  $raw=[IO.File]::ReadAllText((Join-Path $dir.FullName 'recovery-report.json'))
  Check (!$raw.Contains('PRIVATE_FIXTURE') -and !$raw.Contains('FIXTURE_ONLY')) 'report excludes config content and password'
  Check ((Test-Path (Join-Path $dir.FullName 'wp-config.before.php')) -and (Test-Path (Join-Path $dir.FullName 'previous-cron-gate.php')) -and (Test-Path (Join-Path $dir.FullName 'old-task.xml'))) 'config gate and task backups retained'
 }
 Write-Host ("Cron recovery: "+$n+" assertions passed.")
} finally {Remove-Item -LiteralPath $base -Recurse -Force}
