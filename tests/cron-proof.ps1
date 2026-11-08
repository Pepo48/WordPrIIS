# Test real proof matching; an HTTP 200 alone must never authorize the config switch.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Install-VerifiedWordPressCron.ps1')
$n=0;function Assert-Proof($ok,$label){if(!$ok){throw $label};$script:n++}
function Start-ScheduledTask {param($TaskPath,$TaskName);$script:starts++}
function Get-ScheduledTask {param($TaskPath,$TaskName);return @{State='Ready'}}
function Get-ScheduledTaskInfo {param($TaskPath,$TaskName);return @{LastTaskResult=$script:taskResult}}
function Start-Sleep {param($Milliseconds)}
$base=if(Test-Path '/private/tmp'){'/private/tmp'}else{[IO.Path]::GetTempPath()}
$folder=Join-Path $base ('wordpriis-cron-proof-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $folder
$script:taskResult=0;$script:starts=0
$last=@{run_id=('a'*32);phase='after';exit_code=0;http_status=200;cron_complete=$true}
$proof=@{run_id=('a'*32);phase='after';doing_cron=$true;probe_events_cleared=$true;disable_wp_cron=$true}
try{
 Write-CronJson (Join-Path $folder 'task-last.json') $last
 Write-CronJson (Join-Path $folder 'proof.json') $proof
 $result=Wait-CronTaskProof 'fixture' $folder 'after' $true 0 ''
 Assert-Proof ($result.canary_executed -and $result.disable_wp_cron -and $starts -eq 1) 'matching successful task and actual disabled canary accepted'
 foreach($mutation in @('missing','wrong-run','not-cron','still-enabled','uncleared','same-run','task-failed','http-only')){
   $p=@{};foreach($key in $proof.Keys){$p[$key]=$proof[$key]};$previous='';$taskResult=0
   switch($mutation){
     'wrong-run' {$p.run_id='b'*32}
     'not-cron' {$p.doing_cron=$false}
     'still-enabled' {$p.disable_wp_cron=$false}
     'uncleared' {$p.probe_events_cleared=$false}
     'same-run' {$previous='a'*32}
     'task-failed' {$taskResult=1}
     'http-only' {$last.cron_complete=$false;Write-CronJson (Join-Path $folder 'task-last.json') $last}
   }
   Write-CronJson (Join-Path $folder 'proof.json') $p
   if($mutation -eq 'missing'){[IO.File]::WriteAllText((Join-Path $folder 'proof.json'),'')}
   $failed=$false;try{Wait-CronTaskProof 'fixture' $folder 'after' $true 0 $previous}catch{$failed=$true}
   Assert-Proof $failed 'cached HTTP/old run/wrong callback/old flag/uncleared job/task failure cannot verify'
 }
 $last.cron_complete=$true;Write-CronJson (Join-Path $folder 'task-last.json') $last
 $taskResult=0;Write-CronJson (Join-Path $folder 'proof.json') $proof
 $before=$starts;$result=Wait-CronTaskProof 'fixture' $folder 'after' $true 0 '' -Automatic
 Assert-Proof ($starts -eq $before -and $result.automatic) 'automatic verification never manually starts task'
 [IO.File]::WriteAllText((Join-Path $folder 'proof.json'),'')
 $result=Wait-CronTaskProof 'fixture' $folder 'after' $null 0 '' -WithoutCanary
 Assert-Proof (!$result.ContainsKey('canary_executed') -and $result.http_status -eq 200) 'final no-canary run is labeled transport-only'
}finally{Remove-Item -LiteralPath $folder -Recurse -Force}
Write-Host "Cron proof: $n assertions passed."
