# No registration: verify account matching and the exact task factory contract.
. (Join-Path $PSScriptRoot '../scripts/Install-VerifiedWordPressCron.ps1')
$n=0;function Assert-Definition($ok,$label){if(!$ok){throw $label};$script:n++}
function Resolve-CronAccountSid {param($Account);if($Account -in @('wordpress-svc-account','HOST\wordpress-svc-account')){return 'same-sid'};return 'other-sid'}
$credential=New-Object Management.Automation.PSCredential('HOST\wordpress-svc-account',(ConvertTo-SecureString 'SYNTHETIC_TEST_VALUE' -AsPlainText -Force))
$identity=Get-CronTaskIdentity 'wordpress-svc-account' $credential
Assert-Definition ($identity.sid -eq 'same-sid') 'credential checked by SID rather than spelling'
$failed=$false;try{Get-CronTaskIdentity 'wrong-user' $credential}catch{$failed=$true}
Assert-Definition $failed 'mismatched credential refused'
function Get-ScheduledTask {param($TaskPath,$TaskName,$ErrorAction);return $null}
function New-ScheduledTaskAction {param($Execute,$Argument,$WorkingDirectory);return @{execute=$Execute;arguments=$Argument;working=$WorkingDirectory}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel);return @{user=$UserId;logon=$LogonType;level=$RunLevel}}
function New-ScheduledTaskTrigger {param([switch]$Once,$At,$RepetitionInterval);return @{once=[bool]$Once;at=$At;interval=$RepetitionInterval}}
function New-ScheduledTaskSettingsSet {param($MultipleInstances,$ExecutionTimeLimit,[switch]$StartWhenAvailable,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries);return @{instances=$MultipleInstances;limit=$ExecutionTimeLimit}}
function New-ScheduledTask {param($Action,$Principal,$Trigger,$Settings,$Description);return @{action=$Action;principal=$Principal;trigger=$Trigger;settings=$Settings}}
function Register-ScheduledTask {param($TaskPath,$TaskName,$InputObject,$User,$Password);$script:registered=$InputObject;$script:correctCredential=($User -eq 'HOST\wordpress-svc-account' -and $Password -eq 'SYNTHETIC_TEST_VALUE')}
$saved=$env:windir
try{
 $env:windir=[IO.Path]::GetTempPath()
 Register-CronScheduledTask 'WORDPRIIS Cron' ([IO.Path]::GetTempPath()) 1 120 300 $credential
 Assert-Definition $correctCredential 'existing service credential passed to scheduler API only'
 Assert-Definition ($registered.principal.logon -eq 'Password' -and $registered.principal.level -eq 'Limited') 'noninteractive password logon without elevation'
 Assert-Definition ($registered.settings.instances -eq 'IgnoreNew' -and $registered.settings.limit.TotalSeconds -eq 480) 'nonoverlapping task and bounded runtime'
 Assert-Definition ($registered.trigger.once -and $registered.trigger.interval.TotalMinutes -eq 1) 'recurring minute trigger'
 Assert-Definition (!$registered.action.arguments.Contains('SYNTHETIC_TEST_VALUE') -and !$registered.action.arguments.Contains('ExecutionPolicy')) 'no password or policy bypass in action arguments'
}finally{$env:windir=$saved}
Write-Host "Cron task definition: $n assertions passed."
