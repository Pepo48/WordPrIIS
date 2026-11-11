$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
foreach($test in @('core','bootstrap','server-audit','bootstrap-profile-runner','cron-setup','cron-recovery','cron-proof','cron-task-definition')){
 & pwsh -NoLogo -NoProfile -File (Join-Path $root ('tests/'+$test+'.ps1'))
 if($LASTEXITCODE -ne 0){throw ('Verification failed: '+$test)}
}
