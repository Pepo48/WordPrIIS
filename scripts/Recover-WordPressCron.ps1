#requires -Version 5.1
<#
.SYNOPSIS
Recover a deleted cron runtime using the existing task identity and IIS configuration.
.DESCRIPTION
Run elevated from the complete toolkit. No config file is needed. Refuses ambiguous
sites/tasks/gates and existing runtimes. Keeps private backups and verified installer reports.
#>
[CmdletBinding()]
param([uri]$Url,[string]$TaskName,[string]$SiteName,[switch]$Diagnose,[string]$TaskPath='\',[string]$TaskAccount,[Management.Automation.PSCredential]$TaskCredential)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
$recoveryInput=@{Url=$Url;TaskName=$TaskName;TaskAccount=$TaskAccount;TaskCredential=$TaskCredential;SiteName=$SiteName}
. (Join-Path $PSScriptRoot 'Install-VerifiedWordPressCron.ps1')
$Url=$recoveryInput.Url;$TaskName=$recoveryInput.TaskName;$TaskAccount=$recoveryInput.TaskAccount;$TaskCredential=$recoveryInput.TaskCredential;$SiteName=$recoveryInput.SiteName

function Get-RecoveryBindingUrl {
    param([string]$Protocol,[string]$Binding,[string]$ApplicationPath,[uri]$Target,[bool]$ExplicitSite)
    if($Protocol -notin @('http','https') -or $Binding -notmatch '^.*:([0-9]+):(.*)$'){return}
    $port=[int]$matches[1];$hostName=$matches[2]
    if($Target){
        if($Target.Scheme -ne 'https' -or $Target.UserInfo -or $Target.Query -or $Target.Fragment){throw 'WORDPRIIS_RECOVERY:https-site-url-required'}
        if($Target.AbsolutePath.TrimEnd('/') -ne $ApplicationPath.TrimEnd('/')){return}
        if($hostName -ieq $Target.DnsSafeHost -or (!$hostName -and $ExplicitSite)){return $Target.AbsoluteUri}
        return
    }
    if($Protocol -ne 'https' -or !$hostName -or $hostName.Contains('*')){return}
    $authority=$hostName;if($port -ne 443){$authority+=':'+$port}
    return 'https://'+$authority+$ApplicationPath.TrimEnd('/')+'/'
}
function Get-RecoveryIisInventory {
    param([uri]$Target,[string]$RequestedSite)
    Add-Type -Path (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll')
    $manager=New-Object Microsoft.Web.Administration.ServerManager
    try {
        foreach($site in $manager.Sites){if($RequestedSite -and $site.Name -ine $RequestedSite){continue};foreach($app in $site.Applications){
            $root=[Environment]::ExpandEnvironmentVariables($app.VirtualDirectories['/'].PhysicalPath)
            if(!(Test-Path -LiteralPath (Join-Path $root 'wp-settings.php') -PathType Leaf)){continue}
            foreach($binding in $site.Bindings){
                $route=Get-RecoveryBindingUrl $binding.Protocol $binding.BindingInformation $app.Path $Target ([bool]$RequestedSite)
                if($route){@{site=$site.Name;root=$root;url=$route;mu=(Join-Path $root 'wp-content\mu-plugins')}}
            }
        }}
    } finally {$manager.Dispose()}
}
function Select-CronRecoveryTarget {
    param($Tasks,$Sites,[string]$Name,[string]$Path,[string]$Account,[uri]$Target,[switch]$Diagnostics)
    $counts=[ordered]@{tasks_seen=@($Tasks).Count;task_name_matches=0;account_matches=0;usable_actions=0;missing_runtimes=0;site_routes=@($Sites).Count;mu_directories=0;unique_gates=0;lock_path_matches=0;candidate_pairs=0}
    $pairs=@(foreach($task in $Tasks){
        if($Name){if($task.TaskName -ne $Name -or $task.TaskPath -ne $Path){continue}}
        elseif($task.TaskName -notlike '*WordPress Cron*'){continue}
        $counts.task_name_matches++
        $user=([string]$task.Principal.UserId -split '\\')[-1]
        if($Account -and $user -ine ($Account -split '\\')[-1]){continue}
        $counts.account_matches++
        if(@($task.Actions).Count -ne 1 -or !$task.Actions[0].WorkingDirectory){continue}
        $counts.usable_actions++
        $directory=[string]$task.Actions[0].WorkingDirectory
        Assert-WordPrIISPlainPath $directory
        if(Test-Path -LiteralPath $directory){continue}
        $counts.missing_runtimes++
        $oldLock=$directory.Replace('\','/').TrimEnd('/')+'/cron.lock'
        foreach($site in $Sites){
            if($Target -and ([uri]$site.url).AbsoluteUri.TrimEnd('/') -ine $Target.AbsoluteUri.TrimEnd('/')){continue}
            if(!(Test-Path -LiteralPath $site.mu -PathType Container)){continue}
            $counts.mu_directories++
            $gates=@(Get-ChildItem -LiteralPath $site.mu -Filter '*.php' | Where-Object {
                $_.Length -lt 65536 -and [IO.File]::ReadAllText($_.FullName) -match '\b[A-Z][A-Z0-9_]*_CRON_GATE_HASH\b'
            })
            if($gates.Count -ne 1){continue}
            $counts.unique_gates++
            Assert-WordPrIISPlainPath $gates[0].FullName
            if([IO.File]::ReadAllText($gates[0].FullName).IndexOf($oldLock,[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
            $counts.lock_path_matches++
            @{task=$task;site=$site;gate=$gates[0].FullName;old_directory=$directory}
        }
    })
    $counts.candidate_pairs=$pairs.Count
    if($Diagnostics -or $pairs.Count -ne 1){Write-Host ('Discovery counts (no paths, identities or gate contents): '+($counts|ConvertTo-Json -Compress))}
    if($Diagnostics){return [pscustomobject]$counts}
    if($pairs.Count -ne 1){throw 'WORDPRIIS_RECOVERY:ambiguous-or-missing-target'}
    if($pairs[0].task.State -eq 'Running'){throw 'WORDPRIIS_RECOVERY:task-running'}
    return $pairs[0]
}
function Invoke-RecoveryVerifiedInstaller {
    param($Discovery,[uri]$Target,$Credential,[string]$Runtime,[string]$Name)
    # Isolate installer variables/functions; use its returned transaction report, not process exit.
    . (Join-Path $PSScriptRoot 'Install-VerifiedWordPressCron.ps1') -Url $Target -SiteName $Discovery.site_name -WordPressPath $Discovery.root -PhpPath $Discovery.php -TaskAccount $Credential.UserName -TaskCredential $Credential -RuntimeDirectory $Runtime -TaskName $Name
    Invoke-InstallWordPrIISWordPressCron
}
function Invoke-CronRecovery {
    $stage='discovery';$reportPath=$null;$mutex=$null
    $report=[ordered]@{schema_version=1;status='failed';visitor_cron_restored=$false;old_task_disabled=$false;old_gate_removed=$false;replacement_verified=$false;old_task_removed=$false}
    try {
        Assert-ProfileHost
        $sites=@(Get-RecoveryIisInventory $Url $SiteName | Sort-Object -Property @{Expression={$_.site}},@{Expression={$_.root}},@{Expression={$_.url}} -Unique)
        $selected=Select-CronRecoveryTarget @(Get-ScheduledTask) $sites $TaskName $TaskPath $TaskAccount $Url -Diagnostics:$Diagnose
        if($Diagnose){return [pscustomobject]@{status='diagnostic-only';discovery=$selected}}
        $old=$selected.task;$target=[uri]$selected.site.url
        $discovery=Get-ProfileDiscovery $target $selected.site.site $selected.site.root '' '' ''
        if([IO.Path]::GetFullPath($discovery.mu) -ine [IO.Path]::GetFullPath($selected.site.mu)){throw 'WORDPRIIS_RECOVERY:mu-path-mismatch'}
        $mutex=Enter-ProfileLock $discovery.root
        $stage='credential'
        $credential=$TaskCredential
        if(!$credential){$credential=Get-Credential -UserName $old.Principal.UserId -Message 'Existing WordPress service account password'}
        $null=Get-CronTaskIdentity $old.Principal.UserId $credential
        $stage='private-runtime'
        $parent=Split-Path $selected.old_directory -Parent
        if(!(Test-Path -LiteralPath $parent -PathType Container)){throw 'WORDPRIIS_RECOVERY:runtime-parent-missing'}
        $private=New-WordPrIISReportDirectory @{PrivatePath=$parent} 'CronRecovery'
        $reportPath=Join-Path $private 'recovery-report.json'
        $runtime=Join-Path $parent ('Permanent-WordPressCron-Recovered-'+[guid]::NewGuid().ToString('N'))
        $newName='Recovered WordPress Cron - '+[guid]::NewGuid().ToString('N').Substring(0,12)
        $config=Join-Path $discovery.root 'wp-config.php';if(!(Test-Path -LiteralPath $config)){$config=Join-Path (Split-Path $discovery.root -Parent) 'wp-config.php'}
        Assert-ProfilePlainPath $config
        $stage='backups'
        $configHash=(Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $config -Destination (Join-Path $private 'wp-config.before.php')
        if((Get-FileHash -LiteralPath (Join-Path $private 'wp-config.before.php') -Algorithm SHA256).Hash -ne $configHash){throw 'WORDPRIIS_RECOVERY:config-backup-mismatch'}
        $gateHash=(Get-FileHash -LiteralPath $selected.gate -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $selected.gate -Destination (Join-Path $private 'previous-cron-gate.php')
        if((Get-FileHash -LiteralPath (Join-Path $private 'previous-cron-gate.php') -Algorithm SHA256).Hash -ne $gateHash){throw 'WORDPRIIS_RECOVERY:gate-backup-mismatch'}
        [IO.File]::WriteAllText((Join-Path $private 'old-task.xml'),(Export-ScheduledTask -TaskName $old.TaskName -TaskPath $old.TaskPath))
        $stage='visitor-cron'
        $candidate=Join-Path $private 'wp-config.visitor-cron.php'
        $plan=Get-CronConfigPlan $discovery.php $config $candidate -EnableRequestCron
        if($plan.original_sha256 -ine $configHash){throw 'WORDPRIIS_RECOVERY:config-changed'}
        if($plan.changed){$acl=Get-Acl -LiteralPath $config;Publish-CronConfig $candidate $config $plan.original_sha256;Set-Acl -LiteralPath $config -AclObject $acl}else{Remove-Item -LiteralPath $candidate}
        $report.visitor_cron_restored=$true
        $stage='retire-old-bridge'
        if(Test-Path -LiteralPath $selected.old_directory){throw 'WORDPRIIS_RECOVERY:runtime-reappeared'}
        Disable-ScheduledTask -TaskName $old.TaskName -TaskPath $old.TaskPath | Out-Null
        $report.old_task_disabled=$true
        if((Get-ScheduledTask -TaskName $old.TaskName -TaskPath $old.TaskPath).State -eq 'Running'){throw 'WORDPRIIS_RECOVERY:task-running'}
        if(!(Remove-ProfileOwnedFile $selected.gate $gateHash)){throw 'WORDPRIIS_RECOVERY:gate-changed'}
        $report.old_gate_removed=$true
        $stage='verified-install'
        $proof=Invoke-RecoveryVerifiedInstaller $discovery $target $credential $runtime $newName
        if($proof.status -ne 'complete' -or !$proof.request_cron_disabled){throw 'WORDPRIIS_RECOVERY:replacement-not-verified'}
        $report.replacement_verified=$true
        $stage='remove-old-task'
        Unregister-ScheduledTask -TaskName $old.TaskName -TaskPath $old.TaskPath -Confirm:$false
        $report.old_task_removed=$true;$report.status='complete'
        Write-Host ('Verified replacement: '+$newName)
        Write-Warning ('PERMANENT CRON RUNTIME - KEEP THIS DIRECTORY: '+$runtime)
    } catch {
        $report['stage']=$stage
        $report['code']=if($_.Exception.Message -match '^WORDPRIIS(?:_RECOVERY|_CRON|_PROFILE)?:[a-z0-9-]+$'){$_.Exception.Message}else{'recovery-stage-failed'}
        Write-Warning ('Recovery stopped at '+$stage+'. Inspect private reports; do not delete a retained replacement task or gate.')
    } finally {
        if($reportPath){Write-WordPrIISJson $reportPath $report;Write-Host ('Private recovery report: '+$reportPath)}
        $credential=$null
        if($mutex){$mutex.ReleaseMutex();$mutex.Dispose()}
    }
    return [pscustomobject]$report
}
if($MyInvocation.InvocationName -ne '.'){
    $result=Invoke-CronRecovery
    if($result.status -notin @('complete','diagnostic-only')){Write-Error ('Cron recovery failed at '+$result.stage+'; code: '+$result.code);exit 1}
}
