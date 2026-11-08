#requires -Version 5.1
[CmdletBinding()]param([string]$ConfigPath,[switch]$RecordDefender,[ValidateRange(15,180)][int]$Seconds=60)
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
function Invoke-WordPrIISWindowsDiagnostics {
    param([hashtable]$Config,[switch]$Defender,[int]$Duration=60)
    $folder=New-WordPrIISReportDirectory $Config 'Diagnostics';$job=$null
    $report=[ordered]@{schema_version=1;status='incomplete';defender=@{status='not-requested'};scope='Read-only configuration audit, temporary token-gated PHP profile and bounded file-metadata calibration. Optional timed Defender ETL. No security exclusion, cache flush, service restart or tuning.'}
    try {
        & (Join-Path $PSScriptRoot 'Invoke-WordPrIISServerAudit.ps1') -Url $Config.Url -SiteName $Config.SiteName -WordPressPath $Config.WordPressPath -PhpPath (Join-Path $Config.PhpPath 'php.exe') -OutputDirectory (Join-Path $folder 'audit') -SkipHttp
        if($Defender){
            $command=Get-Command New-MpPerformanceRecording -ErrorAction SilentlyContinue
            if(!$command -or !$command.Parameters.ContainsKey('Seconds')){$report.defender=@{status='unavailable';code='timed-defender-recording-not-supported';next='Use the documented interactive recorder in another elevated window; no automatic policy change.'}}
            else {
                $etl=Join-Path $folder 'defender-private.etl'
                $job=Start-Job -ArgumentList $etl,$Duration -ScriptBlock {param($Path,$Time);$ErrorActionPreference='Stop';New-MpPerformanceRecording -RecordTo $Path -Seconds $Time|Out-Null}
                # A startup delay is not proof the recorder is active; report this limitation.
                Start-Sleep -Seconds 2
                $report.defender=@{status='recording-attempted';file='defender-private.etl';seconds=$Duration;coverage='Start time is approximate; no recorder readiness acknowledgement. Raw ETL can contain host paths/process events; keep private.'}
            }
        }
        & (Join-Path $PSScriptRoot 'Invoke-WordPrIISBootstrapProfile.ps1') -Url $Config.Url -SiteName $Config.SiteName -WordPressPath $Config.WordPressPath -PhpPath (Join-Path $Config.PhpPath 'php.exe') -OutputDirectory (Join-Path $folder 'profile') -BenchmarkFileSystem
        if($job){
            $deadline=[DateTime]::UtcNow.AddSeconds($Duration+10)
            while($job.State -in @('Running','NotStarted') -and [DateTime]::UtcNow -lt $deadline){Write-Progress -Activity 'Retaining bounded Defender recording' -Status 'Waiting for the timed recorder';$null=Wait-Job $job -Timeout 1}
            if($job.State -eq 'Completed' -and (Test-Path -LiteralPath $etl)){$report.defender.status='recorded';$report.defender['analyze']='Get-MpPerformanceReport -Path <private ETL> -TopProcesses 10 -TopFiles 10; review locally, do not upload the raw ETL.'}
            else{$report.defender.status='failed';$report.defender['code']='defender-recorder-failed-or-timed-out'}
        }
        $report.status=if($Defender -and $report.defender.status -ne 'recorded'){'partial'}else{'complete'}
    }catch{$report.status='failed';$report['code']='diagnostic-stage-failed';throw}
    finally{
        if($job){if($job.State -in @('Running','NotStarted')){Stop-Job $job -ErrorAction SilentlyContinue;$report.defender['cleanup']='Recorder job stopped; inspect its named ETL/session locally. No unrelated WPR session was cancelled.'};Remove-Job $job -Force -ErrorAction SilentlyContinue}
        Write-WordPrIISJson (Join-Path $folder 'diagnostics.json') $report
        Write-Host ('Diagnostic report: '+$folder)
    }
}
if($MyInvocation.InvocationName -ne '.') { Invoke-WordPrIISWindowsDiagnostics (Read-WordPrIISConfig $ConfigPath) -Defender:$RecordDefender -Duration $Seconds }
