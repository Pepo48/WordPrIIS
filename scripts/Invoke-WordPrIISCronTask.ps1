#requires -Version 5.1
# Durable task action; all code/config is administrator-owned, service account read-only.
[CmdletBinding()]
param([string]$ConfigPath)
. (Join-Path $PSScriptRoot 'Invoke-WordPrIISBootstrapProfile.ps1')
function Invoke-WordPrIISCronTaskRun {
    param([string]$Path)
    $run=[guid]::NewGuid().ToString('N');$phase='normal';$token=''
    $result=@{schema_version=1;generated_utc=[DateTime]::UtcNow.ToString('o');run_id=$run;phase=$phase;status='failed';exit_code=1}
    try{
        $cfg=[IO.File]::ReadAllText($Path)|ConvertFrom-Json
        if($cfg.token -notmatch '^[a-f0-9]{64}$'){throw 'WORDPRIIS_CRON_TASK:invalid-config'}
        $token=$cfg.token
        $uri=[uri]$cfg.url
        if($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or !$uri.AbsolutePath.EndsWith('/wp-cron.php')){throw 'invalid-cron-target'}
        $statePath=Join-Path (Split-Path -LiteralPath $Path) 'verification.json'
        if(Test-Path -LiteralPath $statePath){
            $state=[IO.File]::ReadAllText($statePath)|ConvertFrom-Json
            if($state.phase -notin @('before','after','cleanup','rollback')){throw 'invalid-verification-state'}
            if([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $state.expires){$phase=$state.phase}
        }
        $result.phase=$phase
        $target=[uri]($uri.AbsoluteUri+'?wordpriis_cron_run='+$run+'&wordpriis_cron_phase='+$phase)
        $sample=Invoke-ProfileHttp $cfg.curl $target $token $cfg.origin_address ([int]$cfg.timeout_seconds) -ConfigFile (Join-Path (Split-Path -LiteralPath $Path) 'request.curl')
        $result['http_status']=$sample.status;$result['ttfb_ms']=$sample.ttfb_ms;$result['total_ms']=$sample.total_ms;$result['cache_status']=$sample.cache_status
        if($sample.status -ne 200 -or $sample.cache_status -in @('HIT','STALE','UPDATING','REVALIDATED')){throw 'cron-http-or-cache-failure'}
        # wp-cron.php can flush 200 before bootstrap/jobs: wait for PHP's own completion.
        $until=[DateTime]::UtcNow.AddSeconds([int]$cfg.job_timeout_seconds)
        $completion=$null
        do{
            try{
                $current=[IO.File]::ReadAllText((Join-Path (Join-Path (Split-Path -LiteralPath $Path) 'run-results') ($run+'.json')))|ConvertFrom-Json
                if($current -and $current.run_id -eq $run -and $current.phase -eq $phase){$completion=$current;break}
            }catch{}
            Start-Sleep -Milliseconds 500
        }while([DateTime]::UtcNow -lt $until)
        if(!$completion){throw 'WORDPRIIS_CRON_TASK:php-completion-timeout'}
        $result['cron_complete']=$completion.status -eq 'complete'
        $result['cron_status']=$completion.status
        if($completion.status -eq 'busy'){$result.status='busy';$result.exit_code=0}
        elseif($completion.status -eq 'complete'){$result.status='complete';$result.exit_code=0}
        else{throw 'WORDPRIIS_CRON_TASK:php-cron-failed'}
    }catch{
        $result['diagnostic']=@{code='cron-request-failed';exception_type=$_.Exception.GetType().FullName}
        if($_.Exception.Message -match '^WORDPRIIS_CRON_TASK:([a-z0-9-]+)$'){$result.diagnostic.code=$matches[1]}
        $failure=Get-ProfileHttpFailureData $_;if($failure){$result['http_failure']=$failure}
    }finally{
        $token=$null
        $runs=Join-Path (Split-Path -LiteralPath $Path) 'run-results'
        try{
            $own=Join-Path $runs ($run+'.json');if(Test-Path -LiteralPath $own){Remove-Item -LiteralPath $own -Force}
            # Bounded stale receipt cleanup, confined to the dedicated data directory.
            $checked=0
            foreach($file in [IO.Directory]::EnumerateFiles($runs,'*.json')){
                if(++$checked -gt 200){break}
                if([IO.Path]::GetFileName($file) -match '^[a-f0-9]{32}\.json$' -and [IO.File]::GetLastWriteTimeUtc($file) -lt [DateTime]::UtcNow.AddDays(-1)){[IO.File]::Delete($file)}
            }
        }catch{}
        # Precreated file only; grant this service write access to the status file, not its directory/code.
        $output=Join-Path (Split-Path -LiteralPath $Path) 'task-last.json'
        if(!(Test-Path -LiteralPath $output -PathType Leaf)){throw 'Precreated task status file missing.'}
        [IO.File]::WriteAllText($output,($result|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    }
    return $result
}
if($MyInvocation.InvocationName -ne '.'){
    $result=Invoke-WordPrIISCronTaskRun $ConfigPath
    exit ([int]$result.exit_code)
}
