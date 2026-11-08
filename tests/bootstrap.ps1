$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Invoke-Bootstrap.ps1')
$base=if(Test-Path '/private/tmp'){'/private/tmp'}else{[IO.Path]::GetTempPath()}
$fixture=Join-Path $base ('wordpriis-transaction-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($fixture)
$n=0;function Check($ok,$label){if(!$ok){throw $label};$script:n++}
# Only native host checks/stage functions are replaced. Artifact hashing, validation ordering,
# transaction report publication and failure behavior execute the production orchestrator.
function Assert-WordPrIISWindows {}
function Get-Service {param($Name,$ErrorAction);return $null}
function Get-Item {param($Path,$LiteralPath,[switch]$Force);if($Path -like 'Cert:*'){return @{HasPrivateKey=$true;NotAfter=(Get-Date).AddDays(1)}};Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force}
function New-WordPrIISReportDirectory {param($Config,$Purpose);$script:reportFolder=Join-Path $fixture ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($script:reportFolder);return $script:reportFolder}
function Stage($Name){$script:stages.Add($Name);if($script:fail -eq $Name){throw 'WORDPRIIS:synthetic-stage-failure'}}
function Install-WordPrIISPrerequisites {param($Config);Stage 'Prerequisites'}
function Install-WordPrIISPhp {param($Config);Stage 'PHP'}
function Initialize-WordPrIISWordPress {param($Config,$Credential);Check ($Credential.UserName -eq 'wordpress') 'credential reaches database stage';Stage 'WordPress'}
function Configure-WordPrIISIis {param($Config);Stage 'IIS'}
try{
 $c=Read-WordPrIISConfig (Join-Path $PSScriptRoot '../config/example.json')
 $c.WordPressPath=Join-Path $fixture 'web';$c.PhpPath=Join-Path $fixture 'php';$c.PrivatePath=Join-Path $fixture 'private';$c.CertificateThumbprint='a'*40
 $package=Join-Path $fixture 'verified-package';[IO.File]::WriteAllText($package,'fixture');$c.PhpArchivePath=$package;$c.WordPressArchivePath=$package;$c.PhpArchiveSha256=(Get-FileHash $package).Hash;$c.WordPressArchiveSha256=$c.PhpArchiveSha256
 $credential=New-Object Management.Automation.PSCredential('wordpress',(ConvertTo-SecureString 'NEVER_EXPORT_THIS_PASSWORD' -AsPlainText -Force))
 foreach($fail in @('none','Prerequisites','PHP','WordPress','IIS')){
    $script:fail=$fail;$script:stages=New-Object Collections.Generic.List[string];$failed=$false
    try{Invoke-WordPrIISBootstrap $c $credential}catch{$failed=$true}
    $raw=[IO.File]::ReadAllText((Join-Path $script:reportFolder 'bootstrap.json'));$r=$raw|ConvertFrom-Json
    Check (!$raw.Contains('NEVER_EXPORT_THIS_PASSWORD')) 'journal excludes credentials'
    if($fail -eq 'none'){Check (!$failed -and $r.status -eq 'complete' -and ($stages -join ',') -eq 'Prerequisites,PHP,WordPress,IIS') 'real orchestrator dispatches ordered stages'}
    else{Check ($failed -and $r.status -eq 'failed' -and $r.stage -eq $fail) 'failure checkpoint retained';Check ($stages[$stages.Count-1] -eq $fail) 'no stage runs after failure'}
 }
 $c.DatabaseHost='remote.example.invalid';$script:stages.Clear();$failed=$false
 try{Invoke-WordPrIISBootstrap $c $credential}catch{$failed=$true}
 Check ($failed -and !$stages.Count) 'remote database refused before credentials are sent without a TLS-aware path'
 $c.DatabaseHost='127.0.0.1'
 $c.PhpArchiveSha256='0'*64;$script:stages.Clear();$failed=$false
 try{Invoke-WordPrIISBootstrap $c $credential}catch{$failed=$true}
 Check ($failed -and !$stages.Count) 'invalid package refused before machine changes'
 $c.PhpArchiveSha256=$c.WordPressArchiveSha256;$null=[IO.Directory]::CreateDirectory($c.WordPressPath);$failed=$false
 try{Invoke-WordPrIISBootstrap $c $credential}catch{$failed=$true}
 Check ($failed -and !$stages.Count) 'existing site files refused before machine changes'
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
Write-Host "WordPrIIS bootstrap: $n assertions passed."
