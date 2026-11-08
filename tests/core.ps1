# Portable regressions exercise production functions and real files, not copies of installer logic.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../modules/Common.ps1')
. (Join-Path $PSScriptRoot '../modules/Templates.ps1')
. (Join-Path $PSScriptRoot '../modules/Artifacts.ps1')
. (Join-Path $PSScriptRoot '../scripts/Configure-IIS.ps1')
$n=0;function Assert-Core($ok,$label){if(!$ok){throw $label};$script:n++}
$base=if(Test-Path '/private/tmp'){'/private/tmp'}else{[IO.Path]::GetTempPath()}
$fixture=Join-Path $base ('wordpriis-core-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($fixture)
try {
 $config=Read-WordPrIISConfig (Join-Path $PSScriptRoot '../config/example.json')
 Assert-Core ($config.DatabaseHost -eq '127.0.0.1') 'explicit IPv4 loopback default'
 Assert-Core ((Get-WordPrIISPlan $config).mode -eq 'plan') 'default operation is a pure plan'
 foreach($bad in @(@{SchemaVersion=$true},@{SchemaVersion='1'},@{Password='DO_NOT_EXPORT'},@{DatabasePassword='DO_NOT_EXPORT'},@{Url='http://example.test'},@{Url='https://user:DO_NOT_EXPORT@example.test'},@{PrivatePath='C:\inetpub\wordpress\reports'},@{WordPressPath='C:\site\..\windows'},@{PhpArchiveSha256='not-a-hash'})){
    $copy=$config.Clone();foreach($key in $bad.Keys){$copy[$key]=$bad[$key]};$file=Join-Path $fixture 'bad.json';Write-WordPrIISJson $file $copy
    $failed=$false;try{Read-WordPrIISConfig $file|Out-Null}catch{$failed=$true;Assert-Core (!$_.Exception.Message.Contains('DO_NOT_EXPORT')) 'validation never prints rejected value'}
    Assert-Core $failed 'unsafe/secret config refused'
 }
 $ini=Get-WordPrIISPhpIni $config
 Assert-Core ($ini.Contains('opcache.validate_timestamps=1') -and $ini.Contains('opcache.jit=disable')) 'measured-compatible opcode cache with no speculative JIT'
 Assert-Core ($ini.Contains('fastcgi.impersonate=0') -and $ini.Contains('open_basedir=') -and !$ini.Contains('opcache.preload=')) 'isolation retained; unsupported Windows preloading absent'
 Assert-Core ($ini.Contains('opcache.max_accelerated_files=20000') -and !$ini.Contains('opcache.max_accelerated_files=1000')) 'cache key capacity no longer legacy 1000'
 [xml]$xml=Get-WordPrIISWebConfig
 Assert-Core ($xml.configuration.'system.webServer'.httpProtocol.customHeaders.remove.name -contains 'Cache-Control') 'blanket inherited cache header removed explicitly'
 Assert-Core (!$xml.SelectSingleNode('//clear') -and !$xml.SelectSingleNode('//mimeMap')) 'no collection reset or duplicate MIME entries'
 Assert-Core ($xml.SelectSingleNode('//clientCache').cacheControlMaxAge -eq '30.00:00:00') 'long successful static caching retained'
 Assert-Core ($xml.SelectSingleNode('//outboundRules/rule/action').value -eq 'no-store') '5xx rule overrides cache-control'
 Assert-Core ($xml.SelectSingleNode('//preConditions/preCondition/add').pattern.StartsWith('^5')) 'error cache rewrite is status-gated'
 Assert-Core ($xml.SelectSingleNode('//location').path -eq 'wp-content/uploads' -and $xml.SelectSingleNode('//location/system.webServer/handlers').accessPolicy -eq 'Read' -and $xml.SelectSingleNode('//location').overrideMode -eq 'Deny') 'uploads do not grant script execution'
 $credential=New-Object Management.Automation.PSCredential('wordpress',(ConvertTo-SecureString "SYNTHETIC'quote\backslash`n" -AsPlainText -Force))
 $wp=Get-WordPrIISWpConfig $config $credential
 Assert-Core ($wp.Contains("define('DB_HOST', '127.0.0.1');") -and $wp.Contains("define('DISABLE_WP_CRON', false);")) 'DB transport fixed and request cron not prematurely disabled'
 Assert-Core ($wp.Contains("require_once ABSPATH . 'wp-settings.php';") -and !$wp.Contains('eval(')) 'config remains compatible with conservative cron planner'
 Assert-Core (([regex]::Matches($wp,"define\('[A-Z_]+(?:KEY|SALT)', '[a-f0-9]{64}'\);")).Count -eq 8) 'eight independent random salts'
 $wp2=Get-WordPrIISWpConfig $config $credential
 Assert-Core ($wp -ne $wp2) 'salt entropy fresh per fresh installation'
 $local=$config.Clone();$local.WordPressPath=Join-Path $fixture 'web';$local.PhpPath=Join-Path $fixture 'php';$local.PrivatePath=Join-Path $fixture 'private'
 $acl=@(Get-WordPrIISAclPlan $local)
 Assert-Core (@($acl|Where-Object{$_.path -eq $local.WordPressPath -and $_.rights -eq 'Modify'}).Count -eq 0) 'worker has no blanket code-write grant'
 Assert-Core (@($acl|Where-Object{$_.path -eq $local.PrivatePath -and $_.inherit}).Count -eq 0) 'worker traversal does not expose future private reports'
 Assert-Core (@($acl|Where-Object{$_.rights -eq 'Modify'}).Count -eq 4) 'only four intended data directories writable'
 $environment=@(Get-WordPrIISFastCgiEnvironment $local)
 Assert-Core ((@($environment|Where-Object{$_.name -eq 'PHPRC'})[0].value -eq $local.PhpPath) -and (@($environment|Where-Object{$_.name -eq 'PHP_INI_SCAN_DIR'})[0].value -eq (Join-Path $local.PhpPath 'conf.d'))) 'FastCGI runtime selects its own ini and scan directory'
 # Real ZIP parsing/hash/extraction including adversarial entry names.
 Add-Type -AssemblyName System.IO.Compression
 function New-FixtureZip($Path,$Name,$Content){$stream=[IO.File]::Create($Path);$zip=New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Create);try{$entry=$zip.CreateEntry($Name);$writer=New-Object IO.StreamWriter($entry.Open());try{$writer.Write($Content)}finally{$writer.Dispose()}}finally{$zip.Dispose();$stream.Dispose()}}
 $zip=Join-Path $fixture 'good.zip';New-FixtureZip $zip 'wordpress/index.php' '<?php echo 1;'
 $hash=(Get-FileHash $zip).Hash;$dest=Join-Path $fixture 'expanded';Expand-WordPrIISArtifact $zip $hash $dest 'wordpress/'
 Assert-Core ([IO.File]::ReadAllText((Join-Path $dest 'index.php')) -eq '<?php echo 1;') 'real extraction with prefix stripping'
 $failed=$false;try{Expand-WordPrIISArtifact $zip ('0'*64) (Join-Path $fixture 'wrong') 'wordpress/'}catch{$failed=$true}
 Assert-Core ($failed -and !(Test-Path (Join-Path $fixture 'wrong'))) 'hash rejection precedes destination creation'
 $failed=$false;try{Expand-WordPrIISArtifact $zip $hash $dest 'wordpress/'}catch{$failed=$true}
 Assert-Core $failed 'existing destination not overwritten'
 foreach($name in @('../escape.php','wordpress/../../escape.php','C:/escape.php','/absolute.php','wordpress/NUL.php','wordpress/ending./file.php')){
    $badZip=Join-Path $fixture 'bad.zip';New-FixtureZip $badZip $name 'bad';$failed=$false
    try{Expand-WordPrIISArtifact $badZip (Get-FileHash $badZip).Hash (Join-Path $fixture 'bad-output')}catch{$failed=$true}
    Assert-Core ($failed -and !(Test-Path (Join-Path $fixture 'bad-output'))) 'ZIP traversal rejected before extraction'
 }
 # Production dispatcher resolves standalone scripts; no native command is run by planning/import.
 . (Join-Path $PSScriptRoot '../wordpress-iis.ps1') -Action Plan -ConfigPath (Join-Path $PSScriptRoot '../config/example.json')
 Assert-Core ((Invoke-WordPrIIS).mode -eq 'plan') 'real entry-point plan works without Windows'
 foreach($action in @('Bootstrap','Audit','Profile','Cron','Diagnose','ExportConfig','Verify')){Assert-Core (Test-Path -LiteralPath (Get-WordPrIISCommand $action)) 'each dispatch resolves an existing standalone script'}
 # Secure binary inventory hashes selected known files, not entire configuration dumps.
 . (Join-Path $PSScriptRoot '../scripts/Export-Configuration.ps1')
 $null=[IO.Directory]::CreateDirectory($local.PhpPath);[IO.File]::WriteAllText((Join-Path $local.PhpPath 'php.exe'),'synthetic-binary')
 $inventory=@(Get-WordPrIISBinaryInventory $local)
 Assert-Core ($inventory[0].sha256 -eq (Get-FileHash (Join-Path $local.PhpPath 'php.exe')).Hash -and $inventory[1].status -eq 'missing') 'binary provenance hashes and missing status are accurate'
 Assert-Core (!(($inventory|ConvertTo-Json).Contains('synthetic-binary'))) 'inventory exports hashes not binary content'
 # Execute the real main dispatch against an inert standalone boundary and inspect bound flags/types.
 $ConfigPath=Join-Path $fixture 'good.json';Write-WordPrIISJson $ConfigPath $config
 $leaf=Join-Path $fixture 'leaf.ps1'
 [IO.File]::WriteAllText($leaf,@'
param($ConfigPath,[switch]$BenchmarkFileSystem,[switch]$RecordDefender,[Management.Automation.PSCredential]$TaskCredential)
@{probe=[bool]$BenchmarkFileSystem;record=[bool]$RecordDefender;credential=($null -ne $TaskCredential)} | ConvertTo-Json | Set-Content -LiteralPath ($ConfigPath+'.dispatch.json')
'@)
 function Get-WordPrIISCommand {param($Name);return $leaf}
 $Action='Profile';$BenchmarkFileSystem=$true;Invoke-WordPrIIS
 Assert-Core ((Get-Content ($ConfigPath+'.dispatch.json') -Raw|ConvertFrom-Json).probe) 'main profile flag reaches standalone boundary'
 $Action='Diagnose';$RecordDefender=$true;Invoke-WordPrIIS
 Assert-Core ((Get-Content ($ConfigPath+'.dispatch.json') -Raw|ConvertFrom-Json).record) 'main Defender flag reaches standalone boundary'
 $Action='Cron';$TaskCredential=$credential;Invoke-WordPrIIS
 Assert-Core ((Get-Content ($ConfigPath+'.dispatch.json') -Raw|ConvertFrom-Json).credential) 'main passes credential object without plaintext expansion'
 # Parse every shipped PS script, including retained operation helpers.
 foreach($file in Get-ChildItem (Join-Path $PSScriptRoot '..') -Recurse -Filter '*.ps1'){$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors);Assert-Core (!$errors.Count) ('PowerShell syntax '+$file.Name)}
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
Write-Host "WordPrIIS core: $n assertions passed."
