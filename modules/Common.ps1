#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function Read-WordPrIISConfig {
    param([string]$Path)
    try { $data = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path) | ConvertFrom-Json -ErrorAction Stop } catch { throw 'WORDPRIIS:invalid-config-json' }
    $allowed = @('SchemaVersion','SiteName','Url','WordPressPath','PhpPath','PrivatePath','AppPool','ServiceAccountName','DatabaseHost','DatabaseName','DatabaseUser','TablePrefix','CertificateThumbprint','PhpArchivePath','PhpArchiveSha256','WordPressArchivePath','WordPressArchiveSha256','UrlRewriteMsiPath','UrlRewriteMsiSha256','VcRuntimePath','VcRuntimeSha256')
    $config = @{}
    foreach ($p in $data.PSObject.Properties) {
        if ($p.Name -notin $allowed) { throw 'WORDPRIIS:unknown-or-sensitive-config-field' }
        if ($p.Name -ne 'SchemaVersion' -and $p.Value -isnot [string]) { throw 'WORDPRIIS:config-value-type' }
        if ([string]$p.Value -match '[\x00-\x1f"`]' -or [string]$p.Value -match '\$\(') { throw 'WORDPRIIS:unsafe-config-value' }
        $config[$p.Name] = $p.Value
    }
    if (($config.SchemaVersion -isnot [int] -and $config.SchemaVersion -isnot [long]) -or $config.SchemaVersion -ne 1) { throw 'WORDPRIIS:config-schema' }
    foreach ($key in @('SiteName','AppPool','ServiceAccountName','DatabaseName','DatabaseUser','TablePrefix')) {
        if (!$config.ContainsKey($key) -or $config[$key] -notmatch '^[a-zA-Z0-9_ .-]{1,80}$') { throw ('WORDPRIIS:invalid-'+$key) }
    }
    if ($config.TablePrefix -notmatch '^[a-zA-Z0-9_]+$') { throw 'WORDPRIIS:table-prefix' }
    $url = $null
    if (![uri]::TryCreate($config.Url,[UriKind]::Absolute,[ref]$url) -or $url.Scheme -ne 'https' -or $url.UserInfo -or $url.Query -or $url.Fragment -or $url.AbsolutePath -ne '/') { throw 'WORDPRIIS:https-site-root-required' }
    if ($config.DatabaseHost -notmatch '^[a-zA-Z0-9.-]{1,253}$') { throw 'WORDPRIIS:database-host' }
    foreach ($key in @('WordPressPath','PhpPath','PrivatePath')) {
        if ($config[$key] -notmatch '^[a-zA-Z]:\\[^<>|?*]+$' -or $config[$key] -match '(?:^|[\\/])\.\.?(?:[\\/]|$)' -or $config[$key].Contains("'")) { throw ('WORDPRIIS:invalid-'+$key) }
        $config[$key] = $config[$key].TrimEnd('\')
    }
    foreach ($pair in @(@('PrivatePath','WordPressPath'),@('PhpPath','WordPressPath'),@('PrivatePath','PhpPath'))) {
        $a=$config[$pair[0]].TrimEnd('\')+'\';$b=$config[$pair[1]].TrimEnd('\')+'\'
        if ($a.StartsWith($b,[StringComparison]::OrdinalIgnoreCase) -or $b.StartsWith($a,[StringComparison]::OrdinalIgnoreCase)) { throw 'WORDPRIIS:overlapping-directories' }
    }
    foreach ($key in @('PhpArchiveSha256','WordPressArchiveSha256','UrlRewriteMsiSha256','VcRuntimeSha256')) {
        if ($config.ContainsKey($key) -and $config[$key] -and $config[$key] -notmatch '^[a-fA-F0-9]{64}$') { throw 'WORDPRIIS:artifact-hash' }
    }
    return $config
}
function Assert-WordPrIISWindows {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or ![Environment]::Is64BitProcess) { throw 'WORDPRIIS:windows-64bit-required' }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if (!(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'WORDPRIIS:administrator-required' }
}
function Write-WordPrIISJson {
    param([string]$Path,$Value)
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 24),(New-Object Text.UTF8Encoding($false)))
}
function Assert-WordPrIISPlainPath {
    param([string]$Path)
    if ($Path -match '[\x00-\x1f"`]' -or $Path.Contains('$(') -or $Path.StartsWith('\\')) { throw 'WORDPRIIS:unsafe-path' }
    $item=[IO.Path]::GetFullPath($Path)
    while ($item) {
        if ((Test-Path -LiteralPath $item) -and ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'WORDPRIIS:reparse-path' }
        $parent=[IO.Directory]::GetParent($item);$item=if($parent){$parent.FullName}else{$null}
    }
}
function Set-WordPrIISPrivateAcl {
    param([string]$Path,[switch]$Directory)
    $acl=if($Directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
    $acl.SetAccessRuleProtection($true,$false)
    $inherit=if($Directory){'ContainerInherit,ObjectInherit'}else{'None'}
    foreach($sid in @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)|Select-Object -Unique){
        $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl',$inherit,'None','Allow');$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function New-WordPrIISReportDirectory {
    param([hashtable]$Config,[string]$Purpose)
    Assert-WordPrIISWindows
    Assert-WordPrIISPlainPath $Config.PrivatePath
    # Refuse a private location served by ANY IIS virtual directory, not just this WordPress root.
    $iisAssembly=Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
    if(Test-Path -LiteralPath $iisAssembly){
    Add-Type -Path $iisAssembly
    $manager=New-Object Microsoft.Web.Administration.ServerManager
    try {
        foreach($site in $manager.Sites){foreach($app in $site.Applications){foreach($v in $app.VirtualDirectories){
            $root=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($v.PhysicalPath)).TrimEnd('\')+'\'
            $candidate=[IO.Path]::GetFullPath($Config.PrivatePath).TrimEnd('\')+'\'
            if($candidate.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){throw 'WORDPRIIS:private-path-served-by-iis'}
        }}}
    } finally {$manager.Dispose()}
    }
    if(!(Test-Path -LiteralPath $Config.PrivatePath)){$null=New-Item -ItemType Directory -Path $Config.PrivatePath;Set-WordPrIISPrivateAcl $Config.PrivatePath -Directory}
    $broadSids=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546')
    $unsafe=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach($rule in (Get-Acl -LiteralPath $Config.PrivatePath).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -in $broadSids -and ($rule.FileSystemRights -band $unsafe)) { throw 'WORDPRIIS:private-parent-broad-write-access' }
    }
    $path=Join-Path $Config.PrivatePath ($Purpose+'-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $path;Set-WordPrIISPrivateAcl $path -Directory
    return $path
}
function Get-WordPrIISPlan {
    param([hashtable]$Config)
    [pscustomobject]@{schema_version=1;mode='plan';site=$Config.SiteName;url=$Config.Url;steps=@('Verify pinned local artifacts and prerequisites','Install IIS CGI and explicit prerequisite packages','Install isolated PHP NTS x64 and generated php.ini','Verify an existing EMPTY database with supplied PSCredential','Extract WordPress to a NEW root and generate private wp-config.php','Create a NEW dedicated IIS pool/site and HTTPS binding','Apply narrow code/data ACLs and retain a private bootstrap journal');changes_existing_site=$false;database_installation='Existing managed MySQL/MariaDB required; no root credential or database installer';cron='Separate verified Cron action; DISABLE_WP_CRON stays false until proof';firewall='Unchanged; preserve ZeroTier/RDP management policy';settings=$Config}
}

function Assert-WordPrIISLocalDatabase {
    param([hashtable]$Config)
    if($Config.DatabaseHost -notin @('127.0.0.1','localhost')){throw 'WORDPRIIS:bootstrap-requires-loopback-database'}
}
