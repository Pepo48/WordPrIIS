# Pure renderers: never read host configuration or execute PHP/IIS.
function ConvertTo-WordPrIISPhpLiteral {
    param([string]$Value)
    return "'"+$Value.Replace('\','\\').Replace("'","\'")+"'"
}
function Get-WordPrIISPhpIni {
    param([hashtable]$Config)
    $php=$Config.PhpPath.Replace('\','/');$web=$Config.WordPressPath.Replace('\','/');$private=$Config.PrivatePath.Replace('\','/')
    $cacheId=($Config.SiteName -replace '[^a-zA-Z0-9_-]','_')
    return @"
; WordPrIIS managed fresh-install profile. Change only with measured staging evidence.
[PHP]
engine=On
expose_php=Off
display_errors=Off
log_errors=On
error_log="$private/php-data/php-error.log"
extension_dir="$php/ext"
extension=mysqli
extension=pdo_mysql
extension=mbstring
extension=openssl
extension=curl
extension=fileinfo
extension=gd
extension=intl
extension=zip
memory_limit=256M
max_execution_time=120
upload_max_filesize=32M
post_max_size=40M
date.timezone=UTC
cgi.fix_pathinfo=0
fastcgi.impersonate=0
open_basedir="$web;$private;C:/Windows/Temp"
upload_tmp_dir="$private/php-data/tmp"
session.save_path="$private/php-data/sessions"
session.cookie_httponly=1
session.cookie_secure=1
session.cookie_samesite=Lax
[opcache]
zend_extension=php_opcache.dll
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=256
opcache.interned_strings_buffer=32
opcache.max_accelerated_files=20000
opcache.validate_timestamps=1
opcache.revalidate_freq=60
opcache.save_comments=1
opcache.jit=disable
opcache.jit_buffer_size=0
opcache.file_cache="$private/php-data/opcache"
opcache.file_cache_fallback=1
opcache.cache_id=$cacheId
; open_basedir disables realpath caching. Do not claim a larger realpath cache fixes it.
"@
}
function Get-WordPrIISWebConfig {
    # Successful static responses get a long TTL; dynamic errors override it when the module runs.
    # Pre-pipeline errors still need direct-origin/edge verification.
    return @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <directoryBrowse enabled="false" />
    <defaultDocument><files><remove value="index.php" /><add value="index.php" /></files></defaultDocument>
    <httpErrors existingResponse="PassThrough" />
    <httpProtocol><customHeaders>
      <remove name="Cache-Control" />
      <remove name="X-Powered-By" />
      <remove name="X-Content-Type-Options" /><add name="X-Content-Type-Options" value="nosniff" />
      <remove name="Referrer-Policy" /><add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
    </customHeaders></httpProtocol>
    <staticContent><clientCache cacheControlMode="UseMaxAge" cacheControlMaxAge="30.00:00:00" /></staticContent>
    <security><requestFiltering>
      <hiddenSegments>
        <remove segment=".git" /><add segment=".git" />
        <remove segment=".env" /><add segment=".env" />
      </hiddenSegments>
      <denyUrlSequences><remove sequence=".env" /><add sequence=".env" /></denyUrlSequences>
      <fileExtensions>
        <remove fileExtension=".log" /><add fileExtension=".log" allowed="false" />
        <remove fileExtension=".sql" /><add fileExtension=".sql" allowed="false" />
      </fileExtensions>
    </requestFiltering></security>
    <rewrite>
      <rules>
        <rule name="WordPrIIS protect configuration" stopProcessing="true">
          <match url="^(wp-config\.php|readme\.html|license\.txt)$" ignoreCase="true" />
          <action type="CustomResponse" statusCode="404" statusReason="Not Found" statusDescription="Not Found" />
        </rule>
        <rule name="WordPress permalinks" stopProcessing="true">
          <match url=".*" /><conditions logicalGrouping="MatchAll">
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
            <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
          </conditions><action type="Rewrite" url="index.php" />
        </rule>
      </rules>
      <outboundRules rewriteBeforeCache="true">
        <rule name="WordPrIIS 5xx no-store" preCondition="WordPrIIS error status">
          <match serverVariable="RESPONSE_Cache_Control" pattern=".*" /><action type="Rewrite" value="no-store" />
        </rule>
        <preConditions><preCondition name="WordPrIIS error status"><add input="{RESPONSE_STATUS}" pattern="^5[0-9][0-9](?:\s|$)" /></preCondition></preConditions>
      </outboundRules>
    </rewrite>
  </system.webServer>
  <location path="wp-content/uploads" overrideMode="Deny"><system.webServer><handlers accessPolicy="Read" /></system.webServer></location>
</configuration>
'@
}
function Get-WordPrIISWpConfig {
    param([hashtable]$Config,[Management.Automation.PSCredential]$DatabaseCredential)
    if(!$DatabaseCredential -or $DatabaseCredential.UserName -cne $Config.DatabaseUser){throw 'WORDPRIIS:database-credential-mismatch'}
    $password=$null
    try {
        $password=$DatabaseCredential.GetNetworkCredential().Password
        $lines=New-Object Collections.Generic.List[string]
        $lines.Add('<?php');$lines.Add('// Generated by WordPrIIS. Contains secrets; never add to source control.')
        foreach($pair in @(@('DB_NAME',$Config.DatabaseName),@('DB_USER',$Config.DatabaseUser),@('DB_PASSWORD',$password),@('DB_HOST',$Config.DatabaseHost),@('DB_CHARSET','utf8mb4'),@('DB_COLLATE',''))){$lines.Add("define('"+$pair[0]+"', "+(ConvertTo-WordPrIISPhpLiteral $pair[1])+");")}
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try { foreach($name in @('AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT')){
            $bytes=New-Object byte[] 32;$rng.GetBytes($bytes);$salt=[BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant();$lines.Add("define('$name', '$salt');")
        }}finally{$rng.Dispose()}
        $lines.Add("`$table_prefix = "+(ConvertTo-WordPrIISPhpLiteral $Config.TablePrefix)+";")
        $lines.Add("define('DISALLOW_FILE_EDIT', true);")
        $lines.Add("define('DISABLE_WP_CRON', false);")
        $lines.Add("define('WP_DEBUG', false);")
        $lines.Add("define('WP_ENVIRONMENT_TYPE', 'production');")
        $lines.Add("if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }")
        $lines.Add("require_once ABSPATH . 'wp-settings.php';")
        return ($lines -join "`n")+"`n"
    }finally{$password=$null}
}
