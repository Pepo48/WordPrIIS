<#
================================== WordPress ===================================
This module downloads and configures WordPress, sets up the IIS website,
and prepares the WordPress installation.
#>

"`r`nWordPress..."
# Check if WordPress is already installed
if (-not (Test-ComponentInstalled -Name "WordPress" -TestScript {
    Test-Path -Path "$wordpressPath\wp-config.php"
})) {
    "Installing WordPress..."
    # Download and extract WordPress
    $wordpressUrl = "https://wordpress.org/latest.zip"
    $wordpressZip = "wordpress.zip"

    Invoke-WebRequest $wordpressUrl -OutFile $wordpressZip
    Expand-Archive $wordpressZip -DestinationPath $iisPath

    # Set permissions on WordPress directory
    icacls "$wordpressPath" /grant "IUSR:(OI)(CI)(M)" /grant "IIS_IUSRS:(OI)(CI)(M)" /T

    # Create wp-config.php file with database credentials and improved security settings
    $wpConfig = @"
<?php
/**
 * WordPress Configuration File
 * Generated on $(Get-Date)
 */

// Database settings
define('DB_NAME', 'wordpress');
define('DB_USER', 'wordpress');
define('DB_PASSWORD', '$mysqlWordPressPwd');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

// Authentication unique keys and salts
define('AUTH_KEY',         '$(New-Guid)');
define('SECURE_AUTH_KEY',  '$(New-Guid)');
define('LOGGED_IN_KEY',    '$(New-Guid)');
define('NONCE_KEY',        '$(New-Guid)');
define('AUTH_SALT',        '$(New-Guid)');
define('SECURE_AUTH_SALT', '$(New-Guid)');
define('LOGGED_IN_SALT',   '$(New-Guid)');
define('NONCE_SALT',       '$(New-Guid)');

// WordPress database table prefix
\$table_prefix = 'wp_';

// WordPress debugging mode
define('WP_DEBUG', false);

// Limit the number of post revisions
define('WP_POST_REVISIONS', 3);

// Auto-save interval
define('AUTOSAVE_INTERVAL', 300);

// Disable file editing from admin
define('DISALLOW_FILE_EDIT', true);

// Disable core auto-updates
define('WP_AUTO_UPDATE_CORE', false);

// Set WordPress memory limit
define('WP_MEMORY_LIMIT', '$($config.MemoryLimit)');
define('WP_MAX_MEMORY_LIMIT', '$($config.MemoryLimit)');

/* That's all, stop editing! */
if ( !defined('ABSPATH') )
    define('ABSPATH', dirname(__FILE__) . '/');

require_once(ABSPATH . 'wp-settings.php');
"@
    Set-Content -Path "$wordpressPath\wp-config.php" -Value $wpConfig

    # Create a .htaccess file for WordPress with proper rewrite rules
    $htaccess = @"
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"@
    Set-Content -Path "$wordpressPath\.htaccess" -Value $htaccess

    # Create web.config for IIS with improved security settings
    $webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="WordPress Rule" stopProcessing="true">
                    <match url=".*" />
                    <conditions>
                        <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
                        <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
                    </conditions>
                    <action type="Rewrite" url="index.php" />
                </rule>
            </rules>
        </rewrite>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="$([int]($config.MaxUploadSize.TrimEnd('M')) * 1024 * 1024)" />
            </requestFiltering>
        </security>
        <defaultDocument>
            <files>
                <clear />
                <add value="index.php" />
                <add value="index.html" />
            </files>
        </defaultDocument>
        <staticContent>
            <mimeMap fileExtension=".webp" mimeType="image/webp" />
        </staticContent>
    </system.webServer>
</configuration>
"@
    Set-Content -Path "$wordpressPath\web.config" -Value $webConfig
    "Created web.config file for WordPress."
} else {
    # Check if web.config exists, create it if missing
    if (-not (Test-Path -Path "$wordpressPath\web.config")) {
        "Creating missing web.config file..."
        $webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="WordPress Rule" stopProcessing="true">
                    <match url=".*" />
                    <conditions>
                        <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
                        <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
                    </conditions>
                    <action type="Rewrite" url="index.php" />
                </rule>
            </rules>
        </rewrite>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="$([int]($config.MaxUploadSize.TrimEnd('M')) * 1024 * 1024)" />
            </requestFiltering>
        </security>
        <defaultDocument>
            <files>
                <clear />
                <add value="index.php" />
                <add value="index.html" />
            </files>
        </defaultDocument>
        <staticContent>
            <mimeMap fileExtension=".webp" mimeType="image/webp" />
        </staticContent>
    </system.webServer>
</configuration>
"@
        Set-Content -Path "$wordpressPath\web.config" -Value $webConfig
        "Created web.config file for WordPress."
    }
    "✓ WordPress is already installed at $wordpressPath."
}

# Import WebAdministration module safely
$webAdminAvailable = Import-WebAdministrationModule

# Only proceed with website checks if module is available
if ($webAdminAvailable) {
    # Check if WordPress website is configured in IIS
    if (-not (Test-ComponentInstalled -Name "WordPress Website" -TestScript {
        $site = Get-Website -Name $config.SiteName -ErrorAction SilentlyContinue
        $null -ne $site
    })) {
        "Creating WordPress website in IIS..."
        # Create application pool if it doesn't exist
        if (-not (Test-Path "IIS:\AppPools\WordPress")) {
            New-WebAppPool -Name "WordPress" | Out-Null
            Set-ItemProperty "IIS:\AppPools\WordPress" managedRuntimeVersion ""
            Set-ItemProperty "IIS:\AppPools\WordPress" managedPipelineMode 0
        }

        # Create and configure the website with specified port
        # First check if Default Web Site exists and hasn't been replaced yet
        if (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue) {
            Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
        }
        
        # Create WordPress website if it doesn't exist
        if (-not (Get-Website -Name $config.SiteName -ErrorAction SilentlyContinue)) {
            New-Website -Name $config.SiteName -PhysicalPath $wordpressPath -ApplicationPool "WordPress" -Port $config.SitePort | Out-Null
        }
        
        # Make sure the site is started
        if ((Get-Website -Name $config.SiteName).State -ne "Started") {
            Start-Website -Name $config.SiteName
        }
        
        "WordPress website configured in IIS."
    } else {
        "✓ WordPress website is already configured in IIS."
    }
} else {
    "WARNING: WebAdministration module could not be loaded. WordPress setup will be limited."
    "Please ensure IIS is installed and you're running as Administrator."
}
