<#
================================================================================
===== WordPress Installation Script for Windows Server 2022 =================
================================================================================
This script automates the installation of WordPress on Windows Server 2022
with IIS, PHP, and MySQL.
#>

<#
============================ Script Configuration =============================
You can customize these variables to match your requirements
#>

# Script configuration parameters
$config = @{
    # WordPress site details
    SiteName = "WordPress"
    SitePort = 80
    # Domain configuration
    Domain = ""  # Empty string = use IP address, otherwise set domain name
    UseHTTPS = $true  # Set to true to configure HTTPS
    EmailAddress = "admin@example.com"  # Used for Let's Encrypt
    # Security settings
    ConfigureFirewall = $true
    RestrictWPAdmin = $true
    AllowedIPsForAdmin = @("192.168.1.0/24")  # List of allowed IPs/networks for admin
    FirewallDefaultDeny = $false  # If true, block all traffic except allowed ports (CAUTION: can block remote access)
    # Development/Production toggle
    DevelopmentMode = $true  # true = more lenient settings, false = stricter production settings
    # Hosts file configuration
    ModifyHostsFile = $false  # Whether to update hosts file for local development
    # Backup configuration
    ConfigureBackups = $true
    BackupSchedule = "Daily"  # Daily, Weekly, Monthly
    BackupRetention = 7  # Number of backups to keep
    BackupPath = "$env:SystemDrive\WordPressBackups"
    # MySQL settings
    MySQLVersion = "8.4.4"  # MySQL version
    MySQLRootPwdLength = 20
    MySQLUserPwdLength = 20
    # PHP settings
    PHPVersion = "8.4.5"  # PHP version
    PHPSha256 = "6fd0e9131c242e71a4975a67395c33ac5dab221811ad980c78dfd197f6ead4a7"  # SHA256 for PHP download validation
    MaxUploadSize = "20M"
    MemoryLimit = "256M"
    # Win-acme settings
    WinAcmeVersion = "2.2.9.1701"  # Win-acme version
    # Remote access protection
    PreventRDPLockout = $true  # Prevents firewall from blocking RDP
    RDPPort = 3389  # Default RDP port
    # Paths
    DownloadPath = "$env:USERPROFILE\Downloads"
    LogPath = "$env:TEMP\wp_install_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}

# Start logging
Start-Transcript -Path $config.LogPath -Append

# Display script header
"`r`nWordPress Installation Script for Windows Server 2022"
"===================================================================="
"Installation started at: $(Get-Date)"
"Log file: $($config.LogPath)"
"===================================================================="

# Set working directory to Downloads folder
Set-Location $config.DownloadPath

# Add a function to check if a component is already installed
function Test-ComponentInstalled {
    param (
        [string]$Name,
        [scriptblock]$TestScript
    )
    
    "Checking if $Name is already installed..."
    $installed = & $TestScript
    
    if ($installed) {
        "✓ $Name is already installed. Skipping installation."
        return $true
    } else {
        "○ $Name needs to be installed."
        return $false
    }
}

<#
======================== Interactive Configuration ===========================
This section allows for interactive configuration of the installation script
#>

if (-not $PSBoundParameters.ContainsKey('NonInteractive')) {
    "`r`nWordPress Installation - Interactive Configuration"
    "======================================================================"
    "You can customize the installation or proceed with default values."
    "Press Enter to accept the default value shown in [brackets]."
    
    # Function to prompt for yes/no values
    function Get-YesNoResponse {
        param (
            [string]$Prompt,
            [bool]$Default = $true
        )
        
        $defaultChoice = if ($Default) { "Y" } else { "N" }
        $prompt = "$Prompt [$(if($Default){'Y/n'}else{'y/N'})]"
        
        do {
            $response = Read-Host -Prompt $prompt
            if ([string]::IsNullOrWhiteSpace($response)) {
                $response = $defaultChoice
            }
        } until ($response -match '^[yn]$')
        
        return $response -eq 'y'
    }
    
    # Prompt for key configuration options
    "`r`nSite Configuration:"
    $siteName = Read-Host -Prompt "Site name [$($config.SiteName)]"
    if (-not [string]::IsNullOrWhiteSpace($siteName)) { $config.SiteName = $siteName }
    
    $sitePort = Read-Host -Prompt "HTTP port [$($config.SitePort)]"
    if (-not [string]::IsNullOrWhiteSpace($sitePort)) { $config.SitePort = [int]$sitePort }
    
    $domain = Read-Host -Prompt "Domain name (leave empty to use IP address) [$($config.Domain)]"
    if (-not [string]::IsNullOrWhiteSpace($domain)) { $config.Domain = $domain }
    
    if (-not [string]::IsNullOrWhiteSpace($config.Domain)) {
        $config.UseHTTPS = Get-YesNoResponse -Prompt "Configure HTTPS with Let's Encrypt?" -Default $config.UseHTTPS
        
        if ($config.UseHTTPS) {
            $email = Read-Host -Prompt "Email address for Let's Encrypt [$($config.EmailAddress)]"
            if (-not [string]::IsNullOrWhiteSpace($email)) { $config.EmailAddress = $email }
        }
        
        if ($config.Domain -ne "localhost" -and $config.Domain -notmatch "^([\d]{1,3}\.){3}[\d]{1,3}$") {
            $config.ModifyHostsFile = Get-YesNoResponse -Prompt "Add entry to hosts file for local development?" -Default $config.ModifyHostsFile
        }
    }
    
    "`r`nSecurity Configuration:"
    $config.ConfigureFirewall = Get-YesNoResponse -Prompt "Configure Windows Firewall?" -Default $config.ConfigureFirewall
    
    if ($config.ConfigureFirewall) {
        $config.FirewallDefaultDeny = Get-YesNoResponse -Prompt "Block all inbound traffic except allowed ports? (CAUTION: may break remote administration)" -Default $config.FirewallDefaultDeny
        
        if ($config.FirewallDefaultDeny) {
            $config.PreventRDPLockout = Get-YesNoResponse -Prompt "Prevent RDP lockout (recommended)?" -Default $config.PreventRDPLockout
            
            if ($config.PreventRDPLockout) {
                $rdpPort = Read-Host -Prompt "RDP port [$($config.RDPPort)]"
                if (-not [string]::IsNullOrWhiteSpace($rdpPort)) { $config.RDPPort = [int]$rdpPort }
            }
        }
    }
    
    $config.RestrictWPAdmin = Get-YesNoResponse -Prompt "Restrict wp-admin access by IP address?" -Default $config.RestrictWPAdmin
    
    if ($config.RestrictWPAdmin) {
        $ips = Read-Host -Prompt "Allowed IPs for wp-admin (comma separated, e.g. 192.168.1.0/24,10.0.0.5) [$($config.AllowedIPsForAdmin -join ',')]"
        if (-not [string]::IsNullOrWhiteSpace($ips)) { $config.AllowedIPsForAdmin = $ips -split ',' | ForEach-Object { $_.Trim() } }
    }
    
    "`r`nEnvironment Configuration:"
    $config.DevelopmentMode = Get-YesNoResponse -Prompt "Enable development mode? (less strict security)" -Default $config.DevelopmentMode
    
    "`r`nBackup Configuration:"
    $config.ConfigureBackups = Get-YesNoResponse -Prompt "Configure automated backups?" -Default $config.ConfigureBackups
    
    if ($config.ConfigureBackups) {
        $schedules = @('Daily', 'Weekly', 'Monthly')
        $schedulePrompt = "Backup schedule ($(($schedules | ForEach-Object { if ($_ -eq $config.BackupSchedule) { "$($_.ToUpper())" } else { $_.ToLower() } }) -join '/'))"
        
        do {
            $schedule = Read-Host -Prompt $schedulePrompt
            if ([string]::IsNullOrWhiteSpace($schedule)) { $schedule = $config.BackupSchedule }
        } until ([string]::IsNullOrWhiteSpace($schedule) -or $schedules -contains $schedule)
        
        $config.BackupSchedule = $schedule
        
        $retention = Read-Host -Prompt "Number of backups to retain [$($config.BackupRetention)]"
        if (-not [string]::IsNullOrWhiteSpace($retention)) { $config.BackupRetention = [int]$retention }
        
        $backupPath = Read-Host -Prompt "Backup storage path [$($config.BackupPath)]"
        if (-not [string]::IsNullOrWhiteSpace($backupPath)) { $config.BackupPath = $backupPath }
    }
    
    "`r`nAdvanced Settings:"
    $showAdvanced = Get-YesNoResponse -Prompt "Configure advanced settings?" -Default $false
    
    if ($showAdvanced) {
        # MySQL Advanced Settings
        $mysqlVersion = Read-Host -Prompt "MySQL version [$($config.MySQLVersion)]"
        if (-not [string]::IsNullOrWhiteSpace($mysqlVersion)) { $config.MySQLVersion = $mysqlVersion }
        
        # PHP Advanced Settings
        $phpVersion = Read-Host -Prompt "PHP version [$($config.PHPVersion)]"
        if (-not [string]::IsNullOrWhiteSpace($phpVersion)) { 
            $config.PHPVersion = $phpVersion
            "Warning: Changing PHP version requires manually updating the SHA256 hash."
            $updateHash = Get-YesNoResponse -Prompt "Update PHP SHA256 hash?" -Default $true
            if ($updateHash) {
                $phpHash = Read-Host -Prompt "PHP SHA256 hash (for download validation)"
                if (-not [string]::IsNullOrWhiteSpace($phpHash)) { $config.PHPSha256 = $phpHash }
            }
        }
        
        # Win-acme Advanced Settings
        $winAcmeVersion = Read-Host -Prompt "Win-acme version [$($config.WinAcmeVersion)]"
        if (-not [string]::IsNullOrWhiteSpace($winAcmeVersion)) { $config.WinAcmeVersion = $winAcmeVersion }
    }
    
    "`r`nConfiguration complete. Proceeding with installation..."
}

<#
======================== Internet Information Services =========================
This section installs and configures IIS (Internet Information Services)
which is the web server that will host the WordPress site.
#>

"`r`nInternet Information Server (IIS)..."
# Check if IIS is already installed
if (-not (Test-ComponentInstalled -Name "IIS" -TestScript { 
    (Get-WindowsFeature Web-Server).Installed -eq $true
})) {
    "Installing required IIS features for hosting WordPress..."
    Install-WindowsFeature -Name Web-Server, Web-Common-Http, Web-Static-Content, Web-Default-Doc, 
        Web-Dir-Browsing, Web-Http-Errors, Web-App-Dev, Web-CGI, Web-Health, 
        Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Security, 
        Web-Filtering, Web-Performance, Web-Stat-Compression, Web-Mgmt-Tools, 
        Web-Mgmt-Service, WAS, WAS-Process-Model, WAS-NET-Environment, 
        WAS-Config-APIs, Net-Framework-Core -IncludeManagementTools | Out-Null
    "IIS Installation Complete."
}

# Enable IIS Remote Management Service if not already enabled
if (-not (Test-ComponentInstalled -Name "IIS Remote Management" -TestScript {
    $prop = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -ErrorAction SilentlyContinue
    $prop -and $prop.EnableRemoteManagement -eq 1
})) {
    "Enabling IIS Remote Management..."
    Set-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server EnableRemoteManagement 1
    Set-Service WMSVC -StartupType Automatic
    Start-Service WMSVC
    "IIS Remote Management Enabled."
}

<#
======================== URL Rewrite Module for IIS ===========================
This installs the URL Rewrite module required for WordPress permalinks.
#>

"`r`nURL Rewrite Extension for IIS..."
# Check if URL Rewrite is already installed
if (-not (Test-ComponentInstalled -Name "URL Rewrite Module" -TestScript {
    $rewriteModule = Get-WebGlobalModule -Name "RewriteModule" -ErrorAction SilentlyContinue
    $null -ne $rewriteModule
})) {
    "Installing URL Rewrite 2.1 module..."
    $rewriteUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
    $rewriteInstaller = "rewrite_amd64.msi"
    Invoke-WebRequest $rewriteUrl -OutFile $rewriteInstaller -ErrorAction Stop
    Start-Process "msiexec.exe" "/i $rewriteInstaller /qn" -Wait -NoNewWindow
    "URL Rewrite Installation Complete."
}

<#
========================== Visual C++ Redistributables ========================
These are prerequisites for PHP and MySQL to work properly on Windows.
#>

"`r`nVisual C++ Redistributables..."
# Check if Visual C++ Redistributable is already installed
if (-not (Test-ComponentInstalled -Name "Visual C++ Redistributable 2015-2022" -TestScript {
    Get-WmiObject -Class Win32_Product | Where-Object { 
        $_.Name -like "Microsoft Visual C++ 2015-2022*" -and $_.Name -like "*x64*" 
    }
})) {
    "Installing Visual C++ 2015-2022 Redistributable..."
    $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $vcRedistInstaller = "vc_redist_2022_x64.exe"
    Invoke-WebRequest $vcRedistUrl -OutFile $vcRedistInstaller -ErrorAction Stop
    Start-Process $vcRedistInstaller "/quiet /norestart" -Wait -NoNewWindow
    "Visual C++ Redistributable Installation Complete."
}

<#
================================= MySQL Server =================================
This section installs MySQL Server, creates a database for WordPress,
and configures the necessary user accounts.
#>

"`r`nMySQL Server..."
# Check if MySQL is already installed
if (-not (Test-ComponentInstalled -Name "MySQL Server" -TestScript {
    $service = Get-Service -Name "MySQL" -ErrorAction SilentlyContinue
    $null -ne $service
})) {
    "Installing MySQL Server $($config.MySQLVersion)..."
    # Set MySQL variables
    $mysqlVersion = $config.MySQLVersion
    $mysqlPath = "$env:ProgramFiles\MySQL"
    $mysqlDataPath = "$env:ProgramData\MySQL\data"
    $mysqlServerPath = "$mysqlPath\MySQL Server 8.4"  # Updated to 8.4
    $mysqlInstallerUrl = "https://dev.mysql.com/get/Downloads/MySQL-8.4/mysql-$mysqlVersion-winx64.zip"  # Updated URL
    $mysqlZip = "mysql-$mysqlVersion-winx64.zip"

    # Download and extract MySQL
    Invoke-WebRequest $mysqlInstallerUrl -OutFile $mysqlZip
    New-Item -Path $mysqlPath -ItemType Directory -Force | Out-Null
    Expand-Archive $mysqlZip -DestinationPath $mysqlPath
    Rename-Item "$mysqlPath\mysql-$mysqlVersion-winx64" "$mysqlServerPath"

    # Create data directory
    New-Item -Path $mysqlDataPath -ItemType Directory -Force | Out-Null

    # Create MySQL configuration file
    $myIniContent = @"
[mysqld]
basedir="$mysqlServerPath"
datadir="$mysqlDataPath"
port=3306
default-authentication-plugin=mysql_native_password
explicit_defaults_for_timestamp=1

[client]
port=3306
"@
    Set-Content -Path "$mysqlServerPath\my.ini" -Value $myIniContent

    # Add MySQL bin directory to system path
    $env:Path += ";$mysqlServerPath\bin"
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)

    # Initialize MySQL
    & "$mysqlServerPath\bin\mysqld" --initialize-insecure --console

    # Install MySQL as a Windows service
    & "$mysqlServerPath\bin\mysqld" --install

    # Start MySQL service
    Start-Service MySQL

    # Generate random strong passwords
    Add-Type -AssemblyName System.Web
    $mysqlRootPwd = [System.Web.Security.Membership]::GeneratePassword($config.MySQLRootPwdLength, 5)
    $mysqlWordPressPwd = [System.Web.Security.Membership]::GeneratePassword($config.MySQLUserPwdLength, 5)

    # Configure MySQL: set root password, create WordPress database and user
    $mysqlInit = @"
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysqlRootPwd';
CREATE DATABASE wordpress;
CREATE USER 'wordpress'@'localhost' IDENTIFIED BY '$mysqlWordPressPwd';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpress'@'localhost';
FLUSH PRIVILEGES;
"@
    $mysqlInitFile = "$env:TEMP\mysql-init.sql"
    Set-Content -Path $mysqlInitFile -Value $mysqlInit
    & "$mysqlServerPath\bin\mysql" --user=root --execute="source $mysqlInitFile"
    Remove-Item $mysqlInitFile
    "MySQL Installation Complete."
} else {
    # If MySQL is already installed, check for WordPress database
    "Checking if WordPress database exists..."
    $mysqlServerPath = "$env:ProgramFiles\MySQL\MySQL Server 8.4"  # Updated to 8.4
    
    if ((Test-Path -Path "$mysqlServerPath\bin\mysql.exe")) {
        $mysqlCheck = & "$mysqlServerPath\bin\mysql" "--user=root" "--execute=SHOW DATABASES LIKE 'wordpress';" 2>$null
        if ($mysqlCheck -match "wordpress") {
            "✓ WordPress database already exists."
        } else {
            "Creating WordPress database and user..."
            # Generate random strong passwords if not already defined
            if (-not $mysqlWordPressPwd) {
                Add-Type -AssemblyName System.Web
                $mysqlWordPressPwd = [System.Web.Security.Membership]::GeneratePassword($config.MySQLUserPwdLength, 5)
            }
            
            # Ask for root password if needed
            if (-not $mysqlRootPwd) {
                $secureRootPwd = Read-Host "Enter MySQL root password" -AsSecureString
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureRootPwd)
                $mysqlRootPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
            
            # Create WordPress database and user
            $mysqlInit = @"
CREATE DATABASE IF NOT EXISTS wordpress;
CREATE USER IF NOT EXISTS 'wordpress'@'localhost' IDENTIFIED BY '$mysqlWordPressPwd';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpress'@'localhost';
FLUSH PRIVILEGES;
"@
            $mysqlInitFile = "$env:TEMP\mysql-init.sql"
            Set-Content -Path $mysqlInitFile -Value $mysqlInit
            & "$mysqlServerPath\bin\mysql" "--user=root" "--password=$mysqlRootPwd" "--execute=source $mysqlInitFile"
            Remove-Item $mysqlInitFile
            "WordPress database configured."
        }
    }
}

<#
=================================== PHP 8.4 ===================================
This section installs and configures PHP 8.4, which is required to run WordPress.
#>

"`r`nPHP 8.4..."
# Check if PHP is already installed
if (-not (Test-ComponentInstalled -Name "PHP" -TestScript {
    Test-Path -Path "$env:ProgramFiles\PHP\v8.4\php.exe"
})) {
    "Installing PHP $($config.PHPVersion)..."
    # Set PHP variables
    $phpVersion = $config.PHPVersion
    $phpPath = "$env:ProgramFiles\PHP\v8.4"
    $phpDataPath = "$env:ProgramData\PHP\v8.4"
    # Use Non-Thread Safe (NTS) version explicitly as recommended for IIS with FastCGI
    $phpZip = "php-$phpVersion-nts-Win32-vs16-x64.zip"
    $phpUrl = "https://windows.php.net/downloads/releases/$phpZip"
    # Expected SHA256 hash from configuration
    $phpSha256 = $config.PHPSha256

    # Download PHP
    "Downloading PHP $phpVersion (NTS version for IIS FastCGI)..."
    Invoke-WebRequest $phpUrl -OutFile $phpZip

    # Verify SHA256 hash of the downloaded file
    "Verifying PHP download integrity..."
    $downloadedHash = (Get-FileHash -Path $phpZip -Algorithm SHA256).Hash
    if ($downloadedHash -ne $phpSha256) {
        Write-Error "PHP download validation failed! Expected: $phpSha256, Actual: $downloadedHash"
        "Security warning: Downloaded PHP file has an invalid checksum. Installation aborted."
        "Please verify the correct PHP version and download URL, then try again."
        Stop-Transcript
        exit 1
    }
    "PHP download validated successfully."

    # Extract PHP
    New-Item -Path $phpPath -ItemType Directory -Force | Out-Null
    Expand-Archive $phpZip -DestinationPath $phpPath

    # Create PHP configuration file
    Copy-Item "$phpPath\php.ini-production" "$phpPath\php.ini"

    # Update php.ini settings with improved values
    $phpIni = Get-Content "$phpPath\php.ini"
    $phpIni = $phpIni -replace ';extension=mysqli', 'extension=mysqli'
    $phpIni = $phpIni -replace ';extension=openssl', 'extension=openssl'
    $phpIni = $phpIni -replace ';extension=mbstring', 'extension=mbstring'
    $phpIni = $phpIni -replace ';extension=exif', 'extension=exif'
    $phpIni = $phpIni -replace ';extension=gd', 'extension=gd'
    $phpIni = $phpIni -replace ';extension=curl', 'extension=curl' 
    $phpIni = $phpIni -replace ';extension=fileinfo', 'extension=fileinfo'
    $phpIni = $phpIni -replace ';extension=intl', 'extension=intl'
    $phpIni = $phpIni -replace ';extension=soap', 'extension=soap'
    $phpIni = $phpIni -replace ';cgi.force_redirect = 1', 'cgi.force_redirect = 0'
    $phpIni = $phpIni -replace ';date.timezone =', 'date.timezone = UTC'
    $phpIni = $phpIni -replace ';upload_max_filesize = 2M', "upload_max_filesize = $($config.MaxUploadSize)"
    $phpIni = $phpIni -replace ';post_max_size = 8M', "post_max_size = $($config.MaxUploadSize)"
    $phpIni = $phpIni -replace ';memory_limit = 128M', "memory_limit = $($config.MemoryLimit)"
    $phpIni = $phpIni -replace ';max_execution_time = 30', 'max_execution_time = 300'
    $phpIni = $phpIni -replace ';display_errors = On', 'display_errors = Off'
    $phpIni = $phpIni -replace ';error_reporting = E_ALL', 'error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT'
    Set-Content "$phpPath\php.ini" $phpIni

    # Create PHP upload and log directories
    $phpUploadDir = "$phpDataPath\Upload"
    $phpLogsDir = "$phpDataPath\Logs"
    New-Item -Path $phpUploadDir -ItemType Directory -Force | Out-Null
    New-Item -Path $phpLogsDir -ItemType Directory -Force | Out-Null

    # Set permissions on PHP directories
    icacls "$phpUploadDir" /grant "IUSR:(OI)(CI)(M)" /grant "IIS_IUSRS:(OI)(CI)(M)" /T
    icacls "$phpLogsDir" /grant "IUSR:(OI)(CI)(M)" /grant "IIS_IUSRS:(OI)(CI)(M)" /T

    # Configure IIS to use PHP
    # Install CGI module if not already installed
    Install-WindowsFeature -Name Web-CGI

    # Register PHP with IIS
    $phpCgiPath = "$phpPath\php-cgi.exe"
    New-WebHandler -Name "PHP" -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ScriptProcessor $phpCgiPath -ResourceType File
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -Name "maxInstances" -Value 4
    Add-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi" -Value @{fullPath = $phpCgiPath}

    "PHP Installation Complete."
} else {
    # Verify PHP is registered with IIS
    "Checking if PHP is registered with IIS..."
    $phpRegistered = Get-WebHandler -Name "PHP" -ErrorAction SilentlyContinue
    if (-not $phpRegistered) {
        "Registering PHP with IIS..."
        $phpCgiPath = "$env:ProgramFiles\PHP\v8.4\php-cgi.exe"
        New-WebHandler -Name "PHP" -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ScriptProcessor $phpCgiPath -ResourceType File
        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -Name "maxInstances" -Value 4
        Add-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi" -Value @{fullPath = $phpCgiPath}
        "PHP registered with IIS."
    } else {
        "✓ PHP is already registered with IIS."
    }
}

<#
======================== SSL/HTTPS Configuration with Let's Encrypt ================
This section installs and configures Let's Encrypt for automatic SSL certificates
and sets up HTTPS bindings in IIS.
#>

"`r`nSSL/HTTPS Configuration..."
# Check if SSL configuration is required
if ($config.UseHTTPS) {
    # Check if win-acme (Let's Encrypt client) is already installed
    $winAcmePath = "$env:ProgramData\win-acme"
    if (-not (Test-ComponentInstalled -Name "win-acme" -TestScript {
        Test-Path -Path "$winAcmePath\wacs.exe" -ErrorAction SilentlyContinue
    })) {
        "Installing win-acme (Let's Encrypt client) version $($config.WinAcmeVersion)..."
        # Create directory for win-acme
        New-Item -Path $winAcmePath -ItemType Directory -Force | Out-Null
        
        # Download win-acme using configured version
        $winAcmeUrl = "https://github.com/win-acme/win-acme/releases/download/v$($config.WinAcmeVersion)/win-acme.v$($config.WinAcmeVersion).x64.pluggable.zip"
        $winAcmeZip = "win-acme.zip"
        Invoke-WebRequest $winAcmeUrl -OutFile $winAcmeZip
        
        # Extract win-acme
        Expand-Archive $winAcmeZip -DestinationPath $winAcmePath
        Remove-Item $winAcmeZip -Force
        
        "win-acme installation complete."
    }

    # Determine domain name to use for certificate
    $domainName = if ([string]::IsNullOrWhiteSpace($config.Domain)) {
        # Use IP address if no domain provided
        "localhost"
    } else {
        $config.Domain
    }

    "Configuring SSL certificate for $domainName..."
    
    # For production use with a real domain
    if ($domainName -ne "localhost") {
        # Get the site ID for use with win-acme
        $siteId = (Get-Website -Name $config.SiteName).ID
        
        # Run win-acme to create certificate
        $winAcmeArgs = @(
            "--target", "iis",
            "--siteid", $siteId,
            "--installation", "iis",
            "--websiteroot", $wordpressPath,
            "--emailaddress", $config.EmailAddress,
            "--accepttos"
        )
        
        Start-Process -FilePath "$winAcmePath\wacs.exe" -ArgumentList $winAcmeArgs -Wait -NoNewWindow
        
        "Let's Encrypt certificate created and installed by win-acme."
    } else {
        # For localhost, create a self-signed certificate
        "Creating self-signed certificate for development..."
        $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"
        $thumbprint = $cert.Thumbprint
        
        # Add HTTPS binding to IIS website
        "Configuring HTTPS binding for IIS..."
        New-WebBinding -Name $config.SiteName -Protocol "https" -Port 443 -IPAddress "*" -SslFlags 0
        
        # Assign certificate to HTTPS binding
        $certPath = "IIS:\SslBindings\!443"
        Get-Item -Path "cert:\LocalMachine\My\$thumbprint" | New-Item -Path $certPath
    }
    
    "SSL/HTTPS configuration complete."
    
    # Create web.config redirect from HTTP to HTTPS if domain specified
    if ($domainName -ne "localhost") {
        "Adding HTTP to HTTPS redirect..."
        $redirectWebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="HTTP to HTTPS redirect" stopProcessing="true">
                    <match url="(.*)" />
                    <conditions>
                        <add input="{HTTPS}" pattern="off" ignoreCase="true" />
                    </conditions>
                    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
                </rule>
                <!-- Existing WordPress rule will be after this -->
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
"@
        
        try {
            $existingWebConfig = Get-Content -Path "$wordpressPath\web.config" -Raw
            $newRules = ($redirectWebConfig | Select-String -Pattern '<rules>(?s)(.*?)</rules>' -AllMatches).Matches[0].Groups[1].Value
            
            # Replace existing <rules> section with new rules plus existing rules
            $updatedWebConfig = $existingWebConfig -replace '(<rules>)(.*?)(</rules>)', ('$1' + $newRules + '$2$3')
            Set-Content -Path "$wordpressPath\web.config" -Value $updatedWebConfig
            
            "HTTP to HTTPS redirect configured."
        } catch {
            Write-Error "Failed to update web.config with HTTP to HTTPS redirect: $_"
        }
    }
} else {
    "SSL/HTTPS configuration skipped (UseHTTPS set to false)."
}

<#
======================== Domain Name Configuration ===========================
This section configures IIS for custom domain names.
#>

"`r`nDomain Name Configuration..."
if (-not [string]::IsNullOrWhiteSpace($config.Domain)) {
    "Configuring website for domain: $($config.Domain)"
    
    # Update site bindings to include the domain name
    $site = Get-Website -Name $config.SiteName
    $httpBinding = Get-WebBinding -Name $config.SiteName -Protocol "http"
    
    if ($httpBinding) {
        # Update HTTP binding to use the domain
        Set-WebBinding -Name $config.SiteName -BindingInformation "*:80:" `
                      -PropertyName BindingInformation -Value "*:80:$($config.Domain)"
    }
    
    # Add host entry for local development if requested
    if ($config.ModifyHostsFile -and $config.Domain -ne "localhost") {
        "Adding entry to hosts file for local development..."
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsContent = Get-Content -Path $hostsPath
        
        # Check if hosts entry already exists
        $entryExists = $hostsContent | Where-Object { $_ -match "^\s*127\.0\.0\.1\s+$($config.Domain)\s*$" }
        
        if (-not $entryExists) {
            $hostEntry = "`r`n127.0.0.1`t$($config.Domain)"
            Add-Content -Path $hostsPath -Value $hostEntry -ErrorAction SilentlyContinue
            
            if ($?) {
                "✓ Added hosts file entry for $($config.Domain)"
                
                # Create a cleanup script to remove the hosts entry if needed
                $hostsCleanupScript = @"
# Remove WordPress hosts file entry
# Generated on $(Get-Date)

`$hostsPath = "`$env:SystemRoot\System32\drivers\etc\hosts"
`$domain = "$($config.Domain)"

# Read hosts file content
`$hostsContent = Get-Content -Path `$hostsPath

# Filter out the entry we added
`$newContent = `$hostsContent | Where-Object { -not (`$_ -match "^\s*127\.0\.0\.1\s+`$domain\s*`$") }

# Write back to hosts file
Set-Content -Path `$hostsPath -Value `$newContent -Force

Write-Output "Removed hosts entry for `$domain"
"@
                Set-Content -Path "$wordpressPath\remove-hosts-entry.ps1" -Value $hostsCleanupScript
                "Created script to remove hosts entry: $wordpressPath\remove-hosts-entry.ps1"
            } else {
                "⚠️ Failed to modify hosts file. You may need to run this script as administrator."
            }
        } else {
            "✓ Hosts file entry for $($config.Domain) already exists."
        }
    }
    
    "Domain configuration complete."
} else {
    "Domain configuration skipped (no domain specified)."
}

<#
======================== Enhanced Security Configuration ====================
This section adds security enhancements including Windows Firewall rules,
security headers, and IP restrictions.
#>

"`r`nEnhanced Security Configuration..."

# Configure Windows Firewall if requested
if ($config.ConfigureFirewall) {
    "Configuring Windows Firewall..."
    
    # Define all required firewall rules
    $firewallRules = @(
        @{
            DisplayName = "Allow HTTP (TCP-In)"
            Protocol = "TCP"
            LocalPort = 80
            Action = "Allow"
            Direction = "Inbound"
            Condition = $true
        },
        @{
            DisplayName = "Allow HTTPS (TCP-In)"
            Protocol = "TCP"
            LocalPort = 443
            Action = "Allow"
            Direction = "Inbound"
            Condition = $config.UseHTTPS
        },
        @{
            DisplayName = "Allow RDP (TCP-In)"
            Protocol = "TCP"
            LocalPort = $config.RDPPort
            Action = "Allow"
            Direction = "Inbound"
            Condition = $config.PreventRDPLockout
        },
        @{
            DisplayName = "Allow WinRM (TCP-In)"
            Protocol = "TCP"
            LocalPort = 5985
            Action = "Allow"
            Direction = "Inbound"
            Condition = $config.PreventRDPLockout  # Also protect WinRM for remote management
        }
    )
    
    # Process each firewall rule
    foreach ($rule in $firewallRules) {
        if ($rule.Condition) {
            $existingRule = Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
            
            if (-not $existingRule) {
                New-NetFirewallRule -DisplayName $rule.DisplayName -Direction $rule.Direction `
                                   -Protocol $rule.Protocol -LocalPort $rule.LocalPort -Action $rule.Action | Out-Null
                "✓ Created firewall rule: $($rule.DisplayName)"
            } else {
                "✓ Firewall rule already exists: $($rule.DisplayName)"
            }
        }
    }
    
    # Block all other inbound connections to IIS except those explicitly allowed
    if ($config.FirewallDefaultDeny) {
        "⚠️ Setting firewall to block all inbound connections except those explicitly allowed..."
        
        if ($config.PreventRDPLockout) {
            "✓ RDP lockout prevention is enabled - port $($config.RDPPort) will remain accessible."
        } else {
            "⚠️ WARNING: You have chosen to block all inbound traffic without RDP protection."
            "This could lock you out of remote access to this server."
            $confirmLockout = Get-YesNoResponse -Prompt "Are you absolutely sure you want to continue?" -Default $false
            
            if (-not $confirmLockout) {
                "Enabling RDP lockout prevention for safety..."
                $config.PreventRDPLockout = $true
                
                # Create the RDP rule if it doesn't exist yet
                $rdpRule = Get-NetFirewallRule -DisplayName "Allow RDP (TCP-In)" -ErrorAction SilentlyContinue
                if (-not $rdpRule) {
                    New-NetFirewallRule -DisplayName "Allow RDP (TCP-In)" -Direction Inbound `
                                      -Protocol TCP -LocalPort $config.RDPPort -Action Allow | Out-Null
                    "✓ Created firewall rule: Allow RDP (TCP-In)"
                }
            }
        }
        
        # Apply the default deny rule
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
        
        # Create a reset script to restore default firewall settings if needed
        $firewallResetScript = @"
# Reset Windows Firewall default settings
# Generated on $(Get-Date)

Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Allow
Write-Output "Firewall default inbound action reset to Allow"
"@
        Set-Content -Path "$wordpressPath\reset-firewall.ps1" -Value $firewallResetScript
        "Created script to reset firewall settings: $wordpressPath\reset-firewall.ps1"
    }
    
    "Windows Firewall configured."
}

# Configure IIS security headers based on environment
"Configuring IIS security headers..."
$sitePath = "IIS:\Sites\$($config.SiteName)"

# Add security headers at the site level
$securityHeaders = @(
    @{name="X-Content-Type-Options"; value="nosniff"},
    @{name="X-Frame-Options"; value="SAMEORIGIN"},
    @{name="X-XSS-Protection"; value="1; mode=block"},
    @{name="Referrer-Policy"; value="strict-origin-when-cross-origin"}
)

# Add more restrictive headers in production mode
if (-not $config.DevelopmentMode) {
    # Stricter Content-Security-Policy for production
    $cspValue = "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'"
} else {
    # More permissive CSP for development
    $cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com; img-src 'self' data: https://ssl.google-analytics.com; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; frame-src 'self'"
}

$securityHeaders += @{name="Content-Security-Policy"; value=$cspValue}

# Add HSTS header if HTTPS is enabled and not in development mode
if ($config.UseHTTPS -and -not $config.DevelopmentMode) {
    $securityHeaders += @{name="Strict-Transport-Security"; value="max-age=31536000; includeSubDomains"}
}

# Add each header
foreach ($header in $securityHeaders) {
    # Check if header already exists
    $existingHeader = Get-WebConfigurationProperty -PSPath $sitePath -Filter "system.webServer/httpProtocol/customHeaders/add[@name='$($header.name)']" -Name "." -ErrorAction SilentlyContinue
    
    if ($existingHeader) {
        # Update existing header
        Set-WebConfigurationProperty -PSPath $sitePath -Filter "system.webServer/httpProtocol/customHeaders/add[@name='$($header.name)']" -Name "value" -Value $header.value
    } else {
        # Add new header
        Add-WebConfigurationProperty -PSPath $sitePath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value $header
    }
}

# Configure IP restrictions for WordPress admin area if requested
if ($config.RestrictWPAdmin) {
    "Configuring IP restrictions for WordPress admin area..."
    
    # Create a web.config specifically for wp-admin directory
    $wpAdminWebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <security>
            <ipSecurity allowUnlisted="false">
$(
    $config.AllowedIPsForAdmin | ForEach-Object {
        "                <add ipAddress=`"$($_)`" allowed=`"true`" />"
    }
)
            </ipSecurity>
        </security>
    </system.webServer>
</configuration>
"@
    
    # Create the wp-admin directory if it doesn't exist (should already exist after WordPress installation)
    $wpAdminPath = Join-Path -Path $wordpressPath -ChildPath "wp-admin"
    if (-not (Test-Path -Path $wpAdminPath)) {
        New-Item -Path $wpAdminPath -ItemType Directory -Force | Out-Null
    }
    
    # Save the web.config to wp-admin directory
    Set-Content -Path "$wpAdminPath\web.config" -Value $wpAdminWebConfig
    
    # Create a script to disable IP restrictions if needed
    $ipResetScript = @"
# Remove IP restrictions for WordPress admin
# Generated on $(Get-Date)

`$wpAdminPath = "$wpAdminPath"
Remove-Item -Path "`$wpAdminPath\web.config" -Force
Write-Output "IP restrictions removed from wp-admin"
"@
    Set-Content -Path "$wordpressPath\remove-ip-restrictions.ps1" -Value $ipResetScript
    
    "IP restrictions for WordPress admin area configured."
    "Created script to remove IP restrictions: $wordpressPath\remove-ip-restrictions.ps1"
} else {
    "IP restrictions for WordPress admin area skipped."
}

"Enhanced security configuration complete."

<#
======================== Backup Configuration ================================
This section configures automated backups for WordPress files and database.
#>

"`r`nBackup Configuration..."
if ($config.ConfigureBackups) {
    "Setting up automated backups..."
    
    # Create backup directory if it doesn't exist
    if (-not (Test-Path -Path $config.BackupPath)) {
        New-Item -Path $config.BackupPath -ItemType Directory -Force | Out-Null
    }
    
    # Create backup script
    $backupScriptPath = "$env:SystemDrive\WordPressBackup.ps1"
    $backupScript = @"
# WordPress backup script
# Created on $(Get-Date)

# Backup configuration
`$config = @{
    BackupPath = "$($config.BackupPath)"
    WordPressPath = "$wordpressPath"
    MySQLServerPath = "$mysqlServerPath"
    MySQLRootPassword = "$mysqlRootPwd"
    BackupRetention = $($config.BackupRetention)
}

# Create timestamp for backup files
`$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
`$backupFolder = Join-Path -Path `$config.BackupPath -ChildPath `$timestamp
New-Item -Path `$backupFolder -ItemType Directory -Force | Out-Null

# Backup WordPress files
`$filesBackupPath = "`$backupFolder\wordpress_files.zip"
Compress-Archive -Path "`$(`$config.WordPressPath)\*" -DestinationPath `$filesBackupPath -CompressionLevel Optimal

# Backup MySQL database
`$dbBackupPath = "`$backupFolder\wordpress_db.sql"
& "`$(`$config.MySQLServerPath)\bin\mysqldump" "--user=root" "--password=`$(`$config.MySQLRootPassword)" "--result-file=`$dbBackupPath" "wordpress"

# If successful, compress the database backup
if (Test-Path -Path `$dbBackupPath) {
    Compress-Archive -Path `$dbBackupPath -DestinationPath "`$backupFolder\wordpress_db.zip" -CompressionLevel Optimal
    Remove-Item -Path `$dbBackupPath -Force
}

# Clean up old backups
`$allBackups = Get-ChildItem -Path `$config.BackupPath -Directory | Sort-Object CreationTime -Descending | Select-Object -Skip `$config.BackupRetention
foreach (`$backup in `$allBackups) {
    Remove-Item -Path `$backup.FullName -Recurse -Force
}

Write-Output "WordPress backup completed at `$(Get-Date)"
"@

    # Save the backup script
    Set-Content -Path $backupScriptPath -Value $backupScript
    
    # Create scheduled task for automatic backups
    $taskName = "WordPressBackup"
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    
    if (-not $taskExists) {
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$backupScriptPath`""
        
        # Set trigger based on backup schedule
        $trigger = switch ($config.BackupSchedule) {
            "Daily" { New-ScheduledTaskTrigger -Daily -At "3:00 AM" }
            "Weekly" { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "3:00 AM" }
            "Monthly" { New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At "3:00 AM" }
            Default { New-ScheduledTaskTrigger -Daily -At "3:00 AM" }
        }
        
        # Create the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "WordPress automated backup" -RunLevel Highest
        
        "Scheduled task '$taskName' created for $($config.BackupSchedule.ToLower()) backups."
    } else {
        "Scheduled backup task already exists."
    }
    
    # Run initial backup
    "Running initial backup..."
    Start-Process "PowerShell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$backupScriptPath`"" -NoNewWindow
    
    "Backup configuration complete."
} else {
    "Backup configuration skipped (ConfigureBackups set to false)."
}

<#
================================== WordPress ===================================
This section downloads and configures WordPress, sets up the IIS website,
and prepares the WordPress installation.
#>

"`r`nWordPress..."
# Set WordPress variables
$iisPath = "$env:SystemDrive\inetpub"
$wordpressPath = "$iisPath\wordpress"

# Check if WordPress is already installed
if (-not (Test-ComponentInstalled -Name "WordPress" -TestScript {
    Test-Path -Path "$wordpressPath\wp-config.php"
})) {
    "Installing WordPress..."
    # Set WordPress variables
    $iisPath = "$env:SystemDrive\inetpub"
    $wordpressPath = "$iisPath\wordpress"
    $wordpressUrl = "https://wordpress.org/latest.zip"
    $wordpressZip = "wordpress.zip"

    # Download and extract WordPress
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

<#
======================== Security Recommendations =============================
Add security recommendations section
#>

"`r`nSecurity Recommendations:"
"  - Set up HTTPS with a valid SSL certificate"
"  - Configure Windows Firewall to allow only needed ports"
"  - Implement regular WordPress updates"
"  - Use strong passwords for all accounts"
"  - Install security plugins like Wordfence or Sucuri"
"  - Set up regular database backups"

<#
============================= Summary and Output ==============================
Display configuration information and next steps.
#>

# Stop logging
Stop-Transcript

# Get server IP address for access and store it for output
$ipAddress = (Get-NetIPAddress | Where-Object {($_.AddressFamily -eq "IPv4") -and ($_.IPAddress -ne "127.0.0.1")}).IPAddress

# Check if multiple IP addresses were found, use the first one if so
if ($ipAddress -is [array]) {
    "Multiple IP addresses found on this server. Using the first available address."
    $ipAddress = $ipAddress[0]
}

# Display summary information
"`r`n===================================================================="
"WordPress Installation Completed Successfully!"
"===================================================================="
"MySQL Credentials:"
"    Root Password: $mysqlRootPwd"
"    WordPress User: wordpress"
"    WordPress Password: $mysqlWordPressPwd"
"`r`nWordPress is already installed at: $wordpressPath"
if (-not [string]::IsNullOrWhiteSpace($config.Domain)) {
    if ($config.UseHTTPS) {
        "You can access your WordPress site at: https://$($config.Domain)/"
    } else {
        "You can access your WordPress site at: http://$($config.Domain)/"
    }
} else {
    if ($config.UseHTTPS) {
        "You can access your WordPress site at: https://$($ipAddress):443/"
    } else {
        "You can access your WordPress site at: http://$($ipAddress):$($config.SitePort)/"
    }
}
"Installation log saved to: $($config.LogPath)"
"===================================================================="
"Next Steps:"
"1. Open your browser and navigate to http://$ipAddress`:$($config.SitePort)/"
"2. Complete the WordPress setup wizard"
"3. Secure your installation by setting up HTTPS"
"4. Review the security recommendations above"
"===================================================================="
"WordPress Installation Complete."
"----------------------------------------"
"Production-ready enhancements added:"
if ($config.UseHTTPS) { "✓ SSL/HTTPS configuration with Let's Encrypt" } else { "✗ SSL/HTTPS not configured" }
if (-not [string]::IsNullOrWhiteSpace($config.Domain)) { "✓ Domain configuration for $($config.Domain)" } else { "✗ No domain configured" }
if ($config.ConfigureFirewall) { "✓ Windows Firewall rules" } else { "✗ Firewall not configured" }
"✓ Security headers configured"
if ($config.RestrictWPAdmin) { "✓ IP restrictions for WordPress admin" } else { "✗ No IP restrictions for admin" }
if ($config.ConfigureBackups) { "✓ Automated $($config.BackupSchedule.ToLower()) backups" } else { "✗ No backup configuration" }
"----------------------------------------"

<#
============================== Configuration Rollback ========================
This section creates scripts to reverse configuration changes if needed
#>

"`r`nCreating rollback scripts..."

# Create main rollback script that calls individual reset scripts
$mainRollbackScript = @"
# WordPrIIS Configuration Rollback
# Generated on $(Get-Date)
# This script helps reverse configuration changes made by the WordPrIIS installer

Write-Host 'WordPrIIS Configuration Rollback' -ForegroundColor Green
Write-Host '====================================' -ForegroundColor Green

function Invoke-RollbackAction {
    param (
        [string]`$Title,
        [scriptblock]`$Action
    )
    
    Write-Host "`nRollback: `$Title" -ForegroundColor Yellow
    try {
        & `$Action
        Write-Host "✓ Success" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed: `$_" -ForegroundColor Red
    }
}

# Menu for selecting what to rollback
# Menu for selecting what to rollback
Write-Host "`nAvailable rollback options:"
Write-Host "1. Remove IP restrictions for wp-admin"
Write-Host "2. Reset firewall settings to default"
Write-Host "3. Remove hosts file entry"
Write-Host "4. Restore default security headers"
Write-Host "5. Disable scheduled backups"
Write-Host "6. Exit"

`$choice = Read-Host "`nEnter option number (1-6)"

switch (`$choice) {
    "1" {
        Invoke-RollbackAction -Title "Removing IP restrictions" -Action {
            if (Test-Path "$wordpressPath\remove-ip-restrictions.ps1") {
                & "$wordpressPath\remove-ip-restrictions.ps1"
            } else {
                throw "IP restrictions rollback script not found"
            }
        }
    }
    "2" {
        Invoke-RollbackAction -Title "Resetting firewall settings" -Action {
            if (Test-Path "$wordpressPath\reset-firewall.ps1") {
                & "$wordpressPath\reset-firewall.ps1"
            } else {
                throw "Firewall reset script not found"
            }
        }
    }
    "3" {
        Invoke-RollbackAction -Title "Removing hosts file entry" -Action {
            if (Test-Path "$wordpressPath\remove-hosts-entry.ps1") {
                & "$wordpressPath\remove-hosts-entry.ps1"
            } else {
                throw "Hosts file reset script not found"
            }
        }
    }
    "4" {
        Invoke-RollbackAction -Title "Removing custom security headers" -Action {
            `$sitePath = "IIS:\Sites\$($config.SiteName)"
            Clear-WebConfiguration -PSPath `$sitePath -Filter "system.webServer/httpProtocol/customHeaders"
            Write-Output "Security headers removed"
        }
    }
    "5" {
        Invoke-RollbackAction -Title "Disabling scheduled backups" -Action {
            Unregister-ScheduledTask -TaskName "WordPressBackup" -Confirm:`$false
            Write-Output "Backup task removed"
        }
    }
    "6" {
        Write-Host "Exiting without changes" -ForegroundColor Green
    }
    default {
        Write-Host "Invalid option selected." -ForegroundColor Red
    }
}

Write-Host "`nRollback operation complete." -ForegroundColor Green
"@

# Use the defined variable by writing it to a file
Set-Content -Path "$wordpressPath\rollback-configuration.ps1" -Value $mainRollbackScript
Set-Content -Path "$wordpressPath\rollback-configuration.ps1" -Value $mainRollbackScript
"Created main rollback script: $wordpressPath\rollback-configuration.ps1"
"This script can be used to reverse configuration changes if needed."

# Display summary information
"`r`n===================================================================="
"WordPress Installation Completed Successfully!"
"===================================================================="
"MySQL Credentials:"
"    Root Password: $mysqlRootPwd"
"    WordPress User: wordpress"
"    WordPress Password: $mysqlWordPressPwd"
"`r`nWordPress is installed at: $wordpressPath"
if (-not [string]::IsNullOrWhiteSpace($config.Domain)) {
    if ($config.UseHTTPS) {
        "You can access your WordPress site at: https://$($config.Domain)/"
    } else {
        "You can access your WordPress site at: http://$($config.Domain)/"
    }
} else {
    if ($config.UseHTTPS) {
        "You can access your WordPress site at: https://$($ipAddress):443/"
    } else {
        "You can access your WordPress site at: http://$($ipAddress):$($config.SitePort)/"
    }
}
"Rollback and Management:"
"To reverse configuration changes: $wordpressPath\rollback-configuration.ps1"
if ($config.RestrictWPAdmin) {
    "To remove IP restrictions: $wordpressPath\remove-ip-restrictions.ps1"
}
if ($config.FirewallDefaultDeny) {
    "To reset firewall settings: $wordpressPath\reset-firewall.ps1"
}
if ($config.ModifyHostsFile) {
    "To remove hosts file entry: $wordpressPath\remove-hosts-entry.ps1"
}
"Installation log saved to: $($config.LogPath)"
"===================================================================="
"Next Steps:"
"1. Open your browser and navigate to http://$ipAddress`:$($config.SitePort)/"
"2. Complete the WordPress setup wizard"
"3. Secure your installation by setting up HTTPS"
"4. Review the security recommendations above"
"===================================================================="
"WordPress Installation Complete."
"----------------------------------------"
"Production-ready enhancements added:"
if ($config.UseHTTPS) { "✓ SSL/HTTPS configuration with Let's Encrypt" } else { "✗ SSL/HTTPS not configured" }
if (-not [string]::IsNullOrWhiteSpace($config.Domain)) { "✓ Domain configuration for $($config.Domain)" } else { "✗ No domain configured" }
if ($config.ConfigureFirewall) { "✓ Windows Firewall rules" } else { "✗ Firewall not configured" }
"✓ Security headers configured"
if ($config.RestrictWPAdmin) { "✓ IP restrictions for WordPress admin" } else { "✗ No IP restrictions for admin" }
if ($config.ConfigureBackups) { "✓ Automated $($config.BackupSchedule.ToLower()) backups" } else { "✗ No backup configuration" }
"----------------------------------------"