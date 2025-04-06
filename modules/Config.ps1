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
    # PHP Performance settings
    EnablePHPOptimizations = $true  # Enable Plesk-like PHP optimizations
    # Win-acme settings
    WinAcmeVersion = "2.2.9.1701"  # Win-acme version
    # Remote access protection
    PreventRDPLockout = $true  # Prevents firewall from blocking RDP
    RDPPort = 3389  # Default RDP port
    # Paths
    DownloadPath = "$env:USERPROFILE\Downloads"
    LogPath = "$env:TEMP\wp_install_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
}

# Set WordPress path variables (used by multiple modules)
$global:iisPath = "$env:SystemDrive\inetpub"
$global:wordpressPath = "$iisPath\wordpress"
