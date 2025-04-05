<#
======================== Interactive Configuration ===========================
This module allows for interactive configuration of the installation script
#>

"`r`nWordPress Installation - Interactive Configuration"
"======================================================================"
"You can customize the installation or proceed with default values."
"Press Enter to accept the default value shown in [brackets]."

# Prompt for key configuration options
"`r`nSite Configuration:"
$siteName = Read-Host -Prompt "Site name [$($config.SiteName)]"
if (-not [string]::IsNullOrWhiteSpace($siteName)) { $config.SiteName = $siteName }

$sitePort = Read-Host -Prompt "HTTP port [$($config.SitePort)]"
if (-not [string]::IsNullOrWhiteSpace($sitePort)) { $config.SitePort = [int]$sitePort }

$domain = Read-Host -Prompt "Domain name (leave empty to use IP address) [$($config.Domain)]"
if (-not [string]::IsNullOrWhiteSpace($domain)) { $config.Domain = $domain }

if (-not [string]::IsNullOrWhiteSpace($config.Domain)) {
    $config.UseHTTPS = Get-YesNoResponse -Prompt "Configure HTTPS?" -Default $config.UseHTTPS
    
    if ($config.UseHTTPS) {
        # Add certificate type options
        "SSL Certificate Options:"
        "1. Let's Encrypt (Recommended for production domains)"
        "2. Self-signed certificate (For development only)"
        "3. Cloudflare Origin Certificate (When using Cloudflare as proxy)"
        
        $certOption = "0"
        while ($certOption -notin @("1", "2", "3")) {
            $certOption = Read-Host -Prompt "Select certificate option (1-3)"
        }
        
        $config.CertificateType = switch($certOption) {
            "1" { "LetsEncrypt" }
            "2" { "SelfSigned" }
            "3" { "CloudflareOrigin" }
        }
        
        # Only prompt for email if Let's Encrypt is selected
        if ($config.CertificateType -eq "LetsEncrypt") {
            $email = Read-Host -Prompt "Email address for Let's Encrypt [$($config.EmailAddress)]"
            if (-not [string]::IsNullOrWhiteSpace($email)) { $config.EmailAddress = $email }
        }
        elseif ($config.CertificateType -eq "CloudflareOrigin") {
            $config.CloudflareCertPath = Read-Host -Prompt "Path to Cloudflare Origin Certificate file (.pem)"
            $config.CloudflareKeyPath = Read-Host -Prompt "Path to Cloudflare Private Key file (.key)"
        }
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
