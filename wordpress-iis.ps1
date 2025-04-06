<#
.SYNOPSIS
Automated installer for WordPress on Windows Server with IIS

.DESCRIPTION
This script automates the process of installing and configuring WordPress
on Windows Server with IIS, PHP, and MySQL.

.PARAMETER NonInteractive
Runs the script without user interaction, using default values

.EXAMPLE
.\wordpress-iis.ps1
Runs the script with interactive prompts

.EXAMPLE
.\wordpress-iis.ps1 -NonInteractive
Runs the script with default values, without user interaction
#>

param (
    [switch]$NonInteractive,
    [string]$ConfigPath
)

# Store the script path for module imports
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import utility functions first as other modules depend on them
. "$ScriptPath\modules\Utils.ps1"

# Check if running as administrator
if (-not (Test-IsAdmin)) {
    Write-Host "This script must be run as Administrator. Please restart with elevated privileges." -ForegroundColor Red
    exit 1
}

# Import WebAdministration module for IIS management
$webAdminAvailable = Import-WebAdministrationModule
if (-not $webAdminAvailable) {
    Write-Warning "WebAdministration module could not be imported. This is required for IIS management."
    if (-not (Get-YesNoResponse -Prompt "Do you want to continue anyway? (Not recommended)")) {
        Exit 1
    }
}

# Import configuration and other modules
Write-Host "Importing modules..."
try {
    . "$ScriptPath\modules\Config.ps1"
    Write-Host "Config.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\InteractiveConfig.ps1"
    Write-Host "InteractiveConfig.ps1 imported successfully" -ForegroundColor Green 
    . "$ScriptPath\modules\IIS-Setup.ps1"
    Write-Host "IIS-Setup.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\PHP-Setup.ps1"
    Write-Host "PHP-Setup.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\MySQL-Setup.ps1"
    Write-Host "MySQL-Setup.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\WordPress-Setup.ps1"
    Write-Host "WordPress-Setup.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\SSL-Setup.ps1"
    Write-Host "SSL-Setup.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\Domain-Setup.ps1"
    Write-Host "Domain-Setup.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\Security.ps1"
    Write-Host "Security.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\Backup-Setup.ps1"
    Write-Host "Backup-Setup.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\Rollback-Scripts.ps1"
    Write-Host "Rollback-Scripts.ps1 imported successfully" -ForegroundColor Green
    . "$ScriptPath\modules\Summary.ps1"
    Write-Host "Summary.ps1 imported successfully" -ForegroundColor Green
} catch {
    Write-Host "Error importing module: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}

# Main script execution
try {
    # Create default directories
    if (-not (Test-Path $config.DownloadPath)) {
        New-Item -Path $config.DownloadPath -ItemType Directory -Force | Out-Null
    }
    
    # Start logging
    Start-Transcript -Path $config.LogPath -Append
    
    Write-Host "===== WordPrIIS - WordPress Installer for IIS =====" -ForegroundColor Cyan
    
    # Load configuration - either interactive or from file
    if (-not $NonInteractive) {
        $config = Get-InteractiveConfiguration
    } elseif ($ConfigPath -and (Test-Path $ConfigPath)) {
        $configJson = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        # Convert JSON to hashtable
        $configJson.PSObject.Properties | ForEach-Object {
            $config[$_.Name] = $_.Value
        }
    }
    
    # Installation process
    Setup-IIS -config $config
    Setup-PHP -config $config
    Setup-MySQL -config $config
    Setup-WordPress -config $config
    
    if ($config.Domain -and $config.UseHTTPS) {
        Setup-SSL -config $config
    }
    
    if ($config.ConfigureFirewall) {
        Setup-Security -config $config
    }
    
    if ($config.ConfigureBackups) {
        Setup-Backup -config $config
    }
    
    Create-RollbackScripts -config $config
    Show-Summary -config $config
    
    Write-Host "WordPress installation completed successfully!" -ForegroundColor Green
    Write-Host "Installation log is available at: $($config.LogPath)" -ForegroundColor Cyan
    Write-Host "`nVisit your WordPress site at: "
    if ($config.UseHTTPS) {
        Write-Host "https://$($config.Domain)/" -ForegroundColor Yellow
    } else {
        Write-Host "http://$($config.Domain)/" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "An error occurred during installation:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "Check the log file for more details: $($config.LogPath)" -ForegroundColor Red
    Exit 1
} finally {
    Stop-Transcript
}