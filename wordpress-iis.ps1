<#
================================================================================
===== WordPress Installation Script for Windows Server 2022 =================
================================================================================
This script automates the installation of WordPress on Windows Server 2022
with IIS, PHP, and MySQL.
#>

# Import configuration and utility modules
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Import core modules
. "$ScriptPath\modules\Utils.ps1"
. "$ScriptPath\modules\Config.ps1"

# Check if running as Administrator
if (-not (Test-IsAdmin)) {
    "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Try importing WebAdministration module early to catch issues
$webAdminAvailable = Import-WebAdministrationModule
if (-not $webAdminAvailable) {
    "WARNING: Unable to import WebAdministration module. This is required for IIS management."
    "Ensure you have IIS installed and the WebAdministration module is available."
    
    # Ask if user wants to continue despite the warning
    if (-not (Get-YesNoResponse -Prompt "Do you want to continue anyway?" -Default $false)) {
        "Installation aborted. Please install IIS and run the script again."
        exit 1
    }
    
    "Continuing with limited functionality..."
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

# Interactive configuration if requested
if (-not $PSBoundParameters.ContainsKey('NonInteractive')) {
    . "$ScriptPath\modules\InteractiveConfig.ps1"
}

# Import and run module scripts in the correct sequence
try {
    # Core system components
    . "$ScriptPath\modules\IIS-Setup.ps1"
    . "$ScriptPath\modules\PHP-Setup.ps1"
    . "$ScriptPath\modules\MySQL-Setup.ps1"

    # WordPress installation
    . "$ScriptPath\modules\WordPress-Setup.ps1"

    # Security and additional components
    . "$ScriptPath\modules\Security.ps1"
    if ($config.UseHTTPS) {
        . "$ScriptPath\modules\SSL-Setup.ps1"
    }
    if ($config.Domain) {
        . "$ScriptPath\modules\Domain-Setup.ps1"
    }
    if ($config.ConfigureBackups) {
        . "$ScriptPath\modules\Backup-Setup.ps1"
    }

    # Create rollback scripts
    . "$ScriptPath\modules\Rollback-Scripts.ps1"

    # Display completion message
    . "$ScriptPath\modules\Summary.ps1"
} 
catch {
    "Error occurred during installation: $_"
    "Check the log file for details: $($config.LogPath)"
}
finally {
    # Stop logging
    Stop-Transcript
}