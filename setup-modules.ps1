<#
====================== Module Directory Structure Setup =======================
This script creates the necessary folder structure and moves existing scripts
into the modular format.
#>

# Create modules directory if it doesn't exist
$modulesDir = Join-Path -Path $PSScriptRoot -ChildPath "modules"

if (-not (Test-Path $modulesDir)) {
    Write-Host "Creating modules directory..." -ForegroundColor Green
    New-Item -Path $modulesDir -ItemType Directory | Out-Null
}

# Define all module files that should exist
$moduleFiles = @(
    "Config.ps1",
    "Utils.ps1",
    "InteractiveConfig.ps1",
    "IIS-Setup.ps1",
    "PHP-Setup.ps1",
    "MySQL-Setup.ps1",
    "WordPress-Setup.ps1",
    "SSL-Setup.ps1",
    "Domain-Setup.ps1",
    "Security.ps1",
    "Backup-Setup.ps1",
    "Rollback-Scripts.ps1",
    "Summary.ps1"
)

# Create empty placeholder files for modules that don't exist yet
foreach ($file in $moduleFiles) {
    $filePath = Join-Path -Path $modulesDir -ChildPath $file
    if (-not (Test-Path $filePath)) {
        Write-Host "Creating placeholder for $file..." -ForegroundColor Yellow
        Set-Content -Path $filePath -Value "<# Module placeholder - Replace with actual content #>"
    }
}

Write-Host "`nModule directory structure setup complete!" -ForegroundColor Green
Write-Host "You can now fill each module file with the appropriate code." -ForegroundColor Green
Write-Host "Then use the main wordpress-iis.ps1 script to run your modular installation." -ForegroundColor Green
