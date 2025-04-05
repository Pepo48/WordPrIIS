<#
============================== Configuration Rollback ========================
This module creates scripts to reverse configuration changes if needed
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

# Save the main rollback script
Set-Content -Path "$wordpressPath\rollback-configuration.ps1" -Value $mainRollbackScript
"Created main rollback script: $wordpressPath\rollback-configuration.ps1"
"This script can be used to reverse configuration changes if needed."
