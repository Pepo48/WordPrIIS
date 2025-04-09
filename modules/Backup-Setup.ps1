<#
======================== Backup Configuration ================================
This module configures automated backups for WordPress files and database.
#>

"`r`nBackup Configuration..."
"Setting up automated backups..."

# Create backup directory if it doesn't exist
if (-not (Test-Path -Path $config.BackupPath)) {
    New-Item -Path $config.BackupPath -ItemType Directory -Force | Out-Null
}

# Ensure WordPress directory exists
if (-not (Test-Path -Path $wordpressPath)) {
    New-Item -Path $wordpressPath -ItemType Directory -Force | Out-Null
    "Created WordPress directory at $wordpressPath"
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
`$wpPath = `$config.WordPressPath
if (Test-Path -Path "`$wpPath") {
    `$filesBackupPath = "`$backupFolder\wordpress_files.zip"
    Write-Output "Backing up WordPress files from `$wpPath to `$filesBackupPath"
    Compress-Archive -Path "`$wpPath\*" -DestinationPath `$filesBackupPath -CompressionLevel Optimal
} else {
    Write-Output "WARNING: WordPress path `$wpPath not found. Skipping file backup."
}

# Backup MySQL database
# Try multiple possible locations for mysqldump
`$possibleMySQLPaths = @(
    # Provided path
    `$config.MySQLServerPath,
    # Common installation paths
    "C:\Program Files\MySQL\MySQL Server 8.0",
    "C:\Program Files\MySQL\MySQL Server 8.4",
    "C:\MySQL",
    # Check Program Files directory for MySQL folders
    (Get-ChildItem "C:\Program Files\MySQL" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)
)

`$mysqlDumpPath = `$null
foreach (`$path in `$possibleMySQLPaths | Where-Object { `$_ }) {
    Write-Output "Checking for MySQL in: `$path"
    if (Test-Path -Path `$path) {
        # Try different possible locations for mysqldump
        foreach (`$binPath in @("\bin\mysqldump.exe", "\bin\mysqldump", "\mysqldump.exe", "\mysqldump")) {
            `$testPath = `$path + `$binPath
            if (Test-Path -Path `$testPath) {
                Write-Output "Found mysqldump at: `$testPath"
                `$mysqlDumpPath = `$testPath
                break
            }
        }
    }
    if (`$mysqlDumpPath) { break }
}

if (`$mysqlDumpPath) {
    `$dbBackupPath = "`$backupFolder\wordpress_db.sql"
    Write-Output "Backing up WordPress database to `$dbBackupPath using `$mysqlDumpPath"
    try {
        # First check if MySQL service is running
        `$mysqlService = Get-Service -Name "*mysql*" -ErrorAction SilentlyContinue
        if (-not `$mysqlService -or `$mysqlService.Status -ne 'Running') {
            Write-Output "WARNING: MySQL service is not running. Attempting to start it..."
            
            if (`$mysqlService) {
                try {
                    Start-Service -Name `$mysqlService.Name -ErrorAction Stop
                    Write-Output "✓ MySQL service started successfully."
                    Start-Sleep -Seconds 10  # Give it more time to initialize
                } catch {
                    Write-Output "ERROR: Failed to start MySQL service. Database backup will likely fail."
                }
            } else {
                Write-Output "ERROR: MySQL service not found on this system. Backup will attempt to continue anyway."
                Write-Output "INFO: If this is a test or development environment without MySQL installed, you can ignore this error."
            }
        }
        
        # Create a test connection to check if MySQL is responding
        `$mysqlClientPath = `$null
        if (`$mysqlDumpPath -match "\\bin\\") {
            `$mysqlClientPath = `$mysqlDumpPath -replace "mysqldump(\.exe)?`$", "mysql.exe"
            if (-not (Test-Path `$mysqlClientPath)) {
                `$mysqlClientPath = `$mysqlClientPath -replace "\.exe`$", ""
            }
        }
        
        `$mysqlConnected = `$false
        if (Test-Path -Path `$mysqlClientPath) {
            Write-Output "Testing MySQL connection..."
            try {
                `$testResult = & "`$mysqlClientPath" "--user=root" "--password=`$(`$config.MySQLRootPassword)" "--connect-timeout=10" "-e" "SELECT 1;" 2>`$null
                if (`$testResult -match "1") {
                    Write-Output "MySQL connection successful!"
                    `$mysqlConnected = `$true
                } else {
                    Write-Output "ERROR: MySQL connection test failed."
                }
            } catch {
                Write-Output "ERROR: Failed to execute MySQL connection test."
            }
        } else {
            Write-Output "INFO: MySQL client not found. Skipping connection test."
        }
        
        # Only proceed with backup if connection is successful or we couldn't test the connection
        if (`$mysqlConnected -or -not (Test-Path -Path `$mysqlClientPath)) {
            # Try MySQLDump command
            Write-Output "Running mysqldump command..."
            & "`$mysqlDumpPath" "--user=root" "--password=`$(`$config.MySQLRootPassword)" "--host=localhost" "--port=3306" "--protocol=TCP" "--result-file=`$dbBackupPath" "--connect-timeout=30" "wordpress"
            
            # Check if the database backup was successful
            if (Test-Path -Path `$dbBackupPath -and (Get-Item -Path `$dbBackupPath).Length -gt 0) {
                Compress-Archive -Path `$dbBackupPath -DestinationPath "`$backupFolder\wordpress_db.zip" -CompressionLevel Optimal
                Remove-Item -Path `$dbBackupPath -Force
                Write-Output "Database backup successful and compressed."
            } else {
                Write-Output "WARNING: Database backup failed or created an empty file."
                
                # Skip alternative approach if MySQL connection failed
                if (-not `$mysqlConnected -and (Test-Path -Path `$mysqlClientPath)) {
                    Write-Output "INFO: Skipping alternative backup method because MySQL connection test failed."
                } else {
                    # Try alternative approach
                    Write-Output "Attempting alternative backup method..."
                    `$env:MYSQL_PWD = `$config.MySQLRootPassword
                    try {
                        # Get list of tables
                        `$tables = & "`$mysqlDumpPath" "--user=root" "--host=localhost" "--skip-column-names" "-e" "SHOW TABLES FROM wordpress;" 2>`$null
                        
                        if (`$tables) {
                            `$tempSql = "-- WordPress Database Backup`r`n"
                            foreach (`$table in `$tables.Split("`n") | Where-Object { `$_.Trim() }) {
                                Write-Output "  Backing up table: `$table"
                                `$tableData = & "`$mysqlDumpPath" "--user=root" "--host=localhost" "wordpress" "`$table" 2>`$null
                                if (`$tableData) {
                                    `$tempSql += "`r`n-- Table structure and data for `$table`r`n`$tableData`r`n"
                                }
                            }
                            
                            Set-Content -Path `$dbBackupPath -Value `$tempSql
                            Compress-Archive -Path `$dbBackupPath -DestinationPath "`$backupFolder\wordpress_db.zip" -CompressionLevel Optimal
                            Remove-Item -Path `$dbBackupPath -Force
                            Write-Output "Database backup successful using alternative method."
                        } else {
                            Write-Output "ERROR: Could not retrieve table list from MySQL."
                        }
                    } catch {
                        Write-Output "ERROR: Alternative backup method failed."
                    } finally {
                        # Clear the password variable
                        Remove-Item env:MYSQL_PWD -ErrorAction SilentlyContinue
                    }
                }
            }
        } else {
            Write-Output "ERROR: MySQL connection failed. Skipping database backup."
            Write-Output "INFO: Only WordPress files will be backed up."
        }
    } catch {
        Write-Output "ERROR: Failed to back up database."
        Write-Output "  This could be due to MySQL server not running or invalid credentials."
        Write-Output "  Check that MySQL service is running and that the root password is correct."
    }
} else {
    Write-Output "WARNING: MySQL dump utility not found in any of the following locations:"
    foreach (`$path in `$possibleMySQLPaths | Where-Object { `$_ }) {
        Write-Output "  - `$path"
    }
    Write-Output "Skipping database backup. You may need to specify the correct MySQLServerPath."
}

# Clean up old backups
`$allBackups = Get-ChildItem -Path `$config.BackupPath -Directory | Sort-Object CreationTime -Descending | Select-Object -Skip `$config.BackupRetention
foreach (`$backup in `$allBackups) {
    Write-Output "Removing old backup: `$(`$backup.FullName)"
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

# Create rollback script to remove backups
$backupRollbackScript = @"
# Backup Rollback Script
# Generated on $(Get-Date)
# This script disables the WordPress automated backups

Write-Host "Disabling WordPress automated backups..." -ForegroundColor Yellow

# Remove scheduled task
if (Get-ScheduledTask -TaskName "WordPressBackup" -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName "WordPressBackup" -Confirm:`$false
    Write-Host "✓ Removed backup scheduled task" -ForegroundColor Green
} else {
    Write-Host "! Backup task not found" -ForegroundColor Yellow
}

# Remove backup script
if (Test-Path -Path "$backupScriptPath") {
    Remove-Item -Path "$backupScriptPath" -Force
    Write-Host "✓ Removed backup script" -ForegroundColor Green
} else {
    Write-Host "! Backup script not found" -ForegroundColor Yellow
}

Write-Host "WordPress backups have been disabled." -ForegroundColor Green
"@

# Ensure WordPress directory exists before writing the file
if (-not (Test-Path -Path $wordpressPath)) {
    New-Item -Path $wordpressPath -ItemType Directory -Force | Out-Null
}

Set-Content -Path "$wordpressPath\disable-backups.ps1" -Value $backupRollbackScript

# Run initial backup - only if MySQL is installed
"Running initial backup..."
if (Get-Service -Name "*mysql*" -ErrorAction SilentlyContinue) {
    # MySQL is installed, run the backup
    Start-Process "PowerShell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$backupScriptPath`"" -NoNewWindow
} else {
    "INFO: MySQL service not found. Initial backup will be run the next time MySQL is available."
    "INFO: You can manually run the backup script from: $backupScriptPath"
}

"Backup configuration complete."
