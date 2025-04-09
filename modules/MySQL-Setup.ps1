<#
================================= MySQL Server =================================
This module installs MySQL Server, creates a database for WordPress,
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

    # Download and extract MySQL with improved error handling
    "Downloading MySQL from $mysqlInstallerUrl..."
    try {
        # Try to use Invoke-WebRequest with TLS 1.2 explicitly enabled
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest $mysqlInstallerUrl -OutFile $mysqlZip -UseBasicParsing -ErrorAction Stop
        "MySQL download completed successfully."
    }
    catch {
        "Warning: Failed to download MySQL using Invoke-WebRequest: $($_.Exception.Message)"
        "Trying alternative download method..."
        
        try {
            # Try using .NET WebClient as an alternative
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($mysqlInstallerUrl, (Join-Path $PWD $mysqlZip))
            "MySQL download completed successfully using WebClient."
        }
        catch {
            "Error: Failed to download MySQL: $($_.Exception.Message)"
            "Please download MySQL manually from: $mysqlInstallerUrl"
            "Place the downloaded file at: $(Join-Path $PWD $mysqlZip)"
            $continueWithoutDownload = Read-Host "Continue with installation? (Y/N)"
            
            if ($continueWithoutDownload.ToUpper() -ne "Y") {
                "Installation aborted."
                return
            }
            
            if (-not (Test-Path $mysqlZip)) {
                "MySQL zip file not found. Installation cannot continue."
                return
            }
            "Continuing with existing file: $mysqlZip"
        }
    }

    # Check if the file was downloaded successfully
    if (Test-Path $mysqlZip) {
        "MySQL installer downloaded. Proceeding with extraction..."
        New-Item -Path $mysqlPath -ItemType Directory -Force | Out-Null
        
        try {
            Expand-Archive $mysqlZip -DestinationPath $mysqlPath -Force
            "MySQL extracted successfully."
        }
        catch {
            "Error extracting MySQL: $($_.Exception.Message)"
            "Installation cannot continue."
            return
        }
        
        Rename-Item "$mysqlPath\mysql-$mysqlVersion-winx64" "$mysqlServerPath"
    }
    else {
        "MySQL installer not found. Installation cannot continue."
        return
    }

    # Create data directory
    New-Item -Path $mysqlDataPath -ItemType Directory -Force | Out-Null

    # Backup MySQL config file if it exists
    $mysqlConfigPath = "$env:ProgramFiles\MySQL\MySQL Server $($config.MySQLVersion)\my.ini"
    if (Test-Path $mysqlConfigPath) {
        $backupPath = "$mysqlConfigPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        "Creating backup of MySQL configuration file to $backupPath..."
        Copy-Item -Path $mysqlConfigPath -Destination $backupPath -Force
        "MySQL configuration backup created successfully."
    }

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

    # Start MySQL service with error handling
    "Starting MySQL service..."
    try {
        Start-Service MySQL -ErrorAction Stop
        "MySQL service started successfully."
    }
    catch {
        "Failed to start MySQL service: $($_.Exception.Message)"
        "Attempting to diagnose and fix the issue..."
        
        # Check for common issues
        $errorLogPath = "$mysqlDataPath\$env:COMPUTERNAME.err"
        
        # Create diagnostic information for troubleshooting
        "TROUBLESHOOTING INFORMATION:" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log"
        "MySQL Version: $mysqlVersion" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "MySQL Server Path: $mysqlServerPath" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "MySQL Data Path: $mysqlDataPath" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "Windows Version:" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        (Get-WmiObject -Class Win32_OperatingSystem).Caption | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        
        # Check if error log exists and append it
        if (Test-Path $errorLogPath) {
            "MySQL Error Log Content:" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
            Get-Content $errorLogPath | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
            
            "MySQL error log found. Checking for common issues..."
            $errorLogContent = Get-Content $errorLogPath -Raw
            
            if ($errorLogContent -match "Can't create directory '(.*?)' for shared memory") {
                "The MySQL service failed to start because it can't create the shared memory directory."
                "Trying to fix permission issues on the data directory..."
                
                # Try to fix permission issues
                icacls $mysqlDataPath /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant "NT AUTHORITY\NetworkService:(OI)(CI)F" /T
                
                # Try to start the service again
                "Attempting to start MySQL service again..."
                try {
                    Start-Service MySQL -ErrorAction Stop
                    "MySQL service started successfully after fixing permissions."
                }
                catch {
                    "Still unable to start MySQL service. Please see the troubleshooting log at $env:TEMP\mysql-troubleshoot.log"
                    "You may need to manually install MySQL or consult the error log at $errorLogPath"
                }
            }
            elseif ($errorLogContent -match "Plugin 'caching_sha2_password' init function returned error") {
                "MySQL authentication plugin issue detected."
                "Try reinstalling with explicit authentication plugin settings."
            }
            else {
                "Check the MySQL error log at $errorLogPath for more details on why the service failed to start."
            }
        }
        else {
            "MySQL error log not found at $errorLogPath."
            "Check the Windows Event Log for service startup failures."
        }
        
        "COMMON TROUBLESHOOTING STEPS:" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "1. Verify no other MySQL instances are running" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "2. Make sure ports (default 3306) are not already in use" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "3. Check system firewall settings" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "4. Verify permissions on data directory" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        "5. Try restarting the computer" | Out-File -FilePath "$env:TEMP\mysql-troubleshoot.log" -Append
        
        "A troubleshooting log has been created at $env:TEMP\mysql-troubleshoot.log"
        "Would you like to continue with installation despite the MySQL service failure? (Y/N)"
        $continueAnyway = Read-Host
        
        if ($continueAnyway.ToUpper() -ne "Y") {
            "Installation aborted due to MySQL service failure."
            return
        }
        
        "Continuing installation despite MySQL service failure."
    }

    # Generate random strong passwords
    Add-Type -AssemblyName System.Web
    $global:mysqlRootPwd = [System.Web.Security.Membership]::GeneratePassword($config.MySQLRootPwdLength, 5)
    $global:mysqlWordPressPwd = [System.Web.Security.Membership]::GeneratePassword($config.MySQLUserPwdLength, 5)

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
                $global:mysqlWordPressPwd = [System.Web.Security.Membership]::GeneratePassword($config.MySQLUserPwdLength, 5)
            }
            
            # Ask for root password if needed
            if (-not $mysqlRootPwd) {
                $secureRootPwd = Read-Host "Enter MySQL root password" -AsSecureString
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureRootPwd)
                $global:mysqlRootPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
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
