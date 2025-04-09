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

    # Download and extract MySQL
    Invoke-WebRequest $mysqlInstallerUrl -OutFile $mysqlZip
    New-Item -Path $mysqlPath -ItemType Directory -Force | Out-Null
    Expand-Archive $mysqlZip -DestinationPath $mysqlPath
    Rename-Item "$mysqlPath\mysql-$mysqlVersion-winx64" "$mysqlServerPath"

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

    # Start MySQL service
    Start-Service MySQL

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
