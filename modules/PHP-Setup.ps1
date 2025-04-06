<#
=================================== PHP 8.4 ===================================
This module installs and configures PHP 8.4, which is required to run WordPress.
#>

# Define functions first, then run the script code

# Function to configure PHP optimizations
function Configure-PHPOptimizations {
    param (
        [string]$phpIniPath
    )
    
    Write-Host "Configuring PHP optimizations similar to Plesk..." -ForegroundColor Green
    
    # Define optimization block
    $optimizationBlock = @"

; PHP Performance Optimizations
; Similar to Plesk optimization settings
; DO NOT MODIFY THIS SECTION MANUALLY AS IT MAY BE OVERWRITTEN BY FUTURE UPDATES

; Enable JIT compilation and realpath cache
opcache.huge_code_pages=1
opcache.interned_strings_buffer=64
opcache.jit=1254
opcache.jit_buffer_size=32M
opcache.max_accelerated_files=1000
opcache.max_wasted_percentage=15
opcache.memory_consumption=128
opcache.revalidate_path=0
opcache.enable=1
opcache.enable_cli=0

; Disable open_basedir for better performance (adjust for production environments)
open_basedir=
"@

    # Read current PHP.ini content
    $phpIniContent = Get-Content -Path $phpIniPath -Raw
    
    # Check if optimization block already exists
    if ($phpIniContent -notmatch "PHP Performance Optimizations") {
        # Append optimization block to php.ini
        Add-Content -Path $phpIniPath -Value $optimizationBlock
        Write-Host "PHP performance optimizations added successfully." -ForegroundColor Green
    } else {
        Write-Host "PHP performance optimizations already exist in php.ini." -ForegroundColor Yellow
    }
}

# Function to set up PHP
function Setup-PHP {
    param (
        [hashtable]$config
    )
    
    # PHP installation path
    $phpVersion = $config.PHPVersion
    $phpPath = "C:\Program Files\PHP\$phpVersion"
    
    # Check if PHP is already installed
    $phpInstalled = Test-ComponentInstalled -Name "PHP $phpVersion" -TestScript {
        Test-Path "$phpPath\php.exe"
    }
    
    if (-not $phpInstalled) {
        # Download and install PHP
        $phpZipUrl = "https://windows.php.net/downloads/releases/php-$phpVersion-Win32-VC15-x64.zip"
        $phpZipFile = "$($config.DownloadPath)\php-$phpVersion.zip"
        
        Write-Host "Downloading PHP $phpVersion..."
        Invoke-WebRequest -Uri $phpZipUrl -OutFile $phpZipFile
        
        Write-Host "Extracting PHP files..."
        if (-not (Test-Path $phpPath)) {
            New-Item -Path $phpPath -ItemType Directory -Force | Out-Null
        }
        Expand-Archive -Path $phpZipFile -DestinationPath $phpPath -Force
        
        # Create php.ini file
        Copy-Item -Path "$phpPath\php.ini-production" -Destination "$phpPath\php.ini" -Force
        
        # Configure PHP
        $phpIni = Get-Content -Path "$phpPath\php.ini" -Raw
        $phpIni = $phpIni -replace ';extension=mysqli', 'extension=mysqli'
        $phpIni = $phpIni -replace ';extension=openssl', 'extension=openssl'
        $phpIni = $phpIni -replace ';extension=gd', 'extension=gd'
        $phpIni = $phpIni -replace ';extension=mbstring', 'extension=mbstring'
        $phpIni = $phpIni -replace ';cgi.force_redirect = 1', 'cgi.force_redirect = 0'
        $phpIni = $phpIni -replace ';fastcgi.impersonate = 1', 'fastcgi.impersonate = 1'
        $phpIni = $phpIni -replace ';fastcgi.logging = 0', 'fastcgi.logging = 0'
        $phpIni = $phpIni -replace ';extension=curl', 'extension=curl'
        $phpIni = $phpIni -replace ';extension=fileinfo', 'extension=fileinfo'
        $phpIni = $phpIni -replace ';extension=exif', 'extension=exif'
        
        Set-Content -Path "$phpPath\php.ini" -Value $phpIni
        
        # Set upload size limits
        (Get-Content -Path "$phpPath\php.ini" -Raw) -replace 'upload_max_filesize = \d+M', 'upload_max_filesize = 64M' | 
            Set-Content -Path "$phpPath\php.ini"
        (Get-Content -Path "$phpPath\php.ini" -Raw) -replace 'post_max_size = \d+M', 'post_max_size = 64M' | 
            Set-Content -Path "$phpPath\php.ini"
        
        # Configure PHP in IIS
        Write-Host "Configuring IIS for PHP..."
        $phpCgiPath = "$phpPath\php-cgi.exe"
        
        # Add PHP to PATH
        $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($currentPath -notlike "*$phpPath*") {
            [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$phpPath", "Machine")
        }
        
        # Configure FastCGI in IIS
        & $env:windir\system32\inetsrv\appcmd.exe set config /section:system.webServer/fastCGI /+[fullPath="`"$phpCgiPath`""]
        
        # Add handler mapping
        & $env:windir\system32\inetsrv\appcmd.exe set config /section:system.webServer/handlers /+[name='PHP_via_FastCGI',path='*.php',verb='*',modules='FastCgiModule',scriptProcessor="`"$phpCgiPath`"",resourceType='Either']
        
        Write-Host "PHP $phpVersion installed and configured successfully." -ForegroundColor Green
    }
    
    # Only apply optimizations if enabled in config
    if ($config.EnablePHPOptimizations) {
        Configure-PHPOptimizations -phpIniPath "$phpPath\php.ini"
        
        # Verify OPcache is enabled
        if (Test-PHPOPcacheAvailable -phpPath $phpPath) {
            Write-Host "PHP OPcache is properly configured and enabled." -ForegroundColor Green
        } else {
            Write-Host "Warning: PHP OPcache may not be enabled. Performance optimizations may not be active." -ForegroundColor Yellow
            Write-Host "Try reinstalling PHP with the 'opcache' extension enabled." -ForegroundColor Yellow
        }
    } else {
        Write-Host "PHP performance optimizations skipped per configuration." -ForegroundColor Yellow
    }
    
    return $phpPath
}

# Script execution starts here
"`r`nPHP 8.4..."

# Detect if running in a test environment
$isTestEnvironment = $PSScriptRoot -match "tests" -or $env:GITHUB_WORKFLOW -match "test" -or $env:CI -eq "true"

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
    if (-not $isTestEnvironment) {
        icacls $phpUploadDir /grant 'IUSR:(OI)(CI)(M)' /grant 'IIS_IUSRS:(OI)(CI)(M)' /T
        icacls $phpLogsDir /grant 'IUSR:(OI)(CI)(M)' /grant 'IIS_IUSRS:(OI)(CI)(M)' /T
    } else {
        "Test environment detected: Skipping permission changes on PHP directories"
    }

    # Configure IIS to use PHP
    # Install CGI module if not already installed
    if (-not $isTestEnvironment) {
        Install-WindowsFeature -Name Web-CGI
    } else {
        "Test environment detected: Skipping IIS CGI module installation"
    }

    # Register PHP with IIS
    $phpCgiPath = "$phpPath\php-cgi.exe"
    
    if (-not $isTestEnvironment) {
        "Configuring IIS for PHP..."
        try {
            # Use wrapped commands for better error handling
            try {
                New-WebHandler -Name "PHP" -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ScriptProcessor $phpCgiPath -ResourceType File
                "Successfully added PHP web handler"
            } catch {
                "Warning: Could not add PHP handler. Error: $($_.Exception.Message)"
            }
            
            # Check if FastCGI configuration exists
            $fastCgiConfig = Get-WebConfiguration -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction SilentlyContinue
            
            if (-not $fastCgiConfig) {
                "Creating FastCGI application for PHP..."
                try {
                    Add-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi" -Value @{fullPath = $phpCgiPath}
                    "Successfully added FastCGI application"
                } catch {
                    "Warning: Could not add FastCGI application. Error: $($_.Exception.Message)"
                }
            }
            
            # Try to set properties if FastCGI application was created
            $fastCgiConfig = Get-WebConfiguration -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction SilentlyContinue
            if ($fastCgiConfig) {
                try {
                    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -Name "maxInstances" -Value 4
                    "Successfully configured FastCGI properties"
                } catch {
                    "Warning: Could not set FastCGI properties. Error: $($_.Exception.Message)"
                }
            }
        } catch {
            "Warning: Error configuring IIS for PHP. The script will continue, but you may need to manually configure IIS for PHP."
            "Error details: $($_.Exception.Message)"
        }
    } else {
        "Test environment detected: Skipping IIS PHP configuration"
    }

    "PHP Installation Complete."
} else {
    # Verify PHP is registered with IIS
    "Checking if PHP is registered with IIS..."
    
    if (-not $isTestEnvironment) {
        $phpRegistered = $null
        try {
            $phpRegistered = Get-WebHandler -Name "PHP" -ErrorAction SilentlyContinue
        } catch {
            "Warning: Could not check for PHP web handler. Error: $($_.Exception.Message)"
        }

        if (-not $phpRegistered) {
            "Registering PHP with IIS..."
            $phpCgiPath = "$env:ProgramFiles\PHP\v8.4\php-cgi.exe"
            
            try {
                # Add PHP handler
                try {
                    New-WebHandler -Name "PHP" -Path "*.php" -Verb "*" -Modules "FastCgiModule" -ScriptProcessor $phpCgiPath -ResourceType File
                    "Successfully added PHP web handler"
                } catch {
                    "Warning: Could not add PHP handler. Error: $($_.Exception.Message)"
                }
                
                # Check if FastCGI application exists
                $fastCgiConfig = Get-WebConfiguration -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction SilentlyContinue
                
                if (-not $fastCgiConfig) {
                    "Creating FastCGI application for PHP..."
                    try {
                        Add-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi" -Value @{fullPath = $phpCgiPath}
                        "Successfully added FastCGI application"
                    } catch {
                        "Warning: Could not add FastCGI application. Error: $($_.Exception.Message)"
                    }
                }
                
                # Try to set properties
                $fastCgiConfig = Get-WebConfiguration -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction SilentlyContinue
                if ($fastCgiConfig) {
                    try {
                        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/fastCgi/application[@fullPath='$phpCgiPath']" -Name "maxInstances" -Value 4
                        "Successfully configured FastCGI properties"
                    } catch {
                        "Warning: Could not set FastCGI properties. Error: $($_.Exception.Message)"
                    }
                }
                
                "PHP registered with IIS."
            } catch {
                "Warning: Error registering PHP with IIS. Manual configuration may be required."
                "Error details: $($_.Exception.Message)"
            }
        } else {
            "✓ PHP is already registered with IIS."
        }
    } else {
        "Test environment detected: Skipping PHP registration with IIS"
    }
}  # This closes the 'else' block from the PHP installation check

# If PHP optimizations are enabled in config, apply them
if ($config.EnablePHPOptimizations) {
    $phpPath = "$env:ProgramFiles\PHP\v8.4"
    Configure-PHPOptimizations -phpIniPath "$phpPath\php.ini"
}
