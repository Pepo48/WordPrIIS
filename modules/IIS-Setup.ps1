<#
======================== Internet Information Services =========================
This module installs and configures IIS (Internet Information Services)
which is the web server that will host the WordPress site.
#>

"`r`nInternet Information Server (IIS)..."
# Check if IIS is already installed
if (-not (Test-ComponentInstalled -Name "IIS" -TestScript { 
    (Get-WindowsFeature Web-Server).Installed -eq $true
})) {
    "Installing required IIS features for hosting WordPress..."
    try {
        Install-WindowsFeature -Name Web-Server, Web-Common-Http, Web-Static-Content, Web-Default-Doc, 
            Web-Dir-Browsing, Web-Http-Errors, Web-App-Dev, Web-CGI, Web-Health, 
            Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Security, 
            Web-Filtering, Web-Performance, Web-Stat-Compression, Web-Mgmt-Tools, 
            Web-Mgmt-Service, WAS, WAS-Process-Model, WAS-NET-Environment, 
            WAS-Config-APIs, Net-Framework-Core -IncludeManagementTools | Out-Null
        "IIS Installation Complete."
    }
    catch {
        "ERROR: Failed to install IIS components. $($_.Exception.Message)"
        "You may need to run this script as Administrator or install IIS manually through Server Manager."
        return $false
    }
}

# Define a better WebAdministration import function
function Import-WebAdministrationModule {
    try {
        # First try to import the module directly
        Import-Module WebAdministration -ErrorAction Stop
        return $true
    }
    catch {
        try {
            # If that fails, try to load the assembly and create the module
            Add-PSSnapin WebAdministration -ErrorAction Stop
            return $true
        }
        catch {
            try {
                # If both previous methods fail, try one more approach
                if (!(Get-Module -Name WebAdministration)) {
                    if (!(Get-Module -ListAvailable -Name WebAdministration)) {
                        # Try to install the module if not available
                        Install-WindowsFeature Web-Scripting-Tools -ErrorAction Stop | Out-Null
                        Import-Module WebAdministration -ErrorAction Stop
                    }
                    else {
                        Import-Module WebAdministration -ErrorAction Stop
                    }
                }
                return $true
            }
            catch {
                "ERROR: Could not import WebAdministration module. $($_.Exception.Message)"
                "This is required for IIS management. Ensure you are running as Administrator."
                "You may need to run: Install-WindowsFeature Web-Scripting-Tools -IncludeManagementTools"
                return $false
            }
        }
    }
}

# Enable IIS Remote Management Service if not already enabled
"`r`nChecking IIS Remote Management..."
# First, check if the Web Management Service is installed
if (-not (Get-Service -Name "WMSVC" -ErrorAction SilentlyContinue)) {
    "Installing Web Management Service..."
    try {
        Install-WindowsFeature -Name Web-Mgmt-Service -ErrorAction Stop | Out-Null
        "Web Management Service installed."
    }
    catch {
        "ERROR: Failed to install Web Management Service. $($_.Exception.Message)"
        "Remote management will not be available."
    }
}

# Now try to enable remote management if the service exists
if (Get-Service -Name "WMSVC" -ErrorAction SilentlyContinue) {
    if (-not (Test-ComponentInstalled -Name "IIS Remote Management" -TestScript {
        $prop = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -ErrorAction SilentlyContinue
        $prop -and $prop.EnableRemoteManagement -eq 1
    })) {
        "Enabling IIS Remote Management..."
        # Make sure the registry key exists
        if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -Force | Out-Null
        }
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" EnableRemoteManagement 1 -Type DWord
        Set-Service WMSVC -StartupType Automatic
        Start-Service WMSVC
        "IIS Remote Management Enabled."
    } else {
        "✓ IIS Remote Management is already enabled."
    }
} else {
    "WARNING: Web Management Service (WMSVC) not found. Remote IIS management will not be available."
}

"`r`nURL Rewrite Extension for IIS..."

# Import WebAdministration module safely using our improved function
$webAdminAvailable = Import-WebAdministrationModule

# Continue with IIS setup only if module is available
if ($webAdminAvailable) {
    # Check for RewriteModule
    if (-not (Get-WebGlobalModule -Name "RewriteModule" -ErrorAction SilentlyContinue)) {
        # Check if URL Rewrite is already installed
        if (-not (Test-ComponentInstalled -Name "URL Rewrite Module" -TestScript {
            $rewriteModule = Get-WebGlobalModule -Name "RewriteModule" -ErrorAction SilentlyContinue
            $null -ne $rewriteModule
        })) {
            "Installing URL Rewrite 2.1 module..."
            $rewriteUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
            $rewriteInstaller = "rewrite_amd64.msi"
            Invoke-WebRequest $rewriteUrl -OutFile $rewriteInstaller -ErrorAction Stop
            Start-Process "msiexec.exe" "/i $rewriteInstaller /qn" -Wait -NoNewWindow
            "URL Rewrite Installation Complete."
        }
    }

    "`r`nHTTP Compression Configuration..."
    # Check if HTTP compression is already properly configured
    if (-not (Test-ComponentInstalled -Name "HTTP Compression" -TestScript {
        # Check if dynamic compression is enabled
        $dynamicSection = Get-WebConfigurationProperty -Filter "system.webServer/urlCompression" -Name "doDynamicCompression" -PSPath "MACHINE/WEBROOT/APPHOST"
        $staticSection = Get-WebConfigurationProperty -Filter "system.webServer/urlCompression" -Name "doStaticCompression" -PSPath "MACHINE/WEBROOT/APPHOST"
        return $dynamicSection -and $staticSection
    })) {
        "Configuring HTTP compression for better performance..."
        
        # Enable compression features if not already installed
        Install-WindowsFeature -Name Web-Stat-Compression, Web-Dyn-Compression | Out-Null
        
        # Enable both static and dynamic compression
        Set-WebConfigurationProperty -Filter "system.webServer/urlCompression" -Name "doDynamicCompression" -Value "True" -PSPath "MACHINE/WEBROOT/APPHOST"
        Set-WebConfigurationProperty -Filter "system.webServer/urlCompression" -Name "doStaticCompression" -Value "True" -PSPath "MACHINE/WEBROOT/APPHOST"
        
        # Configure static compression (similar to gzip settings)
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression/staticTypes" -PSPath "MACHINE/WEBROOT/APPHOST" -Name "." -Value @()
        
        # Add MIME types for static compression (similar to gzip_types)
        $staticMimeTypes = @(
            "text/plain",
            "text/css", 
            "text/html",
            "text/xml", 
            "text/javascript",
            "application/javascript",
            "application/json",
            "application/xml", 
            "application/xhtml+xml",
            "application/rss+xml",
            "application/x-javascript",
            "application/atom+xml"
        )
        
        foreach ($mimeType in $staticMimeTypes) {
            Add-WebConfigurationProperty -Filter "system.webServer/httpCompression/staticTypes" -PSPath "MACHINE/WEBROOT/APPHOST" -Name "." -Value @{mimeType=$mimeType}
        }
        
        # Configure dynamic compression (for dynamic content)
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression/dynamicTypes" -PSPath "MACHINE/WEBROOT/APPHOST" -Name "." -Value @()
        
        # Add MIME types for dynamic compression
        $dynamicMimeTypes = @(
            "text/plain",
            "text/css", 
            "text/html",
            "text/xml", 
            "text/javascript",
            "application/javascript",
            "application/json",
            "application/xml", 
            "application/xhtml+xml",
            "application/rss+xml"
        )
        
        foreach ($mimeType in $dynamicMimeTypes) {
            Add-WebConfigurationProperty -Filter "system.webServer/httpCompression/dynamicTypes" -PSPath "MACHINE/WEBROOT/APPHOST" -Name "." -Value @{mimeType=$mimeType}
        }
        
        # Set compression level (similar to gzip_comp_level)
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression/dynamicCompressionLevel" -Name "value" -Value 4 -PSPath "MACHINE/WEBROOT/APPHOST"
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression/staticCompressionLevel" -Name "value" -Value 7 -PSPath "MACHINE/WEBROOT/APPHOST"
        
        # Set minimum file size for compression (similar to gzip_min_length)
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "minFileSizeForComp" -Value 1024 -PSPath "MACHINE/WEBROOT/APPHOST"
        
        # Enable compression for HTTP 1.0 requests as well
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "noCompressionForHttp10" -Value "False" -PSPath "MACHINE/WEBROOT/APPHOST"
        
        # Enable compression for proxied requests
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "noCompressionForProxies" -Value "False" -PSPath "MACHINE/WEBROOT/APPHOST"
        
        # Cache compressed files for better performance
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "staticCompressionDisableCpuUsage" -Value 80 -PSPath "MACHINE/WEBROOT/APPHOST"
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "dynamicCompressionDisableCpuUsage" -Value 80 -PSPath "MACHINE/WEBROOT/APPHOST"
        
        # Configure CPU usage threshold for dynamic compression
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "dynamicCompressionEnableCpuUsage" -Value 50 -PSPath "MACHINE/WEBROOT/APPHOST"
        Set-WebConfigurationProperty -Filter "system.webServer/httpCompression" -Name "staticCompressionEnableCpuUsage" -Value 50 -PSPath "MACHINE/WEBROOT/APPHOST"
        
        "HTTP Compression successfully configured. Content will be automatically compressed to improve performance."
    } else {
        "✓ HTTP Compression is already configured."
    }

    "`r`nVisual C++ Redistributables..."
    # Improved check for Visual C++ Redistributable installation with better idempotency
    if (-not (Test-ComponentInstalled -Name "Visual C++ Redistributable 2015-2022" -TestScript {
        # Using multiple detection methods for better reliability
        
        # Method 1: Check using Win32_Product (can be slow but thorough)
        $usingWMI = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { 
            $_.Name -like "Microsoft Visual C++ 2015-2022*" -and $_.Name -like "*x64*" 
        }
        
        # Method 2: Check registry for installed packages
        $using64BitRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName -like "Microsoft Visual C++ 2015-2022*" -and $_.DisplayName -like "*x64*" }
            
        # Method 3: Check registry for VC runtime DLL version
        $vcRuntimeExists = Test-Path "C:\Windows\System32\vcruntime140.dll"
        
        if ($vcRuntimeExists) {
            try {
                $dllInfo = Get-Item "C:\Windows\System32\vcruntime140.dll" -ErrorAction SilentlyContinue
                $dllVersion = $dllInfo.VersionInfo.ProductVersion
                $versionCheck = [System.Version]::Parse($dllVersion) -ge [System.Version]::Parse("14.20")
            }
            catch {
                $versionCheck = $false
            }
        }
        else {
            $versionCheck = $false
        }
        
        return $usingWMI -or $using64BitRegistry -or $versionCheck
    })) {
        "Installing Visual C++ 2015-2022 Redistributable..."
        $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        $vcRedistInstaller = "vc_redist_2022_x64.exe"
        
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest $vcRedistUrl -OutFile $vcRedistInstaller -UseBasicParsing -ErrorAction Stop
            Start-Process $vcRedistInstaller "/quiet /norestart" -Wait -NoNewWindow
            "Visual C++ Redistributable Installation Complete."
        }
        catch {
            "Warning: Failed to download or install Visual C++ Redistributable: $($_.Exception.Message)"
            "You may need to install it manually from: https://aka.ms/vs/17/release/vc_redist.x64.exe"
        }
    }
    else {
        "✓ Visual C++ Redistributable 2015-2022 is already installed."
    }
} else {
    "WARNING: WebAdministration module could not be loaded. IIS setup will be limited."
    "Please ensure IIS is installed with Web-Scripting-Tools feature and you're running as Administrator."
    "Try running the following command manually before running this script again:"
    "Install-WindowsFeature -Name Web-Server,Web-Scripting-Tools -IncludeManagementTools"
}
