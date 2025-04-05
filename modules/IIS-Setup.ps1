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
    Install-WindowsFeature -Name Web-Server, Web-Common-Http, Web-Static-Content, Web-Default-Doc, 
        Web-Dir-Browsing, Web-Http-Errors, Web-App-Dev, Web-CGI, Web-Health, 
        Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Security, 
        Web-Filtering, Web-Performance, Web-Stat-Compression, Web-Mgmt-Tools, 
        Web-Mgmt-Service, WAS, WAS-Process-Model, WAS-NET-Environment, 
        WAS-Config-APIs, Net-Framework-Core -IncludeManagementTools | Out-Null
    "IIS Installation Complete."
}

# Enable IIS Remote Management Service if not already enabled
if (-not (Test-ComponentInstalled -Name "IIS Remote Management" -TestScript {
    $prop = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -ErrorAction SilentlyContinue
    $prop -and $prop.EnableRemoteManagement -eq 1
})) {
    "Enabling IIS Remote Management..."
    Set-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server EnableRemoteManagement 1
    Set-Service WMSVC -StartupType Automatic
    Start-Service WMSVC
    "IIS Remote Management Enabled."
}

"`r`nURL Rewrite Extension for IIS..."

# Import WebAdministration module safely
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
    # Check if Visual C++ Redistributable is already installed
    if (-not (Test-ComponentInstalled -Name "Visual C++ Redistributable 2015-2022" -TestScript {
        Get-WmiObject -Class Win32_Product | Where-Object { 
            $_.Name -like "Microsoft Visual C++ 2015-2022*" -and $_.Name -like "*x64*" 
        }
    })) {
        "Installing Visual C++ 2015-2022 Redistributable..."
        $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        $vcRedistInstaller = "vc_redist_2022_x64.exe"
        Invoke-WebRequest $vcRedistUrl -OutFile $vcRedistInstaller -ErrorAction Stop
        Start-Process $vcRedistInstaller "/quiet /norestart" -Wait -NoNewWindow
        "Visual C++ Redistributable Installation Complete."
    }
} else {
    "WARNING: WebAdministration module could not be loaded. IIS setup will be limited."
    "Please ensure IIS is installed and you're running as Administrator."
}
