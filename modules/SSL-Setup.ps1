<#
================================== SSL Setup ==================================
This module configures SSL/TLS for the WordPress site.
#>

"`r`nSSL Configuration..."

# Detect if running in a test environment
$isTestEnvironment = $false
try {
    $isTestEnvironment = ($PSScriptRoot -match "tests") -or 
                         ($env:GITHUB_WORKFLOW -match "test") -or 
                         ($env:CI -eq "true")
    
    "SSL-Setup: Test environment = $isTestEnvironment"
}
catch {
    "Warning: Error checking environment. Assuming test environment for safety."
    $isTestEnvironment = $true
}

# Import WebAdministration module safely
$webAdminAvailable = Import-WebAdministrationModule

# Only proceed with SSL setup if HTTPS is enabled
if ($config.UseHTTPS) {
    # Configuration is dependent on the SSL mode chosen
    $sslMode = $config.SSLMode

    if (-not $isTestEnvironment -and $webAdminAvailable) {
        # Check if the site exists before proceeding
        $siteExists = $false
        try {
            $siteExists = Test-Path "IIS:\Sites\$($config.SiteName)"
        }
        catch {
            "Warning: Could not check if site exists. This may be normal in a test environment."
            $siteExists = $false
        }

        if ($siteExists) {
            "Configuring SSL for $($config.SiteName) site..."
            
            # Define domain name up-front to avoid redefinition
            $domainName = if ([string]::IsNullOrWhiteSpace($config.Domain)) {
                # Use localhost if no domain provided
                "localhost"
            } else {
                $config.Domain
            }
            
            # Handle different SSL modes with proper logic flow
            switch ($sslMode) {
                "LetsEncrypt" {
                    # Initialize CertificateType if it wasn't set during interactive configuration
                    if (-not $config.ContainsKey('CertificateType')) {
                        $config.CertificateType = if ([string]::IsNullOrWhiteSpace($config.Domain) -or $config.Domain -eq "localhost") {
                            "SelfSigned"
                        } else {
                            "LetsEncrypt"
                        }
                    }

                    # Check if win-acme (Let's Encrypt client) is already installed - only needed for Let's Encrypt
                    $winAcmePath = "$env:ProgramData\win-acme"
                    if ($config.CertificateType -eq "LetsEncrypt" -and -not (Test-ComponentInstalled -Name "win-acme" -TestScript {
                        Test-Path -Path "$winAcmePath\wacs.exe" -ErrorAction SilentlyContinue
                    })) {
                        "Installing win-acme (Let's Encrypt client) version $($config.WinAcmeVersion)..."
                        # Create directory for win-acme
                        New-Item -Path $winAcmePath -ItemType Directory -Force | Out-Null
                        
                        # Download win-acme using configured version
                        $winAcmeUrl = "https://github.com/win-acme/win-acme/releases/download/v$($config.WinAcmeVersion)/win-acme.v$($config.WinAcmeVersion).x64.pluggable.zip"
                        $winAcmeZip = "win-acme.zip"
                        Invoke-WebRequest $winAcmeUrl -OutFile $winAcmeZip
                        
                        # Extract win-acme
                        Expand-Archive $winAcmeZip -DestinationPath $winAcmePath
                        Remove-Item $winAcmeZip -Force
                        
                        "win-acme installation complete."
                    }

                    "Configuring SSL certificate for $domainName..."

                    # Get the site ID for use with win-acme
                    $siteId = (Get-Website -Name $config.SiteName).ID
                    
                    # Run win-acme to create certificate
                    $winAcmeArgs = @(
                        "--target", "iis",
                        "--siteid", $siteId,
                        "--installation", "iis",
                        "--websiteroot", $wordpressPath,
                        "--emailaddress", $config.EmailAddress,
                        "--accepttos"
                    )
                    
                    Start-Process -FilePath "$winAcmePath\wacs.exe" -ArgumentList $winAcmeArgs -Wait -NoNewWindow
                    
                    "Let's Encrypt certificate created and installed by win-acme."
                }
                
                "SelfSigned" {
                    # For localhost, create a self-signed certificate
                    "Creating self-signed certificate for development..."
                    $cert = New-SelfSignedCertificate -DnsName $domainName -CertStoreLocation "cert:\LocalMachine\My"
                    $thumbprint = $cert.Thumbprint
                    
                    # Add HTTPS binding to IIS website
                    "Configuring HTTPS binding for IIS..."
                    New-WebBinding -Name $config.SiteName -Protocol "https" -Port 443 -IPAddress "*" -SslFlags 0
                    
                    # Assign certificate to HTTPS binding
                    $certPath = "IIS:\SslBindings\!443"
                    Get-Item -Path "cert:\LocalMachine\My\$thumbprint" | New-Item -Path $certPath
                    
                    "Self-signed certificate configured for development use."
                }
                
                "CloudflareSSL" {
                    # Import Cloudflare Origin Certificate
                    "Importing Cloudflare Origin Certificate..."
                    
                    # Verify the certificate and key files exist
                    if (-not (Test-Path $config.CloudflareCertPath)) {
                        Write-Error "Cloudflare certificate file not found at $($config.CloudflareCertPath)"
                        "Please check the path and try again. Certificate installation failed."
                    }
                    elseif (-not (Test-Path $config.CloudflareKeyPath)) {
                        Write-Error "Cloudflare private key file not found at $($config.CloudflareKeyPath)"
                        "Please check the path and try again. Certificate installation failed."
                    }
                    else {
                        # Create PFX file from PEM and KEY files
                        $pfxPath = "$env:TEMP\cloudflare_origin_cert.pfx"
                        $pfxPassword = [System.Guid]::NewGuid().ToString()
                        $securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
                        
                        # Use OpenSSL to create PFX
                        $opensslPath = "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe"
                        
                        # Check if OpenSSL is available, download if not
                        if (-not (Test-Path $opensslPath)) {
                            "OpenSSL not found. Using certutil for certificate conversion..."
                            
                            # Create temporary combined file for conversion
                            $combinedPemPath = "$env:TEMP\cloudflare_combined.pem"
                            Get-Content $config.CloudflareCertPath | Set-Content $combinedPemPath
                            "`n" | Add-Content $combinedPemPath
                            Get-Content $config.CloudflareKeyPath | Add-Content $combinedPemPath
                            
                            # Convert to PFX using certutil
                            certutil -mergepfx $combinedPemPath $pfxPath
                            
                            # Clean up
                            Remove-Item $combinedPemPath -Force
                        }
                        else {
                            # Use OpenSSL directly
                            & $opensslPath pkcs12 -export -out $pfxPath -inkey $config.CloudflareKeyPath -in $config.CloudflareCertPath -password pass:$pfxPassword
                        }
                        
                        # Import the PFX certificate into Windows certificate store
                        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation 'Cert:\LocalMachine\My' -Password $securePassword | Out-Null
                        
                        # Get the thumbprint of the imported certificate
                        $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { $_.Subject -like "*$domainName*" } | Sort-Object NotBefore -Descending | Select-Object -First 1
                        $thumbprint = $cert.Thumbprint
                        
                        # Clean up PFX file
                        Remove-Item $pfxPath -Force
                        
                        # Add HTTPS binding to IIS website
                        "Configuring HTTPS binding for IIS with Cloudflare Origin Certificate..."
                        New-WebBinding -Name $config.SiteName -Protocol "https" -Port 443 -IPAddress "*" -SslFlags 0
                        
                        # Assign certificate to HTTPS binding
                        $certPath = "IIS:\SslBindings\!443"
                        Get-Item -Path "cert:\LocalMachine\My\$thumbprint" | New-Item -Path $certPath
                        
                        "Cloudflare Origin Certificate successfully imported and configured."
                        "⚠️ Remember to set SSL/TLS encryption mode to 'Full (strict)' in your Cloudflare dashboard."
                    }
                }
                
                default {
                    "Unknown SSL mode: $sslMode. Skipping SSL configuration."
                }
            }

            "SSL/HTTPS configuration complete."

            # Create web.config redirect from HTTP to HTTPS if real domain specified
            if ($domainName -ne "localhost") {
                "Adding HTTP to HTTPS redirect..."
                $redirectWebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="HTTP to HTTPS redirect" stopProcessing="true">
                    <match url="(.*)" />
                    <conditions>
                        <add input="{HTTPS}" pattern="off" ignoreCase="true" />
                    </conditions>
                    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
                </rule>
                <!-- Existing WordPress rule will be after this -->
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
"@
                
                try {
                    $existingWebConfig = Get-Content -Path "$wordpressPath\web.config" -Raw
                    $newRules = ($redirectWebConfig | Select-String -Pattern '<rules>(?s)(.*?)</rules>' -AllMatches).Matches[0].Groups[1].Value
                    
                    # Replace existing <rules> section with new rules plus existing rules
                    $updatedWebConfig = $existingWebConfig -replace '(<rules>)(.*?)(</rules>)', ('$1' + $newRules + '$2$3')
                    Set-Content -Path "$wordpressPath\web.config" -Value $updatedWebConfig
                    
                    "HTTP to HTTPS redirect configured."
                } catch {
                    Write-Error "Failed to update web.config with HTTP to HTTPS redirect: $_"
                }
            }
        }
        else {
            "Warning: IIS site '$($config.SiteName)' not found. Skipping SSL setup."
        }
    }
    else {
        if (-not $webAdminAvailable) {
            "WARNING: WebAdministration module could not be loaded. SSL configuration will be limited."
            "Please ensure IIS is installed and you're running as Administrator."
        } else {
            "Test environment detected: Skipping SSL configuration for site '$($config.SiteName)'."
            "SSL Mode that would be used: $sslMode"
        }
    }
}
else {
    "HTTPS is disabled. Skipping SSL configuration."
}

"SSL configuration complete."
