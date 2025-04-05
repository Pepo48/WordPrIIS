<#
=================================== Security ===================================
This module implements security enhancements such as IP restrictions for wp-admin,
security headers, and firewall configuration.
#>

"`r`nSecurity Configuration..."

# Detect if running in a test environment
$isTestEnvironment = $false
try {
    # More thorough detection for test environment
    $isTestEnvironment = ($PSScriptRoot -match "tests") -or 
                         ($env:GITHUB_WORKFLOW -match "test") -or 
                         ($env:CI -eq "true")
    
    # Don't check IIS path here as it can cause the circular dependency
    "Environment check: Test environment = $isTestEnvironment"
}
catch {
    "Warning: Error checking environment. Assuming test environment for safety."
    $isTestEnvironment = $true
}

# Import WebAdministration module safely
$webAdminAvailable = Import-WebAdministrationModule

# Configure security headers for WordPress
"Configuring security headers..."

# Ensure that we can safely access the IIS site path
if (-not $isTestEnvironment -and $webAdminAvailable) {
    # First verify that the site exists in IIS
    $wpSite = $null
    try {
        $wpSite = Get-Item "IIS:\Sites\$($config.SiteName)" -ErrorAction SilentlyContinue
    }
    catch {
        "Warning: Unable to access IIS site '$($config.SiteName)'. This may be normal in a test environment."
    }

    if ($wpSite) {
        # Continue with production security configuration
        $sitePath = "IIS:\Sites\$($config.SiteName)"

        # Add security headers at the site level
        $securityHeaders = @(
            @{name="X-Content-Type-Options"; value="nosniff"},
            @{name="X-Frame-Options"; value="SAMEORIGIN"},
            @{name="X-XSS-Protection"; value="1; mode=block"},
            @{name="Referrer-Policy"; value="strict-origin-when-cross-origin"}
        )

        # Add more restrictive headers in production mode
        if (-not $config.DevelopmentMode) {
            # Stricter Content-Security-Policy for production
            $cspValue = "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'"
        } else {
            # More permissive CSP for development
            $cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com; img-src 'self' data: https://ssl.google-analytics.com; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; frame-src 'self'"
        }

        $securityHeaders += @{name="Content-Security-Policy"; value=$cspValue}

        # Add HSTS header if HTTPS is enabled and not in development mode
        if ($config.UseHTTPS -and -not $config.DevelopmentMode) {
            $securityHeaders += @{name="Strict-Transport-Security"; value="max-age=31536000; includeSubDomains"}
        }

        # Add each header
        foreach ($header in $securityHeaders) {
            # Check if header already exists
            $existingHeader = Get-WebConfigurationProperty -PSPath $sitePath -Filter "system.webServer/httpProtocol/customHeaders/add[@name='$($header.name)']" -Name "." -ErrorAction SilentlyContinue
            
            if ($existingHeader) {
                # Update existing header
                Set-WebConfigurationProperty -PSPath $sitePath -Filter "system.webServer/httpProtocol/customHeaders/add[@name='$($header.name)']" -Name "value" -Value $header.value
            } else {
                # Add new header
                Add-WebConfigurationProperty -PSPath $sitePath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value $header
            }
        }
    }
    else {
        "Warning: IIS site '$($config.SiteName)' not found. Skipping security headers configuration."
    }
}
else {
    if (-not $webAdminAvailable) {
        "WARNING: WebAdministration module could not be loaded. Security configuration will be limited."
        "Please ensure IIS is installed and you're running as Administrator."
    } else {
        "Test environment detected: Skipping security headers configuration."
    }
}

# Configure IP restrictions for wp-admin if enabled
if ($config.RestrictWPAdmin) {
    "Configuring IP restrictions for the WordPress admin area..."
    
    if (-not $isTestEnvironment) {
        $wpAdminPath = Join-Path -Path $wordpressPath -ChildPath "wp-admin"
        
        # Check if the wp-admin directory exists
        if (Test-Path -Path $wpAdminPath) {
            # Create a web.config specifically for wp-admin directory
            $wpAdminWebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <security>
            <ipSecurity allowUnlisted="false">
$(
    $config.AllowedIPsForAdmin | ForEach-Object {
        "                <add ipAddress=`"$($_)`" allowed=`"true`" />"
    }
)
            </ipSecurity>
        </security>
    </system.webServer>
</configuration>
"@
            
            # Create the wp-admin directory if it doesn't exist (should already exist after WordPress installation)
            if (-not (Test-Path -Path $wpAdminPath)) {
                New-Item -Path $wpAdminPath -ItemType Directory -Force | Out-Null
            }
            
            # Save the web.config to wp-admin directory
            Set-Content -Path "$wpAdminPath\web.config" -Value $wpAdminWebConfig
            
            # Create a script to disable IP restrictions if needed
            $ipResetScript = @"
# Remove IP restrictions for WordPress admin
# Generated on $(Get-Date)

`$wpAdminPath = "$wpAdminPath"
Remove-Item -Path "`$wpAdminPath\web.config" -Force
Write-Output "IP restrictions removed from wp-admin"
"@
            Set-Content -Path "$wordpressPath\remove-ip-restrictions.ps1" -Value $ipResetScript
            
            "IP restrictions for WordPress admin area configured."
            "Created script to remove IP restrictions: $wordpressPath\remove-ip-restrictions.ps1"
        }
        else {
            "Warning: WordPress admin directory not found at '$wpAdminPath'. Skipping IP restrictions."
        }
    }
    else {
        "Test environment detected: Skipping wp-admin IP restrictions configuration."
    }
}
else {
    "IP restrictions for the WordPress admin area are disabled."
}

# Configure Windows Firewall if enabled
if ($config.ConfigureFirewall) {
    "Configuring Windows Firewall rules..."
    
    if (-not $isTestEnvironment) {
        # Define all required firewall rules
        $firewallRules = @(
            @{
                DisplayName = "Allow HTTP (TCP-In)"
                Protocol = "TCP"
                LocalPort = 80
                Action = "Allow"
                Direction = "Inbound"
                Condition = $true
            },
            @{
                DisplayName = "Allow HTTPS (TCP-In)"
                Protocol = "TCP"
                LocalPort = 443
                Action = "Allow"
                Direction = "Inbound"
                Condition = $config.UseHTTPS
            },
            @{
                DisplayName = "Allow RDP (TCP-In)"
                Protocol = "TCP"
                LocalPort = $config.RDPPort
                Action = "Allow"
                Direction = "Inbound"
                Condition = $config.PreventRDPLockout
            },
            @{
                DisplayName = "Allow WinRM (TCP-In)"
                Protocol = "TCP"
                LocalPort = 5985
                Action = "Allow"
                Direction = "Inbound"
                Condition = $config.PreventRDPLockout  # Also protect WinRM for remote management
            }
        )
        
        # Process each firewall rule
        foreach ($rule in $firewallRules) {
            if ($rule.Condition) {
                # Check for existing rules with the same display name first
                $exactNameRule = Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
                
                # Also check for any rules that might be functionally equivalent by port/protocol
                $similarRules = Get-NetFirewallRule -Direction $rule.Direction -Action $rule.Action -ErrorAction SilentlyContinue | 
                    ForEach-Object { 
                        $r = $_
                        $portFilter = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                        if ($portFilter -and $portFilter.Protocol -eq $rule.Protocol -and 
                            ($portFilter.LocalPort -contains $rule.LocalPort -or $portFilter.LocalPort -eq $rule.LocalPort)) {
                            $r
                        }
                    }
                
                if ($exactNameRule) {
                    "✓ Firewall rule already exists with exact name: $($rule.DisplayName)"
                    
                    # Verify and update settings if needed
                    $portFilter = $exactNameRule | Get-NetFirewallPortFilter
                    if ($portFilter.Protocol -ne $rule.Protocol -or 
                        $portFilter.LocalPort -ne $rule.LocalPort) {
                        
                        "Updating port/protocol settings for: $($rule.DisplayName)"
                        $exactNameRule | Get-NetFirewallPortFilter | 
                            Set-NetFirewallPortFilter -Protocol $rule.Protocol -LocalPort $rule.LocalPort
                    }
                    
                    # Ensure action and direction are correct
                    if ($exactNameRule.Action -ne $rule.Action -or $exactNameRule.Direction -ne $rule.Direction) {
                        "Updating action/direction settings for: $($rule.DisplayName)"
                        $exactNameRule | Set-NetFirewallRule -Action $rule.Action -Direction $rule.Direction
                    }
                }
                elseif ($similarRules) {
                    # Found functionally similar rules
                    $ruleList = ($similarRules | ForEach-Object { $_.DisplayName }) -join ", "
                    "✓ Found existing rules that already allow $($rule.Protocol) on port $($rule.LocalPort): $ruleList"
                    "  Skipping creation of redundant rule: $($rule.DisplayName)"
                }
                else {
                    # No similar rule exists, create a new one
                    New-NetFirewallRule -DisplayName $rule.DisplayName -Direction $rule.Direction `
                                       -Protocol $rule.Protocol -LocalPort $rule.LocalPort -Action $rule.Action | Out-Null
                    "✓ Created firewall rule: $($rule.DisplayName)"
                }
            }
        }
        
        # Block all other inbound connections to IIS except those explicitly allowed
        if ($config.FirewallDefaultDeny) {
            "⚠️ Setting firewall to block all inbound connections except those explicitly allowed..."
            
            if ($config.PreventRDPLockout) {
                "✓ RDP lockout prevention is enabled - port $($config.RDPPort) will remain accessible."
            } else {
                "⚠️ WARNING: You have chosen to block all inbound traffic without RDP protection."
                "This could lock you out of remote access to this server."
                $confirmLockout = Get-YesNoResponse -Prompt "Are you absolutely sure you want to continue?" -Default $false
                
                if (-not $confirmLockout) {
                    "Enabling RDP lockout prevention for safety..."
                    $config.PreventRDPLockout = $true
                    
                    # Create the RDP rule if it doesn't exist yet
                    $rdpRule = Get-NetFirewallRule -DisplayName "Allow RDP (TCP-In)" -ErrorAction SilentlyContinue
                    if (-not $rdpRule) {
                        New-NetFirewallRule -DisplayName "Allow RDP (TCP-In)" -Direction Inbound `
                                          -Protocol TCP -LocalPort $config.RDPPort -Action Allow | Out-Null
                        "✓ Created firewall rule: Allow RDP (TCP-In)"
                    }
                }
            }
            
            # Apply the default deny rule
            Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
            
            # Create a reset script to restore default firewall settings if needed
            $firewallResetScript = @"
# Reset Windows Firewall default settings
# Generated on $(Get-Date)

Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Allow
Write-Output "Firewall default inbound action reset to Allow"
"@
            Set-Content -Path "$wordpressPath\reset-firewall.ps1" -Value $firewallResetScript
            "Created script to reset firewall settings: $wordpressPath\reset-firewall.ps1"
        }
        
        "Windows Firewall configured."
    }
    else {
        "Test environment detected: Skipping Windows Firewall configuration."
    }
}
else {
    "Windows Firewall configuration is disabled."
}

"Security configuration complete."
