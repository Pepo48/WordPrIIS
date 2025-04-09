<#
======================== Domain Name Configuration ===========================
This module configures IIS for custom domain names.
#>

"`r`nDomain Name Configuration..."
"Configuring website for domain: $($config.Domain)"

# Import WebAdministration module safely
$webAdminAvailable = Import-WebAdministrationModule

# Only proceed with website checks if module is available
if ($webAdminAvailable) {
    # Check if site exists
    $site = Get-Website -Name $config.SiteName -ErrorAction SilentlyContinue
    if ($site) {
        # Update site bindings to include the domain name
        $httpBinding = Get-WebBinding -Name $config.SiteName -Protocol "http"

        if ($httpBinding) {
            # Update HTTP binding to use the domain
            Set-WebBinding -Name $config.SiteName -BindingInformation "*:80:" `
                          -PropertyName BindingInformation -Value "*:80:$($config.Domain)"
        }

        # Add host entry for local development if requested
        if ($config.ModifyHostsFile -and $config.Domain -ne "localhost") {
            "Adding entry to hosts file for local development..."
            $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
            $hostsContent = Get-Content -Path $hostsPath
            
            # Check if hosts entry already exists
            $entryExists = $hostsContent | Where-Object { $_ -match "^\s*127\.0\.0\.1\s+$($config.Domain)\s*$" }
            
            if (-not $entryExists) {
                $hostEntry = "`r`n127.0.0.1`t$($config.Domain)"
                Add-Content -Path $hostsPath -Value $hostEntry -ErrorAction SilentlyContinue
                
                if ($?) {
                    "✓ Added hosts file entry for $($config.Domain)"
                    
                    # Create a cleanup script to remove the hosts entry if needed
                    $hostsCleanupScript = @"
# Remove WordPress hosts file entry
# Generated on $(Get-Date)

`$hostsPath = "`$env:SystemRoot\System32\drivers\etc\hosts"
`$domain = "$($config.Domain)"

# Read hosts file content
`$hostsContent = Get-Content -Path `$hostsPath

# Filter out the entry we added
`$newContent = `$hostsContent | Where-Object { -not (`$_ -match "^\s*127\.0\.0\.1\s+`$domain\s*`$") }

# Write back to hosts file
Set-Content -Path `$hostsPath -Value `$newContent -Force

Write-Output "Removed hosts entry for `$domain"
"@
                    Set-Content -Path "$wordpressPath\remove-hosts-entry.ps1" -Value $hostsCleanupScript
                    "Created script to remove hosts entry: $wordpressPath\remove-hosts-entry.ps1"
                } else {
                    "⚠️ Failed to modify hosts file. You may need to run this script as administrator."
                }
            } else {
                "✓ Hosts file entry for $($config.Domain) already exists."
            }
        }
    }
} else {
    "WARNING: WebAdministration module could not be loaded. Domain setup will be limited."
    "Please ensure IIS is installed and you're running as Administrator."
}

"Domain configuration complete."
