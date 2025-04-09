<#
============================= Summary and Output ==============================
This module displays configuration information and next steps.
#>

# Get server IP address for access
$ipAddress = Get-ServerIPAddress

# Display summary information
"`r`n===================================================================="
"WordPress Installation Completed Successfully!"
"===================================================================="
"MySQL Credentials:"
"    Root Password: $mysqlRootPwd"
"    WordPress User: wordpress"
"    WordPress Password: $mysqlWordPressPwd"
"`r`nWordPress is installed at: $wordpressPath"
if (-not [string]::IsNullOrWhiteSpace($config.Domain)) {
    if ($config.UseHTTPS) {
        "You can access your WordPress site at: https://$($config.Domain)/"
    } else {
        "You can access your WordPress site at: http://$($config.Domain)/"
    }
} else {
    if ($config.UseHTTPS) {
        "You can access your WordPress site at: https://$($ipAddress):443/"
    } else {
        "You can access your WordPress site at: http://$($ipAddress):$($config.SitePort)/"
    }
}
"Rollback and Management:"
"To reverse configuration changes: $wordpressPath\rollback-configuration.ps1"
if ($config.RestrictWPAdmin) {
    "To remove IP restrictions: $wordpressPath\remove-ip-restrictions.ps1"
}
if ($config.FirewallDefaultDeny) {
    "To reset firewall settings: $wordpressPath\reset-firewall.ps1"
}
if ($config.ModifyHostsFile) {
    "To remove hosts file entry: $wordpressPath\remove-hosts-entry.ps1"
}
"Installation log saved to: $($config.LogPath)"
"===================================================================="
"Next Steps:"
"1. Open your browser and navigate to http://$ipAddress`:$($config.SitePort)/"
"2. Complete the WordPress setup wizard"
"3. Secure your installation by setting up HTTPS"
"4. Review the security recommendations below"
"===================================================================="

"`r`nSecurity Recommendations:"
"  - Set up HTTPS with a valid SSL certificate"
"  - Configure Windows Firewall to allow only needed ports"
"  - Implement regular WordPress updates"
"  - Use strong passwords for all accounts"
"  - Install security plugins like Wordfence or Sucuri"
"  - Set up regular database backups"

"===================================================================="
"WordPress Installation Complete."
"----------------------------------------"
"Production-ready enhancements added:"
if ($config.UseHTTPS) { 
    switch ($config.CertificateType) {
        "LetsEncrypt" { "✓ SSL/HTTPS configuration with Let's Encrypt" }
        "SelfSigned" { "✓ SSL/HTTPS configuration with self-signed certificate (development only)" }
        "CloudflareOrigin" { "✓ SSL/HTTPS configuration with Cloudflare Origin Certificate" }
        default { "✓ SSL/HTTPS configuration" }
    }
} else { 
    "✗ SSL/HTTPS not configured" 
}
if (-not [string]::IsNullOrWhiteSpace($config.Domain)) { "✓ Domain configuration for $($config.Domain)" } else { "✗ No domain configured" }
if ($config.ConfigureFirewall) { "✓ Windows Firewall rules" } else { "✗ Firewall not configured" }
"✓ Security headers configured"
if ($config.RestrictWPAdmin) { "✓ IP restrictions for WordPress admin" } else { "✗ No IP restrictions for admin" }
if ($config.ConfigureBackups) { "✓ Automated $($config.BackupSchedule.ToLower()) backups" } else { "✗ No backup configuration" }
"----------------------------------------"
