# WordPrIIS: WordPress on IIS Automated Installer

## Overview

WordPrIIS is a comprehensive PowerShell script that automates the installation and configuration of WordPress on Windows Server 2022 with IIS, PHP 8.4, and MySQL 8.4. It's designed to provide a production-ready WordPress environment with enhanced security features and flexible configuration options.

## Features

- **Full Stack Installation**: Automatically installs and configures IIS, PHP 8.4, MySQL 8.4, and WordPress
- **Interactive Configuration**: Customize installation parameters through an interactive prompt
- **HTTPS Support**: Configures SSL/TTLS with Let's Encrypt certificates (via win-acme) or self-signed certificates for development
- **Enhanced Security**:
  - Security headers configuration (CSP, HSTS, XSS Protection, etc.)
  - IP restrictions for wp-admin area
  - Firewall configuration
  - Optional restrictive mode for production environments
- **Domain Management**: Supports custom domains with automatic configuration
- **Automated Backups**: Schedule regular backups of WordPress files and database
- **Idempotent Design**: Can be run multiple times without duplicating work
- **Reversible Changes**: Includes rollback scripts to undo configuration changes

## Requirements

- Windows Server 2022 (may work on Windows 10/11 with appropriate features)
- PowerShell 5.1 or higher (PowerShell 7.x recommended for best performance)
- Administrator privileges
- Internet connection

## Quick Start

### Basic Execution

```powershell
# Run with default settings (interactive mode)
.\wordpress-iis.ps1

# Run with elevated privileges (recommended)
powershell -ExecutionPolicy Bypass -File .\wordpress-iis.ps1

# Run in non-interactive mode (uses default values)
.\wordpress-iis.ps1 -NonInteractive
```

### Installation Path

By default, WordPress is installed to:
- WordPress files: `C:\inetpub\wordpress\`
- PHP: `C:\Program Files\PHP\v8.4\`
- MySQL: `C:\Program Files\MySQL\MySQL Server 8.4\`

## Configuration Options

The script begins with a configuration section you can modify directly:

```powershell
$config = @{
    # WordPress site details
    SiteName = "WordPress"
    SitePort = 80
    # Domain configuration
    Domain = ""  # Empty string = use IP address, otherwise set domain name
    UseHTTPS = $true
    EmailAddress = "admin@example.com"  # Used for Let's Encrypt
    # Security settings
    ConfigureFirewall = $true
    RestrictWPAdmin = $true
    AllowedIPsForAdmin = @("192.168.1.0/24")
    FirewallDefaultDeny = $false
    # Environment toggle
    DevelopmentMode = $true
    # And more...
}
```

Alternatively, the interactive mode will prompt you for these settings during execution.

## Detailed Features

### SSL/HTTPS Configuration

WordPrIIS can automatically configure HTTPS in two ways:
- For production domains: Using Let's Encrypt certificates via win-acme
- For development: Using self-signed certificates

### Security Enhancements

- **Security Headers**: Configures modern web security headers like CSP, HSTS, etc.
- **IP Restrictions**: Limits access to wp-admin to specified IP addresses
- **Firewall Rules**: Configures Windows Firewall for HTTP/HTTPS traffic
- **Remote Access Protection**: Special safeguards to prevent RDP lockout
- **Environment-Based Settings**: Different security levels for development vs production

### Backup System

WordPrIIS sets up automated backups with these default settings:
- Schedule: Daily at 3:00 AM (configurable to weekly or monthly)
- Retention: 7 backups (configurable)
- Location: `C:\WordPressBackups\` (configurable)
- Content: Both WordPress files and MySQL database

## Using Without a Domain Name

WordPrIIS fully supports installation without a domain name, using just your server's IP address:

1. When prompted for a domain name during interactive setup, simply leave it blank
2. The script will automatically configure WordPress to work with your server's IP address
3. You can access your WordPress site via http://your-server-ip-address/ (or https:// if SSL is enabled)

When you're ready to add a domain name later:

1. Purchase and configure your domain with DNS pointing to your server
2. Run the script again, this time entering your domain name when prompted
3. The script will detect the existing WordPress installation and reconfigure it for your domain
4. Let's Encrypt certificates will be automatically obtained if HTTPS is enabled

This approach allows you to start with a development/testing setup using just an IP address and seamlessly transition to a production environment with a proper domain name without having to reinstall WordPress.

## Management & Rollback

The installation creates several management scripts:

- **Main rollback script**: `C:\inetpub\wordpress\rollback-configuration.ps1`
- **IP restrictions removal**: `C:\inetpub\wordpress\remove-ip-restrictions.ps1`
- **Firewall reset**: `C:\inetpub\wordpress\reset-firewall.ps1`
- **Hosts file cleanup**: `C:\inetpub\wordpress\remove-hosts-entry.ps1`

These scripts allow you to easily undo specific configuration changes if needed.

## Post-Installation Steps

After running the script, you should:

1. Access your WordPress site at the URL shown at the end of the script
2. Complete the WordPress setup wizard
3. Install necessary plugins (security, caching, etc.)
4. Test your site thoroughly
5. Apply any additional security hardening measures

## Security Recommendations

Beyond what WordPrIIS sets up automatically, consider these additional measures:

- Keep WordPress core, themes, and plugins updated
- Use a Web Application Firewall (WAF)
- Implement a monitoring solution
- Use a CDN
- Use strong passwords for all accounts
- Restrict database access to necessary users

## Troubleshooting

Common issues:

1. **Script fails to run**: Ensure you're running as Administrator and have an internet connection
2. **Let's Encrypt certificate fails**: Ensure your domain is properly configured and accessible from the internet
3. **MySQL installation fails**: Check for existing MySQL installations that might conflict
4. **WordPress fails to connect to database**: Verify MySQL credentials in wp-config.

For detailed troubleshooting, check the installation log at the location shown at the end of the script.

## Customization

You can customize the script by:

1. Modifying the `$config` hash table at the beginning of the script
2. Adding additional components or plugins to the installation
3. Customizing security headers or other security settings
4. Adding post-installation steps like theme installation

## Advanced Customization

WordPrIIS is highly customizable through its configuration parameters:

### Component Versions
```powershell
# PHP and MySQL versions can be customized
$config.PHPVersion = "8.4.5"
$config.MySQLVersion = "8.4.4"
$config.WinAcmeVersion = "2.2.9.1701"
```

### Remote Access Protection
```powershell
# Prevent firewall from blocking RDP access
$config.PreventRDPLockout = $true
$config.RDPPort = 3389  # Default RDP port, change if needed
```

### Security Settings
```powershell
# Security settings can be adjusted
$config.FirewallDefaultDeny = $true  # Block all inbound except allowed
$config.DevelopmentMode = $false     # Stricter security in production mode
$config.AllowedIPsForAdmin = @("192.168.1.0/24", "10.0.0.5")
```

## License

This script is provided as-is under the MIT License.

## Acknowledgements

- WordPress - https://wordpress.org/
- PHP - https://www.php.net/
- MySQL - https://www.mysql.com/
- win-acme - https://github.com/win-acme/win-acme
