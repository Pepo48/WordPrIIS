# WordPrIIS: WordPress on IIS Automated Installer

## Overview

WordPrIIS is a comprehensive PowerShell script that automates the installation and configuration of WordPress on Windows Server 2022 with IIS, PHP 8.4, and MySQL 8.4. It's designed to provide a production-ready WordPress environment with enhanced security features and flexible configuration options.

## Features

- **Full Stack Installation**: Automatically installs and configures IIS, PHP 8.4, MySQL 8.4, and WordPress
- **Interactive Configuration**: Customize installation parameters through an interactive prompt
- **HTTPS Support**: Configures SSL/TTLS with Let's Encrypt certificates, Cloudflare Origin certificates, or self-signed certificates for development
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

## Interactive Configuration Steps Explained

When running in interactive mode, the script will prompt you for various settings. Here's what each option means:

### Site Configuration
- **Site name**: The name of your WordPress site in IIS (default: "WordPress")
- **HTTP port**: The port for HTTP traffic (default: 80)
- **Domain name**: Your website's domain name (leave empty to use server IP address)

### SSL/HTTPS Configuration
- **Configure HTTPS?**: Whether to set up SSL/TLS encryption
- **Certificate options**:
  1. **Let's Encrypt**: Automatically obtain and renew free certificates (requires public domain)
  2. **Self-signed**: Create a certificate for development (not trusted by browsers)
  3. **Cloudflare Origin**: Use certificates from Cloudflare for origin encryption
- **Email address**: Used for Let's Encrypt registration and expiry notifications (only required when using Let's Encrypt)

### Security Configuration
- **Configure Windows Firewall?**: Set up firewall rules for web traffic
- **Block all inbound traffic except allowed ports?**: Create restrictive firewall policy (caution: can block remote access)
- **Prevent RDP lockout**: Ensures remote desktop access remains available
- **Restrict wp-admin access by IP address?**: Limit WordPress admin area to specific IP addresses
- **Allowed IPs for wp-admin**: List of IP addresses/ranges allowed to access admin area

### Environment Configuration
- **Enable development mode?**: Less strict security settings for development

### Backup Configuration
- **Configure automated backups?**: Set up scheduled backups of files and database
- **Backup schedule**: Daily, Weekly, or Monthly backups
- **Number of backups to retain**: How many backup copies to keep
- **Backup storage path**: Where to store the backup files

### Advanced Settings
- **MySQL version**: Which MySQL version to install
- **PHP version**: Which PHP version to install
- **Win-acme version**: Which Let's Encrypt client version to use

## Detailed Features

### SSL/HTTPS Configuration

WordPrIIS can automatically configure HTTPS in three ways:
- **Let's Encrypt**: Free, auto-renewing certificates for public domains
- **Self-signed**: For development environments (generates browser warnings)
- **Cloudflare Origin Certificates**: For sites behind Cloudflare proxy

### Security Enhancements

- **Security Headers**: Configures modern web security headers:
  - Content-Security-Policy: Controls what resources can be loaded
  - X-Content-Type-Options: Prevents MIME type sniffing
  - X-Frame-Options: Prevents site from being embedded in frames
  - X-XSS-Protection: Helps prevent cross-site scripting attacks
  - Strict-Transport-Security: Forces HTTPS connections
  - Referrer-Policy: Controls how much referrer information is sent
  
- **IP Restrictions**: Limits access to wp-admin to specified IP addresses:
  - Creates a separate web.config in wp-admin folder
  - Blocks all IPs except the ones you specify
  - Provides easy rollback script if you lock yourself out
  
- **Firewall Rules**: Configures Windows Firewall for proper web traffic:
  - Opens HTTP (Port 80): Allows incoming traffic to reach your WordPress site over standard HTTP
  - Opens HTTPS (Port 443): Enables secure HTTPS connections when SSL is configured
  - Remote Desktop Protection (Port 3389): Ensures you don't get locked out of your server by preserving RDP access
  - WinRM Protection (Port 5985): Preserves Windows Remote Management functionality for remote administration
  - Default Deny Option: Can optionally block all other inbound traffic not explicitly allowed (with safety features to prevent lockout)
  - Custom Rule Creation: Each rule is created with appropriate names and parameters for easy management
  - Rollback Scripts: Provides scripts to restore default firewall settings if needed
  
- **Remote Access Protection**: Special safeguards to prevent RDP lockout:
  - Ensures Remote Desktop port remains accessible
  - Protects Windows Remote Management (WinRM) if needed
  
- **Environment-Based Settings**: Different security levels for development vs production:
  - Stricter Content-Security-Policy in production
  - HSTS in production mode
  - Development mode allows more permissive settings for testing

### Backup System

WordPrIIS sets up automated backups with these default settings:
- **Schedule**: Daily at 3:00 AM (configurable to weekly or monthly)
- **Retention**: 7 backups (configurable)
- **Location**: `C:\WordPressBackups\` (configurable)
- **Content**: Both WordPress files and MySQL database
- **Process**: Files are compressed and old backups are automatically removed

## Using Without a Domain Name

WordPrIIS fully supports installation without a domain name, using just your server's IP address:

1. When prompted for a domain name during interactive setup, simply leave it blank
2. The script will automatically configure WordPress to work with your server's IP address
3. You can access your WordPress site via http://your-server-IP-address/ (or https:// if SSL is enabled)

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

## Testing

### Automated Testing with Pester

WordPrIIS includes a comprehensive test suite built with Pester, PowerShell's testing framework. The tests verify script functionality without affecting the actual environment by mocking system commands.

#### Running Tests Locally

```powershell
# Install Pester if not already installed
Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck

# Navigate to the tests directory
cd c:\Users\pepo4\IdeaProjects\WordPrIIS\tests

# Run the tests
Invoke-Pester -Path .\WordPrIIS.Tests.ps1 -Output Detailed
```

#### Test Structure

The test suite consists of:

- **WordPrIIS.Tests.ps1**: Main test file containing test cases for each component
- **Import-ScriptFunctions.ps1**: Helper script that extracts functions from the main script for isolated testing

#### What's Being Tested

The tests verify that the script correctly:

1. Detects whether components are already installed
2. Installs and configures IIS
3. Installs and configures PHP
4. Installs and configures MySQL
5. Downloads and sets up WordPress
6. Configures HTTPS with Let's Encrypt or self-signed certificates
7. Sets up security features (firewall, IP restrictions)
8. Configures automated backups

#### Mocking Approach

The tests use Pester's mocking capabilities to:

- Prevent actual execution of system-modifying commands
- Simulate both successful and failure scenarios
- Verify that the script calls the right commands with the right parameters

#### CI/CD Integration

The repository includes GitHub Actions workflows to automatically test the script on every push or pull request. The workflow file is located at `.github/workflows/pester-tests.yml`

For full details on the testing suite, see the [testsuite.md](testsuite.md) file in the repository.

## License

This script is provided as-is under the MIT License.

## Acknowledgements

- WordPress - https://wordpress.org/
- PHP - https://www.php.net/
- MySQL - https://www.mysql.com/
- win-acme - https://github.com/win-acme/win-acme
