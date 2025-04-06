<#
==================== Utility Functions =====================
Functions used across multiple script modules
#>

# Add a function to check if a component is already installed
function Test-ComponentInstalled {
    param (
        [string]$Name,
        [scriptblock]$TestScript
    )
    
    Write-Host "Checking if $Name is already installed..."
    $installed = & $TestScript
    
    if ($installed) {
        Write-Host "✓ $Name is already installed. Skipping installation."
        return $true
    } else {
        Write-Host "○ $Name needs to be installed."
        return $false
    }
}

# Function to prompt for yes/no values - used in interactive mode
function Get-YesNoResponse {
    param (
        [string]$Prompt,
        [bool]$Default = $true
    )
    
    $defaultChoice = if ($Default) { 'Y' } else { 'N' }
    $prompt = "$Prompt [$(if($Default){'Y/n'}else{'y/N'})]"
    
    do {
        $response = Read-Host -Prompt $prompt
        
        if ([string]::IsNullOrEmpty($response)) {
            return $Default
        }
        
        $response = $response.Trim().ToUpper()
        if ($response -eq 'Y' -or $response -eq 'YES') {
            return $true
        }
        if ($response -eq 'N' -or $response -eq 'NO') {
            return $false
        }
        
        Write-Host "Please enter Y or N."
    } while ($true)
}

# Function to get the primary IP address of the server
function Get-ServerIPAddress {
    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -ne "127.0.0.1" } | Sort-Object -Property InterfaceIndex
    
    if ($ipAddresses.Count -eq 0) {
        Write-Host "No IPv4 addresses found."
        return $null
    }
    
    if ($ipAddresses.Count -eq 1) {
        return $ipAddresses[0].IPAddress
    }
    
    Write-Host "Multiple IP addresses found. Please select one:"
    for ($i = 0; $i -lt $ipAddresses.Count; $i++) {
        Write-Host "[$i] $($ipAddresses[$i].IPAddress) ($($ipAddresses[$i].InterfaceAlias))"
    }
    
    $selection = Read-Host "Select the IP address to use [0-$($ipAddresses.Count - 1)]"
    if ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $ipAddresses.Count) {
        return $ipAddresses[[int]$selection].IPAddress
    } else {
        Write-Host "Invalid selection. Using the first IP address."
        return $ipAddresses[0].IPAddress
    }
}

# Creates a directory if it doesn't exist and sets IIS permissions
function New-IISSafeDirectory {
    param (
        [string]$Path,
        [switch]$RecursePermissions
    )
    
    if (-not (Test-Path -Path $Path)) {
        Write-Host "Creating directory: $Path"
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
        
        # Set permissions
        $recurseSwitch = if ($RecursePermissions) { '/T' } else { '' }
        # Use single quotes for permission strings to avoid parsing issues
        icacls $Path /grant 'IUSR:(OI)(CI)(M)' /grant 'IIS_IUSRS:(OI)(CI)(M)' $recurseSwitch
    }
}

# Import WebAdministration module safely
function Import-WebAdministrationModule {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning "WebAdministration module could not be imported. This is required for IIS management."
        Write-Host "`nTROUBLESHOOTING STEPS:" -ForegroundColor Yellow
        Write-Host "1. Ensure IIS is installed with Management Tools using one of these methods:" -ForegroundColor Cyan
        Write-Host "   a. Using Server Manager > Add Roles and Features > Web Server Role (IIS)"
        Write-Host "      - Make sure to check 'Management Tools' under Web Server Role"
        Write-Host "   b. Or run the following PowerShell command as administrator:"
        Write-Host "      Install-WindowsFeature -Name Web-Server,Web-Mgmt-Tools,Web-Mgmt-Console,Web-Scripting-Tools" -ForegroundColor Green
        Write-Host "2. After installing IIS with Management Tools, restart your PowerShell session"
        Write-Host "3. Run the WordPrIIS script again"
        Write-Host "`nNOTE: If running on Windows 10/11, use this command instead:" -ForegroundColor Yellow
        Write-Host "Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-ManagementConsole,IIS-ManagementScriptingTools" -ForegroundColor Green
        Write-Host ""
        return $false
    }
}

# Function to check if PHP OPcache is enabled
function Test-PHPOPcacheEnabled {
    param (
        [string]$PHPPath
    )
    
    if (-not (Test-Path "$PHPPath\php.exe")) {
        return $false
    }
    
    $phpInfo = & "$PHPPath\php.exe" -i
    return $phpInfo -match "opcache support => enabled"
}

# Function to check if admin user
function Test-IsAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to validate domain name format
function Test-DomainNameValid {
    param (
        [string]$DomainName
    )
    
    return $DomainName -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
}
