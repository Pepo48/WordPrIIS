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
    
    $defaultChoice = if ($Default) { "Y" } else { "N" }
    $prompt = "$Prompt [$(if($Default){'Y/n'}else{'y/N'})]"
    
    do {
        $response = Read-Host -Prompt $prompt
        if ([string]::IsNullOrWhiteSpace($response)) {
            $response = $defaultChoice
        }
    } until ($response -match '^[yn]$')
    
    return $response -eq 'y'
}

# Function to get the server's IP address
function Get-ServerIPAddress {
    $ipAddress = (Get-NetIPAddress | Where-Object {
        ($_.AddressFamily -eq "IPv4") -and ($_.IPAddress -ne "127.0.0.1")
    }).IPAddress
    
    # Check if multiple IP addresses were found, use the first one if so
    if ($ipAddress -is [array]) {
        "Multiple IP addresses found on this server. Using the first available address."
        $ipAddress = $ipAddress[0]
    }
    
    return $ipAddress
}

# Creates a directory if it doesn't exist and sets IIS permissions
function New-IISSafeDirectory {
    param (
        [string]$Path,
        [switch]$RecursePermissions
    )
    
    if (-not (Test-Path -Path $Path)) {
        "Creating directory: $Path"
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
        
        # Set permissions
        $recurseSwitch = if ($RecursePermissions) { "/T" } else { "" }
        icacls "$Path" /grant "IUSR:(OI)(CI)(M)" /grant "IIS_IUSRS:(OI)(CI)(M)" $recurseSwitch
    }
}

function Import-WebAdministrationModule {
    # Check if the module is already imported
    if (-not (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue)) {
        # Try to import the module
        try {
            Import-Module WebAdministration -ErrorAction Stop
            return $true
        }
        catch {
            Write-Warning "Failed to import WebAdministration module: $_"
            Write-Warning "IIS management functionality may be limited."
            return $false
        }
    }
    return $true
}
