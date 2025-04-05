<#
.SYNOPSIS
    Helper script to extract functions from a PowerShell script for testing.
#>
param (
    [Parameter(Mandatory = $false)]
    [string]$ScriptPath = (Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath "wordpress-iis.ps1")
)

# First, try to use ModuleAdapter to access functions from modules
if (Test-Path "$PSScriptRoot\ModuleAdapter.ps1") {
    Write-Host "Using ModuleAdapter.ps1 to access module functions" -ForegroundColor Green
    . "$PSScriptRoot\ModuleAdapter.ps1"
    return
}

# If ModuleAdapter doesn't exist, fall back to original behavior
try {
    # Get the content of the script file
    $scriptContent = Get-Content -Path $ScriptPath -Raw -ErrorAction Stop
}
catch {
    throw "Failed to load script content from $ScriptPath. Error: $_"
}

# Extract function declarations from the script
$functions = [regex]::Matches($scriptContent, '(?ms)function\s+([\w-]+)\s*(?:\(([^)]*)\))?\s*\{(.*?)\n\}')

if ($functions.Count -eq 0) {
    Write-Warning "No functions found in the script."
    return
}

# Define each function in the current scope
foreach ($function in $functions) {
    $functionName = $function.Groups[1].Value
    $functionParams = $function.Groups[2].Value
    $functionBody = $function.Groups[3].Value
    
    # Create the function definition
    $functionDefinition = "function Script$functionName {"
    if (-not [string]::IsNullOrWhiteSpace($functionParams)) {
        $functionDefinition += "param($functionParams)"
    }
    $functionDefinition += $functionBody + "`n}"
    
    try {
        # Define the function
        Invoke-Expression $functionDefinition
        Write-Verbose "Defined function: Script$functionName" -Verbose
    }
    catch {
        Write-Warning "Failed to define function: Script$functionName. Error: $_"
    }
}

# Extract and set $config and other variables used in the script
try {
    $configMatch = [regex]::Match($scriptContent, '(?ms)\$config\s*=\s*@\{(.*?)\}')
    if ($configMatch.Success) {
        $configContent = $configMatch.Groups[1].Value
        Invoke-Expression "`$global:config = @{$configContent}"
        Write-Verbose "Defined `$config variable" -Verbose
    }
}
catch {
    Write-Warning "Failed to extract and define `$config variable. Error: $_"
}

# Mock required IIS cmdlets
function Get-WindowsFeature {
    param([string]$Name)
    return [PSCustomObject]@{ 
        Name = $Name
        Installed = $false
    }
}

function Install-WindowsFeature {
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string[]]$Name,
        [switch]$IncludeManagementTools
    )
    return $true
}

# Mock IIS web cmdlets
function New-Website {
    param(
        [string]$Name,
        [string]$PhysicalPath,
        [string]$ApplicationPool,
        [int]$Port
    )
    return [PSCustomObject]@{
        Name = $Name
        ID = 1
        State = "Started"
    }
}

function Get-Website {
    param([string]$Name)
    if ($Name -eq "WordPress") {
        return [PSCustomObject]@{
            Name = $Name
            ID = 1
            State = "Started"
        }
    }
    return $null
}

# Mock additional IIS cmdlets for WebAdministration
function Get-WebBinding {
    param(
        [string]$Name,
        [string]$Protocol
    )
    return [PSCustomObject]@{
        Name = $Name
        Protocol = $Protocol
        BindingInformation = "*:80:"
    }
}

function New-WebBinding {
    param(
        [string]$Name,
        [string]$Protocol,
        [int]$Port,
        [string]$IPAddress,
        [int]$SslFlags
    )
    return [PSCustomObject]@{
        Name = $Name
        Protocol = $Protocol
        Port = $Port
        IPAddress = $IPAddress
        SslFlags = $SslFlags
    }
}

function Set-WebBinding {
    param(
        [string]$Name,
        [string]$BindingInformation,
        [string]$PropertyName,
        [string]$Value
    )
    # Mock implementation
}

function New-WebAppPool {
    param(
        [string]$Name
    )
    return [PSCustomObject]@{
        Name = $Name
    }
}

function Set-ItemProperty {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value
    )
    # Mock implementation
}

function Start-Website {
    param(
        [string]$Name
    )
    # Mock implementation
}

function Remove-Website {
    param(
        [string]$Name,
        [switch]$ErrorAction
    )
    # Mock implementation
}

function New-WebHandler {
    param (
        [string]$Name,
        [string]$Path,
        [string]$Verb,
        [string]$Modules,
        [string]$ScriptProcessor,
        [string]$ResourceType
    )
    # Mock implementation
}

function Get-WebHandler {
    param (
        [string]$Name
    )
    # Mock implementation
    return $null
}

function Get-WebGlobalModule {
    param (
        [string]$Name
    )
    # Mock implementation
    return $null
}

function Get-WebConfigurationProperty {
    param (
        [string]$PSPath,
        [string]$Filter,
        [string]$Name
    )
    # Mock implementation
    return $null
}

function Set-WebConfigurationProperty {
    param (
        [string]$PSPath,
        [string]$Filter,
        [string]$Name,
        [object]$Value
    )
    # Mock implementation
}

function Add-WebConfigurationProperty {
    param (
        [string]$PSPath,
        [string]$Filter,
        [string]$Name,
        [object]$Value
    )
    # Mock implementation
}

function Clear-WebConfiguration {
    param (
        [string]$PSPath,
        [string]$Filter
    )
    # Mock implementation
}

# Create mock for scheduled task cmdlets
function New-ScheduledTaskAction {
    param(
        [string]$Execute,
        [string]$Argument
    )
    return [PSCustomObject]@{
        Execute = $Execute
        Arguments = $Argument
    }
}

function Get-ScheduledTask {
    param(
        [string]$TaskName,
        [switch]$ErrorAction
    )
    # Mock implementation
    return $null
}

function Register-ScheduledTask {
    param(
        [string]$TaskName,
        [object]$Action,
        [object]$Trigger,
        [string]$Description,
        [string]$RunLevel
    )
    # Mock implementation
}

function Unregister-ScheduledTask {
    param(
        [string]$TaskName,
        [switch]$Confirm
    )
    # Mock implementation
}

function New-ScheduledTaskTrigger {
    param(
        [switch]$Daily,
        [switch]$Weekly,
        [switch]$Monthly,
        [array]$DaysOfWeek,
        [int]$DaysOfMonth,
        [string]$At
    )
    return [PSCustomObject]@{
        DaysOfWeek = $DaysOfWeek
        DaysOfMonth = $DaysOfMonth
        At = $At
    }
}

# Firewall mocks
function Get-NetFirewallRule {
    param(
        [string]$DisplayName,
        [switch]$ErrorAction
    )
    # Mock implementation
    return $null
}

function New-NetFirewallRule {
    param(
        [string]$DisplayName,
        [string]$Direction,
        [string]$Protocol,
        [int]$LocalPort,
        [string]$Action
    )
    # Mock implementation
    return [PSCustomObject]@{
        DisplayName = $DisplayName
        Direction = $Direction
        Protocol = $Protocol
        LocalPort = $LocalPort
        Action = $Action
    }
}

function Set-NetFirewallProfile {
    param(
        [string]$Profile, # Changed back to match what's used in the test
        [string]$DefaultInboundAction
    )
    # Mock implementation
}

# System service mocks
function Get-Service {
    param(
        [string]$Name,
        [switch]$ErrorAction
    )
    # Mock implementation
    return $null
}

function Set-Service {
    param(
        [string]$Name,
        [string]$StartupType
    )
    # Mock implementation
}

function Start-Service {
    param(
        [string]$Name
    )
    # Mock implementation
}

# Mock WMI functions
function Get-WmiObject {
    param(
        [string]$Class,
        [scriptblock]$Where
    )
    # Mock implementation
    return $null
}

# Certificate mocks
function New-SelfSignedCertificate {
    param(
        [string]$DnsName,
        [string]$CertStoreLocation
    )
    return [PSCustomObject]@{
        Thumbprint = "ABCDEF1234567890"
    }
}

# Environment variable mocks
if (-not $env:SystemDrive) {
    $env:SystemDrive = "C:"
}

if (-not $env:ProgramFiles) {
    $env:ProgramFiles = "C:\Program Files"
}

if (-not $env:ProgramData) {
    $env:ProgramData = "C:\ProgramData"
}

if (-not $env:SystemRoot) {
    $env:SystemRoot = "C:\Windows"
}

if (-not $env:TEMP) {
    $env:TEMP = "C:\Temp"
}

Write-Output "Script functions setup complete for testing"
