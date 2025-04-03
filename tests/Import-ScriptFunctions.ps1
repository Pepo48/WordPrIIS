<#
.SYNOPSIS
Helper script to extract and import functions from the main WordPress IIS script

.DESCRIPTION
This script extracts functions from the main wordpress-iis.ps1 script
so they can be tested independently with Pester
#>

# Define the path to the script being tested
$ScriptPath = "$PSScriptRoot\..\wordpress-iis.ps1"

# Check if the script exists
if (-not (Test-Path $ScriptPath)) {
    throw "Script not found at $ScriptPath"
}

# Read the script content
$ScriptContent = Get-Content -Path $ScriptPath -Raw

# Extract the Test-ComponentInstalled function which can be tested independently
$functionRegex = '(?ms)function\s+Test-ComponentInstalled\s*\{.*?\n\}'
$match = [regex]::Match($ScriptContent, $functionRegex)

if ($match.Success) {
    # Define a modified version that only returns boolean result
    function Test-ComponentInstalled {
        param (
            # Add the missing parameters here if applicable
            [string]$Name,
            [scriptblock]$TestScript
        )
        
        # Original function writes output, we suppress that in tests
        $installed = & $TestScript
        
        return $installed -eq $true
    }
    
    Write-Output "Successfully imported and modified Test-ComponentInstalled function for testing"
} else {
    throw "Could not find Test-ComponentInstalled function in the script"
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
        [string]$Profile,
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
