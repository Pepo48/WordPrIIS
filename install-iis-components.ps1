#Requires -RunAsAdministrator

# Script to install required IIS components for WordPrIIS
Write-Host "WordPrIIS - IIS Components Installer" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Detect OS version
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$isServer = $osInfo.ProductType -ne 1
$osCaption = $osInfo.Caption

Write-Host "Detected OS: $osCaption" -ForegroundColor Yellow
Write-Host ""

try {
    if ($isServer) {
        Write-Host "Installing IIS with Management Tools for Windows Server..." -ForegroundColor Cyan
        Write-Host "This may take a few minutes..." -ForegroundColor Yellow
        
        Install-WindowsFeature -Name Web-Server, Web-Mgmt-Tools, Web-Mgmt-Console, Web-Scripting-Tools -IncludeManagementTools
        
        Write-Host "`nVerifying installation..." -ForegroundColor Cyan
        $iisInstalled = Get-WindowsFeature -Name Web-Server
        $mgmtToolsInstalled = Get-WindowsFeature -Name Web-Mgmt-Tools
        
        if ($iisInstalled.Installed -and $mgmtToolsInstalled.Installed) {
            Write-Host "✅ IIS and Management Tools successfully installed!" -ForegroundColor Green
        } else {
            Write-Host "❌ IIS installation may have failed. Please check Server Manager." -ForegroundColor Red
        }
    } else {
        Write-Host "Installing IIS with Management Tools for Windows Client OS..." -ForegroundColor Cyan
        Write-Host "This may take a few minutes..." -ForegroundColor Yellow
        
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer, IIS-ManagementConsole, IIS-ManagementScriptingTools -All
        
        Write-Host "`nIIS components should now be installed." -ForegroundColor Green
        Write-Host "Please verify in 'Turn Windows features on or off' dialog." -ForegroundColor Yellow
    }
    
    Write-Host "`nTrying to import WebAdministration module..." -ForegroundColor Cyan
    if (Get-Module -Name WebAdministration -ListAvailable) {
        Import-Module WebAdministration
        Write-Host "✅ WebAdministration module is available and can be imported!" -ForegroundColor Green
    } else {
        Write-Host "❌ WebAdministration module is still not available." -ForegroundColor Red
        Write-Host "Try restarting your computer before running the WordPrIIS installer again." -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Error occurred during installation: $_" -ForegroundColor Red
    Write-Host "Please try installing the components manually through Server Manager or Control Panel." -ForegroundColor Yellow
}

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Restart your PowerShell session or computer" -ForegroundColor White
Write-Host "2. Run the WordPrIIS installer script again" -ForegroundColor White
Write-Host ""
