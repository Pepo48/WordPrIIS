# WordPrIIS Test Suite

This document provides detailed information about the testing suite for the WordPrIIS script.

> **Note:** For a quick overview of testing capabilities and instructions, please refer to the [Testing section in the README.md](README.md#testing).

## Detailed Test Components

The test suite uses Pester (PowerShell testing framework) to mock system functions and test the script's functionality without making actual changes to the environment. This allows for safe testing of the installation logic.

### Test File Structure

- **WordPrIIS.Tests.ps1**: Main test file that contains test cases for each component
- **Import-ScriptFunctions.ps1**: Helper script that extracts functions from the main script for isolated testing

### Component Testing

Each major component of the WordPrIIS script is tested individually:

#### Component Detection System

Tests the `Test-ComponentInstalled` function to ensure it correctly identifies whether components are already installed.

```powershell
Describe "Test-ComponentInstalled Function" {
    It "Returns true when component is already installed" {
        # Test implementation
    }
    
    It "Returns false when component is not installed" {
        # Test implementation
    }
}
```

#### Module Testing

With the new modular architecture, each module is tested independently:

- **Config.ps1**: Tests that configuration settings are properly defined
- **Utils.ps1**: Tests utility functions like `Test-ComponentInstalled` and `Get-YesNoResponse`
- **IIS-Setup.ps1**: Tests IIS installation and configuration
- **PHP-Setup.ps1**: Tests PHP download, extraction, and configuration
- **MySQL-Setup.ps1**: Tests MySQL Server installation and database setup
- **WordPress-Setup.ps1**: Tests WordPress download, extraction, and configuration
- **SSL-Setup.ps1**: Tests SSL certificate creation and configuration
- **Domain-Setup.ps1**: Tests domain name configuration
- **Security.ps1**: Tests security features including firewall rules and IP restrictions
- **Backup-Setup.ps1**: Tests backup system configuration
- **Rollback-Scripts.ps1**: Tests creation of rollback scripts
- **Summary.ps1**: Tests summary output generation

### Mocking Strategy

The tests use extensive mocking to prevent any real system changes:

1. System commands are mocked to return success without doing anything
2. File operations are intercepted and simulated
3. IIS operations are simulated with mock cmdlets

### Key Mocked Functions

```powershell
# Core system operations
Mock Start-Process { return @{ ExitCode = 0 } }
Mock Invoke-WebRequest {}
Mock Expand-Archive {}
Mock New-Item { return [PSCustomObject]@{ FullName = $Path } }
Mock Set-Content {}
Mock Get-Content { return @("test content") }

# IIS-specific operations
Mock Get-Website { return @{ Name = "WordPress"; ID = 1; State = "Started" } }
Mock New-Website {}
Mock New-WebBinding {}

# Security operations
Mock New-NetFirewallRule {}
Mock Set-NetFirewallProfile {}
```

## Running Advanced Test Scenarios

For specialized testing scenarios:

```powershell
# Test specific modules
Invoke-Pester -Path .\WordPrIIS.Tests.ps1 -TagFilter "MySQL"

# Run tests with detailed output including code coverage
Invoke-Pester -Path .\WordPrIIS.Tests.ps1 -Output Detailed -CodeCoverage ..\modules\*.ps1
```

## Updating Tests for Modular Architecture

When testing the modular architecture:

1. Import the specific module you want to test
2. Create mocks for functions it depends on
3. Write tests for the functions in that module
4. Ensure proper assertions to verify functionality

Example for testing a module:

```powershell
BeforeAll {
    # Import the module to test
    . "$PSScriptRoot\..\modules\Utils.ps1"
    
    # Create necessary mocks
    Mock Write-Host {}
}

Describe "Utils Module" {
    It "Test-ComponentInstalled returns correct results" {
        # Test implementation
    }
}
```

## Extending the Tests

When adding new functionality to the main script:

1. Create a new module in the modules directory
2. Update Import-ScriptFunctions.ps1 to include your new functions
3. Add appropriate mocks for any new cmdlets used
4. Create new test cases in WordPrIIS.Tests.ps1 or a new test file
5. Ensure proper assertions are made to verify functionality
