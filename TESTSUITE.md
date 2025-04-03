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

#### IIS Installation

Tests the code that installs and configures Internet Information Services (IIS).

#### PHP Installation

Tests the PHP download, extraction, and configuration functionality.

#### MySQL Installation

Tests the MySQL Server installation and database setup.

#### WordPress Installation

Tests WordPress download, extraction, and configuration.

#### Security Configuration

Tests security features including:
- Firewall rules
- IP restrictions for wp-admin area
- Security headers

#### Backup System

Tests the creation of backup scripts and scheduled tasks.

## Mocking Strategy

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
# Test specific components
Invoke-Pester -Path .\WordPrIIS.Tests.ps1 -TagFilter "IIS"

# Run tests with detailed output including code coverage
Invoke-Pester -Path .\WordPrIIS.Tests.ps1 -Output Detailed -CodeCoverage .\Import-ScriptFunctions.ps1
```

## Extending the Tests

When adding new functionality to the main script:

1. Extract the relevant functions in Import-ScriptFunctions.ps1
2. Add appropriate mocks for any new cmdlets used
3. Create new test cases in WordPrIIS.Tests.ps1
4. Ensure proper assertions are made to verify functionality
