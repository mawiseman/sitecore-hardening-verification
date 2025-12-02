# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this codebase.

## Project Overview

Sitecore Hardening Verification is a PowerShell-based security audit toolkit for Sitecore CMS websites. It performs automated security hardening checks and generates reports in multiple formats.

## Documentation

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed documentation including:
- Complete function reference with line numbers
- Security checks performed
- Known issues and areas for improvement

## Key Files

- `report.ps1` - Entry point script, accepts `-Url` and `-Format` parameters
- `sitecore-hardening-report.psm1` - Core module with all check logic and report generators
- `sitecore/` - Contains known-good file hashes for Sitecore version fingerprinting

## Running the Tool

```powershell
# Console output
.\report.ps1 -Url "https://example.com" -Format Console

# HTML report
.\report.ps1 -Url "https://example.com" -Format Html

# CSV report
.\report.ps1 -Url "https://example.com" -Format Csv
```

## Architecture

1. `report.ps1` imports the module and routes to the appropriate report function
2. `Get-HardeningChecks` orchestrates all security checks against the target URL
3. Individual `Get-HardeningResult*` functions perform specific security tests
4. Report functions (`Invoke-*Report`, `Write-*Report`) format and output results

## Security Checks Performed

1. **Force HTTPS Redirect** - Verifies HTTP→HTTPS redirect
2. **Deny Anonymous Access** - Tests Sitecore admin path restrictions
3. **Limit Access to XSL** - Checks if .xslt files are blocked
4. **Remove Headers** - Verifies sensitive headers are stripped
5. **Simple File Check** - Version fingerprinting via file hash comparison
6. **Handle Unsupported Languages** - Tests language code handling

## Code Conventions

- Functions use `Get-` prefix for checks that return data
- Functions use `Invoke-` prefix for entry points that orchestrate work
- All check functions return standardized `PSObject` via `Get-ResultObject`
- Constants `$PASS` and `$FAIL` used for consistent outcome values
