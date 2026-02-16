# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this codebase.

## Project Overview

Sitecore Hardening Verification is a security audit toolkit for Sitecore CMS websites. It performs automated security hardening checks and generates reports. The project is a monorepo containing:

1. **PowerShell toolkit** (`powershell/`) - The original CLI-based audit tool
2. **Chrome extension** (`chrome-extension/`) - A browser extension that runs the same checks from a popup UI

## Repository Structure

```
powershell/                          # PowerShell CLI toolkit
  report.ps1                         # Entry point: -Url and -Format parameters
  report-multiple.ps1                # Batch check multiple URLs
  report-multiple-csv.ps1            # Batch check from CSV input
  sitecore-hardening-report.psm1     # Core module with all check logic
  sitecore/                          # Known-good file hashes for version fingerprinting

chrome-extension/                    # Chrome Extension (Manifest V3)
  manifest.json                      # Extension config
  popup.html / popup.css / popup.js  # Popup UI
  service-worker.js                  # Background service worker
  checks/                            # Individual check modules (ES modules)
    check-runner.js                  # Orchestrator
    result.js                        # Shared PASS/FAIL constants and result factory
    sitecore-version.js              # Version detection
    force-https.js                   # HTTPS redirect check
    deny-anonymous.js                # Anonymous access check
    limit-xsl.js                     # XSL file access check
    remove-headers.js                # Sensitive header check
    simple-file-check.js             # File hash fingerprinting
    unsupported-languages.js         # Language handling check
    xm-cloud.js                      # XM Cloud / JSS detection
  data/
    version-hashes.json              # Pre-computed SHA256 hashes (generated)

scripts/
  generate-hashes.ps1                # Generates version-hashes.json from powershell/sitecore/
```

## Documentation

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed documentation including:
- Complete function reference with line numbers
- Security checks performed
- Known issues and areas for improvement

## Running the PowerShell Tool

```powershell
cd powershell
.\report.ps1 -Url "https://example.com" -Format Console
.\report.ps1 -Url "https://example.com" -Format Csv
```

## Loading the Chrome Extension

1. Open `chrome://extensions/` in Chrome
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `chrome-extension/` folder
4. Navigate to a Sitecore site and click the extension icon

## Architecture

### PowerShell
1. `report.ps1` imports the module and routes to the appropriate report function
2. `Get-HardeningChecks` orchestrates all security checks against the target URL
3. Individual `Get-HardeningResult*` functions perform specific security tests
4. Report functions (`Invoke-*Report`, `Write-*Report`) format and output results

### Chrome Extension
1. `popup.js` gets the active tab URL and communicates with the service worker
2. `service-worker.js` receives messages and calls `check-runner.js`
3. `check-runner.js` orchestrates all checks sequentially, reporting progress
4. Individual check modules in `checks/` perform fetch requests and analyze responses
5. Results are sent back to the popup for rendering

## Security Checks Performed

1. **Sitecore Version** - Detects Sitecore version via version XML
2. **Force HTTPS Redirect** - Verifies HTTP->HTTPS redirect
3. **Deny Anonymous Access** - Tests Sitecore admin path restrictions
4. **Limit Access to XSL** - Checks if .xslt files are blocked
5. **Remove Headers** - Verifies sensitive headers are stripped
6. **Simple File Check** - Version fingerprinting via file hash comparison
7. **Handle Unsupported Languages** - Tests language code handling
8. **Is XM Cloud** - Detects XM Cloud / JSS sites via Next.js data

## Code Conventions

### PowerShell
- Functions use `Get-` prefix for checks that return data
- Functions use `Invoke-` prefix for entry points that orchestrate work
- All check functions return standardized `PSObject` via `Get-ResultObject`
- Constants `$PASS` and `$FAIL` used for consistent outcome values

### Chrome Extension
- ES modules with `import`/`export` (enabled by `"type": "module"` in manifest)
- Each check exports a single async function
- Shared `createResult(title, outcome, tests, details)` factory in `result.js`
- Constants `PASS` and `FAIL` mirror the PowerShell convention

## Regenerating Version Hashes

When new Sitecore version fingerprint files are added to `powershell/sitecore/`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/generate-hashes.ps1
```

This updates `chrome-extension/data/version-hashes.json`.
