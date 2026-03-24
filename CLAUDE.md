# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this codebase.

## Project Overview

Sitecore Hardening Verification is a security audit toolkit for Sitecore CMS websites. It performs automated security hardening checks and generates reports. The project is a monorepo containing:

1. **PowerShell toolkit** (`powershell/`) - The original CLI-based audit tool
2. **Chrome extension** (`chrome-extension/`) - A browser extension that runs the same checks from a popup UI
3. **Node.js CLI** (`cli/`) - CLI that reuses the chrome extension check modules

## Repository Structure

```
powershell/                          # PowerShell CLI toolkit
  report.ps1                         # Entry point: -Url and -Format parameters
  report-multiple.ps1                # Batch check multiple URLs
  report-multiple-csv.ps1            # Batch check from CSV input
  sitecore-hardening-report.psm1     # Core module with all check logic

chrome-extension/                    # Chrome Extension (Manifest V3)
  manifest.json                      # Extension config
  popup.html / popup.css / popup.js  # Popup UI
  service-worker.js                  # Background service worker
  checks/                            # Individual check modules (ES modules)
    check-runner.js                  # Orchestrator
    result.js                        # Shared PASS/FAIL/WARN constants and result factory
    sitecore-version.js              # Version detection (XM/XP via version XML)
    force-https.js                   # HTTPS redirect check
    deny-anonymous.js                # Anonymous access check
    limit-xsl.js                     # XSL file access check
    remove-headers.js                # Sensitive header check
    simple-file-check.js             # File hash fingerprinting
    unsupported-languages.js         # Language handling check
    xm-cloud.js                      # JSS / Content SDK + XM Cloud detection
    jss-version.js                   # SDK family and version range detection (scoring engine)
    xm-cloud-api-key.js             # XM Cloud API key exposure check
  data/
    version-hashes.json              # Pre-computed SHA256 hashes (generated)

cli/                                 # Node.js CLI (reuses chrome-extension/checks/)
  run.js                             # CLI entry point (Node.js 18+)

tests/                               # Detection verification
  known-sites.csv                    # Known sites with expected SDK family/version
  verify-detection.js                # Automated verification runner

data/                                # Shared data
  sitecore/                          # Known-good files for version fingerprinting

scripts/
  generate-hashes.ps1                # Generates version-hashes.json from data/sitecore/
```

## Documentation

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed documentation including:

- Complete function reference with line numbers
- Security checks performed
- Known issues and areas for improvement

See [SDK-VERSION-REFERENCE.md](SDK-VERSION-REFERENCE.md) for:

- Dependency fingerprint table for all known JSS and Content SDK versions
- Detection strategy and signal reliability
- Source data provenance

## Running the PowerShell Tool

```powershell
cd powershell
.\report.ps1 -Url "https://example.com" -Format Console
.\report.ps1 -Url "https://example.com" -Format Csv
```

## Running the Node.js CLI

Requires Node.js 18+. Reuses the Chrome extension's check modules directly.

```bash
node cli/run.js https://example.com
node cli/run.js url1 url2 url3
node cli/run.js --csv urls.csv
node cli/run.js --csv urls.csv --output results.csv
```

## Verifying Detection Accuracy

```bash
node tests/verify-detection.js
node tests/verify-detection.js --filter tonys
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

### Chrome Extension / CLI
1. `popup.js` gets the active tab URL and communicates with the service worker
2. `service-worker.js` receives messages and calls `check-runner.js`
3. `check-runner.js` orchestrates all checks sequentially, reporting progress
4. Individual check modules in `checks/` perform fetch requests and analyze responses
5. Results are sent back to the popup for rendering

### Headless Site Detection Flow (check-runner.js)

1. **JSS / Content SDK Detection** (`xm-cloud.js: checkIsJss`) — fetches HTML, checks for `__NEXT_DATA__` with Sitecore context (Pages Router) or RSC payloads with Sitecore markers (App Router)
2. **SDK Version Detection** (`jss-version.js: checkJssVersion`) — extracts chunk URLs from HTML, fetches up to 10 chunks, scans for bundle signals (package names, runtime identifiers, React version), scores against version candidates
3. **XM Cloud Detection** (`xm-cloud.js: checkIsXMCloud`) — searches HTML, `__NEXT_DATA__` JSON, and bundle content for `edge.sitecorecloud.io`
4. **API Key Exposure** (`xm-cloud-api-key.js`) — checks if `sitecoreApiKey` value is non-empty in the chunk that contains it

## Security Checks Performed

### Headless sites (JSS / Content SDK)

1. **Is JSS / Content SDK** - Detects Sitecore headless apps via Next.js data
2. **SDK Version** - Identifies SDK family (JSS / Content SDK) and major version range
3. **Is XM Cloud** - Detects XM Cloud via edge.sitecorecloud.io in HTML or bundles
4. **XM Cloud API Key** - Checks for exposed API keys in page chunks

### Traditional sites (XM/XP)

1. **Sitecore Version** - Detects Sitecore version via version XML
2. **Force HTTPS Redirect** - Verifies HTTP->HTTPS redirect
3. **Deny Anonymous Access** - Tests Sitecore admin path restrictions
4. **Limit Access to XSL** - Checks if .xslt files are blocked
5. **Remove Headers** - Verifies sensitive headers are stripped
6. **Simple File Check** - Version fingerprinting via file hash comparison
7. **Handle Unsupported Languages** - Tests language code handling

## Code Conventions

### PowerShell
- Functions use `Get-` prefix for checks that return data
- Functions use `Invoke-` prefix for entry points that orchestrate work
- All check functions return standardized `PSObject` via `Get-ResultObject`
- Constants `$PASS`, `$FAIL`, and `$WARN` used for consistent outcome values

### Chrome Extension
- ES modules with `import`/`export` (enabled by `"type": "module"` in manifest)
- Each check exports a single async function
- Shared `createResult(title, outcome, tests, details)` factory in `result.js`
- Constants `PASS`, `FAIL`, and `WARN` mirror the PowerShell convention

## Regenerating Version Hashes

When new Sitecore version fingerprint files are added to `data/sitecore/`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/generate-hashes.ps1
```

This updates `chrome-extension/data/version-hashes.json`.
