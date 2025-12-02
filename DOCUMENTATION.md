# Sitecore Hardening Verification Scripts - Documentation

## Overview

This is a **security audit toolkit** for Sitecore CMS websites. It performs automated security hardening verification checks against Sitecore instances and can output results in multiple formats (Console, HTML, CSV).

---

## File: report.ps1

**Purpose:** Entry point script that orchestrates the hardening verification process.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-Url` | string | Yes | (prompts) | Target URL to scan |
| `-Format` | string | No | `Console` | Output format: `Console` or `Csv` |

**Functionality:**
1. Imports the main module `sitecore-hardening-report.psm1`
2. Routes to appropriate report function based on format:
   - `Console` → `Invoke-ConsoleReport`
   - `Csv` → `Invoke-CsvReport` (outputs to `c:\temp\report.csv`)

---

## File: sitecore-hardening-report.psm1

**Purpose:** Core module containing all hardening check logic and report generation functions.

### Constants
- `$PASS` = "Pass"
- `$FAIL` = "Fail"

---

### Utility Functions

| Function | Lines | Purpose |
|----------|-------|---------|
| `EnableTLS` | 9-21 | Forces TLS 1.2 for web requests |
| `Remove-InvalidFileNameChars` | 23-35 | Sanitizes filenames by removing invalid characters |
| `Join-Uri` | 37-49 | Combines base URI with child path |
| `Get-RedirectedUrl` | 51-97 | Resolves final URL after redirects, handles connection errors |
| `Get-ResultObject` | 99-122 | Creates standardized PSObject with Title, Outcome, Tests, Details |

---

### Version Detection

| Function | Lines | Purpose |
|----------|-------|---------|
| `Get-SitecoreVersion` | 124-175 | Attempts to read `/sitecore/shell/sitecore.version.xml` to determine Sitecore version. Returns version string or status codes (401/403 = "Probably Sitecore") |

---

### Security Hardening Checks

| Function | Lines | Check Type | Sitecore Doc Reference |
|----------|-------|------------|------------------------|
| `Get-HardeningResultDenyAnonymousAccess` | 177-270 | Tests if anonymous access to `/sitecore/admin/`, `/sitecore/debug/`, `/sitecore/login`, `/sitecore/shell/WebService/` is denied | [Deny anonymous access](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html) |
| `Get-HardeningResultLimitAccessToXSL` | 272-328 | Tests if `.xslt` files (e.g., `/xsl/sample%20rendering.xslt`) are blocked | [Limit access to XSL](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/limit-access-to--xml,--xslt,-and--mrt-files.html) |
| `Get-HardeningResultRemoveHeaders` | 330-388 | Checks if sensitive headers are removed: `X-Aspnet-Version`, `X-Powered-By`, `X-AspNetMvc-Version` | [Remove headers](https://doc.sitecore.com/developers/81/sitecore-experience-platform/en/remove-header-information-from-responses-sent-by-your-website.html) |
| `Get-HardeningResultForceHttpsRedirect` | 390-432 | Verifies HTTP requests redirect to HTTPS | [Increase login security](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/increase-login-security.html) |
| `Get-HardeningResultUnsupportedLanguages` | 434-501 | Tests if unsupported language codes (e.g., `/om`, `/br`) return 404 instead of 200 | Custom check |
| `Get-SitecoreSimpleFileCheck` | 503-696 | **Version fingerprinting** - Compares hashes of static files (`webedit.css`, `default.css`, `default.js`) against known Sitecore version signatures stored in `/sitecore/` folder | Custom check |

---

### Orchestration

| Function | Lines | Purpose |
|----------|-------|---------|
| `Get-HardeningChecks` | 698-781 | Main orchestrator - runs all checks against URL(s), handles redirects, shows progress, returns structured report data |

---

### Report Output Functions

| Function | Lines | Purpose |
|----------|-------|---------|
| `Invoke-ConsoleReport` | 783-801 | Entry point for console output |
| `Show-ConsoleReport` | 803-859 | Renders colored console output |
| `Write-ConsoleReportResult` | 861-893 | Helper for formatted console line output |
| `Invoke-CsvReport` | 897-921 | Entry point for CSV output |
| `Write-CsvReport` | 923-965 | Writes CSV with optional detailed columns |

---

### Supporting Data: /sitecore/ Folder

Contains **known-good file hashes** for version fingerprinting:
- Versions covered: 8.0, 8.1, 8.2, 9.0, 9.1, 9.2, 9.3, 10.1, 10.3, 10.4
- Files per version: `webedit.css`, `default.css`, `default.js`

---

## Security Checks Summary

| # | Check Name | Pass Condition | Fail Condition |
|---|------------|----------------|----------------|
| 1 | Force HTTPS Redirect | HTTP → HTTPS redirect | HTTP accessible without redirect |
| 2 | Deny Anonymous Access | Sitecore admin paths return 401/403 | Paths accessible or redirect to login |
| 3 | Limit Access to XSL | .xslt files return 404/403 | Files return 200 |
| 4 | Remove Headers | No X-Aspnet-Version, X-Powered-By, X-AspNetMvc-Version | Headers present in response |
| 5 | Simple File Check | Matches known Sitecore version hashes | No matches (may indicate non-Sitecore) |
| 6 | Handle Unsupported Languages | Unknown language codes return 404 | Return 200 (information disclosure) |

---

## Known Issues / Areas for Improvement

1. **Hardcoded paths:** Output paths (`c:\temp\`) are hardcoded in report.ps1 lines 20-24
3. **Error handling:** Some exception handling silently continues without logging
