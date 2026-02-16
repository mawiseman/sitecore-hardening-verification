# PowerShell CLI Tool

Command-line Sitecore hardening verification tool. Runs security checks against one or more URLs and outputs results to the console or a CSV file.

## Prerequisites

- PowerShell 5.1 or later
- Network access to the target Sitecore site(s)

## Quick Start

```powershell
cd powershell

# Console report for a single site
.\report.ps1 -Url "https://yoursite.com"

# CSV report
.\report.ps1 -Url "https://yoursite.com" -Format Csv
```

## Scripts

### report.ps1

Main entry point for checking a single site.

**Parameters:**

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Url` | Yes | | Target URL to scan |
| `-Format` | No | `Console` | Output format: `Console` or `Csv` |
| `-OutputPath` | No | `$env:TEMP` | Directory for CSV output |

```powershell
# Console output
.\report.ps1 -Url "https://example.com" -Format Console

# CSV output to a specific folder
.\report.ps1 -Url "https://example.com" -Format Csv -OutputPath "C:\reports"
```

### report-multiple.ps1

Example script for checking multiple URLs in a single run. Edit the `$Urls` array in the script to set your target sites.

```powershell
.\report-multiple.ps1
```

### report-multiple-csv.ps1

Batch processing from a CSV input file. Reads URLs from a text file (one per line) and generates a detailed CSV report.

**Input:** `../csv-files/urls.csv` (one URL per line)
**Output:** `../csv-files/urls-sitecore-report.csv`

```powershell
.\report-multiple-csv.ps1
```

## Using the Module Directly

Import the module to call check functions directly in your own scripts:

```powershell
Import-Module .\sitecore-hardening-report.psm1

$Urls = @(
    "https://site1.com"
    "https://site2.com"
)

# Console output
Invoke-ConsoleReport -Urls $Urls

# CSV output
Invoke-CsvReport -Urls $Urls -CsvFilePath "C:\temp\report.csv" -DetailedReport $true
```

## Version Fingerprinting

The `sitecore/` folder contains known-good copies of `webedit.css`, `default.css`, and `default.js` for Sitecore versions 8.0 through 10.4. During a scan, the tool downloads these files from the target site, computes SHA256 hashes, and compares them against the local copies to identify the exact Sitecore version.

To add a new version, create a folder at `sitecore/v{version}/Sitecore {version} rev. {revision}/` containing the three files.
