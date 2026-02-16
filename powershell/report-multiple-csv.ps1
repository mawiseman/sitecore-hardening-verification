Import-Module $PSScriptRoot\sitecore-hardening-report.psm1

$InputCsvPath = "$PSScriptRoot\..\csv-files\urls.csv"
$OutputCsvPath = "$PSScriptRoot\..\csv-files\urls-sitecore-report.csv"

# Read URLs from CSV file
if (-not (Test-Path $InputCsvPath)) {
    Write-Error "Input CSV file not found: $InputCsvPath"
    exit 1
}

$Urls = @(Get-Content -Path $InputCsvPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($Urls.Count -eq 0) {
    Write-Error "No URLs found in input file"
    exit 1
}

Write-Host "Processing $($Urls.Count) URLs from $InputCsvPath"

Invoke-CsvReport -Urls $Urls -CsvFilePath $OutputCsvPath -DetailedReport $true

Write-Host "Report saved to: $OutputCsvPath"
