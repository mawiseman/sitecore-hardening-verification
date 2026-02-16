param (
    [Parameter(Mandatory=$true)]
    [string]$Url = $( Read-Host "Input URL" ),

    [ValidateSet('Console', 'Csv')]
    [string]$Format = "Console",

    [string]$OutputPath = $env:TEMP
)

Import-Module $PSScriptRoot\sitecore-hardening-report.psm1

$Urls = @(
    $Url
)

if ($Format -eq 'Console') {
    Invoke-ConsoleReport -Urls $Urls
}

if ($Format -eq 'Csv') {
    $CsvFilePath = Join-Path $OutputPath "report.csv"
    Invoke-CsvReport -Urls $Urls -CsvFilePath $CsvFilePath -DetailedReport $false
}

