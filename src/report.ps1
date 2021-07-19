param (
    [Parameter(Mandatory=$true)]
    [string]$Url = $( Read-Host "Input URL" ),

    [ValidateSet('Console', 'Html', 'Csv')]
    [string]$Format = "Console"
)

Import-Module ..\src\sitecore-hardening-report.psm1

$Urls = @(
    $Url
)

if($Format -eq 'Console') {
    Invoke-ConsoleReport -Urls $Urls
}

if($Format -eq 'Html') {
    Invoke-HtmlReport -Urls $Urls -OutputFolderPath "c:\temp\" -SplitResults $false
}

if($Format -eq 'Csv') {
    Invoke-CsvReport -Urls $Urls -CsvFilePath "c:\temp\report.csv" -SplitResults $false
}

