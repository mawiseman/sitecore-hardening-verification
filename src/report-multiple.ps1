Import-Module ..\src\sitecore-hardening-report.psm1

$Urls = @(
    "http://qsuper.qld.gov.au"
    "https://www.fernwoodfitness.com.au/"
)

Invoke-ConsoleReport -Urls $Urls

#Invoke-HtmlReport -Urls $Urls -OutputFolderPath "c:\temp\" -SplitResults $false

#Invoke-HtmlReport -Urls $Urls -OutputFolderPath "C:\temp\TargetAndTrack\" -SplitResults $true

#Invoke-CsvReport -Urls $Urls -CsvFilePath "c:\temp\report.csv" -DetailedReport $false
