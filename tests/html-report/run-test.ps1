$dataViewPath = 'testDataView.json'
$mustacheReportPath = 'C:\projects\sitecore-hardening-verification\src\html-report\report.mustache'
$generatedReportPath = 'testDataOutput.html'

Invoke-Expression "mustache $dataViewPath $mustacheReportPath > $generatedReportPath"