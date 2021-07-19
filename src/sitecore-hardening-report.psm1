
# Constants

Set-Variable PASS -option Constant -value 'Pass' -ErrorAction SilentlyContinue
Set-Variable FAIL -option Constant -value 'Fail' -ErrorAction SilentlyContinue

# Functions

function EnableTLS {
    <#
    .SYNOPSIS
        Enable TLS 1.2 Support in Powershell.
    .DESCRIPTION
        When this is not set requests to https sites will often fail.
        https://blog.pauby.com/post/force-powershell-to-use-tls-1-2/
    #>
    process {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
}
EnableTLS

#I'm not sure why i included this function now
# function Set-UseUnsafeHeaderParsing {
#     param(
#         [Parameter(Mandatory, ParameterSetName = 'Enable')]
#         [switch]$Enable,

#         [Parameter(Mandatory, ParameterSetName = 'Disable')]
#         [switch]$Disable
#     )

#     $ShouldEnable = $PSCmdlet.ParameterSetName -eq 'Enable'

#     $netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])

#     if ($netAssembly) {
#         $bindingFlags = [Reflection.BindingFlags] 'Static,GetProperty,NonPublic'
#         $settingsType = $netAssembly.GetType('System.Net.Configuration.SettingsSectionInternal')

#         $instance = $settingsType.InvokeMember('Section', $bindingFlags, $null, $null, @())

#         if ($instance) {
#             $bindingFlags = 'NonPublic', 'Instance'
#             $useUnsafeHeaderParsingField = $settingsType.GetField('useUnsafeHeaderParsing', $bindingFlags)

#             if ($useUnsafeHeaderParsingField) {
#                 $useUnsafeHeaderParsingField.SetValue($instance, $ShouldEnable)
#             }
#         }
#     }
# }
# Set-UseUnsafeHeaderParsing -Enable

function Remove-InvalidFileNameChars {
    param(
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [String]$Name
    )
  
    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re)
}

function Join-Uri {
    [CmdletBinding(DefaultParametersetName = "Uri")]    
    param(
        [Parameter(ParameterSetName = "Uri", Mandatory = $true, Position = 0)]
        [Uri]
        $Uri, 
        [Parameter(ParameterSetName = "Uri", Mandatory = $true, Position = 1)]
        [String]
        $ChildPath
    )
    $CombinedPath = [System.Uri]::new($Uri, $ChildPath)
    return New-Object uri $CombinedPath
}

function Get-RedirectedUrl {
    <#
    .SYNOPSIS
        Just in case the URL provided is not the actual root lets get the actual one
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [String]
        $Url
    )
    process {

        # incase the url given is missing it
        if ($Url -notlike "http*") {
            $Url = "https://$Url"
        }

        $ResponseUri = $Url

        try {
            $Request = [System.Net.WebRequest]::Create($Url)
            $Response = $Request.GetResponse()
    
            $ResponseUri = $Response.ResponseUri.AbsoluteUri 
            
            # Some sites redirect to /en-au or other sub pages... we dont want that
            if ($Response.ResponseUri.AbsolutePath -ne "/") {
                $ResponseUri = $ResponseUri -replace $Response.ResponseUri.AbsolutePath, ""
            }

            $Response.Close()
            $Response.Dispose()
        }
        catch {
            if ($_.Exception.Response.StatusCode.Value__) {
                # We have a valid web request
            }
            else {
                # if  ($_.Exception.Message -like "*Unable to connect to the remote server*") {
                $ResponseUri = "$Url (Unable to connect)"
            }
        }

        $ResponseUri
    }
}

function Get-ResultObject {
    <#
    .SYNOPSIS
        Formats results in a consistent style for reporting
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [String]$Title,
        [String]$Outcome,
        [Object]$Tests,
        [String]$Details
    )
    process {
        $Item = New-Object -TypeName PSObject

        Add-Member -InputObject $Item -MemberType 'NoteProperty' -Name 'Title' -Value $Title
        Add-Member -InputObject $Item -MemberType 'NoteProperty' -Name 'Outcome' -Value $Outcome
        Add-Member -InputObject $Item -MemberType 'NoteProperty' -Name 'Tests' -Value $Tests
        Add-Member -InputObject $Item -MemberType 'NoteProperty' -Name 'Details' -Value $Details

        $Item
    }
}

function Get-SitecoreVersion {
    <#
    .SYNOPSIS
        Try to get the Sitecore Version
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $Version = "Unknown"
        
        # Perform Check

        $VersionUri = Join-Uri $Url "/sitecore/shell/sitecore.version.xml"
        $VersionUrl = $VersionUri.AbsoluteUri

        try {

            $Response = Invoke-WebRequest -Uri $VersionUrl -UseBasicParsing -ErrorAction silentlycontinue -MaximumRedirection 1 -ErrorVariable siteIsNotAlive 
    
            #the version response has some weird characters
            $Content = $Response.Content.Replace("ï»¿", "")
    
            $Xml = [xml]$Content
        
            $Version = "$($Xml.information.version.major).$($Xml.information.version.minor).$($Xml.information.version.revision)"
        
            if (-not($Version)) {
                $Version = "Unknown"
            }
        }
        catch [System.Net.WebException] {
            $StatusCode = $_.Exception.Response.StatusCode.Value__

            if($StatusCode -eq 401 -or $StatusCode -eq 403) {
                $Version = "Probably Sitecore: $StatusCode"
            }
            else {
                $Version = "Unknown version"            
            }
        }
        catch {            
            $Version = "Unhandled Exception"
        }

        $Version
    }
}

function Get-HardeningResultDenyAnonomousAccess {
    <#
    .SYNOPSIS
        Test Deny Anomous Access
    
    .DESCRIPTION
        https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $Result = $PASS
        $TestResults = @()
    
        # Preform Test
    
        # We refer to specific files here to ensure we are redirected
        $Paths = @(
            "/sitecore/admin/dbbrowser.css"
            "/sitecore/debug/Trace.xslt"
            "/sitecore/login"
            "/sitecore/shell/WebService/Service.asmx"
        )
    
        foreach ($Path in $Paths) {
            $TestUri = Join-Uri $Url $Path
            $TestUrl = $TestUri.AbsoluteUri

            $StatusCode = 0
            $ResponseUri = ""

            try {
                $Request = [System.Net.WebRequest]::Create($TestUrl)
                $Request.AllowAutoRedirect = $false
                $Response = $Request.GetResponse()
        
                

                $StatusCode = [int]$Response.StatusCode
                $ResponseUri = $Response.ResponseUri.OriginalString

                $Response.Close()
                $Response.Dispose()
            }
            catch [System.Net.WebException] {
                # Handles 401, 404 etc
                
                If ($_.Exception.Response.StatusCode.value__) {
                    $StatusCode = $_.Exception.Response.StatusCode.Value__
                }
                else {
                    $StatusCode = $_.Exception.Message
                }
            }
            catch {
                $StatusCode = $_.Exception
            }
            
            $PathResult = $PASS

            if ($ResponseUri -ne "" -and $ResponseUri -ne $TestUrl) {

                # If we are redirected to /sitecore/login access has not been denied
                if ($ResponseUri -like "*/Sitecore/login*") {
                    $PathResult = $FAIL
                }
                else {
                    $PathResult = $PASS
                }
                
            }

            if ($ResponseUri -like "*$Path" -and $StatusCode -eq 200 ) {
                $PathResult = $FAIL
            } 
            
            if ($PathResult -eq $FAIL) {
                $Result = $FAIL
            }

            $TestResult = Get-ResultObject -Title $Path -Outcome $PathResult -Details "StatusCode: $StatusCode"
            $TestResults += , $TestResult
        }
        
        # Results

        Get-ResultObject -Title "Deny Anonomous Access" -Outcome $Result -Tests $TestResults
    }
}
   
function Get-HardeningResultLimitAccessToXSL {
    <#
    .SYNOPSIS
        Limit access to .XML, .XSLT, and .MRT files
    
    .DESCRIPTION
        https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/limit-access-to--xml,--xslt,-and--mrt-files.html
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)][String]$Url
    )
    process {
        $Result = $PASS
        $TestResults = @()

        # Perform Tests

        $Paths = @(
            "/xsl/sample%20rendering.xslt"
        )

        foreach ($Path in $Paths) {

            $TestUri = Join-Uri $Url $Path
            
            $StatusCode = '';

            try {
                $Response = Invoke-WebRequest -Uri $TestUri.AbsoluteUri -UseBasicParsing -ErrorAction silentlycontinue -ErrorVariable siteIsNotAlive 
                
                $StatusCode = $Response.StatusCode
            }
            catch {
                $StatusCode = $($_.Exception.Response).StatusCode
            }

            $PathResult = $PASS

            if ($StatusCode -eq 200) {
                $PathResult = $FAIL
            }

            if ($PathResult -eq $FAIL) {
                $Result = $FAIL
            }

            $TestResult = Get-ResultObject -Title $Path -Outcome $PathResult -Details "StatusCode: $StatusCode"
            $TestResults += , $TestResult
        }

        # Results

        Get-ResultObject -Title "Limit Access to XSL" -Outcome $Result -Tests $TestResults
    }
}

function Get-HardeningResultRemoveHeaders {
    <#
    .SYNOPSIS
        Remove header information from responses sent by your website
    .DESCRIPTION
        https://doc.sitecore.com/developers/81/sitecore-experience-platform/en/remove-header-information-from-responses-sent-by-your-website.html
    #>
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $Result = $PASS
        $TestResults = @()

        # Perform Tests

        $Headers = @(
            "X-Aspnet-Version"
            "X-Powered-By"
            "X-AspNetMvc-Version"
        )

        try {
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction silentlycontinue -ErrorVariable siteIsNotAlive 

            foreach ($Header in $Headers) {

                $HeaderResult = $PASS

                $Details = "Removed: $true"

                if ($null -ne $Response.Headers[$Header]) {
                    $HeaderResult = $FAIL
                    $Details = "Removed: $false"
                }

                if ($HeaderResult -eq $FAIL) {
                    $Result = $FAIL
                }

                $TestResult = Get-ResultObject -Title $Header -Outcome $HeaderResult -Details $Details
                $TestResults += , $TestResult
            }
        }
        catch {
            $TestResult = Get-ResultObject -Title "Exception" -Outcome $FAIL -Details $_.Exception.Response.StatusCode.Value__
            $TestResults += , $TestResult

            $Result = $FAIL
        }

        # Results

        Get-ResultObject -title "Remove Header Information" -Outcome $Result -Tests $TestResults
    }
}

function Get-HardeningResultForceHttpsRedirect {
    <#
    .SYNOPSIS
        Increase login security
        Use HTTPS on all your Sitecore instances
    .DESCRIPTION
        https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html
        https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/increase-login-security.html
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $Result = $FAIL
        $Details = ""
        # Perform Tests
    
        $Url = $Url -replace "https", "http"
    
        try {
            $Request = [System.Net.WebRequest]::Create($Url)
            $Response = $Request.GetResponse()
    
            if ($Response.ResponseUri.OriginalString -like "https://*") {
                $Result = $PASS
            } 
    
            $Response.Close()
            $Response.Dispose()
        }
        catch {
            $Details = $_.Exception.Response.ResponseUri.OriginalString
        }
    
        # Results
    
        Get-ResultObject -Title "Force Https Redirect" -Outcome $Result -Details $Details 
    }
}

function Get-HardeningResultUnsupportedLanguages {
    <#
    .SYNOPSIS
        Check handeling is in place for un-support languages
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $Result = $PASS
        
        # Perform Tests
    
        $Languages = @(
            "en"
            "om"
            "br"
        )

        foreach ($Language in $Languages) {
            $TestUri = Join-Uri $Url $Language
            $TestUrl = $TestUri.AbsoluteUri

            $StatusCode = 0

            try {
                $Request = [System.Net.WebRequest]::Create($TestUrl)
                $Response = $Request.GetResponse()
        
                $StatusCode = [int]$Response.StatusCode

                $Response.Close()
                $Response.Dispose()
            }
            catch [System.Net.WebException] {
                # Handles 401, 404 etc
                $StatusCode = $($_.Exception.Response.StatusCode.Value__)
            }
            catch {
                $StatusCode = 500
            }
            
            $LanguageResult = $PASS

            if ($StatusCode -eq 500) {
                $LanguageResult = $FAIL
            }

            if ($LanguageResult -eq $FAIL) {
                $Result = $FAIL
            }

            $TestResult = Get-ResultObject -Title $Language -Outcome $LanguageResult -Details "StatusCode: $StatusCode"
            $TestResults += , $TestResult
        }
        
        # Results

        Get-ResultObject -Title "Handle Unsupported Languages" -Outcome $Result -Tests $TestResults 
    }
}

function Get-SitecoreSimpleFileCheck {
    <#
    .SYNOPSIS
        Provide a measure of simple files that Sitecore normally includes
    .DESCRIPTION
        Becase a site can be locked down really well, all tests might pass and we just dont know if it's sitecore or not.
        We do know that sitecore _typically_ has a few files in the root that we can check for
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $Result = "0%"
        $TestResults = @()
        
        # Preform Test
    
        ## Check known static Sitecore files

        $Paths = @(
            "/webedit.css"
            "/default.css"
            "/default.js"
        )

        foreach ($Path in $Paths) {
            $TestUri = Join-Uri $Url $Path
            $TestUrl = $TestUri.AbsoluteUri

            $StatusCode = 0

            try {
                $Request = [System.Net.WebRequest]::Create($TestUrl)
                $Response = $Request.GetResponse()
        
                $StatusCode = [int]$Response.StatusCode

                $Response.Close()
                $Response.Dispose()
            }
            catch [System.Net.WebException] {
                # Handles 401, 404 etc
                $StatusCode = $($_.Exception.Response.StatusCode.Value__)
            }
            catch {
                $StatusCode = 500
            }
            
            $PathResult = $PASS

            if ($StatusCode -ne 200) {
                $PathResult = $FAIL
            }

            $TestResult = Get-ResultObject -Title $Path -Outcome $PathResult -Details "StatusCode: $StatusCode"
            $TestResults += , $TestResult
        }
        
        ## Check some urls that would return a 404 in non Sitecore Sites

        # check /sitecore
        # if 200 and url is still /sitecore: Is Sitecore
        # if 403 or 401 this is sitecore but hardened: Is Sitecore
        # else Is (probably) Not Sitecore
        
        # Calculate the probability that this site is Sitecore
        
        $FilesFound = $TestResults.GetEnumerator() | ? { $_.Outcome -like "*$PASS" }
        $PercentHitRate = [math]::Round($($FilesFound.length / $Paths.count) * 100)
        
        $Result = $FAIL
        if ($PercentHitRate -gt 80) {
            $Result = $PASS
        }

        # Results

        Get-ResultObject -Title "Simple File Check" -Outcome $Result -Tests $TestResults -Details "Sitecore Certainty: $PercentHitRate%"
    }
}

function Get-HardeningChecks {
    <#
    .SYNOPSIS
        Run all hardening checks against a site
    .OUTPUTS
        Returns an array of Get-ResultObject objects: Title, Value, Results
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [String]
        $Url,
        [Array]
        $Urls
    )
    process {
        $SiteUrls = @()

        if ($Url) {
            $SiteUrls += $Url
        }

        if ($Urls) {
            $SiteUrls += $Urls
        }

        $HardeningReports = @()

        for ($I = 0; $I -lt $SiteUrls.length; $I++) {

            $SiteUrl = $SiteUrls[$I]
            $Tests = 8

            $SiteResults = @()
            $SitecoreVersion = "Unknown"
            
            $ReportProgressActivity = "Report Progress ($I/$($SiteUrls.length)) - $SiteUrl"

            Write-Progress -Activity $ReportProgressActivity -Status "Step: 1 of $($Tests): Checking for Redirects" -PercentComplete ((1 / $Tests) * 100) -ParentId 1
            $RedirectUrl = Get-RedirectedUrl -Url $SiteUrl
            
            # make sure we can connect to the site (or the redirected site) before running the tests
            if ($RedirectUrl -notlike "*(Unable to connect)") {
                
                Write-Progress -Activity $ReportProgressActivity -Status "Step: 2 of $($Tests): Checking Force Https" -PercentComplete ((6 / $Tests) * 100) -ParentId 1
                $SiteResults += Get-HardeningResultForceHttpsRedirect -Url $RedirectUrl 

                Write-Progress -Activity $ReportProgressActivity -Status "Step: 3 of $($Tests): Checking Sitecore Version" -PercentComplete ((2 / $Tests) * 100) -ParentId 1
                $SitecoreVersion = Get-SitecoreVersion -Url $RedirectUrl  
                
                Write-Progress -Activity $ReportProgressActivity -Status "Step: 4 of $($Tests): Checking Deny Anonomous Access" -PercentComplete ((3 / $Tests) * 100) -ParentId 1
                $SiteResults += Get-HardeningResultDenyAnonomousAccess -Url $RedirectUrl
                
                Write-Progress -Activity $ReportProgressActivity -Status "Step: 5 of $($Tests): Checking Limit Access to XSL" -PercentComplete ((4 / $Tests) * 100) -ParentId 1
                $SiteResults += Get-HardeningResultLimitAccessToXSL -Url $RedirectUrl 
                
                Write-Progress -Activity $ReportProgressActivity -Status "Step: 6 of $($Tests): Checking Remove Headers" -PercentComplete ((5 / $Tests) * 100) -ParentId 1
                $SiteResults += Get-HardeningResultRemoveHeaders -Url $RedirectUrl 
                
                Write-Progress -Activity $ReportProgressActivity -Status "Step: 7 of $($Tests): Sitecore Simple File Check" -PercentComplete ((7 / $Tests) * 100) -ParentId 1
                $SiteResults += Get-SitecoreSimpleFileCheck -Url $RedirectUrl 

                Write-Progress -Activity $ReportProgressActivity -Status "Step: 8 of $($Tests): Handle Unsupported Languages Check" -PercentComplete ((7 / $Tests) * 100) -ParentId 1
                $SiteResults += Get-HardeningResultUnsupportedLanguages -Url $RedirectUrl 
            }
           
            if ($RedirectUrl -eq $SiteUrl) {
                $RedirectUrl = ""
            }

            $HardeningReport = @{
                SiteUrl         = $SiteUrl
                RedirectUrl     = $RedirectUrl
                SitecoreVersion = $SitecoreVersion
                SiteResults     = $SiteResults
            }

            # When adding an array to array the "," is required
            $HardeningReports += , $HardeningReport
        }

        $HardeningReports
    }
}

function Invoke-ConsoleReport {
    <#
    .SYNOPSIS
        Retirves report data for the provided URLs and Shos the result
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Array]
        $Urls
    )
    process {
        # Get Report Data
        $SiteReports = $(Get-HardeningChecks -Urls $Urls)

        # Write Report
        Show-ConsoleReport $SiteReports
    }
}

function Show-ConsoleReport {
    <#
    .SYNOPSIS
        Renders $SiteReports to the console
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Array]
        $SiteReports
    )
    process {
        for ($I = 0; $I -lt $SiteReports.length; $I++) {
            
            $SiteReport = $SiteReports[$I]

            $Padding = 40

            Write-ConsoleReportResult "URL" Blue $SiteReport.SiteUrl Blue $null $Padding
            Write-ConsoleReportResult "RedirectURL" White $SiteReport.RedirectUrl White $null $Padding
            
            $ValueForegroundColor = "Green"
            if($SiteReport.SitecoreVersion -like "*Unknown*") {
                $ValueForegroundColor = "White"
            }
            elseif($SiteReport.SitecoreVersion -like "*Probably*") {
                $ValueForegroundColor = "Yellow"
            }

            Write-ConsoleReportResult "Sitecore Version" White $SiteReport.SitecoreVersion $ValueForegroundColor $null $Padding
            
            Write-Host ""

            foreach ($SiteResult in $SiteReport.SiteResults) {

                $TitleForegroundColor = "Green"
                if ($SiteResult.Outcome -eq $FAIL) {
                    $TitleForegroundColor = "Red"
                }

                Write-ConsoleReportResult $SiteResult.Title Yellow $SiteResult.Outcome $TitleForegroundColor $SiteResult.Details $Padding

                foreach ($Test in $SiteResult.Tests) {
                    
                    Write-ConsoleReportResult $Test.Title White $Test.Outcome White $Test.Details $Padding

                }
                Write-Host ""
            }

            Write-Host ""
            
        }

        Write-Host ""
    }
}

function Write-ConsoleReportResult {
    [CmdletBinding()]
    param (
        [String]
        $Title,
        [AllowNull()]
        [System.ConsoleColor]
        $TitleForegroundColor,
        [String]
        $Value,
        [AllowNull()]
        [System.ConsoleColor]
        $ValueForegroundColor,
        [String]
        $Details,
        [Int]
        $TitleLength
    )
    process {
        $PaddingLength = $TitleLength - $Title.length

        Write-Host $Title -ForegroundColor $TitleForegroundColor -NoNewline 
        Write-Host $(" " * $PaddingLength) -NoNewline
        Write-Host "| " -NoNewline
        Write-Host $Value -ForegroundColor $ValueForegroundColor -NoNewline

        if($null -ne $Details -and "" -ne $Details) {
            Write-Host " ($Details)" -NoNewline
        }

        Write-Host ""
    }
}

function Invoke-HtmlReport {
    <#
    .SYNOPSIS
        Retirves report data for the provided URLs and Shos the result
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Array]
        $Urls,
        [String]
        $OutputFolderPath,
        [Boolean]
        $SplitResults
    )
    process {
        # Get Report Data

        $SiteReports = $(Get-HardeningChecks -Urls $Urls)

        # Write Report

        if ($SplitResults) {

            $HtmlReportFileNames = @()

            # Generate the separate reports

            foreach ($SiteReport in $SiteReports) {
                $FileName = Remove-InvalidFileNameChars $SiteReport.SiteUrl
                $FileName = $FileName -Replace 'https', '' -Replace 'http', ''

                $DataViewFileName = "$FileName.json"
                $HtmlReportFileName = "$FileName.html"

                Save-HtmlReport -SiteReports $SiteReport -OutputFolderPath $OutputFolderPath -DataViewFileName $DataViewFileName -HtmlReportFileName $HtmlReportFileName
           
                $HtmlReportFileNames += , $HtmlReportFileName
            }

            # Generate index file

            Save-HtmlReportIndex -HtmlReportFileNames $HtmlReportFileNames -OutputFolderPath $OutputFolderPath
        }
        else {
            Save-HtmlReport -SiteReports $SiteReports -OutputFolderPath $OutputFolderPath
        }
    }
}

function Save-HtmlReport {
    <#
    .SYNOPSIS
        Display a friendly version of the report
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Array]
        $SiteReports,
        [String]
        $OutputFolderPath,
        [String]
        $DataViewFileName = "dataView.json",
        [String]
        $HtmlReportFileName = "report.html"
    )
    process {
        $TemplatPath = Join-Path $PSScriptRoot "\html-report\report.mustache"
        $DataViewFilePath = Join-Path $OutputFolderPath $DataViewFileName
        $HtmlReportPath = Join-Path $OutputFolderPath $HtmlReportFileName

        Write-Host "Data View File Path: $DataViewFilePath"
        Write-Host "Template Path: $TemplatPath"
        Write-Host "Html Report Path: $HtmlReportPath"

        # Delete old files

        if (Test-Path $DataViewFilePath) {
            Remove-Item $DataViewFilePath
        }

        if (Test-Path $HtmlReportPath) {
            Remove-Item $HtmlReportPath
        }

        # Save json file

        $DataViewContent = $SiteReports | ConvertTo-Json -Depth 5
        Add-Content $DataViewFilePath $DataViewContent

        # Generate report
        $MustacheCommand = "mustache $DataViewFilePath $TemplatPath > $HtmlReportPath"

        Write-Verbose $MustacheCommand

        Invoke-Expression $MustacheCommand
    }
}

function Save-HtmlReportIndex {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Array]
        $HtmlReportFileNames,
        [String]
        $OutputFolderPath        
    )
    process {
        $TemplatPath = Join-Path $PSScriptRoot "\html-report\report-index.mustache"
        $DataViewFilePath = Join-Path $OutputFolderPath "_index.json"
        $HtmlReportPath = Join-Path $OutputFolderPath "_index.html"

        Write-Host "Data View File Path: $DataViewFilePath"
        Write-Host "Template Path: $TemplatPath"
        Write-Host "Html Report Path: $HtmlReportPath"

        # Delete old files

        if (Test-Path $DataViewFilePath) {
            Remove-Item $DataViewFilePath
        }

        if (Test-Path $HtmlReportPath) {
            Remove-Item $HtmlReportPath
        }

        # Save json file

        $DataViewContent = $HtmlReportFileNames | ConvertTo-Json
        Add-Content $DataViewFilePath $DataViewContent

        # Generate report
        $MustacheCommand = "mustache $DataViewFilePath $TemplatPath > $HtmlReportPath"

        Write-Verbose $MustacheCommand

        Invoke-Expression $MustacheCommand
    }
}

function Invoke-CsvReport {
    <#
    .SYNOPSIS
        Retirves report data for the provided URLs and Saves the result to CSV
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Array]
        $Urls,
        [String]
        $CsvFilePath,
        [Boolean]
        $DetailedReport
    )
    process {
        # Get Report Data

        $SiteReports = $(Get-HardeningChecks -Urls $Urls)

        # Write Report

        Write-CsvReport -SiteReports $SiteReports -CsvFilePath $CsvFilePath -DetailedReport $DetailedReport
    }
}

function Write-CsvReport {
    <#
    .SYNOPSIS
        Generate Csv version of the report
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Array]
        $SiteReports,
        [String]
        $CsvFilePath,
        [Boolean]
        $DetailedReport
    )
    process {
        # Write CSV Header

        $Row = "SiteUrl, RedirectUrl, SitecoreVersion, "

        foreach ($SiteResult in $SiteReports[0].SiteResults) {
            $Row += "$($SiteResult.Title) Summary, "

            if($true -eq $DetailedReport) {
                foreach ($Test in $SiteResult.Tests) {
                    $Row += "$($SiteResult.Title) ($($Test.Title)), "
                }
            }
        }

        Add-Content $CsvFilePath $Row

        # Write CSV Results

        foreach ($SiteReport in $SiteReports) {

            $Row = "$($SiteReport.SiteUrl), $($SiteReport.RedirectUrl), $($SiteReport.SitecoreVersion), "

            foreach ($SiteResult in $SiteReport.SiteResults) {
                $Row += "$($SiteResult.Outcome), "

                if($true -eq $DetailedReport) {
                    foreach ($Test in $SiteResult.Tests) {
                        $Row += "$($Test.Outcome) - $($Test.Details), "
                    }
                }
            }

            Add-Content $CsvFilePath $Row
        }
    }
}


Export-ModuleMember -function *