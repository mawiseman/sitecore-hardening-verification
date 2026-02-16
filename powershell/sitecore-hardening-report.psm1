
# Constants

Set-Variable PASS -option Constant -value 'Pass' -ErrorAction SilentlyContinue
Set-Variable FAIL -option Constant -value 'Fail' -ErrorAction SilentlyContinue
Set-Variable WARN -option Constant -value 'Warn' -ErrorAction SilentlyContinue

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
            $Response = Invoke-WebRequest -Uri $VersionUrl -UseBasicParsing -ErrorAction Stop -MaximumRedirection 1
        }
        catch {
            $StatusCode = $null
            if ($_.Exception.Response) {
                $StatusCode = [int]$_.Exception.Response.StatusCode
            }

            if ($StatusCode -eq 401 -or $StatusCode -eq 403) {
                $Version = "Probably Sitecore: HTTP $StatusCode"
            }
            elseif ($StatusCode) {
                $Version = "HTTP $StatusCode"
            }
            else {
                $Version = "Connection failed"
            }
            return $Version
        }

        # Check if we got a valid response
        if ($null -eq $Response) {
            $Version = "No response"
            return $Version
        }

        $StatusCode = [int]$Response.StatusCode
        if ($StatusCode -ne 200) {
            $Version = "HTTP $StatusCode"
            return $Version
        }

        # Try to parse the XML version file
        try {
            $Content = $Response.Content -replace '^\xEF\xBB\xBF', '' -replace 'ï»¿', ''
            $Xml = [xml]$Content
            $Version = "$($Xml.information.version.major).$($Xml.information.version.minor).$($Xml.information.version.revision)"

            if (-not($Version) -or $Version -eq "..") {
                $Version = "Unknown"
            }
        }
        catch {
            $Version = "Invalid XML response"
        }

        $Version
    }
}

function Get-HardeningResultDenyAnonymousAccess {
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

        Get-ResultObject -Title "Deny Anonymous Access" -Outcome $Result -Tests $TestResults
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
            
            $StatusCode = 0

            try {
                $Response = Invoke-WebRequest -Uri $TestUri.AbsoluteUri -UseBasicParsing -ErrorAction SilentlyContinue

                if ($null -ne $Response) {
                    $StatusCode = $Response.StatusCode
                }
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
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction SilentlyContinue

            if ($null -eq $Response) {
                $TestResult = Get-ResultObject -Title "Connection" -Outcome $FAIL -Details "Unable to connect"
                $TestResults += , $TestResult
                $Result = $FAIL
            }
            else {
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
    
        $Url = $Url -replace "^https://", "http://"
    
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
        $TestResults = @()

        # Perform Tests

        $Languages = @(
            [PSCustomObject]@{ languageCode = "en"; expectedStatusCode = 200 }
            [PSCustomObject]@{ languageCode = "om"; expectedStatusCode = 404 }
            [PSCustomObject]@{ languageCode = "br"; expectedStatusCode = 404 }
        )

        foreach ($Language in $Languages) {
            $TestUri = Join-Uri $Url $Language.languageCode
            $TestUrl = $TestUri.AbsoluteUri

            $StatusCode = 0

            try {
                $Response = Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -ErrorAction SilentlyContinue -MaximumRedirection 1

                if ($null -ne $Response) {
                    $StatusCode = [int]$Response.StatusCode
                }
            }
            catch [System.Net.WebException] {
                # Handles 401, 404 etc
                $StatusCode = $($_.Exception.Response.StatusCode.Value__)
            }
            catch {
                $StatusCode = 500
            }
            
            $LanguageResult = $FAIL
            $ExpectedStatusMessage = ""

            if ($StatusCode -eq $Language.expectedStatusCode) {
                $LanguageResult = $PASS
            }
            else {
                $ExpectedStatusMessage = " Expected: $($Language.expectedStatusCode)"
                $Result = $FAIL
            }

            $TestResult = Get-ResultObject -Title $Language.languageCode -Outcome $LanguageResult -Details "StatusCode: $StatusCode$ExpectedStatusMessage"
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
        Downloads known static Sitecore files (webedit.css, default.css, default.js),
        computes SHA256 hashes, and matches against pre-computed version-hashes.json.
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $TestResults = @()

        $Paths = @("webedit.css", "default.css", "default.js")

        # Load pre-computed version hashes
        $HashJsonPath = Join-Path $PSScriptRoot "..\chrome-extension\data\version-hashes.json"
        $VersionHashData = Get-Content $HashJsonPath -Raw | ConvertFrom-Json

        $FullHash = ""

        foreach ($Path in $Paths) {
            $TestUri = Join-Uri $Url $Path
            $TestUrl = $TestUri.AbsoluteUri

            $StatusCode = 0
            $SitecoreVersions = @()

            try {
                $Request = [System.Net.WebRequest]::Create($TestUrl)
                $Response = $Request.GetResponse()
                $StatusCode = [int]$Response.StatusCode

                # Compute SHA256 hash of the response
                $ResponseStream = $Response.GetResponseStream()
                $sha256 = [System.Security.Cryptography.SHA256]::Create()
                $hashBytes = $sha256.ComputeHash($ResponseStream)
                $ResponseHash = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ""
                $sha256.Dispose()

                $FullHash += $Path + $ResponseHash

                # Look up per-file matches from version-hashes.json
                $FileHashes = $VersionHashData.files.$Path
                if ($FileHashes -and $FileHashes.$ResponseHash) {
                    $SitecoreVersions = @($FileHashes.$ResponseHash)
                }

                $Response.Close()
                $Response.Dispose()
            }
            catch [System.Net.WebException] {
                $StatusCode = $($_.Exception.Response.StatusCode.Value__)
            }
            catch {
                $StatusCode = 500
            }

            $PathResult = $PASS
            if ($StatusCode -ne 200) {
                $PathResult = $FAIL
            }

            $SitecoreVersionsDisplay = "Unknown"
            if ($SitecoreVersions.Count -gt 0) {
                $First = $SitecoreVersions[0]
                $Last = $SitecoreVersions[$SitecoreVersions.Count - 1]
                $SitecoreVersionsDisplay = if ($First -eq $Last) { $First } else { "$First - $Last" }
            }

            $TestResults += Get-ResultObject -Title $Path -Outcome $PathResult -Details "StatusCode: $StatusCode, Matches: $SitecoreVersionsDisplay"
        }

        # Check composite hash match
        $Result = $FAIL
        $CompositeMatches = $VersionHashData.composites.$FullHash

        if ($CompositeMatches -and $CompositeMatches.Count -gt 0) {
            $Result = $PASS
            $First = $CompositeMatches[0]
            $Last = $CompositeMatches[$CompositeMatches.Count - 1]
            $SitecoreCertainty = if ($First -eq $Last) { $First } else { "$First - $Last" }
        }
        else {
            # Fallback: percentage of files found
            $FilesFound = @($TestResults | Where-Object { $_.Outcome -eq $PASS })
            $PercentHitRate = [math]::Round(($FilesFound.Count / $Paths.Count) * 100)
            $SitecoreCertainty = "$PercentHitRate%"

            if ($PercentHitRate -gt 80) {
                $Result = $PASS
            }
        }

        Get-ResultObject -Title "Simple File Check" -Outcome $Result -Tests $TestResults -Details "Matches: $SitecoreCertainty"
    }
}

function Get-HardeningResultIsXMCloud {
    <#
    .SYNOPSIS
        Check if site is running on Sitecore XM Cloud
    .DESCRIPTION
        XM Cloud sites using Next.js include a script tag with id "__NEXT_DATA__"
        containing a JSON object. Detection versions:
        - v1: props.pageProps.sitecoreContext
        - v2: props.layoutData.sitecore
        - v3: JSON contains "sitecore" string (fallback)
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
        $Details = "Not XM Cloud"

        try {
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop

            if ($null -ne $Response -and $Response.StatusCode -eq 200) {
                $Content = $Response.Content

                # Look for script tag with id="__NEXT_DATA__"
                if ($Content -match '<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>') {
                    $JsonContent = $Matches[1]

                    try {
                        $JsonData = $JsonContent | ConvertFrom-Json

                        # v1: Check for sitecoreContext in props.pageProps
                        if ($null -ne $JsonData.props -and
                            $null -ne $JsonData.props.pageProps -and
                            $null -ne $JsonData.props.pageProps.sitecoreContext) {
                            $Result = $PASS
                            $Details = "XM Cloud detected - v1"
                        }
                        # v2: Check for sitecore in props.layoutData
                        elseif ($null -ne $JsonData.props -and
                            $null -ne $JsonData.props.pageProps -and
                            $null -ne $JsonData.props.pageProps.layoutData -and
                            $null -ne $JsonData.props.pageProps.layoutData.sitecore) {
                            $Result = $PASS
                            $Details = "XM Cloud detected - v2"
                        }
                        # v3: Fallback - search for "sitecore" in the JSON content
                        elseif ($JsonContent -match '"sitecore"') {
                            $Result = $PASS
                            $Details = "XM Cloud detected - unknown"
                        }
                        else {
                            $Details = "Next.js found but no Sitecore data"
                        }
                    }
                    catch {
                        $Details = "Next.js found but invalid JSON"
                    }
                }
                else {
                    $Details = "No __NEXT_DATA__ script found"
                }
            }
        }
        catch {
            $StatusCode = $null
            if ($_.Exception.Response) {
                $StatusCode = [int]$_.Exception.Response.StatusCode
            }
            $Details = "Request failed: HTTP $StatusCode"
        }

        # Results
        Get-ResultObject -Title "Is XM Cloud" -Outcome $Result -Details $Details
    }
}

function Get-HardeningResultJssVersion {
    <#
    .SYNOPSIS
        Identify the Sitecore JSS version by finding which page chunk contains sitecoreApiKey
    .DESCRIPTION
        Scans known Next.js chunk URL patterns to find the chunk containing sitecoreApiKey.
        The chunk URL pattern indicates the JSS version:
          JSS 22.*: _next/static/chunks/pages/_app-{hash}.js
          JSS 21.*: _next/static/chunks/pages/%5B%5B...path%5D%5D-{hash}.js
        Returns the result object plus the chunk JS content for the API key check to reuse.
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $Url
    )
    process {
        $TestResults = @()

        $ChunkPatterns = @(
            @{ Label = "JSS 22.x"; Pattern = '["\u0027]([^"\u0027]*_next/static/chunks/pages/_app-[^"\u0027]+\.js[^"\u0027]*?)["\u0027]' },
            @{ Label = "JSS 21.x"; Pattern = '["\u0027]([^"\u0027]*_next/static/chunks/pages/\[\[\.\.\.path\]\]-[^"\u0027]+\.js[^"\u0027]*?)["\u0027]' },
            @{ Label = "JSS 21.x"; Pattern = '["\u0027]([^"\u0027]*_next/static/chunks/pages/%5B%5B\.\.\.path%5D%5D-[^"\u0027]+\.js[^"\u0027]*?)["\u0027]' }
        )

        try {
            $PageResponse = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop
            $HtmlContent = $PageResponse.Content

            # Collect all matching chunks with their version labels
            $Chunks = @()
            foreach ($Entry in $ChunkPatterns) {
                if ($HtmlContent -match $Entry.Pattern) {
                    $ChunkPath = $Matches[1]
                    if ($ChunkPath -match '^https?://') {
                        $ChunkUrl = $ChunkPath
                    } else {
                        $ChunkUrl = (Join-Uri $Url $ChunkPath).AbsoluteUri
                    }
                    $Chunks += @{ Label = $Entry.Label; Url = $ChunkUrl }
                }
            }

            if ($Chunks.Count -eq 0) {
                return @{
                    Result = Get-ResultObject -Title "Sitecore JSS Version" -Outcome $WARN -Details "No page chunks found"
                    JsContent = $null
                    ChunkName = $null
                }
            }

            # Fetch each chunk and find the one containing sitecoreApiKey
            foreach ($Chunk in $Chunks) {
                $ChunkName = ($Chunk.Url -split '/')[-1] -split '\?' | Select-Object -First 1

                $ChunkResponse = Invoke-WebRequest -Uri $Chunk.Url -UseBasicParsing -ErrorAction Stop
                $JsContent = $ChunkResponse.Content

                if ($JsContent -notmatch 'sitecoreApiKey') {
                    $TestResults += Get-ResultObject -Title $ChunkName -Outcome $WARN -Details "sitecoreApiKey not found"
                    continue
                }

                # Found it
                $TestResults += Get-ResultObject -Title $ChunkName -Outcome $PASS -Details "sitecoreApiKey found"

                return @{
                    Result = Get-ResultObject -Title "Sitecore JSS Version" -Outcome $PASS -Tests $TestResults -Details $Chunk.Label
                    JsContent = $JsContent
                    ChunkName = $ChunkName
                }
            }

            # Not found in any chunk
            return @{
                Result = Get-ResultObject -Title "Sitecore JSS Version" -Outcome $WARN -Tests $TestResults -Details "sitecoreApiKey not found in any chunk"
                JsContent = $null
                ChunkName = $null
            }
        }
        catch {
            return @{
                Result = Get-ResultObject -Title "Sitecore JSS Version" -Outcome $WARN -Details "Error: $($_.Exception.Message)"
                JsContent = $null
                ChunkName = $null
            }
        }
    }
}

function Get-HardeningResultXMCloudApiKey {
    <#
    .SYNOPSIS
        Check that the Sitecore API key is not exposed in the identified chunk
    .DESCRIPTION
        Analyses the JS content (already fetched by JSS version check) to verify
        sitecoreApiKey is "" (empty string). An exposed key is a security issue.
    #>
    [OutputType([psobject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [String]
        $JsContent,

        [Parameter(Mandatory = $False)]
        [String]
        $ChunkName
    )
    process {
        $TestResults = @()

        if ([string]::IsNullOrEmpty($JsContent)) {
            return Get-ResultObject -Title "XM Cloud API Key" -Outcome $WARN -Details "No chunk to analyse"
        }

        # Search for sitecoreApiKey assignments
        $ExposedKeys = @()

        $DirectMatches = [regex]::Matches($JsContent, 'sitecoreApiKey\s*[=:]\s*"([^"]*)"')
        foreach ($Match in $DirectMatches) {
            $Value = $Match.Groups[1].Value
            if ($Value -ne "") {
                $ExposedKeys += $Value
            }
        }

        $FallbackMatches = [regex]::Matches($JsContent, 'sitecoreApiKey\s*=\s*[^"|]+\|\|\s*"([^"]*)"')
        foreach ($Match in $FallbackMatches) {
            $Value = $Match.Groups[1].Value
            if ($Value -ne "") {
                $ExposedKeys += $Value
            }
        }

        $FoundAny = ($DirectMatches.Count -gt 0) -or ($FallbackMatches.Count -gt 0)

        if (-not $FoundAny) {
            $TestResults += Get-ResultObject -Title $ChunkName -Outcome $WARN -Details "sitecoreApiKey not found"
            return Get-ResultObject -Title "XM Cloud API Key" -Outcome $WARN -Tests $TestResults -Details "sitecoreApiKey not found"
        }

        if ($ExposedKeys.Count -gt 0) {
            $MaskedKeys = $ExposedKeys | ForEach-Object {
                if ($_.Length -gt 8) {
                    $_.Substring(0, 4) + "..." + $_.Substring($_.Length - 4)
                } else {
                    $_
                }
            }
            $Details = "API key exposed: $($MaskedKeys -join ', ')"
            $TestResults += Get-ResultObject -Title $ChunkName -Outcome $FAIL -Details $Details
            return Get-ResultObject -Title "XM Cloud API Key" -Outcome $FAIL -Tests $TestResults -Details $Details
        }

        $TestResults += Get-ResultObject -Title $ChunkName -Outcome $PASS -Details 'Value: ""'
        Get-ResultObject -Title "XM Cloud API Key" -Outcome $PASS -Tests $TestResults -Details "sitecoreApiKey is empty"
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
            $Tests = 9

            $SiteResults = @()
            $SitecoreVersion = "Unknown"

            $ReportProgressActivity = "Report Progress ($I/$($SiteUrls.length)) - $SiteUrl"

            Write-Progress -Activity $ReportProgressActivity -Status "Step: 1 of $($Tests): Checking for Redirects" -PercentComplete ((1 / $Tests) * 100) -ParentId 1
            $RedirectUrl = Get-RedirectedUrl -Url $SiteUrl

            # make sure we can connect to the site (or the redirected site) before running the tests
            if ($RedirectUrl -notlike "*(Unable to connect)") {

                # Check for XM Cloud first - if detected, skip XM/XP hardening checks
                Write-Progress -Activity $ReportProgressActivity -Status "Step: 2 of $($Tests): Checking Is XM Cloud" -PercentComplete ((2 / $Tests) * 100) -ParentId 1
                $XMCloudResult = Get-HardeningResultIsXMCloud -Url $RedirectUrl
                $SiteResults += $XMCloudResult

                if ($XMCloudResult.Outcome -eq $PASS) {
                    Write-Host "XM Cloud detected - running XM Cloud checks, skipping XM/XP hardening checks" -ForegroundColor Cyan

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 3 of $($Tests): Checking Sitecore JSS Version" -PercentComplete ((3 / $Tests) * 100) -ParentId 1
                    $JssVersionResult = Get-HardeningResultJssVersion -Url $RedirectUrl
                    $SiteResults += $JssVersionResult.Result
                    $SitecoreVersion = if ($JssVersionResult.Result.Details) { $JssVersionResult.Result.Details } else { "XM Cloud" }

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 4 of $($Tests): Checking XM Cloud API Key" -PercentComplete ((4 / $Tests) * 100) -ParentId 1
                    $SiteResults += Get-HardeningResultXMCloudApiKey -JsContent $JssVersionResult.JsContent -ChunkName $JssVersionResult.ChunkName
                }
                else {
                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 3 of $($Tests): Checking Force Https" -PercentComplete ((3 / $Tests) * 100) -ParentId 1
                    $SiteResults += Get-HardeningResultForceHttpsRedirect -Url $RedirectUrl

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 4 of $($Tests): Checking Sitecore Version" -PercentComplete ((4 / $Tests) * 100) -ParentId 1
                    $SitecoreVersion = Get-SitecoreVersion -Url $RedirectUrl

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 5 of $($Tests): Checking Deny Anonymous Access" -PercentComplete ((5 / $Tests) * 100) -ParentId 1
                    $SiteResults += Get-HardeningResultDenyAnonymousAccess -Url $RedirectUrl

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 6 of $($Tests): Checking Limit Access to XSL" -PercentComplete ((6 / $Tests) * 100) -ParentId 1
                    $SiteResults += Get-HardeningResultLimitAccessToXSL -Url $RedirectUrl

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 7 of $($Tests): Checking Remove Headers" -PercentComplete ((7 / $Tests) * 100) -ParentId 1
                    $SiteResults += Get-HardeningResultRemoveHeaders -Url $RedirectUrl

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 8 of $($Tests): Sitecore Simple File Check" -PercentComplete ((8 / $Tests) * 100) -ParentId 1
                    $SiteResults += Get-SitecoreSimpleFileCheck -Url $RedirectUrl

                    Write-Progress -Activity $ReportProgressActivity -Status "Step: 9 of $($Tests): Handle Unsupported Languages Check" -PercentComplete ((9 / $Tests) * 100) -ParentId 1
                    $SiteResults += Get-HardeningResultUnsupportedLanguages -Url $RedirectUrl
                }
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
            elseif($SiteReport.SitecoreVersion -eq "XM Cloud" -or $SiteReport.SitecoreVersion -like "JSS*") {
                $ValueForegroundColor = "Cyan"
            }

            Write-ConsoleReportResult "Sitecore Version" White $SiteReport.SitecoreVersion $ValueForegroundColor $null $Padding
            
            Write-Host ""

            foreach ($SiteResult in $SiteReport.SiteResults) {

                $TitleForegroundColor = "Green"
                if ($SiteResult.Outcome -eq $FAIL) {
                    $TitleForegroundColor = "Red"
                }
                elseif ($SiteResult.Outcome -eq $WARN) {
                    $TitleForegroundColor = "DarkYellow"
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
        $CsvRows = @()

        foreach ($SiteReport in $SiteReports) {
            $RowData = [ordered]@{
                SiteUrl = $SiteReport.SiteUrl
                RedirectUrl = $SiteReport.RedirectUrl
                SitecoreVersion = $SiteReport.SitecoreVersion
            }

            foreach ($SiteResult in $SiteReport.SiteResults) {
                $RowData["$($SiteResult.Title) Summary"] = $SiteResult.Outcome

                if ($true -eq $DetailedReport) {
                    foreach ($Test in $SiteResult.Tests) {
                        $RowData["$($SiteResult.Title) ($($Test.Title))"] = "$($Test.Outcome) - $($Test.Details)"
                    }
                }
            }

            $CsvRows += [PSCustomObject]$RowData
        }

        $CsvRows | Export-Csv -Path $CsvFilePath -NoTypeInformation
    }
}


Export-ModuleMember -function *