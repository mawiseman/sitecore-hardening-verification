# Sitecore Hardening Report

## Introduction

These Powershell scripts will perform some simple checks to see if the sites provided confirm to Sitecore's Hardening recommendations.

This is primarily done be evaluating a Http Status code response to files and URLs a visitor should not have access to.

The rules for hardening have come from Sitecore's documentation: https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/security-hardening.html


## Implementation

Not all hardening recommendations can be tested without actually hacking a site. This is not something we want to do.

### Supported Checks

- Sitecore Version: Attempt to load the Sitecore Version from `/sitecore/shell/sitecore.version.xml`
- Sitecore Simple File Check: Checks for `webedit.css`, `default.js` and `default.css`
- [Deny Anomous Access](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html)
- [Increase login security](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/increase-login-security.html)
- [Limit access to .XML, .XSLT, and .MRT files](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/limit-access-to--xml,--xslt,-and--mrt-files.html)
- [Remove header information from responses sent by your website](https://doc.sitecore.com/developers/81/sitecore-experience-platform/en/remove-header-information-from-responses-sent-by-your-website.html)
- [Use HTTPS on all your Sitecore instances](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html)


### Unsupported Checks

- [Change the hash algorithm for password encryption](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/change-the-hash-algorithm-for-password-encryption.html)
- [Disable administrative tools](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/disable-administrative-tools.html)
- [Disable client RSS feeds](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/disable-client-rss-feeds.html) 
- [Disable WebDAV](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/disable-webdav.html)
- [Secure the file upload functionality](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/secure-the-file-upload-functionality.html)
- [Improve the security of the website folder](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/improve-the-security-of-the-website-folder.html)
- [Disable SQL Server access from XSLT](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/disable-sql-server-access-from-xslt.html)
- [Secure the Telerik control](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/secure-the-telerik-controls.html)
- [PhantomJS and security hardening](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/phantomjs-and-security-hardening.html)
- [Protect media requests](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/protect-media-requests.html)

## Usage

```powershell
# Usage
# report.ps1 -Url -Format (Console, Html, Csv)

# Quick console report
report.ps1 https://yoursite.com

# Detailed Html Report
report.ps1 -Url https://yoursite.com -Format Html

```

### Important Note

If you are running this script from a computer that is in a location that has been whitelisted you might get false positives.

i.e. The site grants access to `/sitecore/login` from your offices IP address which average users should not have access to

### Script

See [\examples\report-example.ps1](/examples/report-example.ps1) for the most recent example script

```powershell
Import-Module .\src\sitecore-hardening-report.psm1

$Urls = @(
    "https://sitecore.com"
)

Invoke-ConsoleReport -Urls $Urls

Invoke-HtmlReport -Urls $Urls -OutputFolderPath "c:\temp\" -SplitResults $false

Invoke-HtmlReport -Urls $Urls -OutputFolderPath "c:\temp\" -SplitResults $true

Invoke-CsvReport -Urls $Urls -CsvFilePath "c:\temp\report.csv" -DetailedReport $false 

```

![demo](/assets/demo.gif)