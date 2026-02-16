# Sitecore Hardening Verification

Automated security hardening checks for Sitecore CMS websites.

These tools perform checks to see if sites conform to [Sitecore's hardening recommendations](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/security-hardening.html), primarily by evaluating HTTP status code responses to files and URLs a visitor should not have access to.

## Tools

| Tool | Description |
|------|-------------|
| [PowerShell CLI](powershell/) | Command-line tool for single or batch site audits with console and CSV output |
| [Chrome Extension](chrome-extension/) | Browser extension that checks the currently active tab from a popup UI |

## Supported Checks

| Check | Description | Reference |
|-------|-------------|-----------|
| Sitecore Version | Detect version from `/sitecore/shell/sitecore.version.xml` | |
| Force HTTPS Redirect | Verify HTTP requests redirect to HTTPS | [Docs](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html) |
| Deny Anonymous Access | Test that Sitecore admin/shell paths are restricted | [Docs](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html) |
| Limit Access to XSL | Check that .xslt files are blocked | [Docs](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/limit-access-to--xml,--xslt,-and--mrt-files.html) |
| Remove Headers | Verify sensitive headers are stripped from responses | [Docs](https://doc.sitecore.com/developers/81/sitecore-experience-platform/en/remove-header-information-from-responses-sent-by-your-website.html) |
| Simple File Check | Version fingerprinting via `webedit.css`, `default.css`, `default.js` hash comparison | |
| Unsupported Languages | Test that unsupported language codes return 404 | |
| XM Cloud / JSS Detection | Detect Next.js-based Sitecore sites via `__NEXT_DATA__` | |

## Unsupported Checks

Some hardening recommendations cannot be tested without server-side access:

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

## Important Note

If you are running these tools from a location that has been whitelisted you may get false positives. For example, the site may grant access to `/sitecore/login` from your office's IP address which average users should not have access to.

## Repository Structure

```
powershell/              PowerShell CLI tool
chrome-extension/        Chrome browser extension
scripts/                 Shared build scripts
assets/                  Demo images
```

![demo](/assets/demo.gif)
