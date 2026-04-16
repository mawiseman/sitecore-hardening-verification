# Sitecore Hardening Verification

Automated security hardening checks for Sitecore CMS websites.

These tools perform checks to see if sites conform to [Sitecore's hardening recommendations](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/security-hardening.html), primarily by evaluating HTTP status code responses to files and URLs a visitor should not have access to.

For headless Sitecore sites (JSS / Content SDK), the tools detect the SDK family and version, identify XM Cloud deployments, and check for exposed API keys.

## Tools

| Tool | Description |
| ---- | ----------- |
| [PowerShell CLI](powershell/) | Command-line tool for single or batch site audits with console and CSV output |
| [Chrome Extension](chrome-extension/) | Browser extension that checks the currently active tab from a popup UI |
| [Node.js CLI](cli/) | Command-line tool that reuses the Chrome extension's check modules (Node.js 18+) |

## Quick Start

### Node.js CLI

```bash
node cli/run.js https://example.com
node cli/run.js https://site1.com https://site2.com
node cli/run.js --csv urls.csv --output results.csv
node cli/run.js --csv urls.csv --output results.csv --resume
```

When `--output` is used, each site's row is appended and flushed to disk immediately so large batches can be resumed. Pass `--resume` to skip URLs already present in the output file. Batch runs default to 4 concurrent checks; tune with `--concurrency N`.

### PowerShell

```powershell
cd powershell
.\report.ps1 -Url "https://example.com" -Format Console
```

### Chrome Extension

1. Open `chrome://extensions/`, enable Developer mode
2. Click "Load unpacked" and select the `chrome-extension/` folder
3. Navigate to a Sitecore site and click the extension icon

## Supported Checks

### Headless Sites (JSS / Content SDK)

When a Next.js-based Sitecore site is detected, the following checks run:

| Check | Description |
| ----- | ----------- |
| JSS / Content SDK Detection | Detects Sitecore headless apps via `__NEXT_DATA__` (Pages Router) or RSC payloads (App Router) |
| SDK Version | Identifies SDK family and major version by scanning Next.js chunks for runtime signals |
| XM Cloud Detection | Detects XM Cloud deployments via `edge.sitecorecloud.io` in HTML or JS bundles |
| API Key Exposure | Checks if the `sitecoreApiKey` value is exposed (non-empty) in page chunks |

#### Detected Versions

| Label | Covers |
| ----- | ------ |
| **JSS 21.x** | JSS 21.1 through 21.7+ |
| **JSS 22.x** | JSS 22.1 through 22.10+ |
| **Content SDK 1.x** | Content SDK 1.2, 1.3 |
| **Content SDK 2.x** | Content SDK 2.0+ |

See [SDK-VERSION-REFERENCE.md](SDK-VERSION-REFERENCE.md) for the full dependency fingerprint table and detection methodology.

### Traditional Sites (XM/XP)

When a traditional Sitecore site is detected (no JSS/Next.js), the following checks run:

| Check | Description | Reference |
| ----- | ----------- | --------- |
| Sitecore Version | Detect version from `/sitecore/shell/sitecore.version.xml` | |
| Force HTTPS Redirect | Verify HTTP requests redirect to HTTPS | [Docs](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html) |
| Deny Anonymous Access | Test that Sitecore admin/shell paths are restricted | [Docs](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/deny-anonymous-users-access-to-a-folder.html) |
| Limit Access to XSL | Check that .xslt files are blocked | [Docs](https://doc.sitecore.com/developers/82/sitecore-experience-platform/en/limit-access-to--xml,--xslt,-and--mrt-files.html) |
| Remove Headers | Verify sensitive headers are stripped from responses | [Docs](https://doc.sitecore.com/developers/81/sitecore-experience-platform/en/remove-header-information-from-responses-sent-by-your-website.html) |
| Simple File Check | Version fingerprinting via `webedit.css`, `default.css`, `default.js` hash comparison | |
| Unsupported Languages | Test that unsupported language codes return 404 | |

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

```text
powershell/              PowerShell CLI tool
chrome-extension/        Chrome browser extension (Manifest V3)
cli/                     Node.js CLI (reuses chrome-extension/checks/)
tests/                   Detection verification (known-sites.csv + runner)
scripts/                 Shared build scripts
data/                    Known-good files for version fingerprinting
assets/                  Demo images
```

## Verification

To validate detection accuracy against known sites:

```bash
node tests/verify-detection.js
```

![demo](/assets/demo.gif)
