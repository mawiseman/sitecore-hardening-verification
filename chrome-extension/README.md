# Chrome Extension

A Manifest V3 Chrome extension that runs Sitecore hardening checks against the currently active tab.

## Installation

1. Open `chrome://extensions/` in Chrome
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select this `chrome-extension/` folder

## Usage

1. Navigate to a Sitecore website in Chrome
2. Click the **Sitecore Hardening Verifier** icon in the toolbar
3. Click **Run Checks**
4. Review results - each check shows Pass/Fail with expandable sub-test details

## How It Works

The extension runs the same security checks as the PowerShell tool, ported to JavaScript:

1. **Popup** (`popup.js`) reads the active tab's URL and sends a message to the service worker
2. **Service worker** (`service-worker.js`) receives the message and runs all checks sequentially
3. Each **check module** in `checks/` makes `fetch()` requests to the target site and analyzes responses
4. Results are sent back to the popup for rendering with pass/fail badges

## Checks Performed

| Check | What It Does |
|-------|-------------|
| Sitecore Version | Fetches `/sitecore/shell/sitecore.version.xml` and parses the version |
| Force HTTPS Redirect | Tests if HTTP requests redirect to HTTPS |
| Deny Anonymous Access | Tests 4 protected paths for proper access denial |
| Limit Access to XSL | Checks if `.xslt` files are publicly accessible |
| Remove Headers | Checks for `X-Aspnet-Version`, `X-Powered-By`, `X-AspNetMvc-Version` |
| Simple File Check | SHA256 fingerprinting of `webedit.css`, `default.css`, `default.js` |
| Unsupported Languages | Tests that unsupported language codes return 404 |
| XM Cloud / JSS | Detects Next.js `__NEXT_DATA__` with Sitecore context |

## Architecture

```
manifest.json           Extension configuration (Manifest V3)
popup.html/css/js       Popup UI
service-worker.js       Background service worker (ES module)
checks/
  result.js             Shared PASS/FAIL constants and result factory
  check-runner.js       Orchestrator - runs all checks, reports progress
  sitecore-version.js   Version detection
  force-https.js        HTTPS redirect check
  deny-anonymous.js     Anonymous access check
  limit-xsl.js          XSL file access check
  remove-headers.js     Response header check
  simple-file-check.js  File hash fingerprinting
  unsupported-languages.js  Language handling check
  xm-cloud.js           XM Cloud / JSS detection
data/
  version-hashes.json   Pre-computed SHA256 hashes for version matching
icons/
  icon16/48/128.png     Extension icons
```

## Permissions

| Permission | Why |
|------------|-----|
| `activeTab` | Read the URL of the currently active tab |
| `host_permissions: <all_urls>` | Make cross-origin `fetch()` requests to any Sitecore site |

## Updating Version Hashes

The `data/version-hashes.json` file contains pre-computed SHA256 hashes from the PowerShell tool's `sitecore/` fingerprint files. When new Sitecore versions are added, regenerate it:

```powershell
powershell -ExecutionPolicy Bypass -File ../scripts/generate-hashes.ps1
```
