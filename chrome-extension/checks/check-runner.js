import { checkSitecoreVersion } from './sitecore-version.js';
import { checkForceHttps } from './force-https.js';
import { checkDenyAnonymous } from './deny-anonymous.js';
import { checkLimitXsl } from './limit-xsl.js';
import { checkRemoveHeaders } from './remove-headers.js';
import { checkSimpleFileCheck } from './simple-file-check.js';
import { checkUnsupportedLanguages } from './unsupported-languages.js';
import { checkIsJss, checkIsXMCloud } from './xm-cloud.js';
import { checkJssVersion } from './jss-version.js';
import { checkXMCloudApiKey } from './xm-cloud-api-key.js';

// XM/XP checks - skipped when JSS is detected
const XM_XP_CHECKS = [
  { name: 'Sitecore Version', fn: (url) => checkSitecoreVersion(url), isVersion: true },
  { name: 'Force HTTPS Redirect', fn: (url) => checkForceHttps(url) },
  { name: 'Deny Anonymous Access', fn: (url) => checkDenyAnonymous(url) },
  { name: 'Limit Access to XSL', fn: (url) => checkLimitXsl(url) },
  { name: 'Remove Headers', fn: (url) => checkRemoveHeaders(url) },
  { name: 'Simple File Check', fn: (url) => checkSimpleFileCheck(url) },
  { name: 'Unsupported Languages', fn: (url) => checkUnsupportedLanguages(url) },
];

export async function runAllChecks(url, onProgress) {
  // Normalize URL
  if (!url.startsWith('http')) {
    url = 'https://' + url;
  }

  // Ensure trailing slash for proper URL joining
  const baseUrl = url.endsWith('/') ? url : url + '/';

  const results = [];
  let sitecoreVersion = 'Unknown';
  let isXMCloud = false;

  // Step 1: Check for JSS / Content SDK (Next.js + Sitecore)
  if (onProgress) {
    onProgress({ step: 1, total: XM_XP_CHECKS.length + 1, name: 'JSS / Content SDK Detection' });
  }

  const jssCheck = await checkIsJss(baseUrl);
  const isJss = jssCheck.result.outcome === 'Pass';

  // Step 2: If JSS/Content SDK, run headless-specific checks
  if (isJss) {
    if (onProgress) {
      onProgress({ step: 2, total: 4, name: 'SDK Version Detection' });
    }

    // Run version detection first - it fetches chunks we also need for XM Cloud detection
    const jssResult = await checkJssVersion(baseUrl, jssCheck.html, jssCheck.jsonContent, jssCheck.routerType);
    results.push(jssResult.result);

    if (onProgress) {
      onProgress({ step: 3, total: 4, name: 'XM Cloud Detection' });
    }

    // XM Cloud check searches HTML, JSON, and bundle content (edge.sitecorecloud.io
    // may only appear in JS bundles, not in the HTML or __NEXT_DATA__)
    const xmCloudResult = checkIsXMCloud(jssCheck.jsonContent, jssCheck.html, jssResult.bundleContent);
    results.push(xmCloudResult);
    isXMCloud = xmCloudResult.outcome === 'Pass';

    if (onProgress) {
      onProgress({ step: 4, total: 4, name: 'XM Cloud API Key' });
    }

    const apiKeyResult = checkXMCloudApiKey(jssResult.jsContent, jssResult.chunkName);
    results.push(apiKeyResult);

    const version = jssResult.versionLabel || jssResult.result.details || (isXMCloud ? 'XM Cloud' : 'JSS');

    return {
      siteUrl: url,
      sitecoreVersion: version,
      isXMCloud,
      sdkFamily: jssResult.sdkFamily,
      confidence: jssResult.confidence,
      siteResults: results,
    };
  }

  // Step 2 (non-JSS): Run XM/XP checks
  const totalSteps = XM_XP_CHECKS.length + 1;

  for (let i = 0; i < XM_XP_CHECKS.length; i++) {
    const check = XM_XP_CHECKS[i];

    if (onProgress) {
      onProgress({ step: i + 2, total: totalSteps, name: check.name });
    }

    const result = await check.fn(baseUrl);

    if (check.isVersion) {
      sitecoreVersion = result;
    } else {
      results.push(result);
    }
  }

  // If version XML didn't return a definitive version, try Simple File Check
  const isDefinitiveVersion = /^\d+\.\d+/.test(sitecoreVersion);
  if (!isDefinitiveVersion) {
    const simpleFileResult = results.find(r => r.title === 'Simple File Check');
    if (simpleFileResult?.details) {
      const match = simpleFileResult.details.match(/(?:Matches|Probable):\s*(.+)/);
      if (match) {
        sitecoreVersion = `${match[1]} (from file fingerprint)`;
      } else if (simpleFileResult.outcome === 'Pass') {
        sitecoreVersion = 'Sitecore (version unknown)';
      }
    }
  }

  return {
    siteUrl: url,
    sitecoreVersion,
    isXMCloud: false,
    sdkFamily: null,
    confidence: null,
    siteResults: results,
  };
}
