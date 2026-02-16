import { checkSitecoreVersion } from './sitecore-version.js';
import { checkForceHttps } from './force-https.js';
import { checkDenyAnonymous } from './deny-anonymous.js';
import { checkLimitXsl } from './limit-xsl.js';
import { checkRemoveHeaders } from './remove-headers.js';
import { checkSimpleFileCheck } from './simple-file-check.js';
import { checkUnsupportedLanguages } from './unsupported-languages.js';
import { checkXMCloud } from './xm-cloud.js';
import { checkJssVersion } from './jss-version.js';
import { checkXMCloudApiKey } from './xm-cloud-api-key.js';

// XM/XP checks - skipped when XM Cloud is detected
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

  // Step 1: Check for XM Cloud first
  if (onProgress) {
    onProgress({ step: 1, total: XM_XP_CHECKS.length + 1, name: 'XM Cloud Detection' });
  }

  const xmCloudResult = await checkXMCloud(baseUrl);
  results.push(xmCloudResult);
  isXMCloud = xmCloudResult.outcome === 'Pass';

  // Step 2: If XM Cloud, run XM Cloud-specific checks only
  if (isXMCloud) {
    // Step 2a: Identify JSS version and find the chunk with sitecoreApiKey
    if (onProgress) {
      onProgress({ step: 2, total: 3, name: 'Sitecore JSS Version' });
    }

    const jssResult = await checkJssVersion(baseUrl);
    results.push(jssResult.result);

    // Step 2b: Check the API key in the identified chunk
    if (onProgress) {
      onProgress({ step: 3, total: 3, name: 'XM Cloud API Key' });
    }

    const apiKeyResult = checkXMCloudApiKey(jssResult.jsContent, jssResult.chunkName);
    results.push(apiKeyResult);

    const version = jssResult.result.details || 'XM Cloud';

    return {
      siteUrl: url,
      sitecoreVersion: version,
      isXMCloud: true,
      siteResults: results,
    };
  }

  // Step 3: Run XM/XP checks
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

  return {
    siteUrl: url,
    sitecoreVersion,
    isXMCloud: false,
    siteResults: results,
  };
}
