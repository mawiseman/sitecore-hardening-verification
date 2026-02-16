import { checkSitecoreVersion } from './sitecore-version.js';
import { checkForceHttps } from './force-https.js';
import { checkDenyAnonymous } from './deny-anonymous.js';
import { checkLimitXsl } from './limit-xsl.js';
import { checkRemoveHeaders } from './remove-headers.js';
import { checkSimpleFileCheck } from './simple-file-check.js';
import { checkUnsupportedLanguages } from './unsupported-languages.js';
import { checkXMCloud } from './xm-cloud.js';

const CHECKS = [
  { name: 'Sitecore Version', fn: (url) => checkSitecoreVersion(url), isVersion: true },
  { name: 'Force HTTPS Redirect', fn: (url) => checkForceHttps(url) },
  { name: 'Deny Anonymous Access', fn: (url) => checkDenyAnonymous(url) },
  { name: 'Limit Access to XSL', fn: (url) => checkLimitXsl(url) },
  { name: 'Remove Headers', fn: (url) => checkRemoveHeaders(url) },
  { name: 'Simple File Check', fn: (url) => checkSimpleFileCheck(url) },
  { name: 'Unsupported Languages', fn: (url) => checkUnsupportedLanguages(url) },
  { name: 'XM Cloud', fn: (url) => checkXMCloud(url) },
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

  for (let i = 0; i < CHECKS.length; i++) {
    const check = CHECKS[i];

    if (onProgress) {
      onProgress({ step: i + 1, total: CHECKS.length, name: check.name });
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
    siteResults: results,
  };
}
