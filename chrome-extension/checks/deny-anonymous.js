import { PASS, FAIL, createResult, fetchUrl } from './result.js';

const PATHS = [
  '/sitecore/admin/dbbrowser.css',
  '/sitecore/debug/Trace.xslt',
  '/sitecore/login',
  '/sitecore/shell/WebService/Service.asmx',
];

export async function checkDenyAnonymous(baseUrl) {
  let overallOutcome = PASS;
  const tests = [];

  for (const path of PATHS) {
    const url = new URL(path, baseUrl).href;
    let pathOutcome = PASS;
    let details = '';

    try {
      // Phase 1: check for redirect without following
      const manualResponse = await fetchUrl(url, { redirect: 'manual' });

      if (manualResponse.type === 'opaqueredirect') {
        // Redirect detected - follow it to check destination
        const followResponse = await fetchUrl(url, { redirect: 'follow' });
        const finalUrl = followResponse.url.toLowerCase();
        details = `StatusCode: ${followResponse.status} (redirected to ${followResponse.url})`;

        if (finalUrl.includes('/sitecore/login')) {
          pathOutcome = FAIL;
        }
      } else {
        const status = manualResponse.status;
        details = `StatusCode: ${status}`;

        if (status === 200) {
          pathOutcome = FAIL;
        }
        // 401, 403, 404 = PASS
      }
    } catch {
      // Network error means resource is not accessible = PASS
      details = 'Not accessible (network error)';
    }

    if (pathOutcome === FAIL) overallOutcome = FAIL;
    tests.push(createResult(path, pathOutcome, [], details));
  }

  return createResult('Deny Anonymous Access', overallOutcome, tests);
}
