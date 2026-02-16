import { PASS, FAIL, createResult } from './result.js';

export async function checkForceHttps(baseUrl) {
  const httpUrl = baseUrl.replace(/^https:\/\//i, 'http://');

  // If the URL is already HTTP, we still test if it redirects to HTTPS
  try {
    const response = await fetch(httpUrl, { redirect: 'follow' });
    const finalUrl = response.url;
    const outcome = finalUrl.startsWith('https://') ? PASS : FAIL;
    return createResult('Force HTTPS Redirect', outcome, [], `Final URL: ${finalUrl}`);
  } catch (e) {
    return createResult('Force HTTPS Redirect', FAIL, [], `Error: ${e.message}`);
  }
}
