import { PASS, FAIL, createResult } from './result.js';

export async function checkLimitXsl(baseUrl) {
  const path = '/xsl/sample%20rendering.xslt';
  const url = new URL(path, baseUrl).href;
  let pathOutcome = PASS;
  let statusCode = 0;

  try {
    const response = await fetch(url);
    statusCode = response.status;
    if (statusCode === 200) {
      pathOutcome = FAIL;
    }
  } catch {
    statusCode = 'Network error';
  }

  const tests = [createResult(path, pathOutcome, [], `StatusCode: ${statusCode}`)];
  return createResult('Limit Access to XSL', pathOutcome, tests);
}
