import { PASS, FAIL, WARN, createResult } from './result.js';

/**
 * Checks that the Sitecore API key is not exposed in a Next.js page chunk.
 *
 * Expects the JS content of the chunk already identified by the JSS version
 * check. A properly configured site should have: sitecoreApiKey = "" (empty
 * string, resolved from an env var at build time). An exposed key is a
 * security issue.
 */

function analyseApiKey(jsContent) {
  const matches = [];

  // Match direct string assignments: sitecoreApiKey = "value" or sitecoreApiKey: "value"
  const directPattern = /sitecoreApiKey\s*[=:]\s*["']([^"']*)["']/g;
  let m;
  while ((m = directPattern.exec(jsContent)) !== null) {
    matches.push(m[1]);
  }

  // Match env var fallback pattern: sitecoreApiKey=...||"value"
  const fallbackPattern = /sitecoreApiKey\s*=\s*[^"'|]+\|\|\s*["']([^"']*)["']/g;
  while ((m = fallbackPattern.exec(jsContent)) !== null) {
    matches.push(m[1]);
  }

  if (matches.length === 0) {
    return { found: false, exposed: false, values: [] };
  }

  // Filter out empty strings and "undefined" (unresolved env var at build time)
  const exposedValues = matches.filter(v => v.length > 0 && v !== 'undefined');

  return {
    found: true,
    exposed: exposedValues.length > 0,
    values: exposedValues,
  };
}

export function checkXMCloudApiKey(jsContent, chunkName) {
  const tests = [];

  if (!jsContent) {
    return createResult('XM Cloud API Key', WARN, [], 'No chunk to analyse');
  }

  const analysis = analyseApiKey(jsContent);

  if (!analysis.found) {
    tests.push(createResult(chunkName, WARN, [], 'sitecoreApiKey not found'));
    return createResult('XM Cloud API Key', WARN, tests, 'sitecoreApiKey not found');
  }

  if (analysis.exposed) {
    const masked = analysis.values.map(v =>
      v.length > 8 ? v.substring(0, 4) + '...' + v.substring(v.length - 4) : v
    ).join(', ');
    const details = `API key exposed: ${masked}`;
    tests.push(createResult(chunkName, FAIL, [], details));
    return createResult('XM Cloud API Key', FAIL, tests, details);
  }

  tests.push(createResult(chunkName, PASS, [], 'Value: ""'));
  return createResult('XM Cloud API Key', PASS, tests, 'sitecoreApiKey is empty');
}
