export const PASS = 'Pass';
export const FAIL = 'Fail';
export const WARN = 'Warn';

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/**
 * Wrapper around fetch that sets a browser-like User-Agent header.
 * In the Chrome extension context the browser overrides the header,
 * but for Node.js CLI usage this avoids Cloudflare bot detection.
 */
export function fetchUrl(url, options = {}) {
  const headers = { 'User-Agent': USER_AGENT, ...options.headers };
  return fetch(url, { ...options, headers });
}

export function createResult(title, outcome, tests = [], details = '') {
  return { title, outcome, tests, details };
}
