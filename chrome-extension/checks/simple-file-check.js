import { PASS, FAIL, createResult, fetchUrl } from './result.js';

const FILES = ['webedit.css', 'default.css', 'default.js'];

let versionHashesCache = null;

async function loadVersionHashes() {
  if (!versionHashesCache) {
    if (typeof chrome !== 'undefined' && chrome.runtime?.getURL) {
      // Chrome extension context
      const url = chrome.runtime.getURL('data/version-hashes.json');
      const response = await fetch(url);
      versionHashesCache = await response.json();
    } else {
      // Node.js context
      const { readFileSync } = await import('node:fs');
      const { fileURLToPath } = await import('node:url');
      const { dirname, join } = await import('node:path');
      const dir = dirname(fileURLToPath(import.meta.url));
      const raw = readFileSync(join(dir, '..', 'data', 'version-hashes.json'), 'utf8').replace(/^\uFEFF/, '');
      versionHashesCache = JSON.parse(raw);
    }
  }
  return versionHashesCache;
}

async function sha256Hex(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

export async function checkSimpleFileCheck(baseUrl) {
  const versionHashes = await loadVersionHashes();
  let overallOutcome = FAIL;
  const tests = [];
  let fullHash = '';

  for (const file of FILES) {
    // Resolve against host root - Sitecore static files always live at /,
    // never under a path. This avoids issues when baseUrl is a redirected
    // language variant like https://www.ghd.com/en-au/
    const url = new URL('/' + file, baseUrl).href;
    let pathOutcome = FAIL;
    let details = '';

    try {
      const response = await fetchUrl(url);
      const statusCode = response.status;

      if (statusCode === 200) {
        pathOutcome = PASS;
        const buffer = await response.arrayBuffer();
        const hash = await sha256Hex(buffer);
        fullHash += file + hash;

        // Look up per-file matches
        const fileHashes = versionHashes.files[file] || {};
        const matchedVersions = fileHashes[hash] || [];

        if (matchedVersions.length > 0) {
          const first = matchedVersions[0];
          const last = matchedVersions[matchedVersions.length - 1];
          const display = first === last ? first : `${first} - ${last}`;
          details = `StatusCode: ${statusCode}, Matches: ${display}`;
        } else {
          details = `StatusCode: ${statusCode}, Matches: Unknown`;
        }
      } else {
        details = `StatusCode: ${statusCode}`;
      }
    } catch (e) {
      details = `Error: ${e.message}`;
    }

    tests.push(createResult(file, pathOutcome, [], details));
  }

  // Check composite hash match
  const compositeMatches = versionHashes.composites[fullHash] || [];

  if (compositeMatches.length > 0) {
    overallOutcome = PASS;
    const first = compositeMatches[0];
    const last = compositeMatches[compositeMatches.length - 1];
    const display = first === last ? first : `${first} - ${last}`;
    return createResult('Simple File Check', overallOutcome, tests, `Matches: ${display}`);
  }

  // No composite match — check if individual files matched known versions.
  // Collect per-file version matches and find the most specific one.
  const perFileMatches = [];
  for (const test of tests) {
    if (test.details) {
      const m = test.details.match(/Matches:\s*(.+)/);
      if (m && m[1] !== 'Unknown') perFileMatches.push(m[1]);
    }
  }

  const filesFound = tests.filter(t => t.outcome === PASS).length;
  const pct = Math.round((filesFound / FILES.length) * 100);

  if (pct > 80) overallOutcome = PASS;

  if (perFileMatches.length > 0) {
    // Use the narrowest match (fewest versions in its range)
    const best = perFileMatches.sort((a, b) => a.length - b.length)[0];
    return createResult('Simple File Check', overallOutcome, tests, `Probable: ${best}`);
  }

  return createResult('Simple File Check', overallOutcome, tests, `${pct}%`);
}
