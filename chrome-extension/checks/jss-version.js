import { PASS, WARN, createResult, fetchUrl } from './result.js';

/**
 * Identifies the Sitecore JSS version by finding which page chunk contains
 * the sitecoreApiKey reference. The chunk URL pattern indicates the version:
 *   JSS 22.*: /_next/static/chunks/pages/_app-{hash}.js
 *   JSS 21.*: /_next/static/chunks/pages/%5B%5B...path%5D%5D-{hash}.js
 *
 * Also returns the chunk JS content so the API key check can reuse it.
 */

// Each entry maps a chunk URL pattern to its JSS version label
const CHUNK_PATTERNS = [
  {
    label: 'JSS 22.x',
    pattern: /["']([^"']*_next\/static\/chunks\/pages\/_app-[^"']+\.js[^"']*?)["']/,
  },
  {
    label: 'JSS 21.x',
    pattern: /["']([^"']*_next\/static\/chunks\/pages\/\[\[\.\.\.path\]\]-[^"']+\.js[^"']*?)["']/,
  },
  {
    label: 'JSS 21.x',
    pattern: /["']([^"']*_next\/static\/chunks\/pages\/%5B%5B\.\.\.path%5D%5D-[^"']+\.js[^"']*?)["']/,
  },
];

export async function checkJssVersion(baseUrl) {
  const tests = [];

  try {
    const response = await fetchUrl(baseUrl);
    if (response.status !== 200) {
      return {
        result: createResult('Sitecore JSS Version', WARN, [], `HTTP ${response.status}`),
        jsContent: null,
        chunkName: null,
      };
    }

    const html = await response.text();

    // Collect all matching chunks with their version labels
    const chunks = [];
    for (const { label, pattern } of CHUNK_PATTERNS) {
      const match = html.match(pattern);
      if (match) {
        chunks.push({ label, url: new URL(match[1], baseUrl).href });
      }
    }

    if (chunks.length === 0) {
      return {
        result: createResult('Sitecore JSS Version', WARN, [], 'No page chunks found'),
        jsContent: null,
        chunkName: null,
      };
    }

    // Fetch each chunk and find the one containing sitecoreApiKey
    for (const chunk of chunks) {
      const chunkName = chunk.url.split('/').pop().split('?')[0];
      const chunkResponse = await fetchUrl(chunk.url);

      if (chunkResponse.status !== 200) {
        tests.push(createResult(chunkName, WARN, [], `HTTP ${chunkResponse.status}`));
        continue;
      }

      const jsContent = await chunkResponse.text();
      const hasSitecoreApiKey = /sitecoreApiKey/.test(jsContent);

      if (!hasSitecoreApiKey) {
        tests.push(createResult(chunkName, WARN, [], 'sitecoreApiKey not found'));
        continue;
      }

      // Found it - report the version
      tests.push(createResult(chunkName, PASS, [], `sitecoreApiKey found`));

      return {
        result: createResult('Sitecore JSS Version', PASS, tests, chunk.label),
        jsContent,
        chunkName,
      };
    }

    // Not found in any chunk
    return {
      result: createResult('Sitecore JSS Version', WARN, tests, 'sitecoreApiKey not found in any chunk'),
      jsContent: null,
      chunkName: null,
    };
  } catch (e) {
    return {
      result: createResult('Sitecore JSS Version', WARN, tests, `Error: ${e.message}`),
      jsContent: null,
      chunkName: null,
    };
  }
}
