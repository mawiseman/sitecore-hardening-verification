import { PASS, WARN, createResult, fetchUrl } from './result.js';

/**
 * Identifies the Sitecore SDK family and version range by scanning Next.js
 * page chunks for runtime identifiers and dependency markers.
 *
 * Simplified to major-version buckets (minor versions are indistinguishable
 * after production minification strips package-scoped strings):
 *
 *   JSS 21.x:            React 18, sitecoreContext/layoutData in bundles
 *   JSS 22.x (React 18): React 18, CloudSDK core+events (when visible)
 *   JSS 22.x (React 19): React 19, CloudSDK core+events (covers 22.9, 22.10, ...)
 *   Content SDK 1.x:     @sitecore-content-sdk, CloudSDK, Pages or App Router
 *   Content SDK 2.x:     @sitecore-content-sdk, new initContentSdk/events/analytics, no CloudSDK
 *
 * Also returns the chunk JS content so the API key check can reuse it.
 */

// Broad pattern to extract any _next/static/*.js URL from HTML.
// Matches both relative (/_next/static/...) and absolute (https://host/_next/static/...) URLs.
// Covers webpack naming (pages/_app-{hash}.js) and Turbopack naming (node_modules_...js).
const CHUNK_URL_PATTERN = /["']([^"']*_next\/static\/[^"']+\.js(?:\?[^"']*)?)["']/g;

// Bundle string signals and what they indicate
const SIGNALS = {
  // SDK family (package name - may be minified away in production)
  hasJss: /@sitecore-jss[/"']/,
  hasContentSdk: /@sitecore-content-sdk[/"']/,

  // SDK family (runtime identifiers - survive minification)
  hasSitecoreContext: /sitecoreContext/,
  hasLayoutData: /layoutData/,

  // CloudSDK variants (package-scoped, may be minified away)
  hasCloudSdkCore: /@sitecore-cloudsdk\/core/,
  hasCloudSdkEvents: /@sitecore-cloudsdk\/events/,

  // Content SDK 2.x new packages (replace CloudSDK)
  hasContentSdkEvents: /@sitecore-content-sdk\/events/,
  hasContentSdkAnalytics: /@sitecore-content-sdk\/analytics/,
  hasInitContentSdk: /initContentSdk/,

  // API key reference
  hasSitecoreApiKey: /sitecoreApiKey/,
};

/**
 * Version candidates with scoring rules.
 *
 * Reliable signals that survive production minification:
 *   1. sitecoreContext / layoutData  -> JSS family (all versions)
 *   2. React 18 vs 19               -> from framework chunk version string
 *   3. Pages Router vs App Router   -> __NEXT_DATA__ presence
 *   4. @sitecore-content-sdk        -> Content SDK (when not minified)
 *   5. initContentSdk               -> Content SDK 2.x specifically
 *
 * Package-scoped signals (@sitecore-cloudsdk/*, @sitecore/engage, etc.)
 * are bonus differentiators when present but cannot be relied upon.
 */
const VERSION_CANDIDATES = [
  {
    label: 'JSS 21.x',
    family: 'jss',
    rules: {
      hasJss: 20, hasContentSdk: -100,
      hasSitecoreContext: 25, hasLayoutData: 10,
      isReact18: 20, isReact19: -50,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100, hasInitContentSdk: -100,
    },
  },
  {
    label: 'JSS 22.x',
    family: 'jss',
    rules: {
      hasJss: 20, hasContentSdk: -100,
      hasSitecoreContext: 25, hasLayoutData: 10,
      hasCloudSdkCore: 10, hasCloudSdkEvents: 5,
      isReact18: 15, isReact19: -50,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100, hasInitContentSdk: -100,
    },
    // Prefer this over 21.x only when CloudSDK signals are visible
    absentRules: { hasCloudSdkCore: -15, hasCloudSdkEvents: -10 },
  },
  {
    label: 'JSS 22.x',
    family: 'jss',
    // Separate candidate for React 19 variant (22.9+, 22.10+, etc.)
    rules: {
      hasJss: 20, hasContentSdk: -100,
      hasSitecoreContext: 25, hasLayoutData: 10,
      hasCloudSdkCore: 10, hasCloudSdkEvents: 5,
      isReact19: 20, isReact18: -50,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100, hasInitContentSdk: -100,
    },
    htmlRules: { isPagesRouter: 5 },
  },
  {
    label: 'Content SDK 1.x',
    family: 'content-sdk',
    rules: {
      hasContentSdk: 30, hasJss: -100,
      hasSitecoreContext: -30,
      hasCloudSdkCore: 10, hasCloudSdkEvents: 5,
      isReact19: 10,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100, hasInitContentSdk: -100,
    },
    htmlRules: { isPagesRouter: 5, isAppRouter: 5 },
  },
  {
    label: 'Content SDK 2.x',
    family: 'content-sdk',
    rules: {
      hasContentSdk: 30, hasJss: -100,
      hasSitecoreContext: -30,
      hasContentSdkEvents: 25, hasContentSdkAnalytics: 25, hasInitContentSdk: 20,
      hasCloudSdkCore: -30, hasCloudSdkEvents: -30,
      isReact19: 5,
    },
    htmlRules: { isPagesRouter: 5, isNext16Plus: 10 },
  },
];

/**
 * Collect unique chunk URLs from the HTML source.
 * Prioritizes chunks likely to contain Sitecore SDK references:
 *   - Turbopack: chunks named with @sitecore, node_modules_, src_pages
 *   - Webpack: pages/_app, pages/[[...path]], named chunks
 * Falls back to any chunk if no priority matches are found.
 */
function extractChunkUrls(html, baseUrl) {
  const priority = [];
  const other = [];

  for (const match of html.matchAll(CHUNK_URL_PATTERN)) {
    let url;
    try {
      url = new URL(match[1], baseUrl).href;
    } catch { continue; }

    const path = match[1];

    // Skip source maps and non-JS
    if (path.endsWith('.js.map')) continue;
    // Skip manifest/buildManifest files
    if (path.includes('Manifest.js') || path.includes('ssgManifest')) continue;

    // Prioritize chunks likely to contain SDK signals
    const isPriority =
      path.includes('sitecore') ||
      path.includes('node_modules_') ||
      path.includes('pages/_app') ||
      path.includes('pages__app') ||
      path.includes('pages/[[') ||
      path.includes('pages/%5B%5B') ||
      path.includes('src_pages');

    if (isPriority) {
      priority.push(url);
    } else {
      other.push(url);
    }
  }

  // Deduplicate and return priority chunks first
  return [...new Set([...priority, ...other])];
}

/**
 * Scan bundle content for signal patterns, including React version.
 */
function detectBundleSignals(bundleContent) {
  const signals = {};
  for (const [key, pattern] of Object.entries(SIGNALS)) {
    signals[key] = pattern.test(bundleContent);
  }

  // Detect React major version from framework chunk.
  // Patterns vary by bundler/minification:
  //   ReactVersion = "19.2.0"     (dev/unminified)
  //   version:"18.3.1"            (minified, inside react-dom)
  //   {version:"19.1.0"}          (object literal)
  const reactVersionMatch = bundleContent.match(
    /(?:ReactVersion\s*=\s*["']|(?:\.version|version)\s*[=:]\s*["'])(1[89])\.\d+\.\d+/
  );
  if (reactVersionMatch) {
    const major = parseInt(reactVersionMatch[1], 10);
    signals.isReact18 = major === 18;
    signals.isReact19 = major >= 19;
    signals.reactMajor = major;
  } else {
    // Fallback: look for known React 19 APIs that don't exist in React 18
    signals.isReact19 = /useActionState|useFormStatus/.test(bundleContent);
    signals.isReact18 = !signals.isReact19;
    signals.reactMajor = signals.isReact19 ? 19 : null;
  }

  return signals;
}

/**
 * Detect HTML-level signals (router type, Next.js version hints).
 */
function detectHtmlSignals(html, jsonContent) {
  const hasNextData = !!jsonContent || /<script\s+id="__NEXT_DATA__"/.test(html);
  const hasRscPayload = html.includes('self.__next_f.push');

  const chunkPaths = [...html.matchAll(/_next\/static\/chunks\/[^"'\s]+/g)].map(m => m[0]);

  // Turbopack chunk naming: node_modules_..., src_pages__app_..., [root-of-the-server]__...
  const hasTurbopackChunks = chunkPaths.some(p =>
    /node_modules_[^/]/.test(p) || /src_pages_/.test(p) || p.includes('[root-of-the-server]')
  );

  let nextVersionHint = 0;
  if (hasTurbopackChunks || html.includes('turbopack-')) {
    nextVersionHint = 16;
  }
  if (hasRscPayload && !hasNextData) {
    nextVersionHint = Math.max(nextVersionHint, 15);
  }

  return {
    isPagesRouter: hasNextData,
    isAppRouter: hasRscPayload && !hasNextData,
    isNext16Plus: nextVersionHint >= 16,
  };
}

/**
 * Score each version candidate based on collected signals.
 */
function scoreVersions(bundleSignals, htmlSignals) {
  // Merge all signals into one map for unified scoring
  const allSignals = { ...htmlSignals, ...bundleSignals };
  const scores = [];

  for (const candidate of VERSION_CANDIDATES) {
    let score = 0;

    // Apply rules (signal present -> add points)
    for (const [signal, points] of Object.entries(candidate.rules)) {
      if (allSignals[signal]) {
        score += points;
      }
    }

    // Apply HTML signal rules
    if (candidate.htmlRules) {
      for (const [signal, points] of Object.entries(candidate.htmlRules)) {
        if (allSignals[signal]) {
          score += points;
        }
      }
    }

    // Apply absent rules (signal NOT present -> add points)
    if (candidate.absentRules) {
      for (const [signal, points] of Object.entries(candidate.absentRules)) {
        if (!allSignals[signal]) {
          score += points;
        }
      }
    }

    scores.push({ label: candidate.label, family: candidate.family, score });
  }

  // Sort by score descending
  scores.sort((a, b) => b.score - a.score);
  return scores;
}

export async function checkJssVersion(baseUrl, html, jsonContent, routerType) {
  const tests = [];

  try {
    // If we don't have HTML yet, fetch it
    if (!html) {
      const response = await fetchUrl(baseUrl);
      if (response.status !== 200) {
        return {
          result: createResult('SDK Version', WARN, [], `HTTP ${response.status}`),
          jsContent: null,
          chunkName: null,
          sdkFamily: null,
        };
      }
      html = await response.text();
    }

    // Extract chunk URLs from HTML
    const chunkUrls = extractChunkUrls(html, baseUrl);

    if (chunkUrls.length === 0) {
      return {
        result: createResult('SDK Version', WARN, [], 'No page chunks found'),
        jsContent: null,
        chunkName: null,
        sdkFamily: null,
      };
    }

    // Fetch chunks (limit to first 10 to avoid excessive requests)
    const chunksToScan = chunkUrls.slice(0, 10);
    let combinedBundleContent = '';
    let apiKeyChunkContent = null;
    let apiKeyChunkName = null;

    for (const url of chunksToScan) {
      const chunkName = url.split('/').pop().split('?')[0];
      try {
        const chunkResponse = await fetchUrl(url);
        if (chunkResponse.status !== 200) continue;

        const content = await chunkResponse.text();
        combinedBundleContent += content + '\n';

        // Track the chunk containing sitecoreApiKey for downstream use
        if (!apiKeyChunkContent && /sitecoreApiKey/.test(content)) {
          apiKeyChunkContent = content;
          apiKeyChunkName = chunkName;
          tests.push(createResult(chunkName, PASS, [], 'sitecoreApiKey found'));
        }
      } catch { /* skip failed fetches */ }
    }

    if (!combinedBundleContent) {
      return {
        result: createResult('SDK Version', WARN, [], 'Could not fetch any chunks'),
        jsContent: null,
        chunkName: null,
        sdkFamily: null,
      };
    }

    // Collect signals
    const bundleSignals = detectBundleSignals(combinedBundleContent);
    const htmlSignals = detectHtmlSignals(html, jsonContent);

    // Score candidates
    const scores = scoreVersions(bundleSignals, htmlSignals);
    const best = scores[0];

    // Determine confidence
    let confidence;
    if (best.score >= 50) confidence = 'High';
    else if (best.score >= 30) confidence = 'Medium';
    else if (best.score >= 10) confidence = 'Low';
    else confidence = 'Uncertain';

    // Build details string
    const versionWithRouter = routerType ? `${best.label} (${routerType})` : best.label;
    const detailParts = [versionWithRouter];
    if (confidence !== 'High') detailParts.push(`confidence: ${confidence}`);

    // Add signal summary for debugging
    const activeSignals = Object.entries(bundleSignals)
      .filter(([, v]) => v)
      .map(([k]) => k);

    const signalSummary = activeSignals.join(', ');
    if (signalSummary) {
      tests.push(createResult('Bundle signals', PASS, [], signalSummary));
    }

    const activeHtmlSignals = Object.entries(htmlSignals)
      .filter(([, v]) => v)
      .map(([k]) => k);

    if (activeHtmlSignals.length) {
      tests.push(createResult('HTML signals', PASS, [], activeHtmlSignals.join(', ')));
    }

    // Add runner-up if close
    if (scores.length > 1 && scores[1].score > 0) {
      tests.push(createResult('Runner-up', WARN, [], `${scores[1].label} (score: ${scores[1].score})`));
    }

    return {
      result: createResult('SDK Version', PASS, tests, detailParts.join(' - ')),
      jsContent: apiKeyChunkContent,
      chunkName: apiKeyChunkName,
      bundleContent: combinedBundleContent,
      sdkFamily: best.family,
      versionLabel: versionWithRouter,
      confidence,
    };
  } catch (e) {
    return {
      result: createResult('SDK Version', WARN, tests, `Error: ${e.message}`),
      jsContent: null,
      chunkName: null,
      bundleContent: null,
      sdkFamily: null,
    };
  }
}
