import { PASS, WARN, createResult, fetchUrl } from './result.js';

/**
 * Identifies the Sitecore SDK family and version range by scanning Next.js
 * page chunks for package name strings and dependency markers.
 *
 * SDK Families:
 *   - JSS 21.1.x:  @sitecore-jss, @sitecore/engage, no CloudSDK, no FEAAS
 *   - JSS 21.6.x:  @sitecore-jss, @sitecore-cloudsdk/events (no /core), FEAAS
 *   - JSS 22.1.x:  @sitecore-jss, @sitecore-cloudsdk/events (no /core), FEAAS, Next 14
 *   - JSS 22.4-5:  @sitecore-jss, @sitecore-cloudsdk/core+events, Next 14
 *   - JSS 22.9.x:  @sitecore-jss, @sitecore-cloudsdk/core+events, Next 15, React 19
 *   - Content SDK 1.2.x: @sitecore-content-sdk, @sitecore-cloudsdk/core+events, Pages Router
 *   - Content SDK 1.3.x: @sitecore-content-sdk, App Router, next-intl, Tailwind
 *   - Content SDK 2.0.x: @sitecore-content-sdk, @sitecore-content-sdk/events+analytics-core, no CloudSDK
 *
 * Also returns the chunk JS content so the API key check can reuse it.
 */

// Broad pattern to extract any _next/static/*.js URL from HTML.
// Matches both relative (/_next/static/...) and absolute (https://host/_next/static/...) URLs.
// Covers webpack naming (pages/_app-{hash}.js) and Turbopack naming (node_modules_...js).
const CHUNK_URL_PATTERN = /["']([^"']*_next\/static\/[^"']+\.js(?:\?[^"']*)?)["']/g;

// Bundle string signals and what they indicate
const SIGNALS = {
  // SDK family (package name - may be minified away)
  hasJss: /@sitecore-jss[/"']/,
  hasContentSdk: /@sitecore-content-sdk[/"']/,

  // SDK family (runtime identifiers - survive minification)
  hasSitecoreContext: /sitecoreContext/,  // JSS uses sitecoreContext, Content SDK uses page.siteName
  hasLayoutData: /layoutData/,           // JSS layoutData pattern

  // CloudSDK variants
  hasCloudSdkCore: /@sitecore-cloudsdk\/core/,
  hasCloudSdkEvents: /@sitecore-cloudsdk\/events/,
  hasCloudSdkPersonalize: /@sitecore-cloudsdk\/personalize/,

  // Content SDK 2.0 new packages (replaces CloudSDK)
  hasContentSdkEvents: /@sitecore-content-sdk\/events/,
  hasContentSdkAnalytics: /@sitecore-content-sdk\/analytics/,
  hasInitContentSdk: /initContentSdk/,

  // Legacy engage (JSS 21.1 only)
  hasEngageSdk: /@sitecore\/engage/,

  // FEAAS / BYOC
  hasFeaas: /@sitecore-feaas\/clientside/,
  hasByoc: /@sitecore\/byoc/,

  // i18n
  hasNextLocalization: /next-localization/,
  hasNextIntl: /next-intl/,

  // CSS frameworks (in HTML, not bundles)
  // These are checked separately against HTML

  // API key reference
  hasSitecoreApiKey: /sitecoreApiKey/,
};

/**
 * Version candidates with scoring rules.
 * Each signal match adds/subtracts from the candidate's score.
 *
 * Version map (from clean installs):
 *   JSS 21.1:  Next 13, React 18, @sitecore/engage, no CloudSDK, no FEAAS
 *   JSS 21.6:  Next 13, React 18, CloudSDK events only (no core), first FEAAS
 *   JSS 22.1:  Next 14, React 18, CloudSDK events only (no core), FEAAS
 *   JSS 22.4-5: Next 14, React 18, CloudSDK core+events, FEAAS
 *   JSS 22.9+: Next 15, React 19, CloudSDK core+events, FEAAS (covers 22.9, 22.10, etc.)
 *   ContentSDK 1.2: Next 15, React 19, CloudSDK core+events, Pages Router, next-localization
 *   ContentSDK 1.3: Next 15, React 19, CloudSDK core+events, App Router, next-intl, Tailwind
 *   ContentSDK 2.0: Next 16, React 19, no CloudSDK, @sitecore-content-sdk/events+analytics
 */
const VERSION_CANDIDATES = [
  {
    label: 'JSS 21.1.x',
    family: 'jss',
    rules: {
      hasJss: 30, hasContentSdk: -100,
      hasSitecoreContext: 20, hasLayoutData: 10,
      hasEngageSdk: 20,
      hasCloudSdkEvents: -40, hasCloudSdkCore: -40,
      hasFeaas: -40, hasByoc: -40,
      hasNextLocalization: 5,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100,
      isReact18: 10, isReact19: -30,
    },
    // JSS 21.1 has NO CloudSDK, NO FEAAS - penalize when those are present (handled above),
    // but also boost when they're absent (via absentRules)
    absentRules: { hasCloudSdkEvents: 10, hasCloudSdkCore: 10, hasFeaas: 10 },
  },
  {
    label: 'JSS 21.6.x',
    family: 'jss',
    rules: {
      hasJss: 30, hasContentSdk: -100,
      hasSitecoreContext: 20, hasLayoutData: 10,
      hasCloudSdkEvents: 15, hasCloudSdkCore: -30,
      hasEngageSdk: -30,
      hasFeaas: 10,
      hasNextLocalization: 5,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100,
      isReact18: 10, isReact19: -30,
    },
    htmlRules: { isNext13: 10 },
  },
  {
    label: 'JSS 22.1.x',
    family: 'jss',
    rules: {
      hasJss: 30, hasContentSdk: -100,
      hasSitecoreContext: 20, hasLayoutData: 10,
      hasCloudSdkEvents: 15, hasCloudSdkCore: -20,
      hasEngageSdk: -30,
      hasFeaas: 10,
      hasNextLocalization: 5,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100,
      isReact18: 15, isReact19: -30,
    },
    // 22.1 requires CloudSDK events but not core
    absentRules: { hasCloudSdkEvents: -15 },
  },
  {
    label: 'JSS 22.4-22.5',
    family: 'jss',
    rules: {
      hasJss: 30, hasContentSdk: -100,
      hasSitecoreContext: 20, hasLayoutData: 10,
      hasCloudSdkCore: 15, hasCloudSdkEvents: 10,
      hasEngageSdk: -30,
      hasFeaas: 10,
      hasNextLocalization: 5,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100,
      isReact18: 20, isReact19: -30,
    },
    // 22.4+ requires CloudSDK core+events - penalize if absent
    absentRules: { hasCloudSdkCore: -20, hasCloudSdkEvents: -15 },
  },
  {
    label: 'JSS 22.9+',
    family: 'jss',
    rules: {
      hasJss: 30, hasContentSdk: -100,
      hasSitecoreContext: 20, hasLayoutData: 10,
      hasCloudSdkCore: 15, hasCloudSdkEvents: 10,
      hasEngageSdk: -30,
      hasFeaas: 10,
      hasNextLocalization: 5,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100,
      isReact19: 20, isReact18: -30,
    },
    htmlRules: { isPagesRouter: 5 },
    absentRules: { hasCloudSdkCore: -20, hasCloudSdkEvents: -15 },
  },
  {
    label: 'Content SDK 1.2.x',
    family: 'content-sdk',
    rules: {
      hasContentSdk: 30, hasJss: -100,
      hasSitecoreContext: -30,
      hasCloudSdkCore: 15, hasCloudSdkEvents: 10,
      hasNextLocalization: 10, hasNextIntl: -20,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100,
      isReact19: 10,
    },
    htmlRules: { isPagesRouter: 15, isAppRouter: -50 },
  },
  {
    label: 'Content SDK 1.3.x',
    family: 'content-sdk',
    rules: {
      hasContentSdk: 30, hasJss: -100,
      hasSitecoreContext: -30,
      hasCloudSdkCore: 15, hasCloudSdkEvents: 10,
      hasNextIntl: 20, hasNextLocalization: -20,
      hasContentSdkEvents: -100, hasContentSdkAnalytics: -100,
      isReact19: 10,
    },
    htmlRules: { isAppRouter: 25, isPagesRouter: -50 },
  },
  {
    label: 'Content SDK 2.0.x',
    family: 'content-sdk',
    rules: {
      hasContentSdk: 30, hasJss: -100,
      hasContentSdkEvents: 25, hasContentSdkAnalytics: 25, hasInitContentSdk: 15,
      hasCloudSdkCore: -30, hasCloudSdkEvents: -30,
      hasNextLocalization: 5,
    },
    htmlRules: { isPagesRouter: 10, isNext16Plus: 15, isReact19: 5 },
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

  // Next.js version detection from buildManifest or chunk naming
  // Next 13: /_next/static/chunks/pages/ dominant, polyfills-c67a75d1b6f99dc8.js style
  // Next 14: similar to 13 but _app chunk pattern changes
  // Next 15+: can use App Router or Pages Router, different chunk structure
  // Next 16+: experimental features, turbopack
  const chunkPaths = [...html.matchAll(/\/_next\/static\/chunks\/[^"'\s]+/g)].map(m => m[0]);

  // Detect Next.js version from chunk naming patterns and other indicators
  let nextVersionHint = 0;

  // Turbopack chunk naming: node_modules_..., src_pages__app_..., [root-of-the-server]__...
  const hasTurbopackChunks = chunkPaths.some(p =>
    /node_modules_[^/]/.test(p) || /src_pages_/.test(p) || p.includes('[root-of-the-server]')
  );

  // Next 16 indicator: turbopack chunks or turbopack-specific naming
  if (hasTurbopackChunks || html.includes('turbopack-')) {
    nextVersionHint = 16;
  }
  // RSC without __NEXT_DATA__ strongly suggests Next 13.4+ App Router
  if (hasRscPayload && !hasNextData) {
    nextVersionHint = Math.max(nextVersionHint, 15);
  }

  // Traditional webpack _app chunk exists (Next 13/14 pattern)
  const hasWebpackAppChunk = chunkPaths.some(p => /\/pages\/_app-[a-f0-9]+\.js/.test(p));
  // Traditional catch-all path chunk (Next 13 JSS 21.x pattern)
  const hasCatchAllChunk = chunkPaths.some(p => p.includes('/pages/%5B%5B') || p.includes('/pages/[['));

  return {
    isPagesRouter: hasNextData,
    isAppRouter: hasRscPayload && !hasNextData,
    isNext13: hasNextData && hasCatchAllChunk && !hasWebpackAppChunk && nextVersionHint < 14,
    isNext16Plus: nextVersionHint >= 16,
    // CSS framework detection from HTML
    hasBootstrap: html.includes('bootstrap') || html.includes('class="container') || html.includes('class="row'),
    hasTailwind: html.includes('tailwind') || /class="[^"]*(?:flex|grid|bg-|text-|p-|m-)\w/.test(html),
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

    // Apply bundle signal rules (signal present → add points)
    for (const [signal, points] of Object.entries(candidate.rules)) {
      if (allSignals[signal]) {
        score += points;
      }
    }

    // Apply HTML signal rules (signal present → add points)
    if (candidate.htmlRules) {
      for (const [signal, points] of Object.entries(candidate.htmlRules)) {
        if (allSignals[signal]) {
          score += points;
        }
      }
    }

    // Apply absent rules (signal NOT present → add points)
    // Used for expected dependencies: e.g. JSS 22.4 expects CloudSDK core,
    // so if it's missing, penalize that candidate
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

export async function checkJssVersion(baseUrl, html, jsonContent) {
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
    const detailParts = [best.label];
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
      sdkFamily: best.family,
      versionLabel: best.label,
      confidence,
    };
  } catch (e) {
    return {
      result: createResult('SDK Version', WARN, tests, `Error: ${e.message}`),
      jsContent: null,
      chunkName: null,
      sdkFamily: null,
    };
  }
}
