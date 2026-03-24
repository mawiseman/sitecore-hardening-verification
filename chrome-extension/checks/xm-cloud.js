import { PASS, FAIL, createResult, fetchUrl } from './result.js';

/**
 * Detects whether the site is a Sitecore headless application (JSS or Content SDK)
 * by looking for:
 *   1. __NEXT_DATA__ with Sitecore context (Pages Router - JSS all versions, ContentSDK 1.2, 2.0)
 *   2. App Router signals: RSC payloads, editing scripts, Sitecore-specific meta (ContentSDK 1.3)
 *
 * Returns the result, the raw JSON content (if Pages Router), and the full HTML.
 */
export async function checkIsJss(baseUrl) {
  let outcome = FAIL;
  let details = 'Not JSS / Content SDK';
  let jsonContent = null;
  let html = null;

  try {
    const response = await fetchUrl(baseUrl);

    if (response.status === 200) {
      html = await response.text();

      // Strategy 1: Pages Router - __NEXT_DATA__ with Sitecore context
      const match = html.match(/<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);

      if (match) {
        jsonContent = match[1];
        try {
          const data = JSON.parse(jsonContent);

          // v1: props.pageProps.sitecoreContext (older JSS)
          if (data?.props?.pageProps?.sitecoreContext) {
            outcome = PASS;
            details = 'Sitecore detected (Pages Router) - sitecoreContext';
          }
          // v2: props.pageProps.layoutData.sitecore (JSS 22.x)
          else if (data?.props?.pageProps?.layoutData?.sitecore) {
            outcome = PASS;
            details = 'Sitecore detected (Pages Router) - layoutData';
          }
          // v3: props.pageProps.page (Content SDK 1.2 / 2.0)
          else if (data?.props?.pageProps?.page?.siteName) {
            outcome = PASS;
            details = 'Sitecore detected (Pages Router) - Content SDK page';
          }
          // v4: fallback string search
          else if (jsonContent.includes('"sitecore"') || jsonContent.includes('"siteName"')) {
            outcome = PASS;
            details = 'Sitecore detected (Pages Router) - fallback';
          } else {
            details = 'Next.js found but no Sitecore data';
          }
        } catch {
          details = 'Next.js found but invalid JSON';
        }
      }

      // Strategy 2: App Router detection (no __NEXT_DATA__)
      // Content SDK 1.3.x uses App Router with RSC payloads
      if (outcome === FAIL) {
        const isAppRouter = detectAppRouter(html);
        if (isAppRouter) {
          outcome = PASS;
          details = 'Sitecore detected (App Router)';
        }
      }
    } else {
      details = `Request failed: HTTP ${response.status}`;
    }
  } catch (e) {
    details = `Request failed: ${e.message}`;
  }

  return {
    result: createResult('Is JSS / Content SDK', outcome, [], details),
    jsonContent,
    html,
  };
}

/**
 * Detects App Router Sitecore sites by checking for characteristic markers:
 * - RSC payload scripts (self.__next_f.push)
 * - Sitecore editing scripts or class names
 * - Sitecore-specific meta tags or data attributes
 */
function detectAppRouter(html) {
  // RSC payload present (Next.js App Router)
  const hasRscPayload = html.includes('self.__next_f.push');
  if (!hasRscPayload) return false;

  // Look for Sitecore-specific markers in the RSC/HTML
  const sitecoreMarkers = [
    'editing-mode',
    'prod-mode',
    'sitecore',
    'sc_site',
    'edge.sitecorecloud.io',
    'sitecorecloud.io',
    'feaas.blob.core.windows.net',
    'sitecore-content-sdk',
    'sitecore-jss',
  ];

  return sitecoreMarkers.some(marker => html.includes(marker));
}

/**
 * Determines if a site is XM Cloud by checking whether
 * edge.sitecorecloud.io is referenced in:
 *   1. __NEXT_DATA__ JSON content
 *   2. HTML source
 *   3. JS bundle content (fetched during version detection)
 *
 * Some sites resolve the Edge URL at build time so it only appears
 * in the bundled JS, not in the HTML or __NEXT_DATA__.
 */
export function checkIsXMCloud(jsonContent, html, bundleContent) {
  const searchTargets = [jsonContent, html, bundleContent].filter(Boolean);

  if (searchTargets.length === 0) {
    return createResult('Is XM Cloud', FAIL, [], 'No data to analyse');
  }

  for (const content of searchTargets) {
    if (content.includes('edge.sitecorecloud.io')) {
      return createResult('Is XM Cloud', PASS, [], 'edge.sitecorecloud.io detected');
    }
  }

  return createResult('Is XM Cloud', FAIL, [], 'edge.sitecorecloud.io not found');
}
