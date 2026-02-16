import { PASS, FAIL, createResult, fetchUrl } from './result.js';

/**
 * Detects whether the site is a Sitecore JSS (Next.js) application
 * by looking for __NEXT_DATA__ with Sitecore context.
 * Returns the result and the raw JSON content for downstream checks.
 */
export async function checkIsJss(baseUrl) {
  let outcome = FAIL;
  let details = 'Not JSS';
  let jsonContent = null;

  try {
    const response = await fetchUrl(baseUrl);

    if (response.status === 200) {
      const html = await response.text();

      // Extract __NEXT_DATA__ script content
      const match = html.match(/<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);

      if (match) {
        jsonContent = match[1];
        try {
          const data = JSON.parse(jsonContent);

          // v1: props.pageProps.sitecoreContext
          if (data?.props?.pageProps?.sitecoreContext) {
            outcome = PASS;
            details = 'JSS detected - v1';
          }
          // v2: props.pageProps.layoutData.sitecore
          else if (data?.props?.pageProps?.layoutData?.sitecore) {
            outcome = PASS;
            details = 'JSS detected - v2';
          }
          // v3: fallback string search
          else if (jsonContent.includes('"sitecore"')) {
            outcome = PASS;
            details = 'JSS detected - unknown';
          } else {
            details = 'Next.js found but no Sitecore data';
          }
        } catch {
          details = 'Next.js found but invalid JSON';
        }
      } else {
        details = 'No __NEXT_DATA__ script found';
      }
    } else {
      details = `Request failed: HTTP ${response.status}`;
    }
  } catch (e) {
    details = `Request failed: ${e.message}`;
  }

  return {
    result: createResult('Is JSS', outcome, [], details),
    jsonContent,
  };
}

/**
 * Determines if a JSS site is XM Cloud by checking whether
 * edge.sitecorecloud.io is referenced in the __NEXT_DATA__ JSON.
 */
export function checkIsXMCloud(jsonContent) {
  if (!jsonContent) {
    return createResult('Is XM Cloud', FAIL, [], 'No data to analyse');
  }

  if (jsonContent.includes('edge.sitecorecloud.io')) {
    return createResult('Is XM Cloud', PASS, [], 'edge.sitecorecloud.io detected');
  }

  return createResult('Is XM Cloud', FAIL, [], 'edge.sitecorecloud.io not found');
}
