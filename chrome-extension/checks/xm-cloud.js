import { PASS, FAIL, createResult } from './result.js';

export async function checkXMCloud(baseUrl) {
  let outcome = FAIL;
  let details = 'Not XM Cloud';

  try {
    const response = await fetch(baseUrl);

    if (response.status === 200) {
      const html = await response.text();

      // Extract __NEXT_DATA__ script content
      const match = html.match(/<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);

      if (match) {
        const jsonContent = match[1];
        try {
          const data = JSON.parse(jsonContent);

          // v1: props.pageProps.sitecoreContext
          if (data?.props?.pageProps?.sitecoreContext) {
            outcome = PASS;
            details = 'XM Cloud detected - v1';
          }
          // v2: props.pageProps.layoutData.sitecore
          else if (data?.props?.pageProps?.layoutData?.sitecore) {
            outcome = PASS;
            details = 'XM Cloud detected - v2';
          }
          // v3: fallback string search
          else if (jsonContent.includes('"sitecore"')) {
            outcome = PASS;
            details = 'XM Cloud detected - unknown';
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

  return createResult('Is XM Cloud', outcome, [], details);
}
