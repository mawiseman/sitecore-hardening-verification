import { fetchUrl } from './result.js';

export async function checkSitecoreVersion(baseUrl) {
  const url = new URL('/sitecore/shell/sitecore.version.xml', baseUrl).href;

  try {
    const response = await fetchUrl(url, { redirect: 'follow' });
    const status = response.status;

    if (status === 401 || status === 403) {
      return `Probably Sitecore: HTTP ${status}`;
    }

    if (status !== 200) {
      return `HTTP ${status}`;
    }

    const text = await response.text();

    // Parse XML with regex (DOMParser not available in service workers)
    const major = text.match(/<major>([^<]*)<\/major>/)?.[1] ?? '';
    const minor = text.match(/<minor>([^<]*)<\/minor>/)?.[1] ?? '';
    const revision = text.match(/<revision>([^<]*)<\/revision>/)?.[1] ?? '';

    const version = `${major}.${minor}.${revision}`;
    return (version === '..' || !version) ? 'Unknown' : version;
  } catch {
    return 'Connection failed';
  }
}
