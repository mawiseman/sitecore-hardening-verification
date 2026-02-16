import { PASS, FAIL, createResult, fetchUrl } from './result.js';

const HEADERS_TO_CHECK = [
  'X-Aspnet-Version',
  'X-Powered-By',
  'X-AspNetMvc-Version',
];

export async function checkRemoveHeaders(baseUrl) {
  let overallOutcome = PASS;
  const tests = [];

  try {
    const response = await fetchUrl(baseUrl);

    for (const header of HEADERS_TO_CHECK) {
      const value = response.headers.get(header);
      const headerOutcome = value === null ? PASS : FAIL;
      const details = value === null
        ? 'Removed: true'
        : `Removed: false (value: ${value})`;

      if (headerOutcome === FAIL) overallOutcome = FAIL;
      tests.push(createResult(header, headerOutcome, [], details));
    }
  } catch (e) {
    overallOutcome = FAIL;
    tests.push(createResult('Connection', FAIL, [], `Error: ${e.message}`));
  }

  return createResult('Remove Header Information', overallOutcome, tests);
}
