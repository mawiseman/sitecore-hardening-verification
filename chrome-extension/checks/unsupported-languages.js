import { PASS, FAIL, createResult } from './result.js';

const LANGUAGES = [
  { code: 'om', expectedStatus: 404 },
  { code: 'br', expectedStatus: 404 },
  { code: 'en', expectedStatus: 200 },
];

export async function checkUnsupportedLanguages(baseUrl) {
  let overallOutcome = PASS;
  const tests = [];

  for (const lang of LANGUAGES) {
    const url = new URL(lang.code, baseUrl).href;
    let langOutcome = PASS;
    let details = '';

    try {
      const response = await fetch(url);
      const status = response.status;

      if (status !== lang.expectedStatus) {
        langOutcome = FAIL;
        details = `StatusCode: ${status} (expected: ${lang.expectedStatus})`;
      } else {
        details = `StatusCode: ${status}`;
      }
    } catch (e) {
      langOutcome = FAIL;
      details = `Error: ${e.message}`;
    }

    if (langOutcome === FAIL) overallOutcome = FAIL;
    tests.push(createResult(`/${lang.code}`, langOutcome, [], details));
  }

  return createResult('Handle Unsupported Languages', overallOutcome, tests);
}
