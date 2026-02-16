export const PASS = 'Pass';
export const FAIL = 'Fail';

export function createResult(title, outcome, tests = [], details = '') {
  return { title, outcome, tests, details };
}
