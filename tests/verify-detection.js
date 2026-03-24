#!/usr/bin/env node

/**
 * Verifies SDK version detection against known sites.
 * Reads tests/known-sites.csv and checks each URL.
 *
 * Usage:
 *   node tests/verify-detection.js
 *   node tests/verify-detection.js --filter tonys
 */

import { readFileSync } from 'node:fs';
import { runAllChecks } from '../chrome-extension/checks/check-runner.js';

const color = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  dim: '\x1b[2m',
};

function parseCsv(filePath) {
  const content = readFileSync(filePath, 'utf8');
  const [header, ...rows] = content.split(/\r?\n/).filter(l => l.trim());
  const cols = header.split(',');
  return rows.map(row => {
    const values = row.split(',');
    const obj = {};
    cols.forEach((col, i) => obj[col.trim()] = (values[i] || '').trim());
    return obj;
  });
}

const filterArg = process.argv.find(a => a === '--filter') ? process.argv[process.argv.indexOf('--filter') + 1] : null;

const sites = parseCsv(new URL('./known-sites.csv', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'));

let passed = 0;
let failed = 0;

for (const site of sites) {
  if (filterArg && !site.url.includes(filterArg)) continue;

  process.stderr.write(`Testing ${site.url} (expect ${site.expected_sdk} ${site.expected_version})...\n`);

  const data = await runAllChecks(site.url);

  // Check SDK family
  const familyOk = data.sdkFamily === site.expected_sdk;

  // Check version label matches the major range
  // e.g. expected "21.1.0" should match label "JSS 21.x"
  //      expected "22.10.0" should match label "JSS 22.9+"
  const expectedMajor = site.expected_version.split('.')[0];
  const versionLabel = data.sitecoreVersion || '';
  // Also accept range labels like "22.9+" for 22.10
  const labelMatchesMajor = versionLabel.includes(expectedMajor + '.') || versionLabel.includes(expectedMajor);

  if (familyOk && labelMatchesMajor) {
    passed++;
    console.log(`${color.green}PASS${color.reset} ${site.url} -> ${versionLabel} (family: ${data.sdkFamily})`);
  } else {
    failed++;
    console.log(`${color.red}FAIL${color.reset} ${site.url}`);
    console.log(`  Expected: ${site.expected_sdk} ${site.expected_version}`);
    console.log(`  Got:      ${data.sdkFamily || 'null'} / ${versionLabel}`);
    if (data.confidence) console.log(`  Confidence: ${data.confidence}`);
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
