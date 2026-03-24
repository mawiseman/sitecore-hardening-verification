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
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
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

const __dirname = dirname(fileURLToPath(import.meta.url));
const filterIdx = process.argv.indexOf('--filter');
const filterArg = filterIdx !== -1 ? process.argv[filterIdx + 1] : null;

const sites = parseCsv(join(__dirname, '../csv-files/known-sites.csv'));

let passed = 0;
let failed = 0;

for (const site of sites) {
  if (filterArg && !site.url.includes(filterArg)) continue;

  process.stderr.write(`Testing ${site.url} (expect ${site.expected_label})...\n`);

  const data = await runAllChecks(site.url);

  const familyOk = data.sdkFamily === site.expected_family;
  const labelOk = data.sitecoreVersion === site.expected_label;

  if (familyOk && labelOk) {
    passed++;
    console.log(`${color.green}PASS${color.reset} ${site.url} -> ${data.sitecoreVersion} (family: ${data.sdkFamily}, confidence: ${data.confidence})`);
  } else {
    failed++;
    console.log(`${color.red}FAIL${color.reset} ${site.url}`);
    console.log(`  Expected: family=${site.expected_family}, label=${site.expected_label}`);
    console.log(`  Got:      family=${data.sdkFamily || 'null'}, label=${data.sitecoreVersion}`);
    if (data.confidence) console.log(`  Confidence: ${data.confidence}`);
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
