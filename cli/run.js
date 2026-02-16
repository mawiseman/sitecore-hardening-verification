#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'node:fs';
import { runAllChecks } from '../chrome-extension/checks/check-runner.js';

// ANSI color helpers
const color = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  dim: '\x1b[2m',
};

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = { urls: [], csvFile: null, outputFile: null };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--csv' && args[i + 1]) {
      options.csvFile = args[++i];
    } else if (args[i] === '--output' && args[i + 1]) {
      options.outputFile = args[++i];
    } else if (args[i] === '--help' || args[i] === '-h') {
      printUsage();
      process.exit(0);
    } else if (!args[i].startsWith('--')) {
      options.urls.push(args[i]);
    }
  }

  return options;
}

function printUsage() {
  console.log(`
${color.cyan}Sitecore Hardening Verifier - CLI${color.reset}

Usage:
  node cli/run.js <url> [url2] [url3] ...
  node cli/run.js --csv <file>
  node cli/run.js --csv <file> --output <file>

Options:
  --csv <file>      Read URLs from a CSV file (first column)
  --output <file>   Write results to a CSV file
  --help, -h        Show this help message

Examples:
  node cli/run.js https://example.com
  node cli/run.js https://site1.com https://site2.com
  node cli/run.js --csv urls.csv
  node cli/run.js --csv urls.csv --output results.csv

Requires Node.js 18+
`);
}

function readUrlsFromCsv(filePath) {
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/).filter(l => l.trim());

  // Skip header if it doesn't look like a URL
  const urls = [];
  for (const line of lines) {
    const value = line.split(',')[0].trim().replace(/^["']|["']$/g, '');
    if (value && (value.startsWith('http://') || value.startsWith('https://') || value.includes('.'))) {
      // Skip obvious header rows
      if (/^(url|site|domain|host)s?$/i.test(value)) continue;
      urls.push(value);
    }
  }

  return urls;
}

// Console output

const PAD = 40;

function pad(text, length) {
  return text + ' '.repeat(Math.max(1, length - text.length));
}

function outcomeColor(outcome) {
  if (outcome === 'Pass') return color.green;
  if (outcome === 'Warn') return color.yellow;
  return color.red;
}

function printConsoleReport(data) {
  console.log(`${color.blue}${pad('URL', PAD)}${color.reset}| ${color.blue}${data.siteUrl}${color.reset}`);

  let versionColor = color.green;
  if (data.sitecoreVersion.includes('Unknown')) versionColor = color.white;
  else if (data.sitecoreVersion.includes('Probably')) versionColor = color.yellow;
  else if (data.sitecoreVersion === 'XM Cloud' || data.sitecoreVersion.startsWith('JSS')) versionColor = color.cyan;

  console.log(`${color.white}${pad('Sitecore Version', PAD)}${color.reset}| ${versionColor}${data.sitecoreVersion}${color.reset}`);

  if (data.isXMCloud) {
    console.log(`${color.dim}XM Cloud site detected. XM/XP hardening checks do not apply.${color.reset}`);
  }

  console.log();

  for (const result of data.siteResults) {
    const oc = outcomeColor(result.outcome);
    const details = result.details ? ` (${result.details})` : '';
    console.log(`${color.yellow}${pad(result.title, PAD)}${color.reset}| ${oc}${result.outcome}${color.reset}${details}`);

    if (result.tests && result.tests.length > 0) {
      for (const test of result.tests) {
        const toc = outcomeColor(test.outcome);
        const tDetails = test.details ? ` (${test.details})` : '';
        console.log(`  ${color.white}${pad(test.title, PAD - 2)}${color.reset}| ${toc}${test.outcome}${color.reset}${tDetails}`);
      }
    }

    console.log();
  }
}

// CSV output

function escapeCsvField(value) {
  const str = String(value ?? '');
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function buildCsvRows(allResults) {
  // Collect all unique check names across all URLs to build columns
  const checkNames = [];
  for (const data of allResults) {
    for (const result of data.siteResults) {
      if (!checkNames.includes(result.title)) {
        checkNames.push(result.title);
      }
    }
  }

  // Header
  const header = ['URL', 'SitecoreVersion', 'IsXMCloud'];
  for (const name of checkNames) {
    header.push(`${name} Summary`);
  }

  const rows = [header.map(escapeCsvField).join(',')];

  // Data rows - one per URL
  for (const data of allResults) {
    const row = [data.siteUrl, data.sitecoreVersion, data.isXMCloud];

    for (const name of checkNames) {
      const result = data.siteResults.find(r => r.title === name);
      row.push(result ? result.outcome : '');
    }

    rows.push(row.map(escapeCsvField).join(','));
  }

  return rows.join('\n');
}

// Main

async function main() {
  const options = parseArgs(process.argv);

  // Gather URLs
  let urls = options.urls;
  if (options.csvFile) {
    urls = readUrlsFromCsv(options.csvFile);
  }

  if (urls.length === 0) {
    printUsage();
    process.exit(1);
  }

  const allResults = [];
  let hasFailures = false;

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    process.stderr.write(`[${i + 1}/${urls.length}] Checking ${url}...\n`);

    const data = await runAllChecks(url, (progress) => {
      process.stderr.write(`  ${progress.name} (${progress.step}/${progress.total})\r`);
    });

    allResults.push(data);

    // Check for failures
    for (const result of data.siteResults) {
      if (result.outcome === 'Fail') hasFailures = true;
    }

    // Print console output immediately (unless CSV output mode)
    if (!options.outputFile) {
      if (urls.length > 1) {
        console.log(`${'='.repeat(60)}`);
      }
      printConsoleReport(data);
    }
  }

  // Write CSV if requested
  if (options.outputFile) {
    const csv = buildCsvRows(allResults);
    writeFileSync(options.outputFile, csv, 'utf8');
    process.stderr.write(`\nResults written to ${options.outputFile}\n`);
  }

  process.exit(hasFailures ? 1 : 0);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
