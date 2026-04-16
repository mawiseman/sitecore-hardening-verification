#!/usr/bin/env node

import { readFileSync, existsSync, appendFileSync, writeFileSync, openSync, fsyncSync, closeSync, statSync } from 'node:fs';
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

// Canonical CSV column layout. All possible check names from check-runner.js,
// in both XM/XP and headless flows. Columns are deterministic across runs so
// appending new rows to an existing CSV is always safe.
const FIXED_COLUMNS = ['URL', 'SitecoreVersion', 'SDKFamily', 'Confidence', 'IsXMCloud'];
const CHECK_COLUMNS = [
  'SDK Version',
  'Is XM Cloud',
  'XM Cloud API Key',
  'Force HTTPS Redirect',
  'Deny Anonymous Access',
  'Limit Access to XSL',
  'Remove Header Information',
  'Simple File Check',
  'Handle Unsupported Languages',
];
const CSV_HEADER = [...FIXED_COLUMNS, ...CHECK_COLUMNS.map(c => `${c} Summary`)];

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = { urls: [], csvFile: null, outputFile: null, resume: false, concurrency: 4 };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--csv' && args[i + 1]) {
      options.csvFile = args[++i];
    } else if (args[i] === '--output' && args[i + 1]) {
      options.outputFile = args[++i];
    } else if (args[i] === '--resume') {
      options.resume = true;
    } else if (args[i] === '--concurrency' && args[i + 1]) {
      const n = parseInt(args[++i], 10);
      if (!Number.isFinite(n) || n < 1) {
        console.error(`Invalid --concurrency value. Must be a positive integer.`);
        process.exit(1);
      }
      options.concurrency = n;
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
  node cli/run.js --csv <file> --output <file> [--resume]

Options:
  --csv <file>       Read URLs from a CSV file (first column)
  --output <file>    Append results to a CSV file (one row per site, flushed after each)
  --resume           When used with --output, skip URLs already present in the output file
  --concurrency <n>  Number of URLs to check in parallel (default: 4)
  --help, -h         Show this help message

Examples:
  node cli/run.js https://example.com
  node cli/run.js https://site1.com https://site2.com
  node cli/run.js --csv urls.csv
  node cli/run.js --csv urls.csv --output results.csv
  node cli/run.js --csv urls.csv --output results.csv --resume

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
  else if (data.sitecoreVersion.startsWith('JSS') || data.sitecoreVersion.startsWith('Content SDK')) versionColor = color.cyan;

  let versionDisplay = data.sitecoreVersion;
  if (data.confidence && data.confidence !== 'High') {
    versionDisplay += ` ${color.dim}(${data.confidence} confidence)${versionColor}`;
  }

  console.log(`${color.white}${pad('Sitecore Version', PAD)}${color.reset}| ${versionColor}${versionDisplay}${color.reset}`);

  if (data.sdkFamily) {
    const familyLabel = data.sdkFamily === 'content-sdk' ? 'Content SDK' : 'JSS';
    console.log(`${color.white}${pad('SDK Family', PAD)}${color.reset}| ${color.cyan}${familyLabel}${color.reset}`);
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

function buildCsvRow(data) {
  const row = [
    data.siteUrl,
    data.sitecoreVersion,
    data.sdkFamily || '',
    data.confidence || '',
    data.isXMCloud,
  ];
  for (const name of CHECK_COLUMNS) {
    const result = data.siteResults.find(r => r.title === name);
    row.push(result ? result.outcome : '');
  }
  return row.map(escapeCsvField).join(',');
}

// Parse a single CSV line, handling quoted fields with embedded commas/quotes.
function parseCsvLine(line) {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') inQuotes = false;
      else cur += ch;
    } else {
      if (ch === ',') { fields.push(cur); cur = ''; }
      else if (ch === '"' && cur === '') inQuotes = true;
      else cur += ch;
    }
  }
  fields.push(cur);
  return fields;
}

/**
 * Prepare the output CSV:
 *   - If it doesn't exist, write the header.
 *   - If it exists and --resume, validate the header matches and return the
 *     set of URLs already present so we can skip them.
 *   - If it exists and not --resume, error out to avoid accidental appends
 *     to a stale file with a mismatched schema.
 */
function prepareOutputFile(outputPath, resume) {
  const expectedHeader = CSV_HEADER.map(escapeCsvField).join(',');

  if (!existsSync(outputPath) || statSync(outputPath).size === 0) {
    writeFileSync(outputPath, expectedHeader + '\n', 'utf8');
    return new Set();
  }

  const content = readFileSync(outputPath, 'utf8');
  const lines = content.split(/\r?\n/).filter(l => l.length > 0);
  const existingHeader = lines[0];

  if (existingHeader !== expectedHeader) {
    throw new Error(
      `Output file ${outputPath} has a different column layout than this CLI produces.\n` +
      `Delete the file or choose a different --output path to start fresh.\n` +
      `  Expected: ${expectedHeader}\n  Found:    ${existingHeader}`
    );
  }

  if (!resume) {
    throw new Error(
      `Output file ${outputPath} already exists. Pass --resume to append and skip completed URLs, ` +
      `or delete the file to start fresh.`
    );
  }

  const completed = new Set();
  for (let i = 1; i < lines.length; i++) {
    const url = parseCsvLine(lines[i])[0];
    if (url) completed.add(url);
  }
  return completed;
}

function appendRow(outputPath, row) {
  // Append + fsync so the row is durably on disk before we move to the next URL.
  const fd = openSync(outputPath, 'a');
  try {
    appendFileSync(fd, row + '\n', 'utf8');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Serialize writes so concurrent workers never interleave rows.
 * Each call chains onto a single shared promise.
 */
let writeChain = Promise.resolve();
function appendRowSerialized(outputPath, row) {
  writeChain = writeChain.then(() => appendRow(outputPath, row));
  return writeChain;
}

/**
 * Run `worker` on each item of `items` with at most `concurrency` in flight.
 * Preserves no particular ordering of completions.
 */
async function runWithConcurrency(items, concurrency, worker) {
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      await worker(items[i], i);
    }
  });
  await Promise.all(workers);
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

  let completedUrls = new Set();
  if (options.outputFile) {
    completedUrls = prepareOutputFile(options.outputFile, options.resume);
    if (completedUrls.size > 0) {
      process.stderr.write(`Resuming: ${completedUrls.size} URL(s) already in ${options.outputFile}\n`);
    }
  }

  let hasFailures = false;
  let processed = 0;
  let skipped = 0;
  let completedCount = 0;
  const total = urls.length;

  // When writing to CSV in batch mode, use one-line-per-URL progress.
  // For interactive/console output, fall back to sequential to keep the report readable.
  const concurrency = options.outputFile ? options.concurrency : 1;
  if (options.outputFile && concurrency > 1) {
    process.stderr.write(`Running with concurrency ${concurrency}\n`);
  }

  await runWithConcurrency(urls, concurrency, async (url, i) => {
    const normalized = url.startsWith('http') ? url : 'https://' + url;
    const withSlash = normalized.endsWith('/') ? normalized : normalized + '/';

    if (options.outputFile && (completedUrls.has(url) || completedUrls.has(normalized) || completedUrls.has(withSlash))) {
      skipped++;
      completedCount++;
      process.stderr.write(`[${completedCount}/${total}] skip  ${url}\n`);
      return;
    }

    let data;
    try {
      if (concurrency === 1) {
        process.stderr.write(`[${i + 1}/${total}] Checking ${url}...\n`);
        data = await runAllChecks(url, (progress) => {
          process.stderr.write(`  ${progress.name} (${progress.step}/${progress.total})\r`);
        });
      } else {
        data = await runAllChecks(url);
      }
    } catch (e) {
      completedCount++;
      process.stderr.write(`[${completedCount}/${total}] ERROR ${url} - ${e.message}\n`);
      hasFailures = true;
      return;
    }

    processed++;
    completedCount++;

    for (const result of data.siteResults) {
      if (result.outcome === 'Fail') hasFailures = true;
    }

    if (options.outputFile) {
      await appendRowSerialized(options.outputFile, buildCsvRow(data));
      const summary = data.sitecoreVersion + (data.sdkFamily ? ` (${data.sdkFamily === 'content-sdk' ? 'Content SDK' : 'JSS'})` : '');
      process.stderr.write(`[${completedCount}/${total}] done  ${url} - ${summary}\n`);
    } else {
      if (total > 1) {
        console.log(`${'='.repeat(60)}`);
      }
      printConsoleReport(data);
    }
  });

  if (options.outputFile) {
    process.stderr.write(`\nDone. Processed ${processed}, skipped ${skipped}. Results in ${options.outputFile}\n`);
  }

  process.exit(hasFailures ? 1 : 0);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
