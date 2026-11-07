#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { scan } from '../src/scan.js';
import { formatReport } from '../src/report.js';

const HELP = `Usage: shc <url> [options]

Checks a website's HTTP security headers and cookies and gives it a grade.

Options:
  --json             Print the result as JSON
  --fail-under <n>   Exit with code 1 if the score is below n (0-100), useful in CI
  --timeout <ms>     Request timeout in milliseconds (default 10000)
  --no-color         Disable colours
  -h, --help         Show this help
`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    json: { type: 'boolean', default: false },
    'fail-under': { type: 'string' },
    timeout: { type: 'string', default: '10000' },
    'no-color': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

if (values.help || positionals.length !== 1) {
  process.stdout.write(HELP);
  process.exit(values.help ? 0 : 2);
}

try {
  const result = await scan(positionals[0], { timeoutMs: Number(values.timeout) });
  if (values.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    const color = !values['no-color'] && process.stdout.isTTY && !process.env.NO_COLOR;
    process.stdout.write(formatReport(result, { color }) + '\n');
  }
  const failUnder = values['fail-under'] !== undefined ? Number(values['fail-under']) : undefined;
  if (failUnder !== undefined && result.score < failUnder) process.exit(1);
} catch (err) {
  const reason = err.name === 'TimeoutError' ? 'request timed out' : (err.cause?.code ?? err.cause?.errors?.[0]?.code ?? err.cause?.message ?? err.message);
  process.stderr.write(`Could not scan ${positionals[0]}: ${reason}\n`);
  process.exit(2);
}
