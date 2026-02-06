#!/usr/bin/env node

import { scan, isInjection } from './scanner.js';
import { readFileSync } from 'fs';

// ---------------------------------------------------------------------------
// CLI — scan text from stdin, file, or argument
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const flags = {};
const positional = [];

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--threshold' || args[i] === '-t') {
    flags.threshold = parseFloat(args[++i]);
  } else if (args[i] === '--fast' || args[i] === '-f') {
    flags.fast = true;
  } else if (args[i] === '--json' || args[i] === '-j') {
    flags.json = true;
  } else if (args[i] === '--quiet' || args[i] === '-q') {
    flags.quiet = true;
  } else if (args[i] === '--file') {
    flags.file = args[++i];
  } else if (args[i] === '--help' || args[i] === '-h') {
    console.log(`prompt-guard — Scan text for prompt injection attempts

Usage:
  echo "text" | prompt-guard [options]
  prompt-guard --file input.txt [options]
  prompt-guard "text to scan" [options]

Options:
  --threshold, -t <n>  Score threshold (0-1, default: 0.50)
  --fast, -f           Stop at first high-confidence match
  --json, -j           Output full JSON result
  --quiet, -q          Exit code only (0=safe, 1=injection)
  --file <path>        Read text from file
  --help, -h           Show this help

Exit codes:
  0  Text appears safe
  1  Prompt injection detected
  2  Error`);
    process.exit(0);
  } else if (!args[i].startsWith('-')) {
    positional.push(args[i]);
  }
}

async function getText() {
  if (flags.file) {
    return readFileSync(flags.file, 'utf8');
  }
  if (positional.length > 0) {
    return positional.join(' ');
  }
  // Read from stdin
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
    // Timeout after 5 seconds if no input
    setTimeout(() => {
      if (!data) {
        reject(new Error('No input received (timeout after 5s). Provide text via stdin, --file, or as argument.'));
      }
    }, 5000);
  });
}

try {
  const text = await getText();
  const result = scan(text, {
    threshold: flags.threshold,
    fast: flags.fast,
  });

  if (flags.quiet) {
    process.exit(result.safe ? 0 : 1);
  }

  if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    // Human-readable output
    const icon = result.safe ? 'SAFE' : 'BLOCKED';
    const scoreBar = '|' + '#'.repeat(Math.round(result.score * 20)) + '.'.repeat(20 - Math.round(result.score * 20)) + '|';

    console.log(`\n  ${icon}  score=${result.score}  verdict=${result.verdict}`);
    console.log(`  ${scoreBar}`);

    if (result.matches.length > 0) {
      console.log(`\n  Matches (${result.matches.length}):`);
      for (const m of result.matches.slice(0, 10)) {
        console.log(`    [${m.weight.toFixed(2)}] ${m.category}/${m.id}: ${m.description}`);
        console.log(`           "${m.matched.slice(0, 80)}"`);
      }
    }

    if (result.structural.signals.length > 0) {
      console.log(`\n  Structural signals:`);
      for (const s of result.structural.signals) {
        console.log(`    [${s.score.toFixed(2)}] ${s.id}: ${s.detail}`);
      }
    }
    console.log();
  }

  process.exit(result.safe ? 0 : 1);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(2);
}
