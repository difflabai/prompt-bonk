import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan, PATTERNS } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

// Test record #0 at 115KB - should use windowing
const record0 = records[0];
console.log(`Record 0 length: ${record0.text.length}`);

// Time the scan
const t1 = performance.now();
const result = scan(record0.text);
const elapsed = performance.now() - t1;
console.log(`Scan time: ${elapsed.toFixed(1)}ms`);
console.log(`Score: ${result.score}, safe: ${result.safe}`);

// Now time running ALL patterns directly on 20KB window
const window20k = record0.text.substring(0, 20000);
const t2 = performance.now();
let matchCount = 0;
for (const pat of PATTERNS) {
  if (window20k.match(pat.regex)) matchCount++;
}
const patTime = performance.now() - t2;
console.log(`Direct pattern scan of 20KB window: ${patTime.toFixed(1)}ms (${matchCount} matches)`);

// Check if the problem is structural scoring
const t3 = performance.now();
for (let i = 0; i < 3; i++) scan(window20k);
const structTime = performance.now() - t3;
console.log(`3x 20KB window scan: ${structTime.toFixed(1)}ms`);

// Check pattern count and see if any have 's' or 'g' flags that cause issues
console.log(`Total patterns: ${PATTERNS.length}`);
const multilinePatterns = PATTERNS.filter(p => p.regex.flags.includes('s') || p.regex.flags.includes('g'));
console.log(`Patterns with s or g flag: ${multilinePatterns.length}`);
