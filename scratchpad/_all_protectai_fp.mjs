// Show ALL 43 protectai FPs with full match details
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');
const content = readFileSync(path.join(DATASETS_DIR, 'protectai.jsonl'), 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

let count = 0;
const scoreBuckets = {};

for (const row of rows) {
  if (row.label !== 0) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;

  count++;
  const matchDetails = result.matches.map(m => `${m.id}(${m.weight})`).join(', ');

  // Bucket by score range
  const bucket = result.score < 0.55 ? '0.50-0.55' : result.score < 0.60 ? '0.55-0.60' : result.score < 0.70 ? '0.60-0.70' : '0.70+';
  scoreBuckets[bucket] = (scoreBuckets[bucket] || 0) + 1;

  // Only show the ones in the 0.50-0.55 range (most likely to be fixable)
  if (result.score < 0.55) {
    console.log(`FP #${count}: score=${result.score} matches=[${matchDetails}]`);
    console.log(`  text: ${text.slice(0, 200)}`);
    console.log();
  }
}

console.log(`\n=== Score distribution of ${count} FPs ===`);
for (const [bucket, n] of Object.entries(scoreBuckets).sort()) {
  console.log(`  ${bucket}: ${n} FPs`);
}

// Count how many have score exactly 0.50
let exactHalf = 0;
for (const row of rows) {
  if (row.label !== 0) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;
  if (result.score === 0.50) exactHalf++;
}
console.log(`\n  Exactly 0.50: ${exactHalf} FPs`);
