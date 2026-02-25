// For each protectai FP in the 0.50-0.55 range with no pattern matches,
// show which structural signals are firing
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');
const content = readFileSync(path.join(DATASETS_DIR, 'protectai.jsonl'), 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

let count = 0;
for (const row of rows) {
  if (row.label !== 0) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;
  if (result.matches.length > 0) continue; // skip pattern-matched ones
  if (result.score > 0.55) continue;

  count++;
  console.log(`FP #${count}: score=${result.score}`);
  // The scan result should have structural signals info
  if (result.signals) {
    for (const sig of result.signals) {
      console.log(`  signal: ${sig.id} score=${sig.score} detail=${sig.detail}`);
    }
  }
  if (result.structural) {
    console.log(`  structural_score=${result.structural.score}`);
    for (const sig of (result.structural.signals || [])) {
      console.log(`  signal: ${sig.id} score=${sig.score} detail=${sig.detail}`);
    }
  }
  // Print raw result keys to see what's available
  console.log(`  result keys: ${Object.keys(result).join(', ')}`);
  console.log(`  text: ${text.slice(0, 300)}`);
  console.log();
}
console.log(`Total structural-only FPs: ${count}`);
