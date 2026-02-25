// Quick check: what structural signals are driving the 10 structural-only FPs?

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  if (!content) return [];
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('protectai.jsonl');

console.log(`=== Structural-only FPs (no pattern matches) ===\n`);

let structuralOnlyCount = 0;
for (const row of rows) {
  const text = String(row.text || '');
  if (row.label !== 0) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;
  if (result.matches.length > 0) continue; // has pattern matches

  structuralOnlyCount++;
  console.log(`[score=${result.score}] structural=${result.structural.score.toFixed(3)}`);
  for (const s of result.structural.signals) {
    console.log(`  signal: ${s.id} (${s.score.toFixed(3)}) - ${s.detail}`);
  }
  console.log(`  text: ${text.slice(0, 250)}`);
  console.log();
}

console.log(`Total structural-only FPs: ${structuralOnlyCount}`);

// Count which structural signals appear most in these FPs
const signalCounts = {};
for (const row of rows) {
  const text = String(row.text || '');
  if (row.label !== 0) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;
  if (result.matches.length > 0) continue;

  for (const s of result.structural.signals) {
    signalCounts[s.id] = (signalCounts[s.id] || 0) + 1;
  }
}

console.log(`\nSignal frequency in structural-only FPs:`);
for (const [id, count] of Object.entries(signalCounts).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${id}: ${count}`);
}
