// Show protectai FPs where score is 0.50-0.55 with no pattern matches or minimal matches
// These are structural-only or near-structural FPs
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
  if (result.score > 0.55) continue;

  count++;
  const matchDetails = result.matches.map(m => `${m.id}(${m.weight})`).join(', ');
  const signals = result.signals || [];
  console.log(`FP #${count}: score=${result.score} matches=[${matchDetails}]`);
  // Show structural info if available
  if (result.structural_score !== undefined) {
    console.log(`  structural_score=${result.structural_score}`);
  }
  console.log(`  text length: ${text.length}`);
  console.log(`  text: ${text.slice(0, 300)}`);
  console.log();
}
console.log(`Total low-score FPs: ${count}`);
