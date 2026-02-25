// Iter 40: Sample SPML-5k FN and BrowseSafe non-CSS FN
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// Load SPML-5k dataset
const spmlPath = './datasets/spml-5k.jsonl';
const lines = readFileSync(spmlPath, 'utf8').trim().split('\n');

const records = lines.map(l => JSON.parse(l));

// Find FN: injection=true but not detected
const fn = [];
for (const r of records) {
  const label = r.label === 1 || r.label === true || r.label === 'injection';
  if (!label) continue;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const result = scan(text);
  if (result.score < 0.5) {
    fn.push({ text, score: result.score });
  }
}

console.log(`Total SPML FN: ${fn.length}`);
console.log('\n--- Sampling 30 FN ---\n');

// Sample evenly
const step = Math.max(1, Math.floor(fn.length / 30));
const sample = [];
for (let i = 0; i < fn.length && sample.length < 30; i += step) {
  sample.push(fn[i]);
}

for (let i = 0; i < sample.length; i++) {
  console.log(`\n=== FN #${i+1} (score=${sample[i].score.toFixed(3)}) ===`);
  console.log(sample[i].text.substring(0, 500));
}
