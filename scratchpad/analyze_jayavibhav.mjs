import { readFileSync } from 'fs';
import { scan } from '../index.js';

const lines = readFileSync('../datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

// Find false negatives (label=1, score < 0.5)
const fn = records.filter(r => (r.label === 1 || r.label === '1')).filter(r => {
  const result = scan(r.text);
  return result.score < 0.5;
});

console.log(`Total FN: ${fn.length}`);
console.log('\n--- FALSE NEGATIVES ---');
fn.forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[${i+1}] score=${result.score.toFixed(3)}`);
  console.log(r.text.substring(0, 400));
});
