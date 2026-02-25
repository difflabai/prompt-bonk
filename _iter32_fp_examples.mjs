import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const patternsToRaise = ['begin_afresh_exfil', 'clean_slate_exfil', 'initiate_afresh_exfil'];

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');

console.log('=== Benign samples that would become FP ===');
let count = 0;
for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 0) continue;
  const result = scan(row.text);
  const hasTarget = result.matches.some(m => patternsToRaise.includes(m.id));
  if (!hasTarget || result.score !== 0.49) continue;

  count++;
  console.log(`\n--- Benign FP #${count} ---`);
  console.log('Matches:', result.matches.map(m => `${m.id}(${m.weight})`).join(', '));
  console.log(row.text.slice(0, 400));
}
console.log(`\nTotal: ${count}`);
