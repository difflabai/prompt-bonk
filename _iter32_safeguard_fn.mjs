import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/safeguard-test.jsonl', 'utf8').trim().split('\n');
const fn = [];
for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (result.safe) {
    fn.push({ text: row.text.slice(0, 600), score: result.score, fullText: row.text });
  }
}
console.log(`=== safeguard-test FN: ${fn.length} total ===`);
for (let i = 0; i < fn.length; i++) {
  console.log(`\n--- FN #${i+1} (score: ${fn[i].score}) ---`);
  console.log(fn[i].text);
}
