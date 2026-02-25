import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/gandalf-summarization.jsonl', 'utf8').trim().split('\n');
let fnCount = 0;
for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (result.safe) {
    fnCount++;
    console.log(`\n--- FN (score: ${result.score}) ---`);
    if (result.matches.length > 0) console.log('Matches:', JSON.stringify(result.matches.map(m => ({id: m.id, w: m.weight}))));
    console.log(row.text.slice(0, 400));
  }
}
console.log(`\nTotal gandalf-summarization FN: ${fnCount}`);
