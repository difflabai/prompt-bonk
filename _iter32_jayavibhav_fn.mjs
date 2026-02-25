import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const nearMiss = [];
for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (result.safe && result.score > 0 && result.score < 0.5) {
    nearMiss.push({ text: row.text.slice(0, 500), score: result.score, matches: result.matches });
  }
}
console.log(`=== jayavibhav near-miss FN (0 < score < 0.5): ${nearMiss.length} total ===`);
nearMiss.sort((a, b) => b.score - a.score);
const sample = nearMiss.slice(0, 30);
for (let i = 0; i < sample.length; i++) {
  console.log(`\n--- Near-miss #${i+1} (score: ${sample[i].score}) ---`);
  console.log('Matches:', JSON.stringify(sample[i].matches.map(m => ({id: m.id, w: m.weight}))));
  console.log(sample[i].text);
}
