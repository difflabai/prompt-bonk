import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// Check yanismiraoui FN -- 80.85% recall means ~36 FN
const lines = readFileSync('./datasets/yanismiraoui-multilingual.jsonl', 'utf8').trim().split('\n');
let fnCount = 0;
let fnSamples = [];
for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (result.safe) {
    fnCount++;
    if (fnSamples.length < 20) {
      fnSamples.push({ text: row.text.slice(0, 400), score: result.score, matches: result.matches.map(m => ({id: m.id, w: m.weight})) });
    }
  }
}
console.log(`yanismiraoui FN: ${fnCount}`);
for (const s of fnSamples) {
  console.log(`\n--- FN (score: ${s.score}) ---`);
  if (s.matches.length > 0) console.log('Matches:', JSON.stringify(s.matches));
  console.log(s.text);
}
