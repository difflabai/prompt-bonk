// Find ALL browsesafe-test false positives (benign samples flagged as injection)
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

let fp = 0, tp = 0, tn = 0, fn = 0;
const fps = [];

for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const actual = row.label === 1;
  const predicted = !result.safe;

  if (actual && predicted) tp++;
  else if (!actual && predicted) {
    fp++;
    fps.push({ text: text.slice(0, 300), score: result.score, matches: result.matches.map(m => ({ id: m.id, w: m.weight })), structural: result.structuralSignals });
  }
  else if (!actual && !predicted) tn++;
  else fn++;
}

console.log(`TP=${tp} FP=${fp} TN=${tn} FN=${fn}`);
console.log(`Precision: ${(tp/(tp+fp)*100).toFixed(2)}%`);
console.log(`\nAll ${fps.length} false positives:`);
for (const f of fps) {
  console.log(`\n  Score: ${f.score}`);
  console.log(`  Matches: ${JSON.stringify(f.matches)}`);
  console.log(`  Text: "${f.text}..."`);
}
