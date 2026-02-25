import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// Verify jayavibhav impact
const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
let tp = 0, fp = 0, tn = 0, fn = 0;
for (const line of lines) {
  const row = JSON.parse(line);
  const result = scan(row.text);
  const predicted = !result.safe;
  if (row.label === 1 && predicted) tp++;
  if (row.label === 0 && predicted) fp++;
  if (row.label === 0 && !predicted) tn++;
  if (row.label === 1 && !predicted) fn++;
}

const prec = tp / (tp + fp) || 0;
const rec = tp / (tp + fn) || 0;
const f1 = 2 * prec * rec / (prec + rec) || 0;
console.log(`jayavibhav: TP=${tp} FP=${fp} TN=${tn} FN=${fn}`);
console.log(`  Precision: ${(prec * 100).toFixed(2)}%`);
console.log(`  Recall: ${(rec * 100).toFixed(2)}%`);
console.log(`  F1: ${(f1 * 100).toFixed(2)}%`);
