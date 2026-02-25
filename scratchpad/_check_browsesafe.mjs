import { scan } from '../scanner.js';
import { readFileSync } from 'fs';

const content = readFileSync('datasets/browsesafe-test.jsonl', 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
let tp=0, fp=0, fn=0, tn=0;
for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const pred = result.safe === false;
  if (row.label === 1 && pred) tp++;
  else if (row.label === 0 && pred) fp++;
  else if (row.label === 1 && !pred) fn++;
  else tn++;
}
console.log('browsesafe: TP=' + tp + ' FP=' + fp + ' FN=' + fn + ' TN=' + tn);
// Expected before: TP=1229 based on 67.32% recall at browsesafe 1824 injections?
// Actually let me check Ethan's numbers: 41 FP, precision 96.77%
// 96.77% precision with 41 FP: TP/(TP+41) = 0.9677 => TP = 0.9677*(TP+41) => TP = 1229
console.log('Expected baseline TP=1229');
