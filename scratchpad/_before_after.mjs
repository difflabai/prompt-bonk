// Quick check on protectai TP/FP counts after the change
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';

const content = readFileSync('datasets/protectai.jsonl', 'utf8').trim();
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
console.log('AFTER: TP=' + tp + ' FP=' + fp + ' FN=' + fn + ' TN=' + tn);
console.log('Injections: ' + (tp + fn) + ' Benign: ' + (fp + tn));
console.log('Precision: ' + (tp / (tp + fp) * 100).toFixed(2) + '%');
console.log('Recall: ' + (tp / (tp + fn) * 100).toFixed(2) + '%');
