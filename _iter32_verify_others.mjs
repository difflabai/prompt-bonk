import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const datasets = ['protectai', 'browsesafe-test', 'deepset-train', 'deepset-test', 'safeguard-test', 'notinject', 'gandalf-summarization', 'gandalf-ignore', 'yanismiraoui-multilingual', 'spml-5k'];

for (const ds of datasets) {
  let lines;
  try {
    lines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  } catch (e) { continue; }

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
  console.log(`${ds}: Prec=${(prec*100).toFixed(2)}% Rec=${(rec*100).toFixed(2)}% F1=${(f1*100).toFixed(2)}% (TP=${tp} FP=${fp} TN=${tn} FN=${fn})`);
}
