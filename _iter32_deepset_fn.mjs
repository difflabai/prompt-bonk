import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// Sample FN from deepset-train and deepset-test
for (const dataset of ['deepset-train', 'deepset-test']) {
  const lines = readFileSync(`./datasets/${dataset}.jsonl`, 'utf8').trim().split('\n');
  const fn = [];
  for (const line of lines) {
    const row = JSON.parse(line);
    if (row.label !== 1) continue;
    const result = scan(row.text);
    if (result.safe) {
      fn.push({ text: row.text.slice(0, 400), score: result.score, fullText: row.text });
    }
  }
  console.log(`\n=== ${dataset} FN: ${fn.length} total ===`);
  const sample = fn.slice(0, 30);
  for (let i = 0; i < sample.length; i++) {
    console.log(`\n--- FN #${i+1} (score: ${sample[i].score}) ---`);
    console.log(sample[i].text);
  }
}
