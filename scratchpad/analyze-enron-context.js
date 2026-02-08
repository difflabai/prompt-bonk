import { scan } from '../scanner.js';
import fs from 'fs';

const rows = fs.readFileSync('/ml2/nanobot/projects/prompt-guard-ats/datasets/enron-benign.jsonl','utf8').trim().split('\n').map(l=>JSON.parse(l));
const fpExamples = {};

for (const r of rows) {
  const res = scan(r.text);
  if (!res.safe) {
    const ids = res.matches.map(m => m.id);
    for (const id of ids) {
      if (!fpExamples[id]) fpExamples[id] = [];
      if (fpExamples[id].length < 2) {
        fpExamples[id].push({
          score: res.score.toFixed(3),
          matches: res.matches.map(m => m.id),
          text: r.text.substring(0, 200)
        });
      }
    }
  }
}

for (const [id, examples] of Object.entries(fpExamples)) {
  console.log(`\n=== ${id} ===`);
  for (let i = 0; i < examples.length; i++) {
    const ex = examples[i];
    console.log(`Example ${i+1} (score=${ex.score}, all_matches=[${ex.matches.join(',')}]):`);
    console.log(`"${ex.text}..."`);
  }
}
