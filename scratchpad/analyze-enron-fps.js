import { scan } from '../scanner.js';
import fs from 'fs';

const rows = fs.readFileSync('/ml2/nanobot/projects/prompt-guard-ats/datasets/enron-benign.jsonl','utf8').trim().split('\n').map(l=>JSON.parse(l));
const patFPs = {};
const soloFPs = {};
let fpCount = 0;

for (const r of rows) {
  const res = scan(r.text);
  if (!res.safe) {
    fpCount++;
    const ids = res.matches.map(m => m.id);
    for (const id of ids) { patFPs[id] = (patFPs[id]||0)+1; }
    if (ids.length === 1) { soloFPs[ids[0]] = (soloFPs[ids[0]]||0)+1; }
    if (ids.length === 0) console.log('STRUCTURAL-ONLY FP score=' + res.score.toFixed(3));
  }
}

console.log('Total Enron FPs: ' + fpCount);
console.log('');
console.log('Pattern FP counts:');
const sorted = Object.entries(patFPs).sort((a,b)=>b[1]-a[1]);
for (const [id,c] of sorted) console.log('  ' + id + ': ' + c + ' (' + (soloFPs[id]||0) + ' solo)');
