import { scan } from './scanner.js';
import fs from 'fs';

const rows = fs.readFileSync('datasets/openwebtext-benign.jsonl','utf8').trim().split('\n').map(l=>JSON.parse(l));
const patFPs = {};
const soloFPs = {};
const structOnly = [];
let fpCount = 0;

for (const r of rows) {
  const res = scan(r.text);
  if (!res.safe) {
    fpCount++;
    const ids = res.matches.map(m => m.id);
    for (const id of ids) { patFPs[id] = (patFPs[id]||0)+1; }
    if (ids.length === 1) { soloFPs[ids[0]] = (soloFPs[ids[0]]||0)+1; }
    if (ids.length === 0) structOnly.push(res.score.toFixed(3));
  }
}

console.log('Total OWT FPs: ' + fpCount);
console.log('Structural-only: ' + structOnly.length + ' (' + structOnly.join(', ') + ')');
console.log('');
console.log('Pattern FP counts (total / solo):');
const sorted = Object.entries(patFPs).sort((a,b)=>b[1]-a[1]);
for (const [id,c] of sorted) console.log('  ' + id + ': ' + c + ' total, ' + (soloFPs[id]||0) + ' solo');
