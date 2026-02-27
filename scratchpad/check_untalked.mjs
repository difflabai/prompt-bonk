import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const textOf = r => r.text || r.input || '';
const re = /\buntalked[- ]of\b/i;
const weight = 0.35;

const jay = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));
const benign = jay.filter(r => r.label === 0);
const inj = jay.filter(r => r.label === 1);

// Show benign hits and their scores
const benHits = benign.filter(r => re.test(textOf(r)));
console.log(`Benign hits: ${benHits.length}`);

// Which would become FP?
const newFP = benHits.filter(r => {
  const s = scan(textOf(r)).score;
  const newScore = s < weight ? weight : (s + weight * 0.15 / 1);
  return newScore >= 0.5;
});

console.log(`New FP: ${newFP.length}`);
newFP.forEach((r, i) => {
  const s = scan(textOf(r)).score;
  console.log(`\n[FP ${i+1}] score=${s.toFixed(3)}`);
  console.log(textOf(r).substring(0, 300));
});

// Show FN hits
const injFN = inj.filter(r => scan(textOf(r)).score < 0.5 && re.test(textOf(r)));
console.log(`\nFN hits: ${injFN.length}`);
injFN.slice(0, 10).forEach((r, i) => {
  const s = scan(textOf(r)).score;
  console.log(`\n[FN ${i+1}] score=${s.toFixed(3)}`);
  console.log(textOf(r).substring(0, 300));
});
