import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const textOf = r => r.text || r.input || '';
const jay = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));
const benign = jay.filter(r => r.label === 0);
const inj = jay.filter(r => r.label === 1);

const re = /\bsinister\b/i;
const weight = 0.40;

// Check current FP
const currentFP = benign.filter(r => scan(textOf(r)).score >= 0.5);
console.log(`Current FP: ${currentFP.length}`);

// Check what sinister does
const benHits = benign.filter(r => re.test(textOf(r)));
const newFP = benHits.filter(r => {
  const s = scan(textOf(r)).score;
  if (s >= 0.5) return false;
  const newScore = s < weight ? weight : (s + weight * 0.15 / 1);
  return newScore >= 0.5;
});

console.log(`Benign with sinister: ${benHits.length}, new FP: ${newFP.length}`);

// Check FN rescued
const injFN = inj.filter(r => scan(textOf(r)).score < 0.5 && re.test(textOf(r)));
const rescued = injFN.filter(r => {
  const s = scan(textOf(r)).score;
  const newScore = s < weight ? weight : (s + weight * 0.15 / 1);
  return newScore >= 0.5;
});
console.log(`FN with sinister: ${injFN.length}, rescued: ${rescued.length}`);

// Show which ones get rescued
rescued.forEach((r, i) => {
  const s = scan(textOf(r)).score;
  const newS = s < weight ? weight : (s + weight * 0.15 / 1);
  console.log(`\n[Rescued ${i+1}] old=${s.toFixed(3)} new=${newS.toFixed(4)}`);
  console.log(textOf(r).substring(0, 200));
});

// Also verify spml-5k, deepset, safeguard
const spml = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));
const spmlBen = spml.filter(r => r.label === 0);
console.log(`\nspml benign with sinister: ${spmlBen.filter(r=>re.test(textOf(r))).length}`);

const safeguard = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));
const safeguardBen = safeguard.filter(r => r.label === 0);
console.log(`safeguard benign with sinister: ${safeguardBen.filter(r=>re.test(textOf(r))).length}`);
