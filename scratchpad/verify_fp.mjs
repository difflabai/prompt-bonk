import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const textOf = r => r.text || r.input || '';
const jay = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));
const benign = jay.filter(r => r.label === 0);

// Current false positives (already above threshold)
const currentFP = benign.filter(r => scan(textOf(r)).score >= 0.5);
console.log(`Current FP in jayavibhav: ${currentFP.length}`);

// For untalked-of at weight 0.35, which benign would cross threshold?
const re = /\buntalked[- ]of\b/i;
const benHits = benign.filter(r => re.test(textOf(r)));
const newFP = benHits.filter(r => {
  const s = scan(textOf(r)).score;
  // Only benign that are CURRENTLY BELOW threshold (not already FP)
  if (s >= 0.5) return false; // already FP
  const newScore = s < 0.35 ? 0.35 : (s + 0.35 * 0.15 / 1);
  return newScore >= 0.5;
});

console.log(`\nBenign hits with untalked-of: ${benHits.length}`);
console.log(`NEW FP (currently below 0.5, would cross threshold): ${newFP.length}`);
newFP.forEach((r, i) => {
  const s = scan(textOf(r)).score;
  const newS = s < 0.35 ? 0.35 : (s + 0.35 * 0.15 / 1);
  console.log(`\n[${i+1}] old=${s.toFixed(3)} new=${newS.toFixed(3)}`);
  console.log(textOf(r).substring(0, 200));
});
