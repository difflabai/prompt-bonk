import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const textOf = r => r.text || r.input || '';

const skipRe = /\bskip\s+(?:the\s+)?(?:whole\s+)?(?:approval|verification|review|confirmation|validation|authentication|consent|authorization)\s+(?:step|process|procedure|check|requirement|protocol)\b/i;
const goAheadRe = /\b(?:already\s+giving|giving|give|gave|grant(?:ing)?) you (?:the\s+)?go[- ]ahead\b/i;

const spml = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));
const protect = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl', 'utf8').trim().split('\n').map(l=>JSON.parse(l));

// Skip approval
const spmlInj = spml.filter(r => r.label === 1);
const spmlBen = spml.filter(r => r.label === 0);
const spmlFN = spmlInj.filter(r => scan(textOf(r)).score < 0.5);

console.log('=== skip_approval_step ===');
const skipFN = spmlFN.filter(r => skipRe.test(textOf(r)));
const skipBen = spmlBen.filter(r => skipRe.test(textOf(r)));
console.log(`spml FN: ${skipFN.length}, benign: ${skipBen.length}`);
skipFN.forEach((r, i) => {
  const s = scan(textOf(r)).score;
  console.log(`[FN ${i+1}] score=${s.toFixed(3)}: ${textOf(r).substring(0, 200)}`);
});

console.log('\n=== go_ahead_bypass ===');
const protectBen = protect.filter(r => r.label === 0);
const goFN = spmlFN.filter(r => goAheadRe.test(textOf(r)));
const goBen = spmlBen.filter(r => goAheadRe.test(textOf(r)));
const goProtBen = protectBen.filter(r => goAheadRe.test(textOf(r)));
console.log(`spml FN: ${goFN.length}, benign: ${goBen.length}`);
console.log(`protectai benign: ${goProtBen.length}`);

goProtBen.forEach((r, i) => {
  const s = scan(textOf(r)).score;
  const newS = s < 0.5 ? 0.5 : (s + 0.5 * 0.15);
  console.log(`[Protect Ben ${i+1}] score=${s.toFixed(3)} newScore=${newS.toFixed(3)}: ${textOf(r).substring(0, 200)}`);
});

goFN.forEach((r, i) => {
  const s = scan(textOf(r)).score;
  const newS = s < 0.5 ? 0.5 : (s + 0.5 * 0.15);
  console.log(`[FN ${i+1}] old=${s.toFixed(3)} new=${newS.toFixed(3)}: ${textOf(r).substring(0, 200)}`);
});
