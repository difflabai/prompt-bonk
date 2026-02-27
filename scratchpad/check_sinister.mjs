import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const jayLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const jayRecords = jayLines.map(l => JSON.parse(l));
const jayInj = jayRecords.filter(r => r.label === 1);
const jayBenign = jayRecords.filter(r => r.label === 0);

// Check "sinister" hits in FN and benign
const re = /\bsinister\b/i;
const fnHits = jayInj.filter(r => scan(r.text).score < 0.5 && re.test(r.text));
const benignHits = jayBenign.filter(r => re.test(r.text));

console.log(`FN with "sinister": ${fnHits.length}`);
fnHits.forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[FN ${i+1}] score=${result.score.toFixed(3)}`);
  console.log(r.text.substring(0, 300));
});

console.log('\n--- Benign with "sinister" ---');
benignHits.forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[B ${i+1}] score=${result.score.toFixed(3)}`);
  console.log(r.text.substring(0, 300));
});

// Also check protectai
const protLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl', 'utf8').trim().split('\n');
const protRecords = protLines.map(l => JSON.parse(l));
const protBenign = protRecords.filter(r => r.label === 0);
const protBenignHits = protBenign.filter(r => re.test(r.text));
console.log(`\nProtectai benign with "sinister": ${protBenignHits.length}`);
protBenignHits.forEach((r, i) => {
  const result = scan(r.text);
  console.log(`[PB ${i+1}] score=${result.score.toFixed(3)}: ${r.text.substring(0, 200)}`);
});
