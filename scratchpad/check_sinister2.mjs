import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

// What is the protectai benign score before adding sinister?
const protLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl', 'utf8').trim().split('\n');
const protRecords = protLines.map(l => JSON.parse(l));
const protBenign = protRecords.filter(r => r.label === 0);
const protBenignSinister = protBenign.filter(r => /\bsinister\b/i.test(r.text));
protBenignSinister.forEach((r, i) => {
  const result = scan(r.text);
  console.log(`[PB ${i+1}] score=${result.score.toFixed(3)}: ${r.text.substring(0, 250)}`);
});

// More importantly: check the specific jayavibhav benign score
const jayLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const jayRecords = jayLines.map(l => JSON.parse(l));
const jayBenign = jayRecords.filter(r => r.label === 0);
const jayBenignSinister = jayBenign.filter(r => /\bsinister\b/i.test(r.text));
console.log(`Jay benign with sinister: ${jayBenignSinister.length}`);
jayBenignSinister.forEach((r, i) => {
  const result = scan(r.text);
  console.log(`[JB ${i+1}] score=${result.score.toFixed(3)}: ${r.text.substring(0, 250)}`);
});
