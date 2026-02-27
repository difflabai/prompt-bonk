import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));
const injections = records.filter(r => r.label === 1);
const zeroFN = injections.filter(r => scan(r.text).score === 0);

console.log(`Zero-score FN: ${zeroFN.length}`);
zeroFN.slice(0, 30).forEach((r, i) => {
  console.log(`\n[${i+1}]`);
  console.log(r.text.substring(0, 400));
});
