import { readFileSync } from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { scan } = require('../scanner.js');

const jayLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const jayRecords = jayLines.map(l => JSON.parse(l));

const fn = jayRecords.filter(r => (r.label === 1 || r.label === '1')).filter(r => {
  const result = scan(r.text);
  return result.score < 0.5;
});

console.log(`Total FN: ${fn.length}`);
fn.forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[${i+1}] score=${result.score.toFixed(3)}`);
  console.log(r.text.substring(0, 500));
});
