import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

// Find FN that are near-miss (0.2 <= score < 0.5)
const injections = records.filter(r => r.label === 1);
const fn = injections.filter(r => scan(r.text).score < 0.5);

console.log(`Total injections: ${injections.length}, FN: ${fn.length}`);

// Find the near-miss ones
const nearMiss = fn.filter(r => scan(r.text).score >= 0.2);
console.log(`Near-miss (0.2-0.5): ${nearMiss.length}`);

// Show near-miss with their matches
nearMiss.slice(0, 30).forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[${i+1}] score=${result.score.toFixed(3)} matches=[${result.matches.map(m=>m.id).join(',')}]`);
  console.log(r.text.substring(0, 400));
});
