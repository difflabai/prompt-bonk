import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

// Analyze spml-5k FN - find near-miss ones that have some score
const spmlLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl', 'utf8').trim().split('\n');
const spmlRecords = spmlLines.map(l => JSON.parse(l));
const spmlInjections = spmlRecords.filter(r => r.label === 1);
const spmlFN = spmlInjections.filter(r => {
  const s = scan(r.text).score;
  return s >= 0.2 && s < 0.5;
});

console.log(`=== SPML-5k near-miss FN (0.2-0.5): ${spmlFN.length} ===`);
spmlFN.slice(0, 40).forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[${i+1}] score=${result.score.toFixed(3)} matches=[${result.matches.map(m=>m.id).join(',')}]`);
  console.log(r.text.substring(0, 300));
});
