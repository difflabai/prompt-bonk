import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));
const injections = records.filter(r => r.label === 1);
const benign = records.filter(r => r.label === 0);

// Near-miss: score 0.35-0.49 (these are one stacking pattern away from crossing threshold)
const nearMiss = injections.filter(r => { const s = scan(r.text).score; return s >= 0.35 && s < 0.5; });
console.log(`Near-miss (0.35-0.50): ${nearMiss.length}`);

// For each near-miss, find which new stacking pattern (weight 0.35) would push it over 0.5
// Current near-miss scores: 0.35, 0.40, 0.45, 0.402, 0.450, 0.453, 0.479
// Score formula: maxWeight + stacking...
// A stacking pattern at weight 0.35 applied to score=0.35 would:
//   0.35 + 0.35*0.15/1 = 0.35 + 0.0525 = 0.4025 (not enough)
// We need the near-miss ones where score=0.45 or higher
// At 0.45 + stacking 0.35*0.15/1 = 0.45 + 0.0525 = 0.5025 YES
// At 0.40 + 0.35*0.15/1 = 0.40 + 0.0525 = 0.4525 NO

// So we need patterns that hit the 0.45-0.49 near-misses specifically
const highNearMiss = injections.filter(r => { const s = scan(r.text).score; return s >= 0.45 && s < 0.5; });
console.log(`High near-miss (0.45-0.50): ${highNearMiss.length}`);

// What do these have in common?
// Let me check what current patterns they match
highNearMiss.slice(0, 30).forEach((r, i) => {
  const result = scan(r.text);
  console.log(`\n[${i+1}] score=${result.score.toFixed(3)} matches=[${result.matches.map(m=>m.id).join(',')}]`);
  console.log(r.text.substring(0, 200));
});
