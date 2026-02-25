// Show ALL protectai FPs with their pattern matches and scores
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');
const content = readFileSync(path.join(DATASETS_DIR, 'protectai.jsonl'), 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

let fpCount = 0;
const patternFpCounts = {};

for (const row of rows) {
  const text = String(row.text || '');
  if (row.label === 1) continue; // skip injections

  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue; // TN, not FP

  fpCount++;
  const matchIds = result.matches.map(m => m.id);

  // Count which patterns contribute to FPs
  for (const id of matchIds) {
    patternFpCounts[id] = (patternFpCounts[id] || 0) + 1;
  }

  // Check if this FP would be saved by lowering theoretical_scenario to 0.45
  const hasTheoretical = matchIds.includes('theoretical_scenario');
  const hasUnderstandAI = matchIds.includes('understand_ai_limitation');

  if (hasTheoretical || hasUnderstandAI) {
    // Simulate: what score would we get if these patterns had lower weight?
    const allMatches = result.matches;
    const targetPatterns = ['theoretical_scenario', 'understand_ai_limitation'];

    // Check if removing the target pattern would drop score below 0.50
    const otherMatches = allMatches.filter(m => !targetPatterns.includes(m.id));
    const maxOtherWt = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;

    console.log(`FP #${fpCount}: score=${result.score} matches=[${matchIds.join(',')}]`);
    console.log(`  theoretical=${hasTheoretical} understand_ai=${hasUnderstandAI} maxOtherWt=${maxOtherWt}`);
    console.log(`  Would lowering fix it? ${result.score <= 0.52 && maxOtherWt < 0.50 ? 'YES - score would drop below threshold' : 'NO - other patterns keep it flagged'}`);
    console.log(`  text: ${text.slice(0, 200)}`);
    console.log();
  }
}

console.log(`\nTotal protectai FPs: ${fpCount}`);
console.log(`\nPattern contribution to FPs (sorted):`);
const sorted = Object.entries(patternFpCounts).sort((a, b) => b[1] - a[1]);
for (const [id, count] of sorted) {
  console.log(`  ${id}: ${count} FPs`);
}
