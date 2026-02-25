// Show the FULL text of all theoretical_scenario FPs vs TPs in protectai
// to see if there's a regex refinement that can distinguish them
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');
const content = readFileSync(path.join(DATASETS_DIR, 'protectai.jsonl'), 'utf8').trim();
const rows = content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));

const fps = [];
const tps = [];

for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const matchIds = result.matches.map(m => m.id);

  if (!matchIds.includes('theoretical_scenario')) continue;

  if (row.label === 0 && !result.safe) {
    fps.push({ text, score: result.score, matches: matchIds });
  } else if (row.label === 1 && !result.safe) {
    tps.push({ text, score: result.score, matches: matchIds });
  }
}

console.log(`=== theoretical_scenario FPs in protectai (${fps.length}) ===\n`);
for (const fp of fps) {
  console.log(`[score=${fp.score}] matches=[${fp.matches.join(',')}]`);
  console.log(`TEXT (first 500 chars):`);
  console.log(fp.text.slice(0, 500));
  console.log(`---`);
}

console.log(`\n=== theoretical_scenario TPs in protectai (${tps.length}) ===\n`);
for (const tp of tps) {
  console.log(`[score=${tp.score}] matches=[${tp.matches.join(',')}]`);
  console.log(`TEXT (first 500 chars):`);
  console.log(tp.text.slice(0, 500));
  console.log(`---`);
}
