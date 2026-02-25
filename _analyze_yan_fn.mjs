// Extract ALL yanismiraoui false negatives with full text and scores
import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('yanismiraoui-multilingual.jsonl');
const threshold = 0.50;
const fn_all = [];

for (const row of rows) {
  const text = String(row.text || '');
  const actualInjection = row.label === 1;
  const result = scan(text, { threshold });
  const predictedInjection = !result.safe;

  if (actualInjection && !predictedInjection) {
    fn_all.push({
      score: result.score,
      matches: result.matches.map(m => `${m.id}(${m.weight})`),
      textLen: text.length,
      text: text.slice(0, 500),
    });
  }
}

// Sort by score descending (near-misses first)
fn_all.sort((a, b) => b.score - a.score);

console.log(`Total FN: ${fn_all.length}\n`);

// Show score distribution
const scoreBands = { '0.40-0.49': 0, '0.30-0.39': 0, '0.20-0.29': 0, '0.10-0.19': 0, '0.01-0.09': 0, '0.00': 0 };
for (const item of fn_all) {
  if (item.score >= 0.40) scoreBands['0.40-0.49']++;
  else if (item.score >= 0.30) scoreBands['0.30-0.39']++;
  else if (item.score >= 0.20) scoreBands['0.20-0.29']++;
  else if (item.score >= 0.10) scoreBands['0.10-0.19']++;
  else if (item.score > 0) scoreBands['0.01-0.09']++;
  else scoreBands['0.00']++;
}
console.log('Score distribution:');
for (const [band, count] of Object.entries(scoreBands)) {
  console.log(`  ${band}: ${count}`);
}

console.log('\n--- ALL FN (sorted by score desc) ---\n');
for (let i = 0; i < fn_all.length; i++) {
  const item = fn_all[i];
  console.log(`[${i+1}] score=${item.score} matches=[${item.matches.join(', ')}] len=${item.textLen}`);
  console.log(`    "${item.text}"`);
  console.log();
}
