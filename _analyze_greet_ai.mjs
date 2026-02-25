// Quick analysis: greet_ai pattern (weight 0.50) -- TP/FP across all datasets

import { scan, PATTERNS } from './scanner.js';
import { readFileSync, readdirSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

const greetPattern = PATTERNS.find(p => p.id === 'greet_ai');
const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));

console.log(`=== greet_ai analysis ===`);
console.log(`Weight: ${greetPattern.weight}`);
console.log(`Regex: ${greetPattern.regex}\n`);

for (const file of files.sort()) {
  const rows = loadJsonl(file);
  if (rows.length === 0) continue;

  let tp = 0, fp = 0, soleTP = 0;
  const fpDetails = [];

  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const result = scan(text, { threshold: 0.50 });
    const pred = !result.safe;
    const matchesGA = result.matches.some(m => m.id === 'greet_ai');
    if (!matchesGA) continue;

    if (actual && pred) {
      tp++;
      const otherAbove050 = result.matches.filter(m => m.id !== 'greet_ai' && m.weight >= 0.50);
      if (otherAbove050.length === 0 && result.structural.score < 0.50) soleTP++;
    } else if (!actual && pred) {
      fp++;
      fpDetails.push({
        score: result.score,
        match: text.match(greetPattern.regex)?.[0] || '',
        otherPatterns: result.matches.filter(m => m.id !== 'greet_ai').map(m => `${m.id}(${m.weight})`),
        structural: result.structural.score,
        text: text.slice(0, 150),
      });
    }
  }

  if (tp > 0 || fp > 0) {
    console.log(`${file}: TP=${tp} (sole=${soleTP}) FP=${fp}`);
    for (const d of fpDetails) {
      console.log(`  FP [score=${d.score}]: "${d.match}" other=${d.otherPatterns.join(',')||'none'} structural=${d.structural}`);
      console.log(`    text: ${d.text}`);
    }
  }
}
