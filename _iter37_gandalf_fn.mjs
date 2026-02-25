// Analyze gandalf-ignore zero-score FN for potential new patterns
// Also look at gandalf-summarization FN

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
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

console.log('=== ALL gandalf-ignore FN with full text ===\n');
const gi = loadJsonl('gandalf-ignore.jsonl');
let fnIdx = 0;
for (const row of gi) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  fnIdx++;
  console.log(`FN#${fnIdx} [${result.score}] matches=[${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
  console.log(`  structural=[${result.structural.signals.map(s => `${s.id}(${s.score.toFixed(2)})`).join(', ')}]`);
  console.log(`  text: "${text}"`);
  console.log();
}

console.log('\n=== ALL gandalf-summarization FN with full text ===\n');
const gs = loadJsonl('gandalf-summarization.jsonl');
fnIdx = 0;
for (const row of gs) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  fnIdx++;
  console.log(`FN#${fnIdx} [${result.score}] matches=[${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
  console.log(`  structural=[${result.structural.signals.map(s => `${s.id}(${s.score.toFixed(2)})`).join(', ')}]`);
  console.log(`  text: "${text.slice(0, 400)}"`);
  console.log();
}
