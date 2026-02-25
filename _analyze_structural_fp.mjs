// Analyze protectai FPs that are structural-only (no pattern matches)
// or have score <= 0.55 (borderline)

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  if (!content) return [];
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('protectai.jsonl');

// Collect all FPs
const fps = [];
let tp = 0, fp = 0, tn = 0, fn = 0;

for (const row of rows) {
  const text = String(row.text || '');
  const actual = row.label === 1;
  const result = scan(text, { threshold: 0.50 });
  const pred = !result.safe;

  if (actual && pred) tp++;
  else if (!actual && pred) { fp++; fps.push({ text, result }); }
  else if (!actual && !pred) tn++;
  else fn++;
}

console.log(`Protectai: TP=${tp} FP=${fp} TN=${tn} FN=${fn}\n`);

// Categorize FPs
const structuralOnly = fps.filter(f => f.result.matches.length === 0);
const borderline = fps.filter(f => f.result.score <= 0.55);
const lowPattern = fps.filter(f => f.result.matches.length > 0 && f.result.matches.every(m => m.weight < 0.50));

console.log(`=== FP Categories ===`);
console.log(`Structural-only (no pattern matches): ${structuralOnly.length}`);
console.log(`Borderline (score <= 0.55): ${borderline.length}`);
console.log(`Low-pattern only (all patterns < 0.50): ${lowPattern.length}`);

console.log(`\n=== ALL 36 FPs sorted by score ===\n`);
fps.sort((a, b) => a.result.score - b.result.score);

for (const { text, result } of fps) {
  const patternIds = result.matches.map(m => `${m.id}(${m.weight})`).join(', ') || 'NONE';
  const structSignals = result.structural.signals.map(s => `${s.signal}(${s.score.toFixed(3)})`).join(', ') || 'NONE';
  console.log(`[score=${result.score}] patterns: ${patternIds}`);
  console.log(`  structural=${result.structural.score.toFixed(3)} signals: ${structSignals}`);
  console.log(`  text: ${text.slice(0, 200)}`);
  console.log();
}

// Check: how many FPs have score in the 0.50-0.52 range?
const marginal = fps.filter(f => f.result.score >= 0.50 && f.result.score <= 0.52);
console.log(`\n=== MARGINAL FPs (score 0.50-0.52): ${marginal.length} ===`);
console.log(`These are closest to threshold -- any small change could flip them.`);
