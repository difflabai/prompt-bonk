// Detailed analysis of jayavibhav FN near-misses (0.40-0.49)
import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('jayavibhav.jsonl');
const threshold = 0.50;
const nearmiss = [];

for (const row of rows) {
  const text = String(row.text || '');
  const isInjection = row.label === 1;
  const result = scan(text, { threshold });

  if (isInjection && result.safe && result.score >= 0.40) {
    nearmiss.push({
      score: result.score,
      matches: result.matches.map(m => ({ id: m.id, weight: m.weight })),
      structuralScore: result.structuralScore,
      text: text.slice(0, 200),
    });
  }
}

// Count which pattern IDs appear most often in near-misses
const patternCounts = {};
for (const item of nearmiss) {
  for (const m of item.matches) {
    patternCounts[m.id] = (patternCounts[m.id] || 0) + 1;
  }
}

console.log(`Total near-misses (0.40-0.49): ${nearmiss.length}\n`);

console.log('Pattern frequency in near-misses:');
const sorted = Object.entries(patternCounts).sort((a, b) => b[1] - a[1]);
for (const [id, count] of sorted) {
  console.log(`  ${id}: ${count}`);
}

// Check score breakdown: how many at each score level
const scoreFreq = {};
for (const item of nearmiss) {
  const s = item.score.toFixed(3);
  scoreFreq[s] = (scoreFreq[s] || 0) + 1;
}

console.log('\nExact score frequencies:');
for (const [s, c] of Object.entries(scoreFreq).sort((a, b) => parseFloat(b[0]) - parseFloat(a[0]))) {
  console.log(`  ${s}: ${c}`);
}

// Show some samples with their match details
console.log('\n--- Sample near-misses with matches ---');
for (const item of nearmiss.slice(0, 15)) {
  console.log(`score=${item.score} structural=${item.structuralScore || 'N/A'}`);
  console.log(`  matches: ${JSON.stringify(item.matches)}`);
  console.log(`  "${item.text}"`);
  console.log();
}

// Now check: how many near-misses have NO pattern matches (purely structural)?
const purelyStructural = nearmiss.filter(n => n.matches.length === 0);
console.log(`\nPurely structural (no pattern matches): ${purelyStructural.length}/${nearmiss.length}`);

// And how many have exactly 1 match?
const singleMatch = nearmiss.filter(n => n.matches.length === 1);
console.log(`Single pattern match: ${singleMatch.length}/${nearmiss.length}`);

// Check what phrases appear frequently in the near-misses
const phrases = ['start over', 'start from scratch', 'start anew', 'begin afresh', 'start again',
  'reveal secret', 'hidden secret', 'reveal hidden', 'unveil', 'disclose',
  'ignore', 'disregard', 'bypass', 'override', 'forget',
  'system prompt', 'secret', 'confidential', 'private', 'internal'];

console.log('\nPhrase frequency in near-miss texts:');
for (const phrase of phrases) {
  const count = nearmiss.filter(n => n.text.toLowerCase().includes(phrase)).length;
  if (count > 0) console.log(`  "${phrase}": ${count}`);
}
