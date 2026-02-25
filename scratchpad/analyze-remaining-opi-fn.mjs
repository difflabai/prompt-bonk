// Analyze the remaining 1600 open-pi FNs to understand what they are
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const opi = loadJsonl('open-prompt-injection.jsonl');

const patterns = [
  /Write the sentiment conveyed by the following text/i,
  /(?:checks?\s+if\s+(?:a\s+)?message\s+contains?\s+hateful\s+contents)/i,
  /Write spam or not spam for whether the text below contains/i,
];

const matchesAny = text => patterns.some(p => p.test(text));

// Get the remaining FNs
const remainingFN = [];
for (const row of opi) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue; // already caught
  if (matchesAny(text)) continue; // would be caught by new pattern

  remainingFN.push(text);
}

console.log(`Remaining open-pi FNs: ${remainingFN.length}\n`);

// Sample them
for (let i = 0; i < Math.min(20, remainingFN.length); i++) {
  console.log(`[${i+1}] "${remainingFN[i].slice(0, 300)}"\n`);
}

// Count how many contain specific injection patterns
const subPatterns = {
  'Write a simple and brief summary': 0,
  'answer spam or not spam': 0,
  'Translate': 0,
  'Determine': 0,
  'Classify': 0,
};

for (const text of remainingFN) {
  if (/write a simple and brief summary/i.test(text)) subPatterns['Write a simple and brief summary']++;
  if (/answer spam or not spam/i.test(text)) subPatterns['answer spam or not spam']++;
  if (/translate/i.test(text)) subPatterns['Translate']++;
  if (/determine/i.test(text)) subPatterns['Determine']++;
  if (/classify/i.test(text)) subPatterns['Classify']++;
}

console.log('\nRemaining FN sub-patterns:');
for (const [k,v] of Object.entries(subPatterns)) {
  console.log(`  ${v}x: ${k}`);
}
