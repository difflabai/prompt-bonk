// Analyze the named_bot_definition structural signal
// It fires on "AI assistant named Jarvis" in an Iron Man creative prompt
// Question: can we add an exclusion for well-known fictional AI names?

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

// Check all datasets for named_bot_definition signal
const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));

const namedBotRegex = /\b(?:chatbot|bot|assistant|advisor|tutor|coach|helper|guide|companion)\s+(?:named|called|known\s+as)\s+[A-Z]\w+/i;

console.log(`=== named_bot_definition signal analysis ===\n`);

for (const file of files.sort()) {
  const rows = loadJsonl(file);
  if (rows.length === 0) continue;

  let sigTP = 0, sigFP = 0;
  const sigFPdetails = [];
  const sigTPdetails = [];

  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const result = scan(text, { threshold: 0.50 });
    const pred = !result.safe;

    const hasSig = result.structural.signals.some(s => s.id === 'named_bot_definition');
    if (!hasSig) continue;

    if (actual && pred) {
      sigTP++;
      if (sigTPdetails.length < 3) {
        const m = text.match(namedBotRegex);
        sigTPdetails.push({ score: result.score, match: m ? m[0] : '', text: text.slice(0, 150) });
      }
    } else if (!actual && pred) {
      sigFP++;
      const m = text.match(namedBotRegex);
      sigFPdetails.push({ score: result.score, match: m ? m[0] : '', text: text.slice(0, 200) });
    }
  }

  if (sigTP > 0 || sigFP > 0) {
    console.log(`${file}: TP=${sigTP} FP=${sigFP}`);
    for (const d of sigFPdetails) {
      console.log(`  FP [score=${d.score}]: matched "${d.match}"`);
      console.log(`    text: ${d.text}`);
    }
    for (const d of sigTPdetails) {
      console.log(`  TP [score=${d.score}]: matched "${d.match}"`);
      console.log(`    text: ${d.text}`);
    }
    console.log();
  }
}

// Now check: what if we exclude known fictional AI names from named_bot_definition?
// Known fictional: Jarvis, Friday, JARVIS, Cortana, HAL, Samantha, Baymax, Data, WALL-E, R2D2
console.log(`\n=== Check: what names trigger FP? ===\n`);

for (const file of ['protectai.jsonl']) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    const text = String(row.text || '');
    if (row.label !== 0) continue;
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    const hasSig = result.structural.signals.some(s => s.id === 'named_bot_definition');
    if (!hasSig) continue;

    const m = text.match(namedBotRegex);
    console.log(`FP: "${m ? m[0] : ''}" in: ${text.slice(0, 300)}`);
  }
}
