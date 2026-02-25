// Iteration 37: Precise pattern opportunities
// Focus on spml-5k, yanismiraoui, deepset, gandalf-ignore - non-adversarial datasets
// Also: look at jayavibhav injection samples 0.40-0.49 for patterns
// that DON'T appear in jayavibhav benign

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

// === 1. spml-5k: show ALL 15 near-miss FN with full text ===
console.log('=== spml-5k near-miss FN (0.30-0.49) - full analysis ===\n');
const spml = loadJsonl('spml-5k.jsonl');
for (const row of spml) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (result.score < 0.30 || result.score >= 0.50) continue;
  console.log(`[${result.score}] matches=[${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
  console.log(`structural=[${result.structural.signals.map(s => `${s.id}(${s.score.toFixed(2)})`).join(', ')}]`);
  console.log(`text: "${text.slice(0, 300)}"`);
  console.log();
}

// === 2. yanismiraoui: show ALL 5 near-miss FN with full text ===
console.log('\n=== yanismiraoui near-miss FN (0.30-0.49) - full analysis ===\n');
const yanis = loadJsonl('yanismiraoui-multilingual.jsonl');
for (const row of yanis) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (result.score < 0.30 || result.score >= 0.50) continue;
  console.log(`[${result.score}] matches=[${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
  console.log(`structural=[${result.structural.signals.map(s => `${s.id}(${s.score.toFixed(2)})`).join(', ')}]`);
  console.log(`text: "${text}"`);
  console.log();
}

// === 3. deepset FN near-miss: full text ===
console.log('\n=== deepset-train + deepset-test near-miss FN - full analysis ===\n');
for (const file of ['deepset-train.jsonl', 'deepset-test.jsonl']) {
  const ds = loadJsonl(file);
  for (const row of ds) {
    const text = String(row.text || '');
    if (row.label !== 1) continue;
    const result = scan(text, { threshold: 0.50 });
    if (!result.safe) continue;
    if (result.score < 0.30 || result.score >= 0.50) continue;
    console.log(`[${file}] [${result.score}] matches=[${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
    console.log(`structural=[${result.structural.signals.map(s => `${s.id}(${s.score.toFixed(2)})`).join(', ')}]`);
    console.log(`text: "${text.slice(0, 400)}"`);
    console.log();
  }
}

// === 4. browsesafe-test bidi FP problem: are these actually injections or FP? ===
console.log('\n=== browsesafe-test bidi_control: checking if actual injection or benign content ===\n');
const bs = loadJsonl('browsesafe-test.jsonl');
let bidiInjTP = 0, bidiInjFN = 0, bidiBenignTN = 0, bidiBenignFP = 0;
for (const row of bs) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const hasBidi = result.matches.some(m => m.id === 'bidi_control');
  if (!hasBidi) continue;

  if (row.label === 1 && !result.safe) bidiInjTP++;
  else if (row.label === 1 && result.safe) bidiInjFN++;
  else if (row.label === 0 && result.safe) bidiBenignTN++;
  else if (row.label === 0 && !result.safe) bidiBenignFP++;
}
console.log(`bidi_control matching: injTP=${bidiInjTP}, injFN=${bidiInjFN}, benignTN=${bidiBenignTN}, benignFP=${bidiBenignFP}`);

// === 5. Gandalf-ignore: what are the 25 FN? ===
console.log('\n=== gandalf-ignore: ALL FN (score > 0) ===\n');
const gi = loadJsonl('gandalf-ignore.jsonl');
let giFNCount = 0;
for (const row of gi) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  giFNCount++;
  if (result.score > 0) {
    console.log(`[${result.score}] matches=[${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
    console.log(`structural=[${result.structural.signals.map(s => `${s.id}(${s.score.toFixed(2)})`).join(', ')}]`);
    console.log(`text: "${text.slice(0, 300)}"`);
    console.log();
  }
}
console.log(`gandalf-ignore total FN: ${giFNCount}`);

// Show some zero-score gandalf FN
console.log('\n--- gandalf-ignore FN with score=0 (first 10) ---');
let gi0count = 0;
for (const row of gi) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (result.score === 0 && gi0count < 10) {
    gi0count++;
    console.log(`  "${text.slice(0, 200)}"`);
    console.log();
  }
}
