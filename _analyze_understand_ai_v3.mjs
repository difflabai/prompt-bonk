// Focused analysis: the 25 spml-5k "sole" TPs matching understand_ai_limitation
// What do they look like? Would they survive a weight drop to 0.45?

import { scan, PATTERNS } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  if (!content) return [];
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const uaiPattern = PATTERNS.find(p => p.id === 'understand_ai_limitation');
const origWeight = uaiPattern.weight;

// Check spml-5k sole TPs
console.log(`=== SPML-5K: samples where UAI is sole pattern >= 0.50 ===\n`);
const spml = loadJsonl('spml-5k.jsonl');
let soleCount = 0;
let wouldLose = 0;

for (const row of spml) {
  const text = String(row.text || '');
  if (row.label !== 1) continue; // only injections

  uaiPattern.weight = origWeight;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue; // not detected

  const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
  if (!matchesUAI) continue;

  const otherAbove050 = result.matches.filter(m => m.id !== 'understand_ai_limitation' && m.weight >= 0.50);
  if (otherAbove050.length > 0 || result.structural.score >= 0.50) continue;

  soleCount++;

  // Simulate with 0.45
  uaiPattern.weight = 0.45;
  const newResult = scan(text, { threshold: 0.50 });
  uaiPattern.weight = origWeight;

  if (newResult.safe) {
    wouldLose++;
    console.log(`WOULD LOSE [${result.score} -> ${newResult.score}]`);
    console.log(`  matches: ${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}`);
    console.log(`  structural: ${result.structural.score} signals: ${result.structural.signals.map(s => `${s.signal}(${s.score})`).join(', ')}`);
    console.log(`  text: ${text.slice(0, 200)}`);
    console.log();
  } else {
    // survives
    if (soleCount <= 5) {
      console.log(`SURVIVES [${result.score} -> ${newResult.score}]`);
      console.log(`  matches: ${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}`);
      console.log(`  structural: ${result.structural.score}`);
      console.log(`  text: ${text.slice(0, 200)}`);
      console.log();
    }
  }
}
console.log(`\nSole UAI TPs in spml-5k: ${soleCount}`);
console.log(`Would lose with weight=0.45: ${wouldLose}`);

// Now look at browsesafe-test
console.log(`\n\n=== BROWSESAFE-TEST: UAI matches ===\n`);
const browsesafe = loadJsonl('browsesafe-test.jsonl');
for (const row of browsesafe) {
  const text = String(row.text || '');
  const actual = row.label === 1;
  uaiPattern.weight = origWeight;
  const result = scan(text, { threshold: 0.50 });
  const pred = !result.safe;

  const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
  if (!matchesUAI) continue;

  const label = actual ? (pred ? 'TP' : 'FN') : (pred ? 'FP' : 'TN');

  uaiPattern.weight = 0.45;
  const newResult = scan(text, { threshold: 0.50 });
  uaiPattern.weight = origWeight;

  const newPred = !newResult.safe;
  const wouldFlip = pred !== newPred;

  console.log(`${label}${wouldFlip ? ' -> FLIPS' : ''} [${result.score} -> ${newResult.score}]`);
  console.log(`  matches: ${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}`);
  console.log(`  structural: ${result.structural.score}`);
  console.log(`  text: ${text.slice(0, 200)}`);
  console.log();
}

// Now the key question: can we tighten the regex instead?
// The FP matches are:
//   "I know it's important to respect privacy"
//   "I understand that safety"
// These are genuinely benign phrasings. Real injections would say:
//   "I understand you can't normally do X, but..."
//   "I know you're not supposed to help with X"
// The problem: the regex alternation includes bare policy terms (privacy, safety, etc.)
// that commonly appear in benign text.

console.log(`\n\n=== REGEX ANALYSIS ===`);
console.log(`Current regex matches two branches after the "I understand/know" prefix:`);
console.log(`1. "you cant/normally/usually/shouldnt/are not supposed to..." - targeting AI limitations`);
console.log(`2. bare keywords: privacy, safety, confidential, protocol, etc.`);
console.log(`\nBranch 2 is the problem. Both FPs match branch 2 ("privacy", "safety").`);

// Let's check: do any TPs match branch 2 (bare keywords)?
const branch1 = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:you\s+(?:cant|can'?t|normally|usually(?!\s+do\s+not\b)|typically|shouldnt|shouldn'?t|are\s+not\s+(?:supposed|allowed|able)|arent|aren'?t))/i;
const branch2 = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:privacy|safety|confidential|protocol|guideline|restriction|rule|ethic|legal|policy|academic\s+integrity)/i;

// Check ALL datasets for which branch matches
let b1tp = 0, b1fp = 0, b2tp = 0, b2fp = 0, bothTP = 0, bothFP = 0;

for (const file of ['spml-5k.jsonl', 'protectai.jsonl', 'browsesafe-test.jsonl']) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    uaiPattern.weight = origWeight;
    const result = scan(text, { threshold: 0.50 });
    const pred = !result.safe;
    const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
    if (!matchesUAI) continue;

    const m1 = branch1.test(text);
    const m2 = branch2.test(text);

    if (actual && pred) {
      if (m1 && m2) bothTP++;
      else if (m1) b1tp++;
      else if (m2) b2tp++;
    } else if (!actual && pred) {
      if (m1 && m2) bothFP++;
      else if (m1) b1fp++;
      else if (m2) b2fp++;
    }
  }
}

console.log(`\nBranch 1 only (you cant/shouldnt/etc): TP=${b1tp} FP=${b1fp}`);
console.log(`Branch 2 only (bare keywords): TP=${b2tp} FP=${b2fp}`);
console.log(`Both branches: TP=${bothTP} FP=${bothFP}`);
