// Final analysis: simulate splitting understand_ai_limitation into two patterns
// Branch 1: "you cant/shouldnt/normally" at 0.52
// Branch 2: "bare keywords" at 0.45
// Impact across all affected datasets

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

// Find the pattern index
const uaiIdx = PATTERNS.findIndex(p => p.id === 'understand_ai_limitation');
const uaiPattern = PATTERNS[uaiIdx];

// The original regex
const origRegex = uaiPattern.regex;
const origWeight = uaiPattern.weight;

// Branch 1: "you cant/shouldnt/normally" -- keep at 0.52
const branch1Regex = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:you\s+(?:cant|can'?t|normally|usually(?!\s+do\s+not\b)|typically|shouldnt|shouldn'?t|are\s+not\s+(?:supposed|allowed|able)|arent|aren'?t))/i;

// Branch 2: bare keywords -- lower to 0.45
const branch2Regex = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:privacy|safety|confidential|protocol|guideline|restriction|rule|ethic|legal|policy|academic\s+integrity)/i;

// To simulate the split, we replace the single pattern with two
// Save original state
const origPatternCopy = { ...uaiPattern };

// Run baseline for all datasets
const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));

console.log(`=== CROSS-DATASET IMPACT: Split understand_ai_limitation ===\n`);
console.log(`Change: branch1 (you cant/shouldnt) stays at 0.52, branch2 (bare keywords) drops to 0.45\n`);

for (const file of files.sort()) {
  const rows = loadJsonl(file);
  if (rows.length === 0) continue;

  // Baseline: original pattern
  uaiPattern.regex = origRegex;
  uaiPattern.weight = origWeight;
  uaiPattern.id = 'understand_ai_limitation';

  let origTP=0, origFP=0, origTN=0, origFN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) origTP++;
    else if (!actual && pred) origFP++;
    else if (!actual && !pred) origTN++;
    else origFN++;
  }

  // Modified: branch 1 at 0.52
  uaiPattern.regex = branch1Regex;
  uaiPattern.weight = 0.52;
  uaiPattern.id = 'understand_ai_limitation_direct';

  // Add branch 2 at 0.45 as a new pattern
  const branch2Pattern = {
    regex: branch2Regex,
    weight: 0.45,
    category: 'safety_bypass',
    id: 'understand_ai_limitation_keyword',
    description: 'Acknowledges AI policies (keyword variant)',
  };
  PATTERNS.push(branch2Pattern);

  let newTP=0, newFP=0, newTN=0, newFN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) newTP++;
    else if (!actual && pred) newFP++;
    else if (!actual && !pred) newTN++;
    else newFN++;
  }

  // Remove added pattern
  PATTERNS.pop();

  const dTP = newTP - origTP;
  const dFP = newFP - origFP;
  if (dTP !== 0 || dFP !== 0) {
    const origPrec = origTP / (origTP + origFP) || 0;
    const newPrec = newTP / (newTP + newFP) || 0;
    const origRec = origTP / (origTP + origFN) || 0;
    const newRec = newTP / (newTP + newFN) || 0;
    const origF1 = 2*origPrec*origRec/(origPrec+origRec) || 0;
    const newF1 = 2*newPrec*newRec/(newPrec+newRec) || 0;
    console.log(`${file}:`);
    console.log(`  BEFORE: TP=${origTP} FP=${origFP} Prec=${(origPrec*100).toFixed(1)}% Rec=${(origRec*100).toFixed(1)}% F1=${(origF1*100).toFixed(1)}%`);
    console.log(`  AFTER:  TP=${newTP} FP=${newFP} Prec=${(newPrec*100).toFixed(1)}% Rec=${(newRec*100).toFixed(1)}% F1=${(newF1*100).toFixed(1)}%`);
    console.log(`  Delta:  TP ${dTP >= 0 ? '+' : ''}${dTP}, FP ${dFP >= 0 ? '+' : ''}${dFP}, Prec ${((newPrec-origPrec)*100).toFixed(2)}pp, F1 ${((newF1-origF1)*100).toFixed(2)}pp`);
    console.log();
  }
}

// Restore original
uaiPattern.regex = origRegex;
uaiPattern.weight = origWeight;
uaiPattern.id = 'understand_ai_limitation';
