// FINAL v2: Split understand_ai_limitation into TWO separate patterns
// Pattern A: "I understand/know... you cant/shouldnt/normally" at 0.52 (unchanged)
// Pattern B: "I understand/know... [keyword]" at 0.45 (lowered from 0.52)
// The key insight: branch 2 (keywords) catches legitimate discussion of privacy/safety
// 38 TPs vs 4 FPs at 0.52. At 0.45, it can't trigger detection alone but still contributes
// as an additional signal when other patterns are present.

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

const uaiIdx = PATTERNS.findIndex(p => p.id === 'understand_ai_limitation');
const origPattern = { ...PATTERNS[uaiIdx] };

// Split: Replace original with branch 1 (you cant/shouldnt/normally)
const branch1 = {
  regex: /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:you\s+(?:cant|can'?t|normally|usually(?!\s+do\s+not\b)|typically|shouldnt|shouldn'?t|are\s+not\s+(?:supposed|allowed|able)|arent|aren'?t))/i,
  weight: 0.52,
  category: 'safety_bypass',
  id: 'understand_ai_limitation',
  description: 'Acknowledges AI limitations suggesting bypass attempt',
};

// Add branch 2 at 0.45 (keywords)
const branch2 = {
  regex: /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:privacy|safety|confidential|protocol|guideline|restriction|rule|ethic|legal|policy|academic\s+integrity)/i,
  weight: 0.45,
  category: 'safety_bypass',
  id: 'understand_ai_limitation_keyword',
  description: 'Acknowledges AI policies/keywords suggesting bypass attempt',
};

const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));

console.log(`=== SPLIT PATTERN TEST ===`);
console.log(`Branch 1 (you cant/shouldnt): weight 0.52, id: understand_ai_limitation`);
console.log(`Branch 2 (bare keywords): weight 0.45, id: understand_ai_limitation_keyword\n`);

let totalDTP = 0, totalDFP = 0;

for (const file of files.sort()) {
  const rows = loadJsonl(file);
  if (rows.length === 0) continue;

  // Baseline: original pattern
  PATTERNS[uaiIdx] = { ...origPattern };
  // Make sure no extra pattern from previous run
  const extraIdx = PATTERNS.findIndex(p => p.id === 'understand_ai_limitation_keyword');
  if (extraIdx >= 0) PATTERNS.splice(extraIdx, 1);

  let oTP=0, oFP=0, oTN=0, oFN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) oTP++; else if (!actual && pred) oFP++; else if (!actual && !pred) oTN++; else oFN++;
  }

  // Modified: split into two patterns
  PATTERNS[uaiIdx] = { ...branch1 };
  PATTERNS.push({ ...branch2 });

  let nTP=0, nFP=0, nTN=0, nFN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) nTP++; else if (!actual && pred) nFP++; else if (!actual && !pred) nTN++; else nFN++;
  }

  // Clean up
  const removeIdx = PATTERNS.findIndex(p => p.id === 'understand_ai_limitation_keyword');
  if (removeIdx >= 0) PATTERNS.splice(removeIdx, 1);

  const dTP = nTP - oTP;
  const dFP = nFP - oFP;
  if (dTP !== 0 || dFP !== 0) {
    const oPrec = oTP / (oTP + oFP) || 0;
    const nPrec = nTP / (nTP + nFP) || 0;
    const oRec = oTP / (oTP + oFN) || 0;
    const nRec = nTP / (nTP + nFN) || 0;
    const oF1 = 2*oPrec*oRec/(oPrec+oRec) || 0;
    const nF1 = 2*nPrec*nRec/(nPrec+nRec) || 0;
    console.log(`${file}:`);
    console.log(`  BEFORE: TP=${oTP} FP=${oFP} Prec=${(oPrec*100).toFixed(2)}% Rec=${(oRec*100).toFixed(2)}% F1=${(oF1*100).toFixed(2)}%`);
    console.log(`  AFTER:  TP=${nTP} FP=${nFP} Prec=${(nPrec*100).toFixed(2)}% Rec=${(nRec*100).toFixed(2)}% F1=${(nF1*100).toFixed(2)}%`);
    console.log(`  Delta:  TP ${dTP >= 0 ? '+' : ''}${dTP}, FP ${dFP >= 0 ? '+' : ''}${dFP}, Prec ${((nPrec-oPrec)*100).toFixed(3)}pp, F1 ${((nF1-oF1)*100).toFixed(3)}pp`);
    console.log();
    totalDTP += dTP;
    totalDFP += dFP;
  }
}

// Restore
PATTERNS[uaiIdx] = { ...origPattern };

console.log(`\n=== TOTALS ===`);
console.log(`Total TP delta: ${totalDTP >= 0 ? '+' : ''}${totalDTP}`);
console.log(`Total FP delta: ${totalDFP >= 0 ? '+' : ''}${totalDFP}`);
console.log(`Net: ${Math.abs(totalDFP)} fewer FP, ${Math.abs(totalDTP)} fewer TP`);
