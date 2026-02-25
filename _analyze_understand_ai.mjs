// Analyze understand_ai_limitation pattern impact on protectai dataset
// Checks: how many TP/FP match this pattern, what happens if weight drops to 0.45

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

const rows = loadJsonl('protectai.jsonl');
console.log(`Loaded ${rows.length} protectai samples`);

// Find the pattern
const uaiPattern = PATTERNS.find(p => p.id === 'understand_ai_limitation');
console.log(`\nPattern: understand_ai_limitation`);
console.log(`  Weight: ${uaiPattern.weight}`);
console.log(`  Regex: ${uaiPattern.regex}`);

// Track samples that match understand_ai_limitation
const matchingTP = [];
const matchingFP = [];
const matchingTN = [];
const matchingFN = [];

for (const row of rows) {
  const text = String(row.text || '');
  const actualInjection = row.label === 1;
  const result = scan(text, { threshold: 0.50 });
  const predictedInjection = !result.safe;

  const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
  if (!matchesUAI) continue;

  const otherPatterns = result.matches.filter(m => m.id !== 'understand_ai_limitation');
  const otherPatternsAbove050 = otherPatterns.filter(m => m.weight >= 0.50);

  const entry = {
    text: text.slice(0, 150),
    score: result.score,
    structuralScore: result.structural.score,
    allMatchIds: result.matches.map(m => m.id),
    allMatchWeights: result.matches.map(m => `${m.id}(${m.weight})`),
    otherPatternsAbove050: otherPatternsAbove050.map(m => m.id),
    hasOtherPatternAbove050: otherPatternsAbove050.length > 0,
  };

  if (actualInjection && predictedInjection) matchingTP.push(entry);
  else if (!actualInjection && predictedInjection) matchingFP.push(entry);
  else if (!actualInjection && !predictedInjection) matchingTN.push(entry);
  else matchingFN.push(entry);
}

console.log(`\n=== Samples matching understand_ai_limitation ===`);
console.log(`  TP (injection, detected):      ${matchingTP.length}`);
console.log(`  FP (benign, flagged):           ${matchingFP.length}`);
console.log(`  TN (benign, not flagged):       ${matchingTN.length} (below threshold even with UAI match)`);
console.log(`  FN (injection, missed):         ${matchingFN.length}`);

console.log(`\n=== FP details (benign samples flagged, matching UAI) ===`);
for (const fp of matchingFP) {
  console.log(`  [score=${fp.score}] structural=${fp.structuralScore} patterns=${fp.allMatchWeights.join(', ')}`);
  console.log(`    other>=0.50: ${fp.otherPatternsAbove050.length > 0 ? fp.otherPatternsAbove050.join(', ') : 'NONE'}`);
  console.log(`    text: ${fp.text}`);
  console.log();
}

console.log(`\n=== TP details (injection samples detected, matching UAI) ===`);
for (const tp of matchingTP) {
  console.log(`  [score=${tp.score}] structural=${tp.structuralScore} patterns=${tp.allMatchWeights.join(', ')}`);
  console.log(`    other>=0.50: ${tp.otherPatternsAbove050.length > 0 ? tp.otherPatternsAbove050.join(', ') : 'NONE'}`);
  console.log(`    text: ${tp.text}`);
  console.log();
}

// Now simulate: what if understand_ai_limitation weight = 0.45?
console.log(`\n=== SIMULATION: understand_ai_limitation weight -> 0.45 ===`);

// Temporarily patch the weight
const origWeight = uaiPattern.weight;
uaiPattern.weight = 0.45;

let fpSaved = 0;
let tpLost = 0;
const tpLostDetails = [];
const fpSavedDetails = [];

for (const row of rows) {
  const text = String(row.text || '');
  const actualInjection = row.label === 1;

  // Original result (use cached knowledge: we know original weight produced the original result)
  uaiPattern.weight = origWeight;
  const origResult = scan(text, { threshold: 0.50 });
  const origPredicted = !origResult.safe;

  // New result with lowered weight
  uaiPattern.weight = 0.45;
  const newResult = scan(text, { threshold: 0.50 });
  const newPredicted = !newResult.safe;

  if (origPredicted && !newPredicted) {
    // Was flagged, now not flagged
    if (actualInjection) {
      tpLost++;
      tpLostDetails.push({
        text: text.slice(0, 150),
        origScore: origResult.score,
        newScore: newResult.score,
        matches: origResult.matches.map(m => `${m.id}(${m.weight})`),
        structural: origResult.structural.score,
      });
    } else {
      fpSaved++;
      fpSavedDetails.push({
        text: text.slice(0, 150),
        origScore: origResult.score,
        newScore: newResult.score,
        matches: origResult.matches.map(m => `${m.id}(${m.weight})`),
        structural: origResult.structural.score,
      });
    }
  }
}

// Restore original weight
uaiPattern.weight = origWeight;

console.log(`  FP saved: ${fpSaved}`);
console.log(`  TP lost:  ${tpLost}`);
console.log(`  Net improvement: ${fpSaved - tpLost} fewer errors`);

if (tpLostDetails.length > 0) {
  console.log(`\n  TP LOST details:`);
  for (const d of tpLostDetails) {
    console.log(`    [${d.origScore} -> ${d.newScore}] structural=${d.structural} patterns=${d.matches.join(', ')}`);
    console.log(`    text: ${d.text}`);
    console.log();
  }
}

if (fpSavedDetails.length > 0) {
  console.log(`\n  FP SAVED details:`);
  for (const d of fpSavedDetails) {
    console.log(`    [${d.origScore} -> ${d.newScore}] structural=${d.structural} patterns=${d.matches.join(', ')}`);
    console.log(`    text: ${d.text}`);
    console.log();
  }
}

// Also run full benchmark before/after to check cross-dataset impact
console.log(`\n=== FULL PROTECTAI BENCHMARK: before vs after ===`);
uaiPattern.weight = origWeight;
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

uaiPattern.weight = 0.45;
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
uaiPattern.weight = origWeight;

const origPrec = origTP / (origTP + origFP) || 0;
const newPrec = newTP / (newTP + newFP) || 0;
const origRec = origTP / (origTP + origFN) || 0;
const newRec = newTP / (newTP + newFN) || 0;
const origF1 = 2 * origPrec * origRec / (origPrec + origRec) || 0;
const newF1 = 2 * newPrec * newRec / (newPrec + newRec) || 0;

console.log(`  BEFORE: TP=${origTP} FP=${origFP} TN=${origTN} FN=${origFN} Prec=${(origPrec*100).toFixed(1)}% Rec=${(origRec*100).toFixed(1)}% F1=${(origF1*100).toFixed(1)}%`);
console.log(`  AFTER:  TP=${newTP} FP=${newFP} TN=${newTN} FN=${newFN} Prec=${(newPrec*100).toFixed(1)}% Rec=${(newRec*100).toFixed(1)}% F1=${(newF1*100).toFixed(1)}%`);
console.log(`  Delta:  TP ${newTP-origTP}, FP ${newFP-origFP}, Prec ${((newPrec-origPrec)*100).toFixed(2)}pp, Rec ${((newRec-origRec)*100).toFixed(2)}pp, F1 ${((newF1-origF1)*100).toFixed(2)}pp`);
