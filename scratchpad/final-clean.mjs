// Final clean analysis: Patterns 2, 3, 4 only (zero FP patterns)
// Plus a NARROWED Pattern 1 that avoids the "answer ... for whether" FP

import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
  } catch (e) { return []; }
}

// ZERO-FP patterns:
// Pattern A: Embedded sentiment/analysis re-assignment
const embeddedAnalysis = /(?:write|determine|identify|classify)\s+the\s+(?:sentiment|emotion|tone|feeling|intent|category|topic|polarity)\s+(?:conveyed|expressed|present|found|detected)\s+(?:by|in)\s+the\s+following/i;

// Pattern B: "You are a tool that checks/classifies" - always injection
const youAreATool = /you\s+are\s+a\s+tool\s+that\s+(?:checks?|classif(?:y|ies)|determines?|detects?|identifies?|analyzes?|evaluates?)\s/i;

// Pattern C: Embedded grammar/summary task
const embeddedTask = /(?:identify\s+and\s+correct\s+(?:any\s+)?(?:grammatical\s+)?errors?\s+in\s+the\s+following|write\s+(?:a\s+)?(?:simple\s+(?:and\s+)?)?(?:brief\s+)?summary\s+of\s+the\s+following)/i;

// Pattern D: NARROWED classification - only "Write" (not "answer") + "for whether the text below"
// This avoids "answer spam or not spam for whether the message contains" which appears in benign
const narrowClassification = /write\s+(?:(?:spam|not\s+spam|yes|no)\s+or\s+(?:spam|not\s+spam|yes|no)\s+)?for\s+whether\s+the\s+text\s+below\s+contains?/i;

const allPatterns = [embeddedAnalysis, youAreATool, embeddedTask, narrowClassification];
const matchesAny = text => allPatterns.some(p => p.test(text));

const allFiles = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl',
  'notinject.jsonl', 'protectai.jsonl', 'bipia.jsonl',
  'jayavibhav.jsonl', 'browsesafe-test.jsonl', 'open-prompt-injection.jsonl',
  'xxz224.jsonl', 'jailbreak-prompts.jsonl', 'spml-5k.jsonl',
  'gandalf-ignore.jsonl', 'gandalf-summarization.jsonl', 'yanismiraoui-multilingual.jsonl',
  'injecagent.jsonl', 'agentharm.jsonl', 'cyberseceval3.jsonl',
];

// Global FP check
let totalBenignHit = 0, totalBenign = 0;
for (const file of allFiles) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    totalBenign++;
    if (matchesAny(String(row.text || ''))) {
      totalBenignHit++;
      console.log(`FP: ${file}: "${String(row.text).slice(0, 120)}"`);
    }
  }
}
console.log(`\nTotal benign FP: ${totalBenignHit} / ${totalBenign}`);

// Per-pattern
for (let i = 0; i < allPatterns.length; i++) {
  const pat = allPatterns[i];
  let benignFP = 0, xxzRec = 0, opiRec = 0;
  for (const file of allFiles) {
    const rows = loadJsonl(file);
    for (const row of rows) {
      if (row.label !== 0) continue;
      if (pat.test(String(row.text || ''))) benignFP++;
    }
  }
  const xxz = loadJsonl('xxz224.jsonl');
  for (const row of xxz) {
    if (row.label !== 1) continue;
    const result = scan(String(row.text || ''), { threshold: 0.50 });
    if (result.safe && pat.test(String(row.text || ''))) xxzRec++;
  }
  const opi = loadJsonl('open-prompt-injection.jsonl');
  for (const row of opi) {
    if (row.label !== 1) continue;
    const result = scan(String(row.text || ''), { threshold: 0.50 });
    if (result.safe && pat.test(String(row.text || ''))) opiRec++;
  }
  console.log(`Pattern ${i+1}: FP=${benignFP}, xxz224=${xxzRec}, open-pi=${opiRec}`);
}

// Impact table
console.log('\nDataset              | Old Recall | New Recall | +TP  | +FP');
console.log('---------------------|------------|------------|------|-----');
for (const ds of [
  {name:'xxz224',file:'xxz224.jsonl'},
  {name:'open-pi',file:'open-prompt-injection.jsonl'},
]) {
  const rows = loadJsonl(ds.file);
  let tp = 0, fn = 0, fp = 0, tn = 0, newTP = 0, newFP = 0;
  for (const row of rows) {
    const text = String(row.text || '');
    const isInj = row.label === 1;
    const result = scan(text, { threshold: 0.50 });
    const predicted = !result.safe;
    const pm = matchesAny(text);
    if (isInj && predicted) tp++;
    else if (isInj && !predicted) { fn++; if (pm) newTP++; }
    else if (!isInj && predicted) fp++;
    else { tn++; if (pm) newFP++; }
  }
  const totalInj = tp + fn;
  console.log(`${ds.name.padEnd(22)}| ${(tp/totalInj*100).toFixed(1).padEnd(11)}| ${((tp+newTP)/totalInj*100).toFixed(1).padEnd(11)}| ${String(newTP).padEnd(5)}| ${newFP}`);
}
