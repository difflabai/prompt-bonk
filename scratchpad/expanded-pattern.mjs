// Check expanded task-hijack patterns for FP safety
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

// New candidate patterns
const newPatterns = [
  /identify and correct any grammatical errors in the following/i,
  /write a simple and brief summary of the following/i,
];

const allFiles = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl',
  'notinject.jsonl', 'protectai.jsonl', 'bipia.jsonl',
  'jayavibhav.jsonl', 'browsesafe-test.jsonl', 'open-prompt-injection.jsonl',
  'xxz224.jsonl', 'jailbreak-prompts.jsonl', 'spml-5k.jsonl',
  'gandalf-ignore.jsonl', 'gandalf-summarization.jsonl', 'yanismiraoui-multilingual.jsonl',
  'injecagent.jsonl', 'agentharm.jsonl', 'cyberseceval3.jsonl',
];

// Check benign FP for each new pattern
for (const pat of newPatterns) {
  let benignHits = 0;
  let totalBenign = 0;
  for (const file of allFiles) {
    const rows = loadJsonl(file);
    for (const row of rows) {
      if (row.label !== 0) continue;
      totalBenign++;
      if (pat.test(String(row.text || ''))) {
        benignHits++;
        console.log(`BENIGN match for ${pat}: "${String(row.text).slice(0, 120)}" (${file})`);
      }
    }
  }
  console.log(`Pattern ${pat}: ${benignHits} / ${totalBenign} benign hits\n`);
}

// Count total FN recovery with ALL patterns combined
const allPatterns = [
  /Write the sentiment conveyed by the following text/i,
  /(?:checks?\s+if\s+(?:a\s+)?message\s+contains?\s+hateful\s+contents)/i,
  /Write spam or not spam for whether the text below contains/i,
  /identify and correct any grammatical errors in the following/i,
  /write a simple and brief summary of the following/i,
];

const matchesAny = text => allPatterns.some(p => p.test(text));

// Global stats
let totalBenignHit = 0, totalBenign = 0;
for (const file of allFiles) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    totalBenign++;
    if (matchesAny(String(row.text || ''))) totalBenignHit++;
  }
}
console.log(`Combined: ${totalBenignHit} / ${totalBenign} benign FP\n`);

// Dataset-level impact
const targetDatasets = [
  { name: 'xxz224', file: 'xxz224.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'bipia', file: 'bipia.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
];

for (const ds of targetDatasets) {
  const rows = loadJsonl(ds.file);
  let tp = 0, fn = 0, fp = 0, tn = 0, newTP = 0, newFP = 0;

  for (const row of rows) {
    const text = String(row.text || '');
    const isInj = row.label === 1;
    const result = scan(text, { threshold: 0.50 });
    const predicted = !result.safe;
    const patternMatch = matchesAny(text);

    if (isInj && predicted) tp++;
    else if (isInj && !predicted) {
      fn++;
      if (patternMatch) newTP++;
    }
    else if (!isInj && predicted) fp++;
    else {
      tn++;
      if (patternMatch) newFP++;
    }
  }

  const totalInj = tp + fn;
  if (totalInj === 0) continue;
  const oldRecall = tp / totalInj;
  const newRecall = (tp + newTP) / totalInj;
  const oldPrec = tp / (tp + fp) || 0;
  const newPrec = (tp + newTP) / (tp + newTP + fp + newFP) || 0;

  if (newTP > 0 || newFP > 0) {
    console.log(`${ds.name}:`);
    console.log(`  Recall: ${(oldRecall*100).toFixed(1)}% -> ${(newRecall*100).toFixed(1)}% (+${newTP} TP)`);
    console.log(`  Precision: ${(oldPrec*100).toFixed(1)}% -> ${(newPrec*100).toFixed(1)}% (+${newFP} FP)`);
  }
}
