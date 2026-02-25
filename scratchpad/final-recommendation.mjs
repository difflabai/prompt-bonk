// Test the final recommended patterns
// Strategy: 2 patterns that generalize the task-hijack concept
//
// Pattern 1: "Write/Answer [classification-result] for whether the [text/message] [below/] contains"
//   Catches: spam detection, phishing detection, hateful content detection
//   This is a VERY specific indirect injection template
//
// Pattern 2: "Write the [analysis-type] conveyed/expressed by the following"
//   Catches: sentiment analysis re-assignment
//
// Pattern 3 (broader): Detect common task-reassignment phrases that appear ONLY in injections
//   "identify and correct ... errors in the following"
//   "write a ... summary of the following text"
//   "you are a tool that checks/classifies/detects"

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

// FINAL RECOMMENDED PATTERNS:

// Pattern A: Embedded classification task instruction
// Covers: "Write spam or not spam for whether...", "Answer spam or not spam for whether..."
// Also: "checks if a message contains hateful contents", "Write yes or no for whether..."
const embeddedClassification = /(?:write|answer|determine|classify)\s+(?:(?:spam|not\s+spam|yes|no|positive|negative|hateful|toxic)\s+or\s+(?:spam|not\s+spam|yes|no|positive|negative|hateful|toxic)\s+)?for\s+whether\s+(?:the\s+)?(?:text|message|content|input|sentence)\s+(?:below\s+)?(?:contains?|is\s+(?:spam|hateful|toxic|phishing))/i;

// Pattern B: Embedded sentiment/analysis task
// Covers: "Write the sentiment conveyed by the following text"
const embeddedAnalysis = /(?:write|determine|identify|classify)\s+the\s+(?:sentiment|emotion|tone|feeling|intent|category|topic|polarity)\s+(?:conveyed|expressed|present|found|detected)\s+(?:by|in)\s+the\s+following/i;

// Pattern C: "You are a tool that checks/classifies/detects"
// This is ALWAYS an injection -- legitimate prompts don't embed "you are a tool" in content
const youAreATool = /you\s+are\s+a\s+tool\s+that\s+(?:checks?|classif(?:y|ies)|determines?|detects?|identifies?|analyzes?|evaluates?)\s/i;

// Pattern D: Embedded grammar/summary task reassignment
// "identify and correct grammatical errors in the following"
// "write a brief summary of the following"
const embeddedTaskReassignment = /(?:identify\s+and\s+correct\s+(?:any\s+)?(?:grammatical\s+)?errors?\s+in\s+the\s+following|write\s+(?:a\s+)?(?:simple\s+(?:and\s+)?)?(?:brief\s+)?summary\s+of\s+the\s+following)/i;

const allPatterns = [embeddedClassification, embeddedAnalysis, youAreATool, embeddedTaskReassignment];
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

// Per-pattern FP and FN recovery breakdown
console.log('\n=== Per-pattern analysis ===');
for (let i = 0; i < allPatterns.length; i++) {
  const pat = allPatterns[i];
  let benignFP = 0;
  let xxzRecovered = 0, opiRecovered = 0;

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
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    if (result.safe && pat.test(text)) xxzRecovered++;
  }

  const opi = loadJsonl('open-prompt-injection.jsonl');
  for (const row of opi) {
    if (row.label !== 1) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    if (result.safe && pat.test(text)) opiRecovered++;
  }

  console.log(`Pattern ${i+1} (${pat.toString().slice(0, 50)}...):`);
  console.log(`  Benign FP: ${benignFP}, xxz224 recovered: ${xxzRecovered}, open-pi recovered: ${opiRecovered}`);
}

// Overall impact table
console.log('\n=== Overall impact ===');
const targetDatasets = [
  { name: 'xxz224', file: 'xxz224.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  { name: 'bipia', file: 'bipia.jsonl' },
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'gandalf-ignore', file: 'gandalf-ignore.jsonl' },
  { name: 'browsesafe-test', file: 'browsesafe-test.jsonl' },
  { name: 'injecagent', file: 'injecagent.jsonl' },
  { name: 'cyberseceval3', file: 'cyberseceval3.jsonl' },
  { name: 'notinject', file: 'notinject.jsonl' },
];

console.log('Dataset              | Old Recall | New Recall | Delta');
console.log('---------------------|------------|------------|------');
for (const ds of targetDatasets) {
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
  if (totalInj === 0 && newFP === 0) continue;
  const oldRecall = totalInj > 0 ? (tp/totalInj*100).toFixed(1) : 'N/A';
  const newRecall = totalInj > 0 ? ((tp+newTP)/totalInj*100).toFixed(1) : 'N/A';
  const delta = newTP > 0 ? `+${newTP} TP` : (newFP > 0 ? `+${newFP} FP` : 'same');
  console.log(`${ds.name.padEnd(22)}| ${String(oldRecall+'%').padEnd(11)}| ${String(newRecall+'%').padEnd(11)}| ${delta}`);
}
