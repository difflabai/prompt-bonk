// Final impact analysis: combined pattern for task-hijack detection
// Two zero-FP patterns:
// 1. "Write the sentiment conveyed" (10k in xxz224, 0 benign)
// 2. "checks if a message contains hateful" (5k in xxz224, 0 benign)
// Plus: "Write spam or not spam for whether the text below" (3.7k in xxz224)
//       but need to confirm benign safety

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

// Combined pattern
const patterns = [
  /Write the sentiment conveyed by the following text/i,
  /(?:checks?\s+if\s+(?:a\s+)?message\s+contains?\s+hateful\s+contents)/i,
  /Write spam or not spam for whether the text below contains/i,
];

function matchesAny(text) {
  return patterns.some(p => p.test(text));
}

const allFiles = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl',
  'notinject.jsonl', 'protectai.jsonl', 'bipia.jsonl',
  'jayavibhav.jsonl', 'browsesafe-test.jsonl', 'open-prompt-injection.jsonl',
  'xxz224.jsonl', 'jailbreak-prompts.jsonl', 'spml-5k.jsonl',
  'gandalf-ignore.jsonl', 'gandalf-summarization.jsonl', 'yanismiraoui-multilingual.jsonl',
  'injecagent.jsonl', 'agentharm.jsonl', 'cyberseceval3.jsonl',
];

// Global FP check
let totalBenignHit = 0;
let totalBenign = 0;
for (const file of allFiles) {
  const rows = loadJsonl(file);
  let hit = 0;
  let benign = 0;
  for (const row of rows) {
    if (row.label !== 0) continue;
    benign++;
    totalBenign++;
    if (matchesAny(String(row.text || ''))) {
      hit++;
      totalBenignHit++;
    }
  }
  if (hit > 0) console.log(`  FP in ${file}: ${hit} / ${benign}`);
}
console.log(`Total benign FP: ${totalBenignHit} / ${totalBenign}\n`);

// Now check FN recovery per dataset
const targetDatasets = [
  { name: 'xxz224', file: 'xxz224.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'bipia', file: 'bipia.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
];

for (const ds of targetDatasets) {
  const rows = loadJsonl(ds.file);
  let tp = 0, fn = 0, fp = 0, tn = 0;
  let newTP = 0; // FNs that our pattern would recover

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
    else tn++;
  }

  const totalInj = tp + fn;
  const oldRecall = tp / totalInj;
  const newRecall = (tp + newTP) / totalInj;

  if (newTP > 0) {
    console.log(`${ds.name}: ${fn} FN, pattern recovers ${newTP} -> recall ${(oldRecall*100).toFixed(1)}% -> ${(newRecall*100).toFixed(1)}%`);
  }
}

// But wait - these are very xxz224-specific patterns.
// Let me think about a more GENERAL pattern that catches task re-assignment broadly.

// The real insight for a GENERAL pattern:
// All these injections follow the form: "Write/Answer/Determine [classification-task] for whether..."
// This is a VERY specific indirect injection signature.

// BUT: could a more general pattern help with other datasets too?
// Let me check: do any open-pi FNs contain OTHER task-hijack phrases?
console.log('\n=== open-pi FN task-hijack phrases NOT matching our patterns ===');
const opi = loadJsonl('open-prompt-injection.jsonl');
let opiOtherFN = 0;
const otherPhrases = {};
for (const row of opi) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (matchesAny(text)) continue;

  opiOtherFN++;
  // What's the injection pattern?
  const snippet = text.slice(-200).slice(0, 150);
  const m = snippet.match(/(Write|Answer|Translate|Determine|Classify)\s+.{0,60}/i);
  if (m) {
    const key = m[0].slice(0, 80);
    otherPhrases[key] = (otherPhrases[key] || 0) + 1;
  }
}
console.log(`Remaining open-pi FNs after pattern: ${opiOtherFN}`);
console.log('Top other phrases:');
for (const [k,v] of Object.entries(otherPhrases).sort((a,b) => b[1]-a[1]).slice(0, 20)) {
  console.log(`  ${v}x: "${k}"`);
}
