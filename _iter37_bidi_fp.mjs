// Check bidi_control matches across ALL datasets - benign only
// If zero benign FP at 0.50 weight, we can safely bump from 0.45 to 0.50

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

const allDatasets = [
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'notinject', file: 'notinject.jsonl' },
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'browsesafe-test', file: 'browsesafe-test.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'gandalf-ignore', file: 'gandalf-ignore.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'bipia', file: 'bipia.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
  { name: 'xxz224', file: 'xxz224.jsonl' },
  { name: 'injecagent', file: 'injecagent.jsonl' },
  { name: 'agentharm', file: 'agentharm.jsonl' },
  { name: 'cyberseceval3', file: 'cyberseceval3.jsonl' },
  { name: 'llmail-benign', file: 'llmail-benign.jsonl' },
  { name: 'enron-benign', file: 'enron-benign.jsonl' },
  { name: 'openwebtext-benign', file: 'openwebtext-benign.jsonl' },
  { name: 'llmail-inject', file: 'llmail-inject.jsonl' },
  { name: 'jailbreak-prompts', file: 'jailbreak-prompts.jsonl' },
  { name: 'jailbreak-class', file: 'jailbreak-class.jsonl' },
  { name: 'trustailab-wild', file: 'trustailab-wild.jsonl' },
  { name: 'satml-ctf', file: 'satml-ctf.jsonl' },
];

console.log('=== bidi_control match analysis across ALL datasets ===\n');

for (const ds of allDatasets) {
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) continue;

  let benignMatch = 0, benignMatchAbove45 = 0, injMatch = 0;
  const benignExamples = [];

  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const hasBidi = result.matches.some(m => m.id === 'bidi_control');
    if (!hasBidi) continue;

    if (row.label === 0) {
      benignMatch++;
      if (result.score > 0.45) benignMatchAbove45++;
      if (benignExamples.length < 3) {
        benignExamples.push({ score: result.score, text: text.slice(0, 100) });
      }
    } else {
      injMatch++;
    }
  }

  if (benignMatch > 0 || injMatch > 0) {
    console.log(`${ds.name}: benign=${benignMatch} (>0.45: ${benignMatchAbove45}), injection=${injMatch}`);
    for (const ex of benignExamples) {
      console.log(`  BENIGN [${ex.score}]: "${ex.text}..."`);
    }
  }
}

// Also: if bidi_control were at 0.50, what would the score be?
// Currently bidi_control is at 0.45. If we bump to 0.50, then
// single-match samples go from 0.45 to 0.50, crossing the threshold.
// Check: are there benign samples where bidi_control=0.45 is the only match
// and the total score would cross 0.50?
console.log('\n\n=== Simulated bidi_control at 0.50: FP impact ===\n');

const bs = loadJsonl('browsesafe-test.jsonl');
let newFP = 0, newTP = 0;
for (const row of bs) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });

  const hasBidi = result.matches.some(m => m.id === 'bidi_control');
  if (!hasBidi) continue;

  // Simulate: if bidi_control weight were 0.50 instead of 0.45
  // Recalculate score
  const bidiMatch = result.matches.find(m => m.id === 'bidi_control');
  const otherMatches = result.matches.filter(m => m.id !== 'bidi_control');

  let newMaxWeight = 0.50; // bidi_control at 0.50
  for (const m of otherMatches) {
    newMaxWeight = Math.max(newMaxWeight, m.weight);
  }

  let newScore = newMaxWeight;
  const allMatchesSorted = [...otherMatches, { ...bidiMatch, weight: 0.50 }].sort((a, b) => b.weight - a.weight);
  if (allMatchesSorted.length > 1) {
    const additionalWeight = allMatchesSorted.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
    newScore += additionalWeight;
  }
  if (newMaxWeight > 0) {
    newScore += result.structural.score * 0.3;
  } else {
    const lengthDampening = (text.length > 3000 && result.structural.score < 0.65) ? 0.6 : 1.0;
    newScore += result.structural.score * lengthDampening;
  }
  newScore = Math.min(Math.max(newScore, 0), 1.0);

  if (result.safe && newScore >= 0.50) {
    if (row.label === 0) {
      newFP++;
      console.log(`  NEW FP: [old=${result.score} -> new=${newScore.toFixed(3)}] "${text.slice(0, 100)}..."`);
    } else {
      newTP++;
    }
  }
}
console.log(`\nbidi_control 0.45->0.50: new TP=${newTP}, new FP=${newFP}`);

// Also check all other datasets for bidi_control benign FP
console.log('\n=== Other datasets: simulated bidi_control at 0.50 ===');
for (const ds of allDatasets) {
  if (ds.file === 'browsesafe-test.jsonl') continue;
  const rows = loadJsonl(ds.file);
  if (rows.length === 0) continue;

  let dsNewFP = 0;
  for (const row of rows) {
    if (row.label !== 0) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const hasBidi = result.matches.some(m => m.id === 'bidi_control');
    if (!hasBidi || !result.safe) continue;

    // Simulate bump to 0.50
    const bidiMatch = result.matches.find(m => m.id === 'bidi_control');
    const otherMatches = result.matches.filter(m => m.id !== 'bidi_control');
    let newMaxWeight = 0.50;
    for (const m of otherMatches) newMaxWeight = Math.max(newMaxWeight, m.weight);
    let newScore = newMaxWeight;
    const allMatchesSorted = [...otherMatches, { ...bidiMatch, weight: 0.50 }].sort((a, b) => b.weight - a.weight);
    if (allMatchesSorted.length > 1) {
      const additionalWeight = allMatchesSorted.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
      newScore += additionalWeight;
    }
    if (newMaxWeight > 0) {
      newScore += result.structural.score * 0.3;
    }
    newScore = Math.min(Math.max(newScore, 0), 1.0);

    if (newScore >= 0.50) {
      dsNewFP++;
      console.log(`  ${ds.name} NEW FP: [old=${result.score} -> new=${newScore.toFixed(3)}] "${text.slice(0, 100)}..."`);
    }
  }
}
