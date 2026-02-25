// Check if lowering theoretical_scenario (0.50) or understand_ai_limitation (0.52)
// to 0.45 would cause any TP to drop below threshold 0.50
// Safety check: find all TPs where one of these patterns is the SOLE or critical contributor

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
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

// All datasets used in benchmarks
const DATASETS = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'notinject',
  'jailbreak-prompts', 'spml-5k', 'protectai', 'browsesafe-test',
  'agentharm', 'cyberseceval3', 'bipia', 'injecagent',
  'gandalf-ignore', 'open-prompt-injection', 'xxz224',
  'jayavibhav', 'gandalf-summarization', 'yanismiraoui-multilingual',
  'tensor-trust'
];

const TARGET_PATTERNS = ['theoretical_scenario', 'understand_ai_limitation'];
const THRESHOLD = 0.50;

let totalChecked = 0;
let totalTP = 0;
const atRisk = { theoretical_scenario: [], understand_ai_limitation: [] };

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  if (rows.length === 0) continue;

  for (const row of rows) {
    const text = String(row.text || '');
    const isInjection = row.label === 1;
    if (!isInjection) continue; // only check TPs

    totalChecked++;
    const result = scan(text, { threshold: THRESHOLD });
    if (result.safe) continue; // it's a FN, not relevant

    totalTP++;

    const matchIds = result.matches.map(m => m.id);

    for (const targetId of TARGET_PATTERNS) {
      if (!matchIds.includes(targetId)) continue;

      // This TP matches our target pattern. Check if it's the sole/critical contributor.
      // The score formula: maxWeight + sum(additional * 0.15/(i+1)) + structural * factor
      // If this pattern IS the maxWeight and no other pattern >= 0.50 exists, lowering it is risky

      const targetMatch = result.matches.find(m => m.id === targetId);
      const otherMatches = result.matches.filter(m => m.id !== targetId);
      const maxOtherWeight = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;

      // Critical case: target pattern IS the highest-weight match
      // AND the score is close to threshold (within 0.10 margin)
      if (targetMatch && targetMatch.weight >= maxOtherWeight && result.score < 0.60) {
        atRisk[targetId].push({
          dataset: ds,
          score: result.score,
          targetWeight: targetMatch.weight,
          maxOtherWeight,
          otherMatchIds: otherMatches.map(m => m.id),
          text: text.slice(0, 150),
        });
      }
    }
  }
}

console.log(`\n=== Pattern Safety Check ===`);
console.log(`Total injection samples checked: ${totalChecked}`);
console.log(`Total TPs (detected): ${totalTP}`);

for (const targetId of TARGET_PATTERNS) {
  console.log(`\n--- ${targetId} ---`);
  console.log(`At-risk TPs (score < 0.60, pattern is top match): ${atRisk[targetId].length}`);
  for (const item of atRisk[targetId]) {
    console.log(`  [${item.dataset}] score=${item.score} targetWt=${item.targetWeight} maxOtherWt=${item.maxOtherWeight}`);
    console.log(`    others: ${item.otherMatchIds.join(', ') || '(none)'}`);
    console.log(`    text: ${item.text}`);
  }
}

// Also count total matches per pattern across all datasets
console.log(`\n=== Total pattern match counts across ALL datasets ===`);
const matchCounts = { theoretical_scenario: { tp: 0, total: 0 }, understand_ai_limitation: { tp: 0, total: 0 } };

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: THRESHOLD });
    const matchIds = result.matches.map(m => m.id);
    for (const targetId of TARGET_PATTERNS) {
      if (matchIds.includes(targetId)) {
        matchCounts[targetId].total++;
        if (row.label === 1) matchCounts[targetId].tp++;
      }
    }
  }
}

for (const targetId of TARGET_PATTERNS) {
  const c = matchCounts[targetId];
  console.log(`${targetId}: ${c.tp} TP matches, ${c.total} total matches (${c.total - c.tp} benign matches = FP contributors)`);
}
