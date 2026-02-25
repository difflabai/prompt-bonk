// Simulate: if theoretical_scenario weight goes from 0.50 to 0.45,
// how many TPs become FNs? And how many FPs become TNs?
// Do this across ALL datasets.
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

const DATASETS = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'notinject',
  'jailbreak-prompts', 'spml-5k', 'protectai', 'browsesafe-test',
  'agentharm', 'cyberseceval3', 'bipia', 'injecagent',
  'gandalf-ignore', 'open-prompt-injection', 'xxz224',
  'jayavibhav', 'gandalf-summarization', 'yanismiraoui-multilingual',
  'tensor-trust'
];

const THRESHOLD = 0.50;
const TARGET = 'theoretical_scenario';
const OLD_WEIGHT = 0.50;
const NEW_WEIGHT = 0.45;

console.log(`=== Simulating ${TARGET}: ${OLD_WEIGHT} -> ${NEW_WEIGHT} ===\n`);

let totalTPLost = 0;
let totalFPSaved = 0;

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  if (rows.length === 0) continue;

  let tpLost = 0;
  let fpSaved = 0;
  const lostDetails = [];

  for (const row of rows) {
    const text = String(row.text || '');
    const isInjection = row.label === 1;
    const result = scan(text, { threshold: THRESHOLD });
    const matchIds = result.matches.map(m => m.id);

    if (!matchIds.includes(TARGET)) continue;

    // This sample matches theoretical_scenario.
    // Check if reducing its weight from 0.50 to 0.45 would change the verdict.
    // The pattern IS the max weight (0.50), and if no other pattern >= 0.50 exists,
    // the new max would be 0.45 which is < threshold.
    // But we need to account for the exact score formula.

    // Simplification: if score == 0.50 and the only match is theoretical_scenario,
    // then lowering weight to 0.45 means score = 0.45 < 0.50 threshold.
    // If there are other matches, need to check more carefully.

    // Actually, let's be precise about the score change.
    // The current score uses theoretical_scenario at 0.50.
    // If we lower it to 0.45, the score changes.
    // Delta depends on whether it was maxWeight or an additional match.

    const targetMatch = result.matches.find(m => m.id === TARGET);
    const otherMatches = result.matches.filter(m => m.id !== TARGET);
    const maxOtherWeight = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;

    let scoreDrop;
    if (targetMatch.weight >= maxOtherWeight) {
      // theoretical_scenario is (one of) the top match(es)
      // New maxWeight would be max(0.45, maxOtherWeight)
      // If maxOtherWeight >= 0.45: theoretical_scenario becomes additional, barely changes
      // If maxOtherWeight < 0.45: new max = 0.45, drop = 0.05
      if (maxOtherWeight >= NEW_WEIGHT) {
        scoreDrop = 0; // essentially negligible
      } else {
        scoreDrop = OLD_WEIGHT - NEW_WEIGHT; // 0.05
      }
    } else {
      // theoretical_scenario was already an additional match, weight barely matters
      scoreDrop = 0;
    }

    const newScore = result.score - scoreDrop;

    if (result.score >= THRESHOLD && newScore < THRESHOLD) {
      // Verdict flips
      if (isInjection) {
        tpLost++;
        lostDetails.push({ score: result.score, newScore, text: text.slice(0, 120) });
      } else {
        fpSaved++;
      }
    }
  }

  if (tpLost > 0 || fpSaved > 0) {
    console.log(`${ds}: TP lost=${tpLost}, FP saved=${fpSaved}`);
    for (const d of lostDetails) {
      console.log(`  LOST TP: ${d.score}->${d.newScore.toFixed(3)} "${d.text}"`);
    }
  }
  totalTPLost += tpLost;
  totalFPSaved += fpSaved;
}

console.log(`\n=== TOTALS ===`);
console.log(`Total TP lost: ${totalTPLost}`);
console.log(`Total FP saved: ${totalFPSaved}`);
console.log(`Net: ${totalFPSaved > totalTPLost ? 'SAFE' : 'RISKY'} (${totalFPSaved} FP saved vs ${totalTPLost} TP lost)`);
