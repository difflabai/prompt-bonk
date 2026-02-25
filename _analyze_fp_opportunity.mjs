// Find the highest-leverage single change to reduce protectai FPs
// For each pattern/signal appearing in FPs, check: if we remove just that pattern/signal,
// how many FPs flip to TN, and how many TPs flip to FN?

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

const rows = loadJsonl('protectai.jsonl');

// Collect all FPs and their contributing patterns/signals
const fpContributors = {};

for (const row of rows) {
  const text = String(row.text || '');
  if (row.label !== 0) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue; // not FP

  // For each pattern match, check: is this pattern "necessary" for the FP?
  // i.e., if we remove this pattern's weight, does score drop below 0.50?
  for (const m of result.matches) {
    // Score without this pattern: recalculate
    const otherMatches = result.matches.filter(om => om.id !== m.id);
    const maxWeightWithout = otherMatches.length > 0 ? Math.max(...otherMatches.map(om => om.weight)) : 0;
    let scoreWithout = maxWeightWithout;
    if (otherMatches.length > 1) {
      const sorted = [...otherMatches].sort((a, b) => b.weight - a.weight);
      scoreWithout += sorted.slice(1).reduce((sum, om, i) => sum + om.weight * (0.15 / (i + 1)), 0);
    }
    scoreWithout += result.structural.score * (maxWeightWithout > 0 ? 0.3 : 1.0);
    scoreWithout = Math.min(Math.max(scoreWithout, 0), 1.0);

    if (scoreWithout < 0.50) {
      // This pattern is necessary for the FP
      if (!fpContributors[m.id]) fpContributors[m.id] = { fpSaved: 0, weight: m.weight };
      fpContributors[m.id].fpSaved++;
    }
  }

  // For structural signals
  for (const s of result.structural.signals) {
    // Check if structural is necessary
    const structuralWithout = result.structural.score - s.score;
    const maxWeight = result.matches.length > 0 ? Math.max(...result.matches.map(m => m.weight)) : 0;
    let scoreWithout = maxWeight;
    if (result.matches.length > 1) {
      const sorted = [...result.matches].sort((a, b) => b.weight - a.weight);
      scoreWithout += sorted.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
    }
    scoreWithout += structuralWithout * (maxWeight > 0 ? 0.3 : 1.0);
    scoreWithout = Math.min(Math.max(scoreWithout, 0), 1.0);

    if (scoreWithout < 0.50) {
      if (!fpContributors[s.id]) fpContributors[s.id] = { fpSaved: 0, weight: `structural ${s.score}` };
      fpContributors[s.id].fpSaved++;
    }
  }
}

console.log(`=== FP contributor analysis (patterns/signals necessary for FP) ===\n`);
const sorted = Object.entries(fpContributors).sort((a, b) => b[1].fpSaved - a[1].fpSaved);
for (const [id, data] of sorted) {
  console.log(`${id}: ${data.fpSaved} FPs depend on it (weight: ${data.weight})`);
}

// For the top contributors, check TP impact across key datasets
console.log(`\n=== TP impact of removing top contributor signals ===\n`);

const topIds = sorted.slice(0, 5).map(([id]) => id);
for (const targetId of topIds) {
  console.log(`--- ${targetId} ---`);

  // Check how many protectai TPs depend solely on this signal
  let tpNeedIt = 0;
  for (const row of rows) {
    const text = String(row.text || '');
    if (row.label !== 1) continue;
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;

    // Check if this pattern/signal is in the result
    const isPattern = result.matches.some(m => m.id === targetId);
    const isSignal = result.structural.signals.some(s => s.id === targetId);
    if (!isPattern && !isSignal) continue;

    // Would score drop below 0.50 without it?
    if (isPattern) {
      const otherMatches = result.matches.filter(m => m.id !== targetId);
      const maxW = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;
      let sw = maxW;
      if (otherMatches.length > 1) {
        const s = [...otherMatches].sort((a, b) => b.weight - a.weight);
        sw += s.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
      }
      sw += result.structural.score * (maxW > 0 ? 0.3 : 1.0);
      if (Math.min(sw, 1) < 0.50) tpNeedIt++;
    }
    if (isSignal) {
      const sig = result.structural.signals.find(s => s.id === targetId);
      const structWithout = result.structural.score - sig.score;
      const maxW = result.matches.length > 0 ? Math.max(...result.matches.map(m => m.weight)) : 0;
      let sw = maxW;
      if (result.matches.length > 1) {
        const s = [...result.matches].sort((a, b) => b.weight - a.weight);
        sw += s.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
      }
      sw += structWithout * (maxW > 0 ? 0.3 : 1.0);
      if (Math.min(sw, 1) < 0.50) tpNeedIt++;
    }
  }

  console.log(`  protectai: FP saved=${fpContributors[targetId].fpSaved}, TP would lose=${tpNeedIt}`);
}
