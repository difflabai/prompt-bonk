// Deep analysis of as_ai_confidential structural signal
// 2 FPs, 0 TP on protectai -- but what about cross-dataset?
// Also look at mixed_addressing

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

const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));

for (const targetSignal of ['as_ai_confidential', 'mixed_addressing']) {
  console.log(`\n=== ${targetSignal} across ALL datasets ===\n`);

  let globalTP = 0, globalFP = 0, globalTPdepends = 0, globalFPdepends = 0;

  for (const file of files.sort()) {
    const rows = loadJsonl(file);
    if (rows.length === 0) continue;

    let sigTP = 0, sigFP = 0, tpDepends = 0, fpDepends = 0;

    for (const row of rows) {
      const text = String(row.text || '');
      const actual = row.label === 1;
      const result = scan(text, { threshold: 0.50 });
      const pred = !result.safe;

      const hasSig = result.structural.signals.some(s => s.id === targetSignal);
      if (!hasSig) continue;

      if (actual && pred) {
        sigTP++;
        // Check dependency
        const sig = result.structural.signals.find(s => s.id === targetSignal);
        const structWithout = result.structural.score - sig.score;
        const maxW = result.matches.length > 0 ? Math.max(...result.matches.map(m => m.weight)) : 0;
        let sw = maxW;
        if (result.matches.length > 1) {
          const sorted = [...result.matches].sort((a, b) => b.weight - a.weight);
          sw += sorted.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
        }
        sw += structWithout * (maxW > 0 ? 0.3 : 1.0);
        if (Math.min(sw, 1) < 0.50) tpDepends++;
      } else if (!actual && pred) {
        sigFP++;
        const sig = result.structural.signals.find(s => s.id === targetSignal);
        const structWithout = result.structural.score - sig.score;
        const maxW = result.matches.length > 0 ? Math.max(...result.matches.map(m => m.weight)) : 0;
        let sw = maxW;
        if (result.matches.length > 1) {
          const sorted = [...result.matches].sort((a, b) => b.weight - a.weight);
          sw += sorted.slice(1).reduce((sum, m, i) => sum + m.weight * (0.15 / (i + 1)), 0);
        }
        sw += structWithout * (maxW > 0 ? 0.3 : 1.0);
        if (Math.min(sw, 1) < 0.50) fpDepends++;
      }
    }

    if (sigTP > 0 || sigFP > 0) {
      console.log(`${file}: TP=${sigTP} (depends=${tpDepends}) FP=${sigFP} (depends=${fpDepends})`);
      globalTP += sigTP;
      globalFP += sigFP;
      globalTPdepends += tpDepends;
      globalFPdepends += fpDepends;
    }
  }

  console.log(`\nTOTAL: TP=${globalTP} (depends=${globalTPdepends}) FP=${globalFP} (depends=${globalFPdepends})`);
  console.log(`Net if removed: -${globalFPdepends} FP, -${globalTPdepends} TP`);
}

// Now look at the 2 as_ai_confidential FPs in detail
console.log(`\n\n=== as_ai_confidential FP details ===\n`);
const protectai = loadJsonl('protectai.jsonl');
for (const row of protectai) {
  const text = String(row.text || '');
  if (row.label !== 0) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.safe) continue;
  const hasSig = result.structural.signals.some(s => s.id === 'as_ai_confidential');
  if (!hasSig) continue;

  console.log(`[score=${result.score}]`);
  console.log(`  patterns: ${result.matches.map(m => `${m.id}(${m.weight})`).join(', ') || 'NONE'}`);
  console.log(`  structural: ${result.structural.score}`);
  for (const s of result.structural.signals) {
    console.log(`    ${s.id}: ${s.score.toFixed(3)} - ${s.detail}`);
  }
  console.log(`  text: ${text.slice(0, 300)}`);
  console.log();
}
