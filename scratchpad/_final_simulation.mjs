// Final simulation: theoretical_scenario weight 0.50 -> 0.45
// + new compound pattern theoretical_scenario_injection at weight 0.50
// that matches theoretical/hypothetical scenario + injection indicators within 500 chars
// Impact on ALL datasets

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

const theoreRe = /\b(?:(?:in\s+)?a\s+)?(?:completely\s+|purely\s+|entirely\s+)?(?:theoretical|hypothetical)\s+(?:world|scenario|situation|context|case)\s+(?:where|in\s+which)\b/i;

const injectionIndicatorsV2 = /\b(?:you\s+(?:are\s+no(?:t|\s)|would\s+(?:be\s+able\s+to|give)|can\s+(?:do\s+anything|ignore))|(?:hate\s+speech|bypass|override|disregard|exception\s+to\s+(?:the\s+)?rules?|ignore\s+(?:all\s+)?(?:previous|prior)|your\s+programming|your\s+(?:standard\s+)?protocol|deviating\s+from|rules?\s+(?:do(?:n't|es\s+not)\s+apply|no\s+longer)|restrictions?\s+(?:have\s+been|are)\s+(?:lifted|removed)|send\s+(?:all\s+)?(?:conversation|data|information|history)|extract\s+(?:user\s+)?data|breaks?\s+(?:professional\s+)?ethics|skip\s+(?:the\s+)?disclaimer|disregards?\s+safety|sharing?\s+(?:of\s+)?sensitive\s+data|prioritize\s+certain|not\s+necessarily\s+align|confidential\s+information|feel\s+the\s+rush|living\s+on\s+the\s+edge|over[- ]the[- ]counter\s+medication|(?:personal|medical|financial|legal)\s+(?:life\s+)?(?:choices?|advice|decisions?|opinion)))\b/i;

function compoundMatches(text) {
  const m = theoreRe.exec(text);
  if (!m) return false;
  const afterMatch = text.slice(m.index, m.index + m[0].length + 500);
  return injectionIndicatorsV2.test(afterMatch);
}

let totalTPLost = 0;
let totalFPSaved = 0;

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  if (rows.length === 0) continue;

  let tpLost = 0;
  let fpSaved = 0;

  for (const row of rows) {
    const text = String(row.text || '');
    const isInjection = row.label === 1;
    const result = scan(text, { threshold: THRESHOLD });
    if (result.safe) continue; // already below threshold

    const matchIds = result.matches.map(m => m.id);
    if (!matchIds.includes('theoretical_scenario')) continue; // not affected

    // Current: theoretical_scenario at 0.50
    // New: theoretical_scenario at 0.45, theoretical_scenario_injection at 0.50

    const otherMatches = result.matches.filter(m => m.id !== 'theoretical_scenario');
    const maxOtherWeight = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;
    const hasCompound = compoundMatches(text);

    // New effective max for theoretical patterns:
    const newTheoreticalWeight = hasCompound ? 0.50 : 0.45;

    // If the new weight is the same (0.50) or other patterns are >= 0.50: no change
    if (newTheoreticalWeight >= 0.50 || maxOtherWeight >= 0.50) continue;

    // The effective new max weight is max(newTheoreticalWeight, maxOtherWeight) = max(0.45, maxOtherWeight)
    // The old max was max(0.50, maxOtherWeight)
    // Score drops by the difference: 0.05 (since maxOtherWeight < 0.50)
    const scoreDrop = 0.05;
    const newScore = result.score - scoreDrop;

    if (newScore < THRESHOLD) {
      if (isInjection) {
        tpLost++;
      } else {
        fpSaved++;
      }
    }
  }

  if (tpLost > 0 || fpSaved > 0) {
    console.log(`${ds}: TP lost=${tpLost}, FP saved=${fpSaved}`);
  }
  totalTPLost += tpLost;
  totalFPSaved += fpSaved;
}

console.log(`\n=== FINAL TOTALS ===`);
console.log(`Total TP lost: ${totalTPLost}`);
console.log(`Total FP saved: ${totalFPSaved}`);
console.log(`Ratio: ${totalFPSaved}:${totalTPLost} (FP saved : TP lost)`);
console.log(`Net: ${totalFPSaved > totalTPLost ? 'SAFE' : totalTPLost > totalFPSaved ? 'RISKY' : 'NEUTRAL'}`);
