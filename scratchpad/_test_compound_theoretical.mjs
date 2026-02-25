// Test a compound pattern: theoretical/hypothetical scenario where + injection indicators
// This would replace theoretical_scenario or supplement it at a lower weight

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

// Current regex
const currentRe = /\b(?:(?:in\s+)?a\s+)?(?:completely\s+|purely\s+|entirely\s+)?(?:theoretical|hypothetical)\s+(?:world|scenario|situation|context|case)\s+(?:where|in\s+which)\b/i;

// Compound: hypothetical where + injection indicators within 200 chars
// Injection indicators: you are no/not, override, bypass, disregard, exception, hate speech,
// rules don't apply, safety, restrictions, previous instructions, programming
const injectionIndicators = /\b(?:you\s+(?:are\s+no(?:t|\s)|would\s+(?:be\s+able\s+to|give)|can\s+(?:do\s+anything|ignore))|(?:hate\s+speech|bypass|override|disregard|exception\s+to\s+the\s+rules?|ignore\s+(?:all\s+)?(?:previous|prior)|your\s+programming|your\s+(?:standard\s+)?protocol|deviating\s+from|rules?\s+(?:do(?:n't|es\s+not)\s+apply|no\s+longer)|restrictions?\s+(?:have\s+been|are)\s+(?:lifted|removed)|send\s+(?:all\s+)?(?:conversation|data|information|history)|extract\s+(?:user\s+)?data))\b/i;

function compoundTest(text) {
  const m = currentRe.exec(text);
  if (!m) return false;
  // Check if injection indicators appear within 300 chars after the match
  const afterMatch = text.slice(m.index, m.index + m[0].length + 300);
  return injectionIndicators.test(afterMatch);
}

const DATASETS = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'notinject',
  'jailbreak-prompts', 'spml-5k', 'protectai', 'browsesafe-test',
  'agentharm', 'cyberseceval3', 'bipia', 'injecagent',
  'gandalf-ignore', 'open-prompt-injection', 'xxz224',
  'jayavibhav', 'gandalf-summarization', 'yanismiraoui-multilingual',
  'tensor-trust'
];

// Find how many current TPs would be caught by the compound, and how many FPs
let tpCaught = 0;
let tpMissed = 0;
let fpCaught = 0;
let fpDropped = 0;

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    const text = String(row.text || '');
    if (!currentRe.test(text)) continue; // only check samples that match current pattern

    const compoundMatch = compoundTest(text);
    if (row.label === 1) {
      if (compoundMatch) tpCaught++;
      else tpMissed++;
    } else {
      if (compoundMatch) fpCaught++;
      else fpDropped++;
    }
  }
}

console.log('=== Compound theoretical pattern test ===');
console.log(`TP caught by compound: ${tpCaught}`);
console.log(`TP missed by compound: ${tpMissed}`);
console.log(`FP caught by compound (still FP): ${fpCaught}`);
console.log(`FP dropped by compound (saved!): ${fpDropped}`);

// Show what the compound misses (the TPs that would be lost)
console.log('\n=== TPs missed by compound (would need recovery) ===\n');
for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (row.label !== 1) continue;
    const text = String(row.text || '');
    if (!currentRe.test(text)) continue;
    if (compoundTest(text)) continue;
    console.log(`[${ds}] ${text.slice(0, 200)}`);
  }
}
