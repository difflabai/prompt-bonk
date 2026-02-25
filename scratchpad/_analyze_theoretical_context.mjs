// Look at what comes AFTER "theoretical/hypothetical scenario where" in FP vs TP cases
// to see if there's a distinguishing regex pattern
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

const theoreRe = /\b(?:(?:in\s+)?a\s+)?(?:completely\s+|purely\s+|entirely\s+)?(?:theoretical|hypothetical)\s+(?:world|scenario|situation|context|case)\s+(?:where|in\s+which)\s+(.{0,200})/ig;

console.log('=== TP context after "theoretical/hypothetical ... where" ===\n');
let tpCount = 0;
for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (row.label !== 1) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    if (!result.matches.some(m => m.id === 'theoretical_scenario')) continue;

    theoreRe.lastIndex = 0;
    const m = theoreRe.exec(text);
    if (m) {
      tpCount++;
      console.log(`[TP ${tpCount}] "${m[1].slice(0, 200)}"`);
    }
  }
}

console.log('\n=== FP context after "theoretical/hypothetical ... where" ===\n');
let fpCount = 0;
for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (row.label !== 0) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    if (!result.matches.some(m => m.id === 'theoretical_scenario')) continue;

    theoreRe.lastIndex = 0;
    const m = theoreRe.exec(text);
    if (m) {
      fpCount++;
      console.log(`[FP ${fpCount}] "${m[1].slice(0, 200)}"`);
    }
  }
}
