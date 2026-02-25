// Show ALL at-risk theoretical_scenario TPs (score exactly 0.50, sole match)
// across all datasets to understand what they look like
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

console.log(`=== ALL at-risk theoretical_scenario TPs (sole match, score=0.50) ===\n`);

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (row.label !== 1) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    const matchIds = result.matches.map(m => m.id);
    if (!matchIds.includes('theoretical_scenario')) continue;
    if (result.score > 0.50) continue; // only the ones at exactly 0.50

    console.log(`[${ds}] score=${result.score}`);
    console.log(text.slice(0, 400));
    console.log('---');
  }
}

// Also show ALL FPs across all datasets caused by theoretical_scenario
console.log(`\n=== ALL theoretical_scenario FPs across all datasets ===\n`);
for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (row.label !== 0) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    const matchIds = result.matches.map(m => m.id);
    if (!matchIds.includes('theoretical_scenario')) continue;

    console.log(`[${ds}] score=${result.score} matches=[${matchIds.join(',')}]`);
    console.log(text.slice(0, 400));
    console.log('---');
  }
}
