import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const re = /\bsinister\b/i;

// Load ALL benchmark datasets to check FP risk
const datasets = [
  ['jayavibhav', '/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'text', 'label'],
  ['spml-5k', '/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl', 'text', 'label'],
  ['deepset-train', '/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl', 'text', 'label'],
  ['deepset-test', '/ml2/nanobot/projects/prompt-bonk/datasets/deepset-test.jsonl', 'text', 'label'],
  ['protectai', '/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl', 'text', 'label'],
  ['safeguard-test', '/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl', 'text', 'label'],
  ['yanismiraoui', '/ml2/nanobot/projects/prompt-bonk/datasets/yanismiraoui.jsonl', 'text', 'label'],
];

for (const [name, path, textField, labelField] of datasets) {
  const lines = readFileSync(path, 'utf8').trim().split('\n');
  const records = lines.map(l => JSON.parse(l));
  const benign = records.filter(r => r[labelField] === 0 || r[labelField] === '0' || r[labelField] === false);
  const injections = records.filter(r => r[labelField] === 1 || r[labelField] === '1' || r[labelField] === true);
  
  const benignHits = benign.filter(r => re.test(r[textField] || ''));
  const injFN = injections.filter(r => {
    const s = scan(r[textField] || '').score;
    return s < 0.5 && re.test(r[textField] || '');
  });
  
  // Check which benign hits would become FP at weight 0.40
  const newFP = benignHits.filter(r => {
    const s = scan(r[textField] || '').score;
    // If sinister adds as stacking at 0.40: current_max + 0.40*0.15/1 OR becomes maxWeight 0.40
    const newScore = s === 0 ? 0.40 : (s + 0.40 * 0.15 / 1);
    return newScore >= 0.5;
  });
  
  if (benignHits.length > 0 || injFN.length > 0) {
    console.log(`${name}: benign_hits=${benignHits.length} new_FP=${newFP.length} FN_rescued=${injFN.length}`);
    if (newFP.length > 0) {
      newFP.forEach((r, i) => {
        const s = scan(r[textField] || '').score;
        console.log(`  NEW FP [${i+1}] score=${s.toFixed(3)}: ${(r[textField]||'').substring(0, 150)}`);
      });
    }
  }
}
