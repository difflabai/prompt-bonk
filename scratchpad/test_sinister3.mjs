import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const re = /\bsinister\b/i;

// Load ALL benchmark datasets to check FP risk
const datasets = [
  ['jayavibhav', '/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl'],
  ['spml-5k', '/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl'],
  ['deepset-train', '/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl'],
  ['deepset-test', '/ml2/nanobot/projects/prompt-bonk/datasets/deepset-test.jsonl'],
  ['protectai', '/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl'],
  ['safeguard-test', '/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl'],
  ['yanismiraoui-multilingual', '/ml2/nanobot/projects/prompt-bonk/datasets/yanismiraoui-multilingual.jsonl'],
  ['browsesafe-test', '/ml2/nanobot/projects/prompt-bonk/datasets/browsesafe-test.jsonl'],
];

for (const [name, path] of datasets) {
  try {
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    const records = lines.map(l => JSON.parse(l));
    const benign = records.filter(r => r.label === 0 || r.label === '0' || r.expected === false);
    const injections = records.filter(r => r.label === 1 || r.label === '1' || r.expected === true);
    
    const textOf = r => r.text || r.input || '';
    
    const benignHits = benign.filter(r => re.test(textOf(r)));
    const injFN = injections.filter(r => {
      const s = scan(textOf(r)).score;
      return s < 0.5 && re.test(textOf(r));
    });
    
    // Check which benign hits would become FP at weight 0.40
    const newFP = benignHits.filter(r => {
      const s = scan(textOf(r)).score;
      const newScore = s < 0.35 ? 0.40 : (s + 0.40 * 0.15 / 1);
      return newScore >= 0.5;
    });
    
    if (benignHits.length > 0 || injFN.length > 0) {
      console.log(`${name}: benign_hits=${benignHits.length} new_FP=${newFP.length} FN_rescued=${injFN.length}`);
      if (newFP.length > 0) {
        newFP.forEach((r, i) => {
          const s = scan(textOf(r)).score;
          console.log(`  NEW FP [${i+1}] score=${s.toFixed(3)}: ${textOf(r).substring(0, 150)}`);
        });
      }
    }
  } catch(e) {
    console.log(`${name}: SKIP (${e.message.substring(0, 40)})`);
  }
}
