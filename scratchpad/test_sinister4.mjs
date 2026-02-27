import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const re = /\bsinister\b/i;
const textOf = r => r.text || r.input || '';

const checkDataset = (name, path) => {
  try {
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    const records = lines.map(l => JSON.parse(l));
    const benign = records.filter(r => r.label === 0 || r.label === '0' || r.expected === false);
    const injections = records.filter(r => r.label === 1 || r.label === '1' || r.expected === true);
    
    const benignHits = benign.filter(r => re.test(textOf(r)));
    const injFN = injections.filter(r => {
      const t = textOf(r);
      if (!re.test(t)) return false;
      return scan(t).score < 0.5;
    });
    
    const newFP = benignHits.filter(r => {
      const s = scan(textOf(r)).score;
      const newScore = s < 0.35 ? 0.40 : (s + 0.40 * 0.15 / 1);
      return newScore >= 0.5;
    });
    
    if (benignHits.length > 0 || injFN.length > 0) {
      console.log(`${name}: benign_hits=${benignHits.length} new_FP=${newFP.length} FN_rescued=${injFN.length}`);
    } else {
      console.log(`${name}: no hits`);
    }
  } catch(e) {
    console.log(`${name}: ERROR`);
  }
};

// Only check smaller datasets
checkDataset('deepset-train', '/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl');
checkDataset('deepset-test', '/ml2/nanobot/projects/prompt-bonk/datasets/deepset-test.jsonl');
checkDataset('safeguard-test', '/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl');
checkDataset('yanismiraoui', '/ml2/nanobot/projects/prompt-bonk/datasets/yanismiraoui-multilingual.jsonl');
checkDataset('gandalf-sum', '/ml2/nanobot/projects/prompt-bonk/datasets/gandalf-summarization.jsonl');
checkDataset('injecagent', '/ml2/nanobot/projects/prompt-bonk/datasets/injecagent.jsonl');
console.log('Done');
